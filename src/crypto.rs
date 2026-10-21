use crate::types::{CleartextMailPayload, SealedMessage};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Compute constant-size SHA-256 hash of a Bearer token.
pub fn hash_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.trim().as_bytes());
    hasher.finalize().into()
}

/// Compute 16-byte MAC for the 32-byte stateless UDP probe packet:
/// `MAC = SHA256(token_hash || id_le8 || timestamp_ms_le8)[0..16]`
pub fn compute_udp_probe_mac(token_hash: &[u8; 32], id: u64, ts_ms: u64) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(token_hash);
    hasher.update(id.to_le_bytes());
    hasher.update(ts_ms.to_le_bytes());
    let digest = hasher.finalize();
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&digest[0..16]);
    mac
}

/// Zero-Knowledge RAM Encryption with mandatory sender AAD binding:
/// Encrypts `plaintext` using an ephemeral X25519 keypair + ChaCha20-Poly1305
/// toward `recipient_pubkey_bytes` with `verified_from` (lowercased) bound as AEAD
/// Associated Authenticated Data (AAD), then immediately zeroes out `plaintext`
/// and all ephemeral key material in RAM.
pub fn seal_and_zeroize(
    recipient_pubkey_bytes: &[u8; 32],
    plaintext: &mut Vec<u8>,
    verified_from: &str,
) -> Result<(String, String, String), &'static str> {
    let recipient_pk = PublicKey::from(*recipient_pubkey_bytes);
    let mut eph_sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut eph_sk_bytes);
    let eph_sk = StaticSecret::from(eph_sk_bytes);
    eph_sk_bytes.zeroize();

    let eph_pk = PublicKey::from(&eph_sk);
    let shared = eph_sk.diffie_hellman(&recipient_pk);

    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    hasher.update(eph_pk.as_bytes());
    hasher.update(recipient_pk.as_bytes());
    let mut sym_key: [u8; 32] = hasher.finalize().into();

    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    sym_key.zeroize();

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad_lower = verified_from.trim().to_ascii_lowercase();
    let payload = Payload {
        msg: plaintext.as_slice(),
        aad: aad_lower.as_bytes(),
    };
    let ciphertext = cipher.encrypt(nonce, payload).map_err(|_| {
        plaintext.zeroize();
        "encryption failed"
    })?;

    plaintext.zeroize();
    plaintext.clear();

    Ok((
        hex::encode(eph_pk.as_bytes()),
        hex::encode(nonce_bytes),
        B64.encode(ciphertext),
    ))
}

/// Client-side Decryption (used by `agpop` binary CLI SDK):
/// Decrypts a `SealedMessage` locally using the Agent's X25519 private key and
/// verifies the server-stamped `verified_from` via ChaCha20-Poly1305 AAD and inner JSON match.
pub fn unseal_message(
    agent_privkey_bytes: &[u8; 32],
    sealed: &SealedMessage,
) -> Result<CleartextMailPayload, &'static str> {
    let agent_sk = StaticSecret::from(*agent_privkey_bytes);
    let agent_pk = PublicKey::from(&agent_sk);

    let eph_vec = hex::decode(&sealed.ephemeral_pubkey).map_err(|_| "invalid ephemeral_pubkey")?;
    let eph_bytes: [u8; 32] = eph_vec.try_into().map_err(|_| "invalid ephemeral_pubkey len")?;
    let eph_pk = PublicKey::from(eph_bytes);

    let shared = agent_sk.diffie_hellman(&eph_pk);
    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    hasher.update(eph_pk.as_bytes());
    hasher.update(agent_pk.as_bytes());
    let mut sym_key: [u8; 32] = hasher.finalize().into();

    let cipher = ChaCha20Poly1305::new((&sym_key).into());
    sym_key.zeroize();

    let nonce_vec = hex::decode(&sealed.nonce).map_err(|_| "invalid nonce hex")?;
    if nonce_vec.len() != 12 {
        return Err("invalid nonce length");
    }
    let ciphertext = B64
        .decode(&sealed.ciphertext_b64)
        .map_err(|_| "invalid base64 ciphertext")?;

    let aad_lower = sealed.verified_from.trim().to_ascii_lowercase();
    let payload = Payload {
        msg: ciphertext.as_ref(),
        aad: aad_lower.as_bytes(),
    };
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_vec), payload)
        .map_err(|_| "decryption failed (wrong private key, forged sender AAD, or corrupted ciphertext)")?;

    let mut cleartext: CleartextMailPayload =
        serde_json::from_slice(&plaintext).map_err(|_| "invalid decrypted JSON payload")?;
    if !cleartext.from.trim().eq_ignore_ascii_case(&aad_lower) {
        return Err("sender spoofing detected: inner payload 'from' does not match authenticated sender");
    }
    cleartext.from = aad_lower;

    // Verify end-to-end Ed25519 sender signature:
    // - Internal same-domain user emails MUST carry a valid Ed25519 signature (no downgrade to unsigned).
    // - Only external SMTP senders and `mailer-daemon@<domain>` system notices may be unsigned.
    let is_internal_user_mail = match (
        cleartext.from.rsplit_once('@'),
        cleartext.to.trim().rsplit_once('@'),
    ) {
        (Some((from_local, from_dom)), Some((_, to_dom))) => {
            from_dom.eq_ignore_ascii_case(to_dom)
                && !from_local.eq_ignore_ascii_case("mailer-daemon")
        }
        _ => false,
    };

    match (
        cleartext.sender_ed25519_pubkey.as_deref(),
        cleartext.sender_signature.as_deref(),
    ) {
        (Some(pk_hex), Some(sig_hdr)) => {
            let signing_bytes = canonical_mail_signing_bytes(
                &cleartext.from,
                &cleartext.to,
                &cleartext.subject,
                &cleartext.text,
                cleartext.received_at_ms,
            );
            if !verify_ed25519(pk_hex, &signing_bytes, sig_hdr) {
                return Err("end-to-end Ed25519 sender signature verification failed");
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err("incomplete sender Ed25519 signature fields in payload");
        }
        (None, None) => {
            if is_internal_user_mail {
                return Err("missing mandatory Ed25519 signature on internal user message");
            }
        }
    }
    Ok(cleartext)
}

/// Builds canonical length-prefixed byte representation for end-to-end Ed25519 mail signing.
pub fn canonical_mail_signing_bytes(
    from: &str,
    to: &str,
    subject: &str,
    text: &str,
    received_at_ms: u64,
) -> Vec<u8> {
    let from_norm = from.trim().to_ascii_lowercase();
    let to_norm = to.trim().to_ascii_lowercase();
    let mut out = Vec::with_capacity(
        32 + from_norm.len() + to_norm.len() + subject.len() + text.len(),
    );
    out.extend_from_slice(b"agpop-e2ee-sig-v1\0");
    for field in [
        from_norm.as_bytes(),
        to_norm.as_bytes(),
        subject.as_bytes(),
        text.as_bytes(),
    ] {
        out.extend_from_slice(&(field.len() as u64).to_le_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&received_at_ms.to_le_bytes());
    out
}

/// Signs a `CleartextMailPayload` end-to-end using the sender's deterministic Ed25519 keypair.
pub fn sign_cleartext_mail(seed_32: &[u8; 32], payload: &mut CleartextMailPayload) {
    let (_, ed_pk) = derive_ed25519_identity(seed_32);
    let msg_bytes = canonical_mail_signing_bytes(
        &payload.from,
        &payload.to,
        &payload.subject,
        &payload.text,
        payload.received_at_ms,
    );
    let sig = sign_ed25519(seed_32, &msg_bytes);
    payload.sender_ed25519_pubkey = Some(ed_pk);
    payload.sender_signature = Some(sig);
}

/// Deterministically derives an RFC 8032 Ed25519 verifying public key (64 hex chars)
/// and `key_id` (first 16 hex chars) from the same 32-byte seed.
pub fn derive_ed25519_identity(seed_32: &[u8; 32]) -> (String, String) {
    use ed25519_dalek::SigningKey;
    let signing_key = SigningKey::from_bytes(seed_32);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = hex::encode(verifying_key.to_bytes());
    let key_id = pubkey_hex[0..16].to_string();
    (key_id, pubkey_hex)
}

/// Signs arbitrary message bytes using the deterministic Ed25519 signing key from `seed_32`.
/// Returns `"ed25519=<128-char hex signature>"`.
pub fn sign_ed25519(seed_32: &[u8; 32], message: &[u8]) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    let signing_key = SigningKey::from_bytes(seed_32);
    let sig = signing_key.sign(message);
    format!("ed25519={}", hex::encode(sig.to_bytes()))
}

/// Verifies an `"ed25519=<128-char hex>"` signature against a 64-char hex Ed25519 public key.
pub fn verify_ed25519(pubkey_hex: &str, message: &[u8], sig_header: &str) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let raw_sig_hex = sig_header.strip_prefix("ed25519=").unwrap_or(sig_header);
    let Ok(pk_vec) = hex::decode(pubkey_hex) else {
        return false;
    };
    let Ok(pk_bytes): Result<[u8; 32], _> = pk_vec.try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else {
        return false;
    };
    let Ok(sig_vec) = hex::decode(raw_sig_hex) else {
        return false;
    };
    let Ok(sig_bytes): Result<[u8; 64], _> = sig_vec.try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(message, &sig).is_ok()
}

/// Computes lowercase 64-char hex SHA-256 of arbitrary bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Generates a time-ordered RFC 9562 UUIDv7 string (`xxxxxxxx-xxxx-7xxx-xxxx-xxxxxxxxxxxx`).
pub fn generate_uuid_v7(ts_ms: u64) -> String {
    let mut rand_bytes = [0u8; 10];
    OsRng.fill_bytes(&mut rand_bytes);

    let mut b = [0u8; 16];
    let ts_be = ts_ms.to_be_bytes();
    b[0..6].copy_from_slice(&ts_be[2..8]); // 48-bit Unix epoch ms
    b[6] = 0x70 | (rand_bytes[0] & 0x0f); // version 7 (0111) + 4 bits rand_a
    b[7] = rand_bytes[1]; // remaining 8 bits of rand_a
    b[8] = 0x80 | (rand_bytes[2] & 0x3f); // variant RFC 4122 (10xx) + 6 bits rand_b
    b[9..16].copy_from_slice(&rand_bytes[3..10]); // remaining 56 bits of rand_b

    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&b[0..4]),
        hex::encode(&b[4..6]),
        hex::encode(&b[6..8]),
        hex::encode(&b[8..10]),
        hex::encode(&b[10..16])
    )
}

/// Formats a Unix millisecond timestamp as RFC3339 with explicit `+00:00` timezone offset
/// (`YYYY-MM-DDTHH:MM:SS.mmm+00:00`) using Howard Hinnant's civil-from-days algorithm.
pub fn format_rfc3339_utc(ts_ms: u64) -> String {
    let total_secs = (ts_ms / 1000) as i64;
    let millis = ts_ms % 1000;
    let days = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);

    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    // Civil date from days since 1970-01-01
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}+00:00")
}

/// Computes the 3-tuple excerpt metrics + UTF-8 safe excerpt string:
/// `(body_excerpt, body_total_bytes, excerpt_bytes, body_truncated)`
pub fn utf8_safe_excerpt(text: &str, max_bytes: usize) -> (String, usize, usize, bool) {
    let total_bytes = text.len();
    if total_bytes <= max_bytes {
        return (text.to_string(), total_bytes, total_bytes, false);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let slice = &text[..end];
    (slice.to_string(), total_bytes, end, true)
}

/// Default client-side Proof-of-Work difficulty for Free-tier registration (`26` leading zero bits,
/// ~67.1M single-block SHA-256 hashes, ~6-7s on 1 CPU core, verified by the server in 1 hash / ~0.1µs).
pub const REGISTER_POW_BITS: u32 = 26;

#[inline]
fn register_pow_leading_zeros(pubkey: &[u8; 32], ts_ms: u64, nonce: u64) -> u32 {
    let mut block = [0u8; 55];
    block[0..7].copy_from_slice(b"agpop01");
    block[7..39].copy_from_slice(pubkey);
    block[39..47].copy_from_slice(&ts_ms.to_le_bytes());
    block[47..55].copy_from_slice(&nonce.to_le_bytes());
    let digest = Sha256::digest(block);
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]).leading_zeros()
}

/// Client-side Proof-of-Work solver for `agpop init`.
pub fn solve_register_pow(pubkey: &[u8; 32], ts_ms: u64, required_bits: u32) -> u64 {
    if required_bits == 0 {
        return 0;
    }
    let mut nonce = 0u64;
    loop {
        if register_pow_leading_zeros(pubkey, ts_ms, nonce) >= required_bits {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock-free server-side Proof-of-Work verification (`O(1)` single SHA-256 hash) for roundtrip tests.
    fn verify_register_pow(
        pubkey: &[u8; 32],
        ts_ms: u64,
        nonce: u64,
        now_ms: u64,
        required_bits: u32,
    ) -> bool {
        if required_bits == 0 {
            return true;
        }
        if ts_ms > now_ms.saturating_add(5_000) {
            return false;
        }
        if now_ms.saturating_sub(ts_ms) > 90_000 {
            return false;
        }
        register_pow_leading_zeros(pubkey, ts_ms, nonce) >= required_bits
    }

    #[test]
    fn test_register_pow_roundtrip_and_anti_tamper() {
        let pk = [0x42u8; 32];
        let ts = 1_792_477_200_000u64;
        let bits = 16;
        let nonce = solve_register_pow(&pk, ts, bits);
        assert!(verify_register_pow(&pk, ts, nonce, ts + 5_000, bits));
        // Future timestamp beyond 5s drift is rejected (prevents window extension)
        assert!(!verify_register_pow(&pk, ts + 10_000, nonce, ts, bits));
        // Expired timestamp (> 90s) rejected
        assert!(!verify_register_pow(&pk, ts, nonce, ts + 95_000, bits));
        // Different pubkey cannot reuse the same nonce
        let other_pk = [0x43u8; 32];
        assert!(!verify_register_pow(&other_pk, ts, nonce, ts + 5_000, bits));
    }

    #[test]
    fn test_e2ee_aad_sender_binding_rejects_spoofing() {
        let sk_bytes = [0x11u8; 32];
        let sk = StaticSecret::from(sk_bytes);
        let pk_bytes = *PublicKey::from(&sk).as_bytes();

        let real_sender = "alice-rzo5@mail.sealedbyte.com";
        let sender_seed = [0x99u8; 32];
        // 1. Valid seal & unseal where inner `from`, `verified_from`, and Ed25519 signature match
        let mut cleartext = CleartextMailPayload {
            from: real_sender.to_string(),
            to: "bob-rye5@mail.sealedbyte.com".to_string(),
            subject: "E2EE Test".to_string(),
            text: "Hello Bob".to_string(),
            received_at_ms: 1000,
            ..Default::default()
        };
        sign_cleartext_mail(&sender_seed, &mut cleartext);
        let mut pt = serde_json::to_vec(&cleartext).unwrap();
        let (eph_pk, nonce, ct_b64) = seal_and_zeroize(&pk_bytes, &mut pt, real_sender).unwrap();
        let sealed = SealedMessage {
            msg_id: 1,
            received_at_ms: 1000,
            expires_at_ms: 2000,
            ephemeral_pubkey: eph_pk.clone(),
            nonce: nonce.clone(),
            ciphertext_b64: ct_b64.clone(),
            verified_from: real_sender.to_string(),
        };
        let dec = unseal_message(&sk_bytes, &sealed).unwrap();
        assert_eq!(dec.from, real_sender);
        assert_eq!(dec.text, "Hello Bob");
        assert!(dec.sender_signature.is_some());

        // 1b. Forged Ed25519 signature is rejected by unseal_message
        let mut forged_sig_mail = cleartext.clone();
        forged_sig_mail.text = "Tampered body".to_string();
        let mut pt_forged = serde_json::to_vec(&forged_sig_mail).unwrap();
        let (eph_f, nonce_f, ct_f) =
            seal_and_zeroize(&pk_bytes, &mut pt_forged, real_sender).unwrap();
        let sealed_forged = SealedMessage {
            msg_id: 99,
            received_at_ms: 1000,
            expires_at_ms: 2000,
            ephemeral_pubkey: eph_f,
            nonce: nonce_f,
            ciphertext_b64: ct_f,
            verified_from: real_sender.to_string(),
        };
        assert!(unseal_message(&sk_bytes, &sealed_forged).is_err());

        // 1c. Unsigned internal user message (downgrade attack) is rejected by unseal_message
        let unsigned_internal = CleartextMailPayload {
            from: real_sender.to_string(),
            to: "bob-rye5@mail.sealedbyte.com".to_string(),
            subject: "Unsigned downgrade".to_string(),
            text: "Forged by relay without Ed25519 sig".to_string(),
            received_at_ms: 1000,
            sender_ed25519_pubkey: None,
            sender_signature: None,
        };
        let mut pt_unsigned = serde_json::to_vec(&unsigned_internal).unwrap();
        let (eph_u, nonce_u, ct_u) =
            seal_and_zeroize(&pk_bytes, &mut pt_unsigned, real_sender).unwrap();
        let sealed_unsigned = SealedMessage {
            msg_id: 100,
            received_at_ms: 1000,
            expires_at_ms: 2000,
            ephemeral_pubkey: eph_u,
            nonce: nonce_u,
            ciphertext_b64: ct_u,
            verified_from: real_sender.to_string(),
        };
        assert!(unseal_message(&sk_bytes, &sealed_unsigned).is_err());

        // 2. If client encrypted with fake AAD ("ceo@apple.com"), server stamps real_sender -> AEAD tag fails
        let mut pt_fake_aad = serde_json::to_vec(&cleartext).unwrap();
        let (eph2, nonce2, ct2) =
            seal_and_zeroize(&pk_bytes, &mut pt_fake_aad, "ceo@apple.com").unwrap();
        let sealed_fake_aad = SealedMessage {
            msg_id: 2,
            received_at_ms: 1000,
            expires_at_ms: 2000,
            ephemeral_pubkey: eph2,
            nonce: nonce2,
            ciphertext_b64: ct2,
            verified_from: real_sender.to_string(),
        };
        assert!(unseal_message(&sk_bytes, &sealed_fake_aad).is_err());

        // 3. Even if client used real_sender as AAD, but put fake `from` inside JSON -> inner check rejects!
        let spoofed_inner = CleartextMailPayload {
            from: "ceo@apple.com".to_string(),
            to: "bob-rye5@mail.sealedbyte.com".to_string(),
            subject: "Spoof".to_string(),
            text: "Spoofed".to_string(),
            received_at_ms: 1000,
            ..Default::default()
        };
        let mut pt_spoof_inner = serde_json::to_vec(&spoofed_inner).unwrap();
        let (eph3, nonce3, ct3) =
            seal_and_zeroize(&pk_bytes, &mut pt_spoof_inner, real_sender).unwrap();
        let sealed_spoof_inner = SealedMessage {
            msg_id: 3,
            received_at_ms: 1000,
            expires_at_ms: 2000,
            ephemeral_pubkey: eph3,
            nonce: nonce3,
            ciphertext_b64: ct3,
            verified_from: real_sender.to_string(),
        };
        assert!(unseal_message(&sk_bytes, &sealed_spoof_inner).is_err());
    }
}



