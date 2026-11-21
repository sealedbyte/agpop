use crate::types::{
    CleartextMailPayload, SealedMessage, is_valid_email_addr, is_valid_logical_message_id,
    is_valid_receipt_value,
};
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

/// Compute 16-byte MAC for the 33-byte stateless UDP probe packet with `wake_mode`:
/// `MAC = SHA256(token_hash || id_le8 || timestamp_ms_le8 || wake_mode_u8)[0..16]`
pub fn compute_udp_probe_mac_with_wake(
    token_hash: &[u8; 32],
    id: u64,
    ts_ms: u64,
    wake_mode: u8,
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(token_hash);
    hasher.update(id.to_le_bytes());
    hasher.update(ts_ms.to_le_bytes());
    hasher.update([wake_mode]);
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
    if cleartext.signed_at_ms.is_some() {
        return Err("unexpected signed_at_ms field in wire payload");
    }
    if !cleartext.from.trim().eq_ignore_ascii_case(&aad_lower) {
        return Err("sender spoofing detected: inner payload 'from' does not match authenticated sender");
    }
    if !is_valid_email_addr(&aad_lower) {
        return Err("invalid or oversized sender 'from' address in payload");
    }
    cleartext.from = aad_lower;

    verify_cleartext_mail_fields_and_signatures(&cleartext, cleartext.received_at_ms)?;
    Ok(cleartext)
}

fn verify_cleartext_mail_fields_and_signatures(
    cleartext: &CleartextMailPayload,
    signed_ts_ms: u64,
) -> Result<(), &'static str> {
    let from_norm = cleartext.from.trim().to_ascii_lowercase();
    if !is_valid_email_addr(&from_norm) {
        return Err("invalid or oversized sender 'from' address in payload");
    }
    let to_norm = cleartext
        .to
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_ascii_lowercase();
    if !is_valid_email_addr(&to_norm) {
        return Err("invalid or oversized recipient 'to' address in payload");
    }

    if let Some(ref mid) = cleartext.message_id {
        if !is_valid_logical_message_id(mid) {
            return Err("invalid message_id format in payload");
        }
    }
    if let Some(ref irt) = cleartext.in_reply_to {
        if !is_valid_logical_message_id(irt) {
            return Err("invalid in_reply_to format in payload");
        }
    }
    if let Some(ref rcpt) = cleartext.receipt {
        if !is_valid_receipt_value(rcpt) {
            return Err("invalid receipt value in payload");
        }
        if cleartext.message_id.is_none() {
            return Err("receipt requires message_id");
        }
        if cleartext.in_reply_to.is_none() {
            return Err("receipt requires in_reply_to message_id");
        }
        if cleartext.message_id.as_deref() == cleartext.in_reply_to.as_deref() {
            return Err("receipt message_id must differ from in_reply_to");
        }
    }

    // Verify end-to-end Ed25519 sender signature over the original unmutated fields:
    // - Internal platform user emails (`mail.<root>` / `pop.<root>`) MUST carry a valid Ed25519 signature (no downgrade to unsigned).
    // - Only external SMTP senders and `mailer-daemon@<domain>` system notices may be unsigned.
    let is_internal_user_mail = match (from_norm.rsplit_once('@'), to_norm.rsplit_once('@')) {
        (Some((from_local, from_dom)), Some((_, to_dom))) => {
            is_dedicated_platform_domain(to_dom, from_dom)
                && !from_local.eq_ignore_ascii_case("mailer-daemon")
        }
        _ => false,
    };

    match (
        cleartext.sender_ed25519_pubkey.as_deref(),
        cleartext.sender_signature.as_deref(),
    ) {
        (Some(ed_pk), Some(sig)) => {
            let msg_bytes = if let Some(ref cc_to) = cleartext.cc_to {
                canonical_mail_signing_bytes_v2(
                    &cleartext.from,
                    &cleartext.to,
                    &cleartext.subject,
                    &cleartext.text,
                    signed_ts_ms,
                    cc_to,
                )
            } else {
                canonical_mail_signing_bytes(
                    &cleartext.from,
                    &cleartext.to,
                    &cleartext.subject,
                    &cleartext.text,
                    signed_ts_ms,
                )
            };
            if !verify_ed25519(ed_pk, &msg_bytes, sig) {
                return Err("sender Ed25519 signature verification failed");
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err("incomplete sender Ed25519 signature fields");
        }
        (None, None) => {
            if is_internal_user_mail {
                return Err("missing mandatory Ed25519 signature on internal user message");
            }
        }
    }

    let has_v3_meta = cleartext.message_id.is_some()
        || cleartext.in_reply_to.is_some()
        || cleartext.receipt.is_some();
    if has_v3_meta || cleartext.sender_v3_signature.is_some() {
        match (
            cleartext.sender_ed25519_pubkey.as_deref(),
            cleartext.sender_v3_signature.as_deref(),
        ) {
            (Some(ed_pk), Some(v3_sig)) => {
                let v3_bytes = canonical_mail_signing_bytes_v3(
                    &cleartext.from,
                    &cleartext.to,
                    &cleartext.subject,
                    &cleartext.text,
                    signed_ts_ms,
                    cleartext.cc_to.as_deref(),
                    cleartext.message_id.as_deref(),
                    cleartext.in_reply_to.as_deref(),
                    cleartext.receipt.as_deref(),
                );
                if !verify_ed25519(ed_pk, &v3_bytes, v3_sig) {
                    return Err("sender Ed25519 v3 signature verification failed");
                }
            }
            _ => {
                return Err("missing mandatory Ed25519 v3 signature for message metadata");
            }
        }
    }
    Ok(())
}

/// Re-verifies syntax, metadata invariants, and Ed25519 v1/v2/v3 signatures on a persisted
/// local `CleartextMailPayload` JSON file, using `signed_at_ms` when present (preserved before
/// `received_at_ms` was overwritten with the server receipt timestamp).
pub fn verify_persisted_cleartext_mail(cleartext: &CleartextMailPayload) -> Result<(), &'static str> {
    let signed_ts = cleartext.signed_at_ms.unwrap_or(cleartext.received_at_ms);
    verify_cleartext_mail_fields_and_signatures(cleartext, signed_ts)
}

/// Extracts the platform root domain from an AgentPop mailbox domain
/// (e.g., `mail.sealedbyte.com` -> `sealedbyte.com`, `pop.sealedbyte.com` -> `sealedbyte.com`).
pub fn platform_root_domain(domain: &str) -> String {
    let norm = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    for prefix in ["mail.", "pop."] {
        if let Some(rest) = norm.strip_prefix(prefix) {
            if rest.contains('.') {
                return rest.to_string();
            }
        }
    }
    norm
}

/// Returns `true` if `candidate_domain` is a dedicated AgentPop mailbox subdomain
/// (`mail.<root>` or `pop.<root>`) belonging to the same platform family as `own_domain`.
pub fn is_dedicated_platform_domain(own_domain: &str, candidate_domain: &str) -> bool {
    let own_norm = own_domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let cand_norm = candidate_domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if own_norm.is_empty() || cand_norm.is_empty() {
        return false;
    }
    let root = platform_root_domain(&own_norm);
    cand_norm == format!("mail.{root}") || cand_norm == format!("pop.{root}")
}

/// Differentiated error causes for recipient `to` validation so callers never
/// mistake a broken local identity configuration for a spoofed incoming message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientToError {
    LocalIdentityInvalid(&'static str),
    RecipientMismatch(&'static str),
}

/// Validates the locally configured mailbox email address from `identity.json`
/// before any network polling or message acknowledgement takes place.
pub fn validate_local_identity_email(own_email: Option<&str>) -> Result<String, &'static str> {
    let raw = own_email
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("missing local mailbox email address in identity")?;
    let norm = raw
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_ascii_lowercase();
    if !is_valid_email_addr(&norm) {
        return Err("invalid local mailbox email address in identity");
    }
    Ok(norm)
}

/// Validates that a message's `to` field is syntactically valid (`<= 254` bytes) and
/// matches the recipient mailbox's locally saved canonical email address (`own_email`).
pub fn verify_recipient_to_address(
    raw_to: &str,
    own_email: Option<&str>,
) -> Result<String, RecipientToError> {
    let saved_norm = validate_local_identity_email(own_email)
        .map_err(RecipientToError::LocalIdentityInvalid)?;
    let to_norm = raw_to
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_ascii_lowercase();
    if !is_valid_email_addr(&to_norm) {
        return Err(RecipientToError::RecipientMismatch(
            "recipient 'to' address is malformed or exceeds 254 bytes",
        ));
    }
    if to_norm != saved_norm {
        return Err(RecipientToError::RecipientMismatch(
            "recipient 'to' address does not match this mailbox",
        ));
    }
    Ok(to_norm)
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

pub fn canonical_mail_signing_bytes_v2(
    from: &str,
    to: &str,
    subject: &str,
    text: &str,
    received_at_ms: u64,
    cc_to: &str,
) -> Vec<u8> {
    let from_norm = from.trim().to_ascii_lowercase();
    let to_norm = to.trim().to_ascii_lowercase();
    let cc_norm = cc_to.trim().to_ascii_lowercase();
    let mut out = Vec::with_capacity(
        32 + from_norm.len() + to_norm.len() + subject.len() + text.len() + cc_norm.len(),
    );
    out.extend_from_slice(b"agpop-e2ee-sig-v2\0");
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
    out.extend_from_slice(&(cc_norm.len() as u64).to_le_bytes());
    out.extend_from_slice(cc_norm.as_bytes());
    out
}

/// Generates a random opaque logical message ID (`msg_<32 lowercase hex chars>`)
/// shared between a primary message and its Owner CC copy.
pub fn generate_logical_message_id() -> String {
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    format!("msg_{}", hex::encode(raw))
}

#[allow(clippy::too_many_arguments)]
pub fn canonical_mail_signing_bytes_v3(
    from: &str,
    to: &str,
    subject: &str,
    text: &str,
    received_at_ms: u64,
    cc_to: Option<&str>,
    message_id: Option<&str>,
    in_reply_to: Option<&str>,
    receipt: Option<&str>,
) -> Vec<u8> {
    let from_norm = from.trim().to_ascii_lowercase();
    let to_norm = to.trim().to_ascii_lowercase();
    let cc_norm = cc_to.map(|s| s.trim().to_ascii_lowercase());
    let mid_norm = message_id.map(str::trim);
    let irt_norm = in_reply_to.map(str::trim);
    let rcpt_norm = receipt.map(str::trim);

    let mut out = Vec::with_capacity(
        64 + from_norm.len() + to_norm.len() + subject.len() + text.len(),
    );
    out.extend_from_slice(b"agpop-e2ee-sig-v3\0");
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

    let push_opt = |buf: &mut Vec<u8>, opt: Option<&str>| match opt {
        None => buf.push(0u8),
        Some(v) => {
            buf.push(1u8);
            buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
            buf.extend_from_slice(v.as_bytes());
        }
    };
    push_opt(&mut out, cc_norm.as_deref());
    push_opt(&mut out, mid_norm);
    push_opt(&mut out, irt_norm);
    push_opt(&mut out, rcpt_norm);
    out
}

/// Signs a `CleartextMailPayload` end-to-end using the sender's deterministic Ed25519 keypair.
pub fn sign_cleartext_mail(seed_32: &[u8; 32], payload: &mut CleartextMailPayload) {
    let (_, ed_pk) = derive_ed25519_identity(seed_32);
    let msg_bytes = if let Some(ref cc_to) = payload.cc_to {
        canonical_mail_signing_bytes_v2(
            &payload.from,
            &payload.to,
            &payload.subject,
            &payload.text,
            payload.received_at_ms,
            cc_to,
        )
    } else {
        canonical_mail_signing_bytes(
            &payload.from,
            &payload.to,
            &payload.subject,
            &payload.text,
            payload.received_at_ms,
        )
    };
    let sig = sign_ed25519(seed_32, &msg_bytes);
    payload.sender_ed25519_pubkey = Some(ed_pk);
    payload.sender_signature = Some(sig);

    let has_v3_meta = payload.message_id.is_some()
        || payload.in_reply_to.is_some()
        || payload.receipt.is_some();
    if has_v3_meta {
        let v3_bytes = canonical_mail_signing_bytes_v3(
            &payload.from,
            &payload.to,
            &payload.subject,
            &payload.text,
            payload.received_at_ms,
            payload.cc_to.as_deref(),
            payload.message_id.as_deref(),
            payload.in_reply_to.as_deref(),
            payload.receipt.as_deref(),
        );
        payload.sender_v3_signature = Some(sign_ed25519(seed_32, &v3_bytes));
    } else {
        payload.sender_v3_signature = None;
    }
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

/// Maximum UTF-8 byte length for bounded notification subject fields (`512` bytes).
pub const SUBJECT_EXCERPT_MAX_BYTES: usize = 512;

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

/// Sanitizes a single-line notification field (`subject`, `from`, `to`) after signature verification:
/// - Strips `\0` and all control characters (replacing `\r`, `\n`, `\t` with a single space `' '`).
/// - Bounds the result to at most `max_bytes` UTF-8 bytes on a valid char boundary.
/// - Returns `(sanitized_excerpt, raw_total_bytes, excerpt_bytes, truncated)`.
pub fn sanitize_notification_inline(
    raw: &str,
    max_bytes: usize,
) -> (String, usize, usize, bool) {
    let raw_total_bytes = raw.len();
    let mut cleaned = String::with_capacity(raw_total_bytes.min(max_bytes + 64));
    for c in raw.chars() {
        if matches!(c, '\r' | '\n' | '\t') {
            cleaned.push(' ');
        } else if !c.is_control() {
            cleaned.push(c);
        }
    }
    let (excerpt, _cleaned_len, excerpt_bytes, cleaned_truncated) =
        utf8_safe_excerpt(&cleaned, max_bytes);
    let truncated = cleaned_truncated || raw_total_bytes > max_bytes;
    (excerpt, raw_total_bytes, excerpt_bytes, truncated)
}

/// Sanitizes a multi-line notification body excerpt after signature verification:
/// - Preserves `\n` and `\t`, strips `\0`, `\r`, and all other control characters so
///   `std::process::Command` (`--exec`) and JSON envelopes never contain interior NULs or terminal escapes.
/// - Bounds the result to at most `max_bytes` UTF-8 bytes on a valid char boundary.
/// - Returns `(sanitized_excerpt, raw_total_bytes, excerpt_bytes, truncated)`.
pub fn sanitize_notification_excerpt(
    raw: &str,
    max_bytes: usize,
) -> (String, usize, usize, bool) {
    let raw_total_bytes = raw.len();
    let mut cleaned = String::with_capacity(raw_total_bytes.min(max_bytes + 64));
    for c in raw.chars() {
        if c == '\n' || c == '\t' || !c.is_control() {
            cleaned.push(c);
        }
    }
    let (excerpt, _cleaned_len, excerpt_bytes, cleaned_truncated) =
        utf8_safe_excerpt(&cleaned, max_bytes);
    let truncated = cleaned_truncated || raw_total_bytes > max_bytes;
    (excerpt, raw_total_bytes, excerpt_bytes, truncated)
}

/// Default client-side Proof-of-Work difficulty for Free-tier registration (`26` leading zero bits,
/// ~67.1M single-block SHA-256 hashes, ~6-7s on 1 CPU core, verified by the server in 1 hash / ~0.1µs).
pub const REGISTER_POW_BITS: u32 = 26;

fn challenge_binding_digest(pubkey: &[u8; 32], challenge: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"agpop-ch-bind-v1");
    hasher.update(pubkey);
    hasher.update(challenge.trim().as_bytes());
    hasher.finalize().into()
}

#[inline]
fn register_challenge_pow_leading_zeros(
    binding_digest: &[u8; 32],
    pow_bits: u32,
    nonce: u64,
) -> u32 {
    let mut block = [0u8; 55];
    block[0..7].copy_from_slice(b"agpop02");
    block[7..39].copy_from_slice(binding_digest);
    block[39..43].copy_from_slice(&pow_bits.to_le_bytes());
    block[47..55].copy_from_slice(&nonce.to_le_bytes());
    let digest = Sha256::digest(block);
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]).leading_zeros()
}

/// Client-side Proof-of-Work solver for a server-signed stateless challenge (`pow_challenge`).
pub fn solve_register_challenge_pow(
    pubkey: &[u8; 32],
    challenge: &str,
    required_bits: u32,
) -> u64 {
    if required_bits == 0 {
        return 0;
    }
    let binding_digest = challenge_binding_digest(pubkey, challenge);
    let mut nonce = 0u64;
    loop {
        if register_challenge_pow_leading_zeros(&binding_digest, required_bits, nonce)
            >= required_bits
        {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

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

/// Client-side Proof-of-Work solver for legacy `pow_ts` flow (`agpop init`).
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
        let ts = 1_713_000_000_000u64;
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
    fn test_challenge_pow_solver_binding() {
        let pk = [0x42u8; 32];
        let ch = "ch1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let bits = 12;
        let nonce = solve_register_challenge_pow(&pk, ch, bits);
        let bd = challenge_binding_digest(&pk, ch);
        assert!(register_challenge_pow_leading_zeros(&bd, bits, nonce) >= bits);
        // Different pubkey or challenge string produces different binding digest
        let other_pk = [0x43u8; 32];
        let other_bd = challenge_binding_digest(&other_pk, ch);
        assert_ne!(bd, other_bd);
    }

    #[test]
    fn test_notification_sanitization_and_recipient_to_validation() {
        // 1. NUL (\0) and control characters are stripped after signature verification
        let raw_subj = "Alert\0Injected\r\nLine2\tTab\x1b[31mRed";
        let (clean_subj, raw_len, clean_len, trunc) =
            sanitize_notification_inline(raw_subj, SUBJECT_EXCERPT_MAX_BYTES);
        assert!(!clean_subj.contains('\0'));
        assert!(!clean_subj.contains('\r'));
        assert!(!clean_subj.contains('\n'));
        assert!(!clean_subj.contains('\x1b'));
        assert_eq!(raw_len, raw_subj.len());
        assert_eq!(clean_len, clean_subj.len());
        assert!(!trunc);

        // 2. Oversized subject (10 KB) is bounded to <= 512 bytes with truncated=true
        let huge_subj = "A".repeat(10_240);
        let (bounded_subj, total_s, exc_s, s_trunc) =
            sanitize_notification_inline(&huge_subj, SUBJECT_EXCERPT_MAX_BYTES);
        assert_eq!(bounded_subj.len(), 512);
        assert_eq!(total_s, 10_240);
        assert_eq!(exc_s, 512);
        assert!(s_trunc);

        // 3. Body excerpt preserves \n and \t, strips \0 and \r, and bounds to 512 bytes
        let raw_body = format!("Line 1\0with nul\r\nLine 2\twith tab\n{}", "B".repeat(2_000));
        let (bounded_body, total_b, exc_b, b_trunc) =
            sanitize_notification_excerpt(&raw_body, 512);
        assert!(!bounded_body.contains('\0'));
        assert!(!bounded_body.contains('\r'));
        assert!(bounded_body.starts_with("Line 1with nul\nLine 2\twith tab\n"));
        assert_eq!(bounded_body.len(), 512);
        assert_eq!(exc_b, 512);
        assert_eq!(total_b, raw_body.len());
        assert!(b_trunc);

        // 4. Recipient `to` validation checks syntax, <= 254 bytes, and local saved canonical mailbox ownership
        let primary_to = "bob-rxo5@mail.sealedbyte.com";
        assert!(verify_recipient_to_address(primary_to, Some(primary_to)).is_ok());
        // Deprecated numeric alias `<prefix>-<id>@<domain>` is rejected (only saved canonical short-tag address is valid)
        assert!(
            verify_recipient_to_address("bob-100000@mail.sealedbyte.com", Some(primary_to))
                .is_err()
        );
        // Mismatched mailbox is rejected
        assert!(
            verify_recipient_to_address("alice-k9x2@mail.sealedbyte.com", Some(primary_to))
                .is_err()
        );
        // Missing or invalid local saved email returns LocalIdentityInvalid (distinct from RecipientMismatch)
        assert!(matches!(
            verify_recipient_to_address(primary_to, None),
            Err(RecipientToError::LocalIdentityInvalid(_))
        ));
        assert!(matches!(
            verify_recipient_to_address(primary_to, Some("not-an-email")),
            Err(RecipientToError::LocalIdentityInvalid(_))
        ));
        // Oversized `to` (> 254 bytes) is rejected as RecipientMismatch
        let oversized_to = format!("{}@mail.sealedbyte.com", "a".repeat(300));
        assert!(matches!(
            verify_recipient_to_address(&oversized_to, Some(primary_to)),
            Err(RecipientToError::RecipientMismatch(_))
        ));
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
            ..Default::default()
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

    #[test]
    fn test_e2ee_sig_v2_cc_to_binding() {
        let sk_bytes = [7u8; 32];
        let sk = x25519_dalek::StaticSecret::from(sk_bytes);
        let pk_bytes = x25519_dalek::PublicKey::from(&sk).to_bytes();
        let sender = "agent-a@mail.sealedbyte.com";
        let owner = "owner@mail.sealedbyte.com";

        let mut cc_mail = CleartextMailPayload {
            from: sender.to_string(),
            to: owner.to_string(),
            subject: "CC".to_string(),
            text: "Hello".to_string(),
            received_at_ms: 12345,
            cc_to: Some("agent-b@mail.sealedbyte.com".to_string()),
            ..Default::default()
        };
        sign_cleartext_mail(&sk_bytes, &mut cc_mail);

        let mut pt = serde_json::to_vec(&cc_mail).unwrap();
        let (eph, nonce, ct) = seal_and_zeroize(&pk_bytes, &mut pt, sender).unwrap();
        let sealed = SealedMessage {
            msg_id: 1,
            received_at_ms: 12345,
            expires_at_ms: 99999,
            ephemeral_pubkey: eph,
            nonce,
            ciphertext_b64: ct,
            verified_from: sender.to_string(),
        };
        let dec = unseal_message(&sk_bytes, &sealed).unwrap();
        assert_eq!(dec.cc_to.as_deref(), Some("agent-b@mail.sealedbyte.com"));

        // Stripping or tampering cc_to invalidates sig-v2
        let mut tampered = cc_mail.clone();
        tampered.cc_to = None;
        let mut pt_bad = serde_json::to_vec(&tampered).unwrap();
        let (eph_b, nonce_b, ct_b) = seal_and_zeroize(&pk_bytes, &mut pt_bad, sender).unwrap();
        let sealed_bad = SealedMessage {
            msg_id: 2,
            received_at_ms: 12345,
            expires_at_ms: 99999,
            ephemeral_pubkey: eph_b,
            nonce: nonce_b,
            ciphertext_b64: ct_b,
            verified_from: sender.to_string(),
        };
        assert!(unseal_message(&sk_bytes, &sealed_bad).is_err());
    }

    #[test]
    fn test_e2ee_sig_v3_message_id_and_receipt_binding() {
        let sk_bytes = [8u8; 32];
        let sk = x25519_dalek::StaticSecret::from(sk_bytes);
        let pk_bytes = x25519_dalek::PublicKey::from(&sk).to_bytes();
        let sender = "agent-a@mail.sealedbyte.com";
        let rcpt = "agent-b@mail.sealedbyte.com";
        let owner = "owner@mail.sealedbyte.com";

        let seal_and_unseal = |clear: &CleartextMailPayload| -> Result<CleartextMailPayload, &'static str> {
            let mut pt = serde_json::to_vec(clear).unwrap();
            let (eph, nonce, ct) = seal_and_zeroize(&pk_bytes, &mut pt, sender).unwrap();
            let sealed = SealedMessage {
                msg_id: 1,
                received_at_ms: clear.received_at_ms,
                expires_at_ms: 999_999,
                ephemeral_pubkey: eph,
                nonce,
                ciphertext_b64: ct,
                verified_from: sender.to_string(),
            };
            unseal_message(&sk_bytes, &sealed)
        };

        let logical_id = generate_logical_message_id();
        let orig_id = "msg_00000000000000000000000000000001".to_string();
        assert!(logical_id.starts_with("msg_") && is_valid_logical_message_id(&logical_id));
        assert!(!is_valid_logical_message_id("latest"));
        assert!(!is_valid_logical_message_id("1"));
        assert!(!is_valid_logical_message_id("msg_orig_001"));
        assert!(!is_valid_logical_message_id("msg_0000000000000000000000000000000A"));
        assert!(!is_valid_logical_message_id("msg_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));

        // 1. Primary receipt mail carries both legacy v1 sender_signature and v3 signature
        let mut primary = CleartextMailPayload {
            from: sender.to_string(),
            to: rcpt.to_string(),
            subject: "Re: Task".to_string(),
            text: "On it".to_string(),
            received_at_ms: 54321,
            message_id: Some(logical_id.clone()),
            in_reply_to: Some(orig_id.clone()),
            receipt: Some("accepted".to_string()),
            ..Default::default()
        };
        sign_cleartext_mail(&sk_bytes, &mut primary);
        assert!(primary.sender_signature.is_some());
        assert!(primary.sender_v3_signature.is_some());

        let dec_p = seal_and_unseal(&primary).unwrap();
        assert_eq!(dec_p.message_id.as_deref(), Some(logical_id.as_str()));
        assert_eq!(dec_p.in_reply_to.as_deref(), Some(orig_id.as_str()));
        assert_eq!(dec_p.receipt.as_deref(), Some("accepted"));

        // 2. CC copy shares same logical_id, in_reply_to, and receipt, plus v2 + v3 signatures
        let mut cc_copy = CleartextMailPayload {
            from: sender.to_string(),
            to: owner.to_string(),
            subject: "Re: Task".to_string(),
            text: "On it".to_string(),
            received_at_ms: 54322,
            cc_to: Some(rcpt.to_string()),
            message_id: Some(logical_id.clone()),
            in_reply_to: Some(orig_id.clone()),
            receipt: Some("accepted".to_string()),
            ..Default::default()
        };
        sign_cleartext_mail(&sk_bytes, &mut cc_copy);
        let dec_cc = seal_and_unseal(&cc_copy).unwrap();
        assert_eq!(dec_cc.cc_to.as_deref(), Some(rcpt));
        assert_eq!(dec_cc.receipt.as_deref(), Some("accepted"));

        // 3. Tampering message_id, in_reply_to, or receipt fails v3 signature verification
        let mut t_mid = primary.clone();
        t_mid.message_id = Some("msg_ffffffffffffffffffffffffffffffff".to_string());
        assert!(seal_and_unseal(&t_mid).is_err());

        let mut t_irt = primary.clone();
        t_irt.in_reply_to = Some("msg_99999999999999999999999999999999".to_string());
        assert!(seal_and_unseal(&t_irt).is_err());

        let mut t_rcpt = primary.clone();
        t_rcpt.receipt = Some("seen".to_string());
        assert!(seal_and_unseal(&t_rcpt).is_err());

        // 4. Stripping sender_v3_signature while retaining metadata fails closed
        let mut stripped_v3 = primary.clone();
        stripped_v3.sender_v3_signature = None;
        assert!(seal_and_unseal(&stripped_v3).is_err());

        // 5. Receipt completeness invariants fail closed even if validly signed
        // 5a. Missing in_reply_to
        let mut no_irt = CleartextMailPayload {
            from: sender.to_string(),
            to: rcpt.to_string(),
            subject: "Re: Task".to_string(),
            text: "".to_string(),
            received_at_ms: 54323,
            message_id: Some(generate_logical_message_id()),
            receipt: Some("seen".to_string()),
            ..Default::default()
        };
        sign_cleartext_mail(&sk_bytes, &mut no_irt);
        assert!(seal_and_unseal(&no_irt).is_err());

        // 5b. Missing own message_id
        let mut no_mid = CleartextMailPayload {
            from: sender.to_string(),
            to: rcpt.to_string(),
            subject: "Re: Task".to_string(),
            text: "".to_string(),
            received_at_ms: 54324,
            in_reply_to: Some(orig_id.clone()),
            receipt: Some("seen".to_string()),
            ..Default::default()
        };
        sign_cleartext_mail(&sk_bytes, &mut no_mid);
        assert!(seal_and_unseal(&no_mid).is_err());

        // 5c. Self-referencing message_id == in_reply_to
        let mut self_ref = CleartextMailPayload {
            from: sender.to_string(),
            to: rcpt.to_string(),
            subject: "Re: Task".to_string(),
            text: "".to_string(),
            received_at_ms: 54325,
            message_id: Some(orig_id.clone()),
            in_reply_to: Some(orig_id),
            receipt: Some("seen".to_string()),
            ..Default::default()
        };
        sign_cleartext_mail(&sk_bytes, &mut self_ref);
        assert!(seal_and_unseal(&self_ref).is_err());

        // 5d. Invalid receipt state
        let mut bad_rcpt = primary.clone();
        bad_rcpt.receipt = Some("invalid".to_string());
        sign_cleartext_mail(&sk_bytes, &mut bad_rcpt);
        assert!(seal_and_unseal(&bad_rcpt).is_err());

        // 6. Wire payloads carrying local-only `signed_at_ms` must be rejected by `unseal_message`
        let mut wire_signed_at = primary.clone();
        wire_signed_at.signed_at_ms = Some(54321);
        assert!(seal_and_unseal(&wire_signed_at).is_err());

        // 7. Persisted local verification supports preserved `signed_at_ms` after server timestamp rewrite
        let mut persisted = dec_p.clone();
        persisted.signed_at_ms = Some(dec_p.received_at_ms);
        persisted.received_at_ms = dec_p.received_at_ms + 5_000;
        assert!(verify_persisted_cleartext_mail(&persisted).is_ok());

        let mut tamper_text = persisted.clone();
        tamper_text.text = "Tampered".to_string();
        assert!(verify_persisted_cleartext_mail(&tamper_text).is_err());

        let mut tamper_to = persisted.clone();
        tamper_to.to = "other-9999@mail.sealedbyte.com".to_string();
        assert!(verify_persisted_cleartext_mail(&tamper_to).is_err());

        let mut tamper_mid = persisted.clone();
        tamper_mid.message_id = Some("msg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
        assert!(verify_persisted_cleartext_mail(&tamper_mid).is_err());

        let mut tamper_ts = persisted;
        tamper_ts.signed_at_ms = Some(99_999);
        assert!(verify_persisted_cleartext_mail(&tamper_ts).is_err());
    }
}
