use serde::{Deserialize, Serialize};

pub const UDP_PROBE_REQ_BYTES: usize = 32;
pub const UDP_PROBE_RESP_BYTES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    #[serde(alias = "free")]
    Free,
    #[serde(alias = "pro")]
    Pro,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TierLimits {
    pub max_whitelist: usize,
    pub max_msg_bytes: usize,
    pub msg_ttl_secs: u64,
    pub max_queue_len: usize,
    pub poll_cooldown_ms: u64,
    pub send_cooldown_ms: u64,
    pub ext_reply_cooldown_ms: u64,
    pub account_ttl_secs: u64,
}

/// Encrypted message envelope returned by `GET /v1/messages/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedMessage {
    pub msg_id: u64,
    pub received_at_ms: u64,
    pub expires_at_ms: u64,
    pub ephemeral_pubkey: String,
    pub nonce: String,
    pub ciphertext_b64: String,
    /// Server-authenticated canonical sender email address (`from`), bound as ChaCha20-Poly1305 AAD.
    pub verified_from: String,
}

/// Decrypted mail payload produced locally by the `agpop` binary CLI SDK.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CleartextMailPayload {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub text: String,
    pub received_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_ed25519_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_signature: Option<String>,
}

/// Validates an email address to prevent SMTP command or RFC 5322 header injection.
/// Rejects control characters, whitespace, angle brackets, and malformed local/domain parts.
pub fn is_valid_email_addr(addr: &str) -> bool {
    if addr.is_empty() || addr.len() > 254 {
        return false;
    }
    let Some((local, domain)) = addr.split_once('@') else {
        return false;
    };
    if local.is_empty() || local.len() > 64 || domain.is_empty() || domain.contains('@') {
        return false;
    }
    if local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return false;
    }
    let valid_local = local.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'.' | b'!'
                    | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'/'
                    | b'='
                    | b'?'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'{'
                    | b'|'
                    | b'}'
                    | b'~'
            )
    });
    let valid_domain = domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'));
    valid_local && valid_domain
}
