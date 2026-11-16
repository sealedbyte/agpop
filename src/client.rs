#![allow(clippy::collapsible_if)]

use crate::crypto::{
    REGISTER_POW_BITS, compute_udp_probe_mac_with_wake, derive_ed25519_identity, hash_token,
    is_dedicated_platform_domain, seal_and_zeroize, sha256_hex, sign_cleartext_mail,
    solve_register_challenge_pow, solve_register_pow, unseal_message, validate_local_identity_email,
};
use crate::types::{
    CleartextMailPayload, SealedMessage, Tier, TierLimits, UDP_PROBE_RESP_BYTES,
    UDP_PROBE_WAKE_REQ_BYTES, WakeMode,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const AGPOP_VERSION: &str = "0.9.1-beta";
pub const CURL_BIN: &str = if cfg!(windows) { "curl.exe" } else { "curl" };

pub static SERVER_HOST: RwLock<Option<String>> = RwLock::new(None);

pub fn set_server_host(host: &str) {
    if let Ok(mut g) = SERVER_HOST.write() {
        *g = Some(host.to_string());
    }
}

pub fn get_server_host() -> Option<String> {
    SERVER_HOST.read().ok().and_then(|g| g.clone())
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Serialize, Deserialize)]
pub struct RegisterChallengeResponse {
    pub challenge: String,
    pub pow_bits: u32,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
pub struct TicketResponse {
    pub status: String,
    pub ticket: String,
    pub ready_in_secs: u64,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct AccountReadyResponse {
    pub status: String,
    pub id: u64,
    pub email: String,
    pub token: String,
    pub tier: Tier,
    pub limits: TierLimits,
}

#[derive(Serialize, Deserialize)]
pub struct PollResponse {
    pub id: u64,
    pub count: usize,
    pub remaining_slots: u64,
    pub messages: Vec<SealedMessage>,
}

#[derive(Serialize, Deserialize)]
pub struct WhitelistResponse {
    pub active_slots: usize,
    pub max_slots: usize,
    pub entries: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct PubkeyLookupResponse {
    pub pubkey: String,
    pub sender_email: String,
    pub to: String,
    pub max_msg_bytes: usize,
}

#[derive(Serialize, Deserialize)]
pub struct SendResponse {
    pub status: String,
    pub msg_id: u64,
    #[serde(default)]
    pub from: String,
}

pub fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMemberEntry {
    pub id: u64,
    pub email: String,
    #[serde(default)]
    pub local_part: String,
    pub prefix: String,
    #[serde(default)]
    pub role: String,
    pub pubkey: String,
    pub max_msg_bytes: usize,
    #[serde(default = "default_true")]
    pub allows_team: bool,
    pub status: String,
    pub idle_secs: u64,
    #[serde(default)]
    pub unread_count: usize,
    #[serde(default)]
    pub max_queue_len: usize,
    #[serde(default)]
    pub wake_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff_age_secs: Option<u64>,
    #[serde(default)]
    pub os_arch: String,
    #[serde(default)]
    pub runtime: String,
    #[serde(default)]
    pub host_tag: String,
    #[serde(default)]
    pub attrs: BTreeMap<String, String>,
    pub is_self: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamDirectoryResponse {
    pub team_name: String,
    #[serde(default)]
    pub key_hint: String,
    pub self_id: u64,
    pub self_email: String,
    pub member_count: usize,
    pub members: Vec<TeamMemberEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamCardPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_arch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_attrs: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unset_attrs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clear_attrs: Option<bool>,
}

impl TeamCardPatch {
    pub fn is_empty(&self) -> bool {
        self.role.is_none()
            && self.os_arch.is_none()
            && self.runtime.is_none()
            && self.host_tag.is_none()
            && self.set_attrs.as_ref().is_none_or(BTreeMap::is_empty)
            && self.unset_attrs.as_ref().is_none_or(Vec::is_empty)
            && self.clear_attrs != Some(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalIdentity {
    pub prefix: String,
    pub privkey_hex: String,
    pub pubkey_hex: String,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub ed25519_pubkey_hex: Option<String>,
    pub ticket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reg_auth_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_team_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_team_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_team_card: Option<TeamCardPatch>,
    pub id: Option<u64>,
    pub email: Option<String>,
    pub token: Option<String>,
    #[serde(default)]
    pub allow_list: Option<Vec<String>>,
}

pub fn load_identity(path: &Path) -> Result<LocalIdentity, &'static str> {
    let raw = fs::read_to_string(path).map_err(|_| {
        "identity not initialized in current directory (run `agpop init` or pass `--config <path>`)"
    })?;
    let mut ident: LocalIdentity =
        serde_json::from_str(&raw).map_err(|_| "corrupted identity.json")?;
    let mut dirty = false;
    // Backfill Ed25519 key_id and verifying public key deterministically from the 32-byte seed
    if ident.key_id.is_none() || ident.ed25519_pubkey_hex.is_none() {
        if let Ok(mut vec) = hex::decode(&ident.privkey_hex) {
            if let Ok(mut seed) = <[u8; 32]>::try_from(vec.as_slice()) {
                let (kid, ed_pk) = derive_ed25519_identity(&seed);
                seed.zeroize();
                ident.key_id = Some(kid);
                ident.ed25519_pubkey_hex = Some(ed_pk);
                dirty = true;
            }
            vec.zeroize();
        }
    }
    if dirty {
        let _ = save_identity(path, &ident);
    }
    Ok(ident)
}

pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

pub fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    Ok(())
}

/// Writes a decrypted mail message to `inbox_dir` without ever truncating or overwriting
/// a pre-existing different message file.
pub fn write_new_private_mail_file(
    inbox_dir: &Path,
    server_received_at_ms: u64,
    msg_id: u64,
    bytes: &[u8],
) -> std::io::Result<String> {
    ensure_private_dir(inbox_dir)?;
    let primary_name = format!("mail-{server_received_at_ms}-id{msg_id}.json");
    let primary_path = inbox_dir.join(&primary_name);

    match create_exclusive_private_file(&primary_path, bytes) {
        Ok(()) => return Ok(primary_name),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if let Ok(existing) = fs::read(&primary_path) {
                if sha256_hex(&existing) == sha256_hex(bytes) {
                    return Ok(primary_name);
                }
            }
        }
        Err(e) => return Err(e),
    }

    for _ in 0..8 {
        let suffix = OsRng.next_u32();
        let alt_name = format!("mail-{server_received_at_ms}-id{msg_id}-{suffix:08x}.json");
        let alt_path = inbox_dir.join(&alt_name);
        match create_exclusive_private_file(&alt_path, bytes) {
            Ok(()) => return Ok(alt_name),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "unable to allocate unique mail file name without overwriting",
    ))
}

pub fn resolve_absolute_mail_file_path(inbox_dir: &Path, rel_path: &str) -> PathBuf {
    let joined = inbox_dir.join(rel_path);
    if let Ok(canon) = fs::canonicalize(&joined) {
        #[cfg(windows)]
        {
            let s = canon.to_string_lossy();
            if let Some(stripped) = s.strip_prefix(r"\\?\") {
                return PathBuf::from(stripped);
            }
        }
        return canon;
    }
    if joined.is_absolute() {
        joined
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(joined)
    }
}

pub fn create_exclusive_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityStateError {
    Rejected(String),
    StateIo(String),
}

impl std::fmt::Display for SecurityStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityStateError::Rejected(msg) | SecurityStateError::StateIo(msg) => {
                write!(f, "{msg}")
            }
        }
    }
}

pub struct StateLockGuard {
    lock_path: PathBuf,
}

impl Drop for StateLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

pub fn acquire_state_file_lock(
    dir: &Path,
    lock_name: &str,
) -> Result<StateLockGuard, SecurityStateError> {
    acquire_state_file_lock_with_retries(dir, lock_name, 400)
}

pub fn acquire_state_file_lock_with_retries(
    dir: &Path,
    lock_name: &str,
    max_attempts: usize,
) -> Result<StateLockGuard, SecurityStateError> {
    ensure_private_dir(dir).map_err(|e| {
        SecurityStateError::StateIo(format!(
            "failed to create state directory '{}': {e}",
            dir.display()
        ))
    })?;
    let lock_path = dir.join(format!("{lock_name}.lock"));
    let pid_bytes = std::process::id().to_string().into_bytes();

    for _ in 0..max_attempts.max(1) {
        match create_exclusive_private_file(&lock_path, &pid_bytes) {
            Ok(()) => return Ok(StateLockGuard { lock_path }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                return Err(SecurityStateError::StateIo(format!(
                    "failed to acquire lock '{}': {e}",
                    lock_path.display()
                )));
            }
        }
    }
    Err(SecurityStateError::StateIo(format!(
        "timed out acquiring state file lock '{}'",
        lock_path.display()
    )))
}

pub fn write_private_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), SecurityStateError> {
    let parent = path.parent().unwrap_or_else(|| Path::new(".agpop"));
    ensure_private_dir(parent).map_err(|e| {
        SecurityStateError::StateIo(format!(
            "failed to create directory '{}': {e}",
            parent.display()
        ))
    })?;
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("state.json");
    let tmp_path = parent.join(format!(
        ".{fname}.tmp.{}.{:08x}",
        std::process::id(),
        OsRng.next_u32()
    ));
    create_exclusive_private_file(&tmp_path, bytes).map_err(|e| {
        SecurityStateError::StateIo(format!(
            "failed to write temporary state file '{}': {e}",
            tmp_path.display()
        ))
    })?;
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(SecurityStateError::StateIo(format!(
            "failed to atomically replace '{}': {e}",
            path.display()
        )));
    }
    Ok(())
}

pub fn load_known_peers_checked(
    peers_path: &Path,
) -> Result<BTreeMap<String, String>, SecurityStateError> {
    match fs::read_to_string(peers_path) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| {
            SecurityStateError::StateIo(format!(
                "corrupted TOFU state file '{}': {e}",
                peers_path.display()
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(SecurityStateError::StateIo(format!(
            "failed to read TOFU state file '{}': {e}",
            peers_path.display()
        ))),
    }
}

pub fn has_pinned_peer_key(
    config_path: &Path,
    peer_id: &str,
) -> Result<bool, SecurityStateError> {
    let dir = config_path.parent().unwrap_or_else(|| Path::new(".agpop"));
    let _lock = acquire_state_file_lock(dir, "known_peers")?;
    let peers_path = dir.join("known_peers.json");
    let key = peer_id.trim().to_ascii_lowercase();
    if key.is_empty() {
        return Ok(false);
    }
    let map = load_known_peers_checked(&peers_path)?;
    Ok(map.contains_key(&key) || map.contains_key(&format!("ed25519:{key}")))
}

pub fn verify_or_pin_peer_key(
    config_path: &Path,
    peer_id: &str,
    pubkey_hex: &str,
) -> Result<(), SecurityStateError> {
    let dir = config_path.parent().unwrap_or_else(|| Path::new(".agpop"));
    let _lock = acquire_state_file_lock(dir, "known_peers")?;
    let peers_path = dir.join("known_peers.json");
    let key = peer_id.trim().to_ascii_lowercase();
    let clean_pk = pubkey_hex.trim().to_ascii_lowercase();
    if key.is_empty() || clean_pk.is_empty() {
        return Err(SecurityStateError::Rejected(
            "empty peer identifier or public key in TOFU check".to_string(),
        ));
    }

    let mut map = load_known_peers_checked(&peers_path)?;
    if let Some(pinned) = map.get(&key) {
        if pinned != &clean_pk {
            return Err(SecurityStateError::Rejected(format!(
                "TOFU key mismatch for '{key}': pinned={pinned}, received={clean_pk} (refusing potential MITM key substitution)"
            )));
        }
        return Ok(());
    }

    map.insert(key, clean_pk);
    let bytes = serde_json::to_vec_pretty(&map)
        .map_err(|e| SecurityStateError::StateIo(format!("failed to serialize known_peers: {e}")))?;
    write_private_file_atomic(&peers_path, &bytes)
}

pub fn verify_or_pin_sender_identity(
    config_path: &Path,
    own_domain: &str,
    from_addr: &str,
    sender_ed25519_pubkey: Option<&str>,
) -> Result<(), SecurityStateError> {
    let from_clean = from_addr.trim().to_ascii_lowercase();
    let own_dom_clean = own_domain.trim().to_ascii_lowercase();
    let is_internal_user = from_clean
        .rsplit_once('@')
        .map(|(from_local, from_dom)| {
            is_dedicated_platform_domain(&own_dom_clean, from_dom)
                && !from_local.eq_ignore_ascii_case("mailer-daemon")
        })
        .unwrap_or(false);
    let ed_key = format!("ed25519:{from_clean}");

    if let Some(pk) = sender_ed25519_pubkey {
        return verify_or_pin_peer_key(config_path, &ed_key, pk);
    }

    if is_internal_user {
        return Err(SecurityStateError::Rejected(format!(
            "unsigned internal user message from '{from_clean}' rejected"
        )));
    }

    let dir = config_path.parent().unwrap_or_else(|| Path::new(".agpop"));
    let _lock = acquire_state_file_lock(dir, "known_peers")?;
    let peers_path = dir.join("known_peers.json");
    let map = load_known_peers_checked(&peers_path)?;
    if map.contains_key(&ed_key) {
        return Err(SecurityStateError::Rejected(format!(
            "signature downgrade rejected: sender '{from_clean}' has a pinned Ed25519 identity key"
        )));
    }
    Ok(())
}

pub fn check_and_record_seen_nonce(
    config_path: &Path,
    ephemeral_pubkey: &str,
    nonce: &str,
    msg_id: u64,
) -> Result<(), SecurityStateError> {
    const MAX_SEEN_NONCES: usize = 2048;
    let dir = config_path.parent().unwrap_or_else(|| Path::new(".agpop"));
    let _lock = acquire_state_file_lock(dir, "seen_nonces")?;
    let nonces_path = dir.join("seen_nonces.json");
    let tag = format!(
        "{}:{}",
        ephemeral_pubkey.trim().to_ascii_lowercase(),
        nonce.trim().to_ascii_lowercase()
    );

    let mut entries: Vec<(String, u64)> = match fs::read_to_string(&nonces_path) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| {
            SecurityStateError::StateIo(format!(
                "corrupted nonce state file '{}': {e}",
                nonces_path.display()
            ))
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            return Err(SecurityStateError::StateIo(format!(
                "failed to read nonce state file '{}': {e}",
                nonces_path.display()
            )));
        }
    };

    if let Some((_, recorded_id)) = entries.iter().find(|(k, _)| k == &tag) {
        if *recorded_id == msg_id {
            return Ok(());
        }
        return Err(SecurityStateError::Rejected(format!(
            "replayed E2EE (ephemeral_pubkey, nonce) detected: previously seen in msg_id={recorded_id}, replayed in msg_id={msg_id}"
        )));
    }

    if entries.len() >= MAX_SEEN_NONCES {
        entries.remove(0);
    }
    entries.push((tag, msg_id));
    let bytes = serde_json::to_vec(&entries)
        .map_err(|e| SecurityStateError::StateIo(format!("failed to serialize seen_nonces: {e}")))?;
    write_private_file_atomic(&nonces_path, &bytes)
}

pub fn escape_curl_config_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

pub fn save_identity(path: &Path, id: &LocalIdentity) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent).map_err(|e| {
            format!(
                "cannot create config directory '{}': {e} (pass --config <writable-path>/identity.json)",
                parent.display()
            )
        })?;
    }
    let mut bytes = serde_json::to_vec_pretty(id)?;
    let res = write_private_file(path, &bytes).map_err(|e| {
        format!(
            "cannot write config file '{}': {e} (pass --config <writable-path>/identity.json)",
            path.display()
        )
        .into()
    });
    bytes.zeroize();
    res
}

pub fn extract_url_host(url: &str) -> Option<&str> {
    let trimmed = url.trim();
    let after_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(authority);
    if let Some(rest) = host_port.strip_prefix('[') {
        let (ipv6_host, _) = rest.split_once(']')?;
        Some(ipv6_host)
    } else {
        Some(
            host_port
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(host_port),
        )
    }
}

pub fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_matches(['[', ']']).trim_end_matches('.');
    if h.is_empty() {
        return false;
    }
    if h.eq_ignore_ascii_case("localhost")
        || (h.len() > 10 && h.to_ascii_lowercase().ends_with(".localhost"))
    {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        if ip.is_loopback() {
            return true;
        }
        if let std::net::IpAddr::V6(v6) = ip {
            if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()) {
                return true;
            }
        }
    }
    false
}

pub fn is_loopback_url_target(url: &str) -> bool {
    extract_url_host(url).is_some_and(is_loopback_host)
}

pub fn host_matches_no_proxy(host: &str, port: u16) -> bool {
    let raw = std::env::var("no_proxy")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            std::env::var("NO_PROXY")
                .ok()
                .filter(|v| !v.trim().is_empty())
        });
    let Some(no_proxy_val) = raw else {
        return false;
    };
    let host_norm = host
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host_norm.is_empty() {
        return false;
    }

    for entry in no_proxy_val.split(',') {
        let token = entry.trim();
        if token.is_empty() {
            continue;
        }
        if token == "*" {
            return true;
        }
        let (pat_host_raw, pat_port_opt) = if let Some(rest) = token.strip_prefix('[') {
            match rest.split_once(']') {
                Some((h, after)) => {
                    let p = after.strip_prefix(':').and_then(|s| s.parse::<u16>().ok());
                    (h, p)
                }
                None => (token, None),
            }
        } else if token.matches(':').count() == 1 {
            match token.rsplit_once(':') {
                Some((h, p_str)) => match p_str.parse::<u16>() {
                    Ok(p) => (h, Some(p)),
                    Err(_) => (token, None),
                },
                None => (token, None),
            }
        } else {
            (token, None)
        };

        if let Some(expected_port) = pat_port_opt {
            if expected_port != port {
                continue;
            }
        }

        let pat_host = pat_host_raw
            .trim()
            .trim_matches(['[', ']'])
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if pat_host.is_empty() {
            continue;
        }
        if host_norm == pat_host || host_norm.ends_with(&format!(".{pat_host}")) {
            return true;
        }
    }
    false
}

pub fn has_http_proxy_env() -> bool {
    [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ]
    .iter()
    .any(|k| {
        std::env::var(k)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    })
}

pub fn pick_preferred_socket_addr<I: IntoIterator<Item = SocketAddr>>(
    addrs: I,
) -> Option<SocketAddr> {
    let list: Vec<SocketAddr> = addrs.into_iter().collect();
    list.iter()
        .copied()
        .find(|a| a.is_ipv4())
        .or_else(|| list.into_iter().next())
}

pub async fn resolve_server_endpoint(
    server_str: &str,
    is_local_only_cmd: bool,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(addr) = server_str.parse::<SocketAddr>() {
        return Ok(addr);
    }

    let (host_part, port_str) = server_str
        .rsplit_once(':')
        .ok_or_else(|| format!("invalid server address '{server_str}'"))?;
    let port_num: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid server port in '{server_str}'"))?;
    let host_clean = host_part.trim_matches(['[', ']']);

    if is_local_only_cmd {
        return Ok(SocketAddr::from(([0, 0, 0, 0], port_num)));
    }

    if is_loopback_host(host_clean) {
        if let Ok(ip) = host_clean.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, port_num));
        }
        if let Ok(iter) = tokio::net::lookup_host(server_str).await {
            if let Some(addr) = pick_preferred_socket_addr(iter) {
                return Ok(addr);
            }
        }
        return Ok(SocketAddr::from(([127, 0, 0, 1], port_num)));
    }

    if let Ok(ip) = host_clean.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port_num));
    }

    if has_http_proxy_env() && !host_matches_no_proxy(host_clean, port_num) {
        return Ok(SocketAddr::from(([0, 0, 0, 0], port_num)));
    }

    match timeout(Duration::from_secs(2), tokio::net::lookup_host(server_str)).await {
        Ok(Ok(iter)) => Ok(pick_preferred_socket_addr(iter)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], port_num)))),
        _ => Ok(SocketAddr::from(([0, 0, 0, 0], port_num))),
    }
}

pub async fn raw_http_req(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String), Box<dyn std::error::Error + Send + Sync>> {
    let allow_insecure_http = !addr.ip().is_unspecified()
        && (addr.ip().is_loopback()
            || std::env::var("AGPOP_INSECURE_HTTP")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false));

    if !allow_insecure_http {
        let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
        for attempt in 0..3 {
            match curl_https_req(addr, method, path, auth, body) {
                Ok(res) => return Ok(res),
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(150 * (attempt + 1))).await;
                }
            }
        }
        return Err(last_err.unwrap_or_else(|| "https request failed".into()));
    }

    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    for attempt in 0..3 {
        match raw_http_req_once(addr, method, path, auth, body).await {
            Ok(res) => return Ok(res),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(150 * (attempt + 1))).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "http request failed".into()))
}

pub fn curl_https_req(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String), Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Stdio;

    let host_owned = get_server_host().unwrap_or_else(|| "mail.sealedbyte.com".to_string());
    let host = host_owned.as_str();
    let is_domain = host.parse::<std::net::IpAddr>().is_err() && !is_loopback_host(host);
    let url = if is_domain {
        if matches!(addr.port(), 443 | 8080 | 19080) {
            format!("https://{host}{path}")
        } else {
            format!("https://{host}:{}{path}", addr.port())
        }
    } else {
        format!("https://{addr}{path}")
    };

    let use_stdin_cfg = auth.is_some() || body.is_some();
    let mut cmd = std::process::Command::new(CURL_BIN);
    cmd.arg("-sS");
    if is_loopback_url_target(&url) {
        cmd.arg("--noproxy").arg("*");
    }
    cmd.arg("--proto")
        .arg("=https")
        .arg("--tlsv1.2")
        .arg("--max-time")
        .arg("10")
        .arg("-X")
        .arg(method)
        .arg("-w")
        .arg("\n__HTTP_CODE__:%{http_code}");

    if use_stdin_cfg {
        cmd.arg("--config").arg("-");
    }
    cmd.arg(&url)
        .stdin(if use_stdin_cfg {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    if use_stdin_cfg {
        if let Some(mut stdin) = child.stdin.take() {
            let mut cfg_buf = String::new();
            if let Some(t) = auth {
                let safe_tok: String = t
                    .chars()
                    .filter(|c| !matches!(c, '"' | '\\' | '\r' | '\n'))
                    .collect();
                if safe_tok.starts_with("ApiKey ") || safe_tok.starts_with("Bearer ") {
                    cfg_buf.push_str(&format!("header = \"Authorization: {safe_tok}\"\n"));
                } else {
                    cfg_buf.push_str(&format!("header = \"Authorization: Bearer {safe_tok}\"\n"));
                }
            }
            if let Some(b) = body {
                let escaped = escape_curl_config_str(b);
                cfg_buf.push_str("header = \"Content-Type: application/json\"\n");
                cfg_buf.push_str(&format!("data-binary = \"{escaped}\"\n"));
            }
            let _ = stdin.write_all(cfg_buf.as_bytes());
            cfg_buf.zeroize();
        }
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let err_msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(format!("https request failed: {err_msg}").into());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let (body_part, code_part) = text
        .rsplit_once("\n__HTTP_CODE__:")
        .ok_or("missing status marker")?;
    let body_part = body_part.strip_suffix('\r').unwrap_or(body_part);
    let code = code_part.trim().parse::<u16>()?;
    Ok((code, body_part.to_string()))
}

pub fn localhost_dualstack_fallback_addr(
    addr: SocketAddr,
    configured_host: Option<&str>,
) -> Option<SocketAddr> {
    if !configured_host.is_some_and(|h| {
        let trimmed = h.trim().trim_end_matches('.');
        trimmed.eq_ignore_ascii_case("localhost")
            || (trimmed.len() > 10 && trimmed.to_ascii_lowercase().ends_with(".localhost"))
    }) {
        return None;
    }
    match addr.ip() {
        std::net::IpAddr::V4(v4) if v4 == std::net::Ipv4Addr::LOCALHOST => Some(SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            addr.port(),
        )),
        std::net::IpAddr::V6(v6) if v6 == std::net::Ipv6Addr::LOCALHOST => Some(SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            addr.port(),
        )),
        _ => None,
    }
}

pub async fn raw_http_req_once(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String), Box<dyn std::error::Error + Send + Sync>> {
    const MAX_HTTP_RESP_BYTES: usize = 2 * 1024 * 1024;

    timeout(Duration::from_secs(10), async {
        let server_host = get_server_host();
        let mut stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(primary_err) => {
                if let Some(alt_addr) =
                    localhost_dualstack_fallback_addr(addr, server_host.as_deref())
                {
                    TcpStream::connect(alt_addr)
                        .await
                        .map_err(|_| primary_err)?
                } else {
                    return Err(primary_err.into());
                }
            }
        };
        let host_hdr = match server_host.as_deref() {
            Some(h) if !h.is_empty() && h.parse::<std::net::IpAddr>().is_err() => {
                format!("{h}:{}", addr.port())
            }
            _ => addr.to_string(),
        };
        let auth_hdr = auth
            .map(|t| {
                if t.starts_with("ApiKey ") || t.starts_with("Bearer ") {
                    format!("Authorization: {t}\r\n")
                } else {
                    format!("Authorization: Bearer {t}\r\n")
                }
            })
            .unwrap_or_default();
        let req = if let Some(body_str) = body {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\n{auth_hdr}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body_str}",
                body_str.len()
            )
        } else {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\n{auth_hdr}\r\n"
            )
        };
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() + n > MAX_HTTP_RESP_BYTES {
                        return Err("http response exceeded maximum allowed size".into());
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(hdr_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let body_start = hdr_end + 4;
                        let hdr_str = String::from_utf8_lossy(&buf[..hdr_end]);
                        if let Some(cl) = hdr_str.lines().find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        }) {
                            if buf.len() >= body_start + cl {
                                break;
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset && !buf.is_empty() => {
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }

        let resp = String::from_utf8_lossy(&buf);
        let (head, body_part) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
        let status_line = head.lines().next().unwrap_or("");
        let code = status_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("0")
            .parse::<u16>()
            .unwrap_or(0);
        Ok((code, body_part.to_string()))
    })
    .await
    .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> { "http request timed out".into() })?
}

pub fn sync_default_allow_list_from_email(ident: &mut LocalIdentity, email: &str) {
    let Some(idx) = email.rfind('@') else {
        return;
    };
    let actual_dom = &email[idx..];
    if actual_dom.len() <= 1 {
        return;
    }
    let placeholder_host = get_server_host()
        .map(|h| format!("@{h}"))
        .unwrap_or_else(|| "@mail.sealedbyte.com".to_string());
    let is_api_key_team = ident.reg_auth_mode.as_deref() == Some("api_key");
    let default_entries = || {
        if is_api_key_team {
            vec![actual_dom.to_string(), "@team".to_string()]
        } else {
            vec![actual_dom.to_string()]
        }
    };
    match ident.allow_list.as_mut() {
        None => {
            ident.allow_list = Some(default_entries());
        }
        Some(list)
            if list.len() == 1
                && (list[0] == placeholder_host || list[0] == "@mail.sealedbyte.com") =>
        {
            *list = default_entries();
        }
        _ => {}
    }
}

pub fn generate_fresh_identity(prefix: &str) -> LocalIdentity {
    let mut sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_bytes);
    let sk = StaticSecret::from(sk_bytes);
    let pk = PublicKey::from(&sk);
    let (key_id, ed25519_pk) = derive_ed25519_identity(&sk_bytes);
    sk_bytes.zeroize();
    let default_dom = get_server_host()
        .filter(|h| h.parse::<std::net::IpAddr>().is_err() && h.as_str() != "localhost")
        .map(|h| format!("@{h}"))
        .unwrap_or_else(|| "@mail.sealedbyte.com".to_string());
    LocalIdentity {
        prefix: prefix.to_string(),
        privkey_hex: hex::encode(sk.to_bytes()),
        pubkey_hex: hex::encode(pk.as_bytes()),
        key_id: Some(key_id),
        ed25519_pubkey_hex: Some(ed25519_pk),
        ticket: None,
        reg_auth_mode: None,
        pending_team_only: None,
        pending_team_role: None,
        pending_team_card: None,
        id: None,
        email: None,
        token: None,
        allow_list: Some(vec![default_dom]),
    }
}

/// High-level client API helpers shared with GUI / SDK consumers.
pub async fn fetch_team_directory(
    server_addr: SocketAddr,
    owner_id: u64,
    bearer_token: &str,
) -> Result<TeamDirectoryResponse, String> {
    let (code, body) = raw_http_req(
        server_addr,
        "GET",
        &format!("/v1/team/{owner_id}"),
        Some(bearer_token),
        None,
    )
    .await
    .map_err(|e| format!("team directory request failed: {e}"))?;
    if code != 200 {
        return Err(format!("GET /v1/team/{owner_id} returned {code}: {body}"));
    }
    serde_json::from_str::<TeamDirectoryResponse>(&body)
        .map_err(|e| format!("invalid team directory json: {e}"))
}

/// Registers and activates an owner mailbox bound to `api_key` with `team_only = true`
/// and `runtime = "agpop-gui"`. Returns HTTP status code inside error string on 429/401/403.
pub async fn register_owner_with_api_key(
    server_addr: SocketAddr,
    config_path: &Path,
    prefix: &str,
    api_key: &str,
) -> Result<LocalIdentity, String> {
    let mut ident = generate_fresh_identity(prefix);
    ident.reg_auth_mode = Some("api_key".to_string());
    ident.pending_team_only = Some(true);
    ident.pending_team_role = Some("owner".to_string());
    ident.pending_team_card = Some(TeamCardPatch {
        role: Some("owner".to_string()),
        runtime: Some("agpop-gui".to_string()),
        ..Default::default()
    });

    let pk_vec = hex::decode(&ident.pubkey_hex).map_err(|e| e.to_string())?;
    let pk_bytes: [u8; 32] = pk_vec
        .as_slice()
        .try_into()
        .map_err(|_| "invalid pubkey length".to_string())?;

    let challenge_path = format!("/v1/register/challenge?pubkey={}", ident.pubkey_hex.trim());
    let reg_body = match raw_http_req(server_addr, "GET", &challenge_path, None, None).await {
        Ok((200, ch_body)) => {
            let ch: RegisterChallengeResponse = serde_json::from_str(&ch_body)
                .map_err(|e| format!("invalid register challenge json: {e}"))?;
            let n = solve_register_challenge_pow(&pk_bytes, ch.challenge.trim(), ch.pow_bits);
            serde_json::json!({
                "prefix": ident.prefix,
                "pubkey": ident.pubkey_hex,
                "pow_challenge": ch.challenge.trim(),
                "pow_nonce": n,
            })
        }
        Ok((404, _)) | Ok((405, _)) => {
            let ts_ms = now_ms();
            let n = solve_register_pow(&pk_bytes, ts_ms, REGISTER_POW_BITS);
            serde_json::json!({
                "prefix": ident.prefix,
                "pubkey": ident.pubkey_hex,
                "pow_ts": ts_ms,
                "pow_nonce": n,
            })
        }
        Ok((code, body)) => {
            return Err(format!("GET /v1/register/challenge failed ({code}): {}", body.trim()));
        }
        Err(e) => {
            return Err(format!("GET /v1/register/challenge failed: {e}"));
        }
    };

    let auth_hdr = format!("ApiKey {}", api_key.trim());
    let (code, body) = raw_http_req(
        server_addr,
        "POST",
        "/v1/register",
        Some(&auth_hdr),
        Some(&reg_body.to_string()),
    )
    .await
    .map_err(|e| format!("register request failed: {e}"))?;

    if code == 200 || code == 201 {
        let ready: AccountReadyResponse = serde_json::from_str(&body)
            .map_err(|e| format!("invalid register ready json: {e}"))?;
        return finish_owner_registration(server_addr, config_path, &mut ident, ready).await;
    }
    if code != 202 {
        return Err(format!("POST /v1/register failed ({code}): {body}"));
    }

    let ticket_resp: TicketResponse =
        serde_json::from_str(&body).map_err(|e| format!("invalid ticket json: {e}"))?;
    ident.ticket = Some(ticket_resp.ticket.clone());
    save_identity(config_path, &ident).map_err(|e| format!("save pending identity failed: {e}"))?;

    if ticket_resp.ready_in_secs > 0 {
        tokio::time::sleep(Duration::from_secs(ticket_resp.ready_in_secs.clamp(1, 55))).await;
    }

    let claim_path = format!("/v1/register/{}", ticket_resp.ticket);
    for _ in 0..24 {
        let (fcode, fbody) = raw_http_req(server_addr, "GET", &claim_path, None, None)
            .await
            .map_err(|e| format!("claim ticket request failed: {e}"))?;
        if fcode == 200 || fcode == 201 {
            let ready: AccountReadyResponse = serde_json::from_str(&fbody)
                .map_err(|e| format!("invalid claim ready json: {e}"))?;
            return finish_owner_registration(server_addr, config_path, &mut ident, ready).await;
        }
        if fcode == 202 {
            let wait_secs = serde_json::from_str::<TicketResponse>(&fbody)
                .map(|tk| tk.ready_in_secs.clamp(1, 10))
                .unwrap_or(2);
            tokio::time::sleep(Duration::from_secs(wait_secs)).await;
            continue;
        }
        return Err(format!("GET {claim_path} failed ({fcode}): {fbody}"));
    }
    Err("timed out waiting for registration ticket claim".to_string())
}

async fn finish_owner_registration(
    server_addr: SocketAddr,
    config_path: &Path,
    ident: &mut LocalIdentity,
    ready: AccountReadyResponse,
) -> Result<LocalIdentity, String> {
    ident.id = Some(ready.id);
    ident.email = Some(ready.email.clone());
    ident.token = Some(ready.token.clone());
    ident.ticket = None;
    sync_default_allow_list_from_email(ident, &ready.email);
    save_identity(config_path, ident).map_err(|e| format!("save identity failed: {e}"))?;

    // Apply team_only whitelist and owner team card
    let wl_path = format!("/v1/whitelist/{}", ready.id);
    let wl_payload = serde_json::json!({ "entries": ["@team"] }).to_string();
    let (wl_code, wl_body) =
        raw_http_req(server_addr, "PUT", &wl_path, Some(&ready.token), Some(&wl_payload))
            .await
            .map_err(|e| format!("whitelist update failed: {e}"))?;
    if wl_code == 200 {
        ident.allow_list = Some(vec!["@team".to_string()]);
        ident.pending_team_only = None;
    } else {
        return Err(format!("failed to apply team_only whitelist ({wl_code}): {wl_body}"));
    }

    if let Some(card) = ident.pending_team_card.clone() {
        let team_path = format!("/v1/team/{}", ready.id);
        let card_payload = serde_json::to_string(&card).map_err(|e| e.to_string())?;
        let (tcode, tbody) =
            raw_http_req(server_addr, "PUT", &team_path, Some(&ready.token), Some(&card_payload))
                .await
                .map_err(|e| format!("team card update failed: {e}"))?;
        if tcode != 200 {
            return Err(format!("failed to update owner team card ({tcode}): {tbody}"));
        }
        ident.pending_team_role = None;
        ident.pending_team_card = None;
    }

    save_identity(config_path, ident).map_err(|e| format!("save identity failed: {e}"))?;
    Ok(ident.clone())
}

pub async fn send_e2ee_mail(
    server_addr: SocketAddr,
    config_path: &Path,
    ident: &LocalIdentity,
    to_email: &str,
    subject: &str,
    text: &str,
) -> Result<SendResponse, String> {
    let self_id = ident.id.ok_or("missing local mailbox id")?;
    let self_token = ident.token.as_deref().ok_or("missing local mailbox token")?;
    let self_email = ident
        .email
        .as_deref()
        .ok_or("missing local mailbox email")?;
    validate_local_identity_email(Some(self_email)).map_err(|e| e.to_string())?;

    let mut privkey_vec = hex::decode(&ident.privkey_hex).map_err(|e| e.to_string())?;
    let mut privkey_bytes: [u8; 32] = privkey_vec
        .as_slice()
        .try_into()
        .map_err(|_| "invalid privkey length".to_string())?;
    privkey_vec.zeroize();

    let to_clean = to_email.trim();
    let (pk_code, pk_body) = raw_http_req(
        server_addr,
        "GET",
        &format!("/v1/pubkey/{self_id}?to={to_clean}"),
        Some(self_token),
        None,
    )
    .await
    .map_err(|e| format!("pubkey lookup failed: {e}"))?;
    if pk_code != 200 {
        privkey_bytes.zeroize();
        return Err(format!("GET /v1/pubkey/{self_id} failed ({pk_code}): {pk_body}"));
    }
    let pk_resp: PubkeyLookupResponse = serde_json::from_str(&pk_body)
        .map_err(|e| format!("invalid pubkey lookup json: {e}"))?;

    if let Err(e) = verify_or_pin_peer_key(config_path, &pk_resp.to, &pk_resp.pubkey) {
        privkey_bytes.zeroize();
        return Err(e.to_string());
    }

    let rec_pk_vec = hex::decode(&pk_resp.pubkey).map_err(|e| e.to_string())?;
    let rec_pk: [u8; 32] = rec_pk_vec
        .as_slice()
        .try_into()
        .map_err(|_| "invalid recipient pubkey length".to_string())?;

    let mut cleartext = CleartextMailPayload {
        from: self_email.to_string(),
        to: pk_resp.to.clone(),
        subject: subject.to_string(),
        text: text.to_string(),
        received_at_ms: now_ms(),
        sender_ed25519_pubkey: None,
        sender_signature: None,
    };
    sign_cleartext_mail(&privkey_bytes, &mut cleartext);
    privkey_bytes.zeroize();

    let mut pt = serde_json::to_vec(&cleartext).map_err(|e| e.to_string())?;
    let (eph, nonce, ct) = seal_and_zeroize(&rec_pk, &mut pt, self_email)
        .map_err(|e| format!("e2ee seal failed: {e}"))?;

    let send_body = serde_json::json!({
        "to": pk_resp.to,
        "ephemeral_pubkey": eph,
        "nonce": nonce,
        "ciphertext": ct,
    })
    .to_string();

    let (scode, sbody) = raw_http_req(
        server_addr,
        "POST",
        &format!("/v1/send/{self_id}"),
        Some(self_token),
        Some(&send_body),
    )
    .await
    .map_err(|e| format!("send request failed: {e}"))?;
    if scode != 200 {
        return Err(format!("POST /v1/send/{self_id} failed ({scode}): {sbody}"));
    }
    serde_json::from_str::<SendResponse>(&sbody).map_err(|e| format!("invalid send json: {e}"))
}

pub async fn udp_probe_once(
    server_addr: SocketAddr,
    ident: &LocalIdentity,
    wake_mode: WakeMode,
) -> Option<[u8; UDP_PROBE_RESP_BYTES]> {
    if server_addr.ip().is_unspecified() {
        return None;
    }
    let id = ident.id?;
    let token = ident.token.as_deref()?;
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let mut pkt = [0u8; UDP_PROBE_WAKE_REQ_BYTES];
    let ts_ms = now_ms();
    pkt[0..8].copy_from_slice(&id.to_le_bytes());
    pkt[8..16].copy_from_slice(&ts_ms.to_le_bytes());
    pkt[16] = wake_mode as u8;
    let token_hash = hash_token(token);
    let mac = compute_udp_probe_mac_with_wake(&token_hash, id, ts_ms, wake_mode as u8);
    pkt[17..33].copy_from_slice(&mac);
    sock.send_to(&pkt, server_addr).await.ok()?;
    let mut rbuf = [0u8; UDP_PROBE_RESP_BYTES];
    let (n, _) = timeout(Duration::from_millis(800), sock.recv_from(&mut rbuf))
        .await
        .ok()?
        .ok()?;
    if n == UDP_PROBE_RESP_BYTES {
        Some(rbuf)
    } else {
        None
    }
}

/// Polls `GET /v1/messages/{id}?wake=exec_hook`, decrypts, verifies TOFU + anti-replay,
/// writes each message atomically to `inbox_dir`, and sends `DELETE?wake=exec_hook` ONLY
/// after disk persistence succeeds.
pub async fn poll_and_decrypt_once(
    server_addr: SocketAddr,
    config_path: &Path,
    ident: &LocalIdentity,
    inbox_dir: &Path,
    wake_mode: WakeMode,
) -> Result<Vec<(u64, CleartextMailPayload)>, String> {
    let self_id = ident.id.ok_or("missing local mailbox id")?;
    let self_token = ident.token.as_deref().ok_or("missing local mailbox token")?;
    let self_email = ident
        .email
        .as_deref()
        .ok_or("missing local mailbox email")?;
    let own_domain = self_email
        .rsplit_once('@')
        .map(|(_, d)| d)
        .ok_or("invalid local mailbox email")?;

    let mut privkey_vec = hex::decode(&ident.privkey_hex).map_err(|e| e.to_string())?;
    let mut privkey_bytes: [u8; 32] = privkey_vec
        .as_slice()
        .try_into()
        .map_err(|_| "invalid privkey length".to_string())?;
    privkey_vec.zeroize();

    let path = format!("/v1/messages/{self_id}?wake={}", wake_mode.as_str());
    let res = raw_http_req(server_addr, "GET", &path, Some(self_token), None).await;
    let (code, body) = match res {
        Ok(r) => r,
        Err(e) => {
            privkey_bytes.zeroize();
            return Err(format!("poll failed: {e}"));
        }
    };
    if code == 204 {
        privkey_bytes.zeroize();
        return Ok(Vec::new());
    }
    if code != 200 {
        privkey_bytes.zeroize();
        return Err(format!("GET {path} returned {code}: {body}"));
    }
    let poll: PollResponse = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => {
            privkey_bytes.zeroize();
            return Err(format!("invalid poll json: {e}"));
        }
    };

    let mut persisted = Vec::new();
    let mut ack_ids = Vec::new();

    for sealed in poll.messages {
        let mut payload: CleartextMailPayload = match unseal_message(&privkey_bytes, &sealed) {
            Ok(p) => p,
            Err(_) => {
                ack_ids.push(sealed.msg_id);
                continue;
            }
        };

        if !payload.to.eq_ignore_ascii_case(self_email) {
            ack_ids.push(sealed.msg_id);
            continue;
        }
        match verify_or_pin_sender_identity(
            config_path,
            own_domain,
            &payload.from,
            payload.sender_ed25519_pubkey.as_deref(),
        ) {
            Ok(()) => {}
            Err(SecurityStateError::Rejected(_)) => {
                ack_ids.push(sealed.msg_id);
                continue;
            }
            Err(SecurityStateError::StateIo(_)) => continue,
        }
        match check_and_record_seen_nonce(
            config_path,
            &sealed.ephemeral_pubkey,
            &sealed.nonce,
            sealed.msg_id,
        ) {
            Ok(()) => {}
            Err(SecurityStateError::Rejected(_)) => {
                ack_ids.push(sealed.msg_id);
                continue;
            }
            Err(SecurityStateError::StateIo(_)) => continue,
        }

        payload.received_at_ms = sealed.received_at_ms;
        let json_bytes = serde_json::to_vec_pretty(&payload).map_err(|e| e.to_string())?;
        write_new_private_mail_file(inbox_dir, sealed.received_at_ms, sealed.msg_id, &json_bytes)
            .map_err(|e| format!("failed to persist mail {}: {e}", sealed.msg_id))?;

        ack_ids.push(sealed.msg_id);
        persisted.push((sealed.msg_id, payload));
    }

    privkey_bytes.zeroize();

    if !ack_ids.is_empty() {
        let del_body = serde_json::json!({ "msg_ids": ack_ids }).to_string();
        let del_path = format!("/v1/messages/{self_id}?wake={}", wake_mode.as_str());
        let _ = raw_http_req(
            server_addr,
            "DELETE",
            &del_path,
            Some(self_token),
            Some(&del_body),
        )
        .await;
    }

    Ok(persisted)
}
