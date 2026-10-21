#![allow(clippy::collapsible_if)]

use agentpop::crypto::{
    REGISTER_POW_BITS, compute_udp_probe_mac, derive_ed25519_identity, format_rfc3339_utc,
    generate_uuid_v7, hash_token, seal_and_zeroize, sha256_hex, sign_cleartext_mail, sign_ed25519,
    solve_register_pow, unseal_message, utf8_safe_excerpt,
};
use agentpop::types::{
    CleartextMailPayload, SealedMessage, Tier, TierLimits, UDP_PROBE_REQ_BYTES,
    UDP_PROBE_RESP_BYTES,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const AGPOP_VERSION: &str = "0.4.9-beta";
pub const ENVELOPE_VERSION: &str = "1.0";
pub const EXCERPT_MAX_BYTES: usize = 512;
pub const RETRY_BACKOFF_SECS: [u64; 5] = [1, 2, 4, 8, 16];
const CURL_BIN: &str = if cfg!(windows) { "curl.exe" } else { "curl" };

static SERVER_HOST: OnceLock<String> = OnceLock::new();

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Serialize, Deserialize)]
struct TicketResponse {
    pub status: String,
    pub ticket: String,
    pub ready_in_secs: u64,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
struct AccountReadyResponse {
    pub status: String,
    pub id: u64,
    pub email: String,
    pub token: String,
    pub tier: Tier,
    pub limits: TierLimits,
}

#[derive(Serialize, Deserialize)]
struct PollResponse {
    pub id: u64,
    pub count: usize,
    pub remaining_slots: u64,
    pub messages: Vec<SealedMessage>,
}

#[derive(Serialize, Deserialize)]
struct WhitelistResponse {
    pub active_slots: usize,
    pub max_slots: usize,
    pub entries: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct PubkeyLookupResponse {
    pub pubkey: String,
    pub sender_email: String,
    pub to: String,
    pub max_msg_bytes: usize,
}

#[derive(Serialize, Deserialize)]
struct SendResponse {
    pub status: String,
    pub msg_id: u64,
    #[serde(default)]
    pub from: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalIdentity {
    prefix: String,
    privkey_hex: String,
    pubkey_hex: String,
    #[serde(default)]
    key_id: Option<String>,
    #[serde(default)]
    ed25519_pubkey_hex: Option<String>,
    ticket: Option<String>,
    id: Option<u64>,
    email: Option<String>,
    token: Option<String>,
    #[serde(default)]
    allow_list: Option<Vec<String>>,
}

/// Envelope v1.0 placed in the HTTP POST body (delivery metadata goes in HTTP headers).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebhookEnvelope {
    pub envelope_version: String,
    pub event_id: String,
    pub event_type: String,
    pub data_schema_version: String,
    pub occurred_at: String,
    pub attempt: u32,
    pub key_id: String,
    pub ed25519_pubkey: String,
    pub data: EventData,
}

/// Strongly-typed per-event payload variants (no generic catch-all map).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum EventData {
    MailReceived(MailReceivedData),
    AccountReady(AccountReadyData),
    DaemonHeartbeat(DaemonHeartbeatData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MailReceivedData {
    pub msg_id: u64,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub body_excerpt: String,
    pub body_total_bytes: usize,
    pub excerpt_bytes: usize,
    pub body_truncated: bool,
    pub rel_path: String,
    pub content_sha256: String,
    pub received_at: String,
    pub received_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountReadyData {
    pub id: u64,
    pub email: String,
    pub prefix: String,
    pub key_id: String,
    pub ed25519_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonHeartbeatData {
    pub id: u64,
    pub email: String,
    pub uptime_secs: u64,
    pub delivered_count: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let subcmd = args.get(1).map(String::as_str).unwrap_or("help");
    if matches!(subcmd, "version" | "--version" | "-V") {
        println!("agpop {AGPOP_VERSION}");
        return Ok(());
    }
    if matches!(subcmd, "help" | "--help" | "-h")
        || args.get(2).is_some_and(|a| a == "--help" || a == "-h" || a == "help")
    {
        print_usage();
        return Ok(());
    }

    let raw_server = flag_val(&args, "--server")
        .or_else(|| std::env::var("AGPOP_SERVER").ok())
        .unwrap_or_else(|| "mail.sealedbyte.com:443".to_string());
    let raw_trimmed = raw_server
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let server_str = if raw_trimmed.contains(':') {
        raw_trimmed.to_string()
    } else {
        format!("{raw_trimmed}:443")
    };
    let host_only = server_str
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(['[', ']']).to_string())
        .unwrap_or_else(|| server_str.clone());
    let _ = SERVER_HOST.set(host_only);

    let server_addr: SocketAddr = tokio::net::lookup_host(&server_str)
        .await?
        .find(|a| a.is_ipv4())
        .or_else(|| std::net::ToSocketAddrs::to_socket_addrs(&server_str.as_str()).ok()?.next())
        .ok_or("failed to resolve server address")?;

    let config_path = resolve_config_path(&args);

    match subcmd {
        "init" => {
            check_allowed_flags(
                &args,
                2,
                &["--prefix", "--pro-key", "--server", "--config"],
                &["--wait", "--no-wait", "--force"],
            )?;
            let prefix = flag_val(&args, "--prefix").unwrap_or_else(|| "agent".to_string());
            let wait = !args.iter().any(|a| a == "--no-wait");
            let force = args.iter().any(|a| a == "--force");
            let pro_key = flag_val(&args, "--pro-key");
            cmd_init(
                server_addr,
                &config_path,
                &prefix,
                wait,
                force,
                pro_key.as_deref(),
            )
            .await?;
        }
        "status" => {
            check_allowed_flags(&args, 2, &["--server", "--config"], &["--reveal"])?;
            let reveal = args.iter().any(|a| a == "--reveal");
            let mut ident = load_and_auto_claim(server_addr, &config_path, false).await?;
            if !reveal {
                ident.privkey_hex = "<redacted: pass --reveal to show>".to_string();
                if ident.token.is_some() {
                    ident.token = Some("<redacted: pass --reveal to show>".to_string());
                }
            }
            let mut val = serde_json::to_value(&ident)?;
            if let Some(obj) = val.as_object_mut() {
                obj.remove("id");
                if ident.ticket.is_none() {
                    obj.remove("ticket");
                }
            }
            println!("{}", serde_json::to_string_pretty(&val)?);
        }
        "pop" => {
            check_allowed_flags(&args, 2, &["--inbox-dir", "--server", "--config"], &[])?;
            let inbox_dir = flag_val(&args, "--inbox-dir")
                .map(PathBuf::from)
                .or_else(|| std::env::var("AGPOP_INBOX_DIR").ok().map(PathBuf::from));
            let msgs = cmd_wait_or_pop(
                server_addr,
                &config_path,
                Some(0),
                false,
                inbox_dir,
                None,
                None,
                None,
            )
            .await?;
            println!("{}", serde_json::to_string(&msgs)?);
        }
        "wait" | "daemon" => {
            check_allowed_flags(
                &args,
                2,
                &[
                    "--timeout",
                    "--webhook-url",
                    "--callback-url",
                    "--webhook-token",
                    "--exec",
                    "--on-mail",
                    "--inbox-dir",
                    "--server",
                    "--config",
                ],
                &["--forever"],
            )?;
            if subcmd == "daemon" {
                if let Some(d_act) = args.get(2).map(String::as_str) {
                    if matches!(d_act, "start" | "stop" | "status") {
                        cmd_daemon_ctl(server_addr, &config_path, d_act, &args)?;
                        return Ok(());
                    }
                }
            }
            let forever = subcmd == "daemon"
                || args.iter().any(|a| a == "--forever")
                || flag_val(&args, "--timeout").as_deref() == Some("0");
            let timeout_secs = if forever {
                None
            } else {
                Some(
                    flag_val(&args, "--timeout")
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(60),
                )
            };
            let webhook_url = flag_val(&args, "--webhook-url")
                .or_else(|| flag_val(&args, "--callback-url"))
                .or_else(|| std::env::var("AGPOP_WEBHOOK_URL").ok());
            let webhook_token = flag_val(&args, "--webhook-token")
                .or_else(|| std::env::var("AGPOP_WEBHOOK_TOKEN").ok());
            let on_mail_cmd = flag_val(&args, "--exec")
                .or_else(|| flag_val(&args, "--on-mail"))
                .or_else(|| std::env::var("AGPOP_ON_MAIL").ok());
            let inbox_dir = flag_val(&args, "--inbox-dir")
                .map(PathBuf::from)
                .or_else(|| std::env::var("AGPOP_INBOX_DIR").ok().map(PathBuf::from));

            let msgs = cmd_wait_or_pop(
                server_addr,
                &config_path,
                timeout_secs,
                forever,
                inbox_dir,
                webhook_url,
                webhook_token,
                on_mail_cmd,
            )
            .await?;
            if !forever {
                println!("{}", serde_json::to_string(&msgs)?);
            }
        }
        "inbox" => {
            check_allowed_flags(&args, 2, &["--inbox-dir", "--server", "--config"], &[])?;
            let inbox_dir = flag_val(&args, "--inbox-dir")
                .map(PathBuf::from)
                .or_else(|| std::env::var("AGPOP_INBOX_DIR").ok().map(PathBuf::from))
                .unwrap_or_else(|| default_inbox_dir(&config_path));
            let action = args.get(2).map(String::as_str).unwrap_or("list");
            let target = args.get(3).map(String::as_str);
            cmd_inbox(&inbox_dir, action, target)?;
        }
        "reply" => {
            check_allowed_flags(
                &args,
                2,
                &[
                    "--inbox-dir",
                    "--body",
                    "--body-file",
                    "--subject",
                    "--server",
                    "--config",
                ],
                &[],
            )?;
            let inbox_dir = flag_val(&args, "--inbox-dir")
                .map(PathBuf::from)
                .or_else(|| std::env::var("AGPOP_INBOX_DIR").ok().map(PathBuf::from))
                .unwrap_or_else(|| default_inbox_dir(&config_path));
            let target = args
                .get(2)
                .map(String::as_str)
                .filter(|s| !s.starts_with("--"))
                .unwrap_or("latest");
            let mut body = read_body_input(&args)?.ok_or(
                "missing body (pass --body <text>, --body-file <path>, or pipe via stdin)",
            )?;
            let subject_override = flag_val(&args, "--subject");
            let res = cmd_reply(
                server_addr,
                &config_path,
                &inbox_dir,
                target,
                &body,
                subject_override.as_deref(),
            )
            .await;
            body.zeroize();
            res?;
        }
        "allow" => {
            check_allowed_flags(&args, 2, &["--server", "--config"], &[])?;
            let action = args.get(2).map(String::as_str).unwrap_or("list");
            cmd_allow(server_addr, &config_path, action, &args[3..]).await?;
        }
        "send" => {
            check_allowed_flags(
                &args,
                2,
                &[
                    "--to",
                    "--subject",
                    "--body",
                    "--body-file",
                    "--server",
                    "--config",
                ],
                &[],
            )?;
            let to = flag_val(&args, "--to").ok_or("missing --to <address>")?;
            let subject =
                flag_val(&args, "--subject").unwrap_or_else(|| "(no subject)".to_string());
            let mut body = read_body_input(&args)?.unwrap_or_default();
            let res = cmd_send(server_addr, &config_path, &to, &subject, &body).await;
            body.zeroize();
            res?;
        }
        _ => {
            print_usage();
        }
    }

    Ok(())
}

fn print_usage() {
    println!(
        "agpop v{AGPOP_VERSION} — Command-Line Email Client for AI Agents\n\
         Usage:\n  \
           agpop init --prefix <name> [--wait] [--force] [--server host:port] [--config path]\n  \
           agpop status [--reveal]\n  \
           agpop wait [--timeout 60 | --forever] [--inbox-dir <dir>] [--webhook-url <url>] [--webhook-token <tok>] [--exec '<cmd>']\n  \
           agpop daemon [start | stop | status] [--inbox-dir <dir>] [--webhook-url <url>] [--webhook-token <tok>] [--exec '<cmd>']\n  \
           agpop pop\n  \
           agpop inbox [list | read <index|latest|sender|file>]\n  \
           agpop reply [index|latest|sender|file] [--body <text> | --body-file <path> | stdin] [--subject <subj>]\n  \
           agpop allow add | rm | set <@example.org> <sender@example.org>\n  \
           agpop allow list | clear\n  \
           agpop send --to <addr> --subject <subj> [--body <text> | --body-file <path> | stdin]\n\n\
         Webhook Envelope v1.0 Headers:\n  \
           X-Agpop-Event, X-Agpop-Event-Id (UUIDv7), X-Agpop-Attempt, X-Agpop-Key-Id, X-Agpop-Signature (ed25519=<hex>)"
    );
}

fn flag_val(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
}

fn check_allowed_flags(
    args: &[String],
    start_idx: usize,
    value_flags: &[&str],
    bool_flags: &[&str],
) -> Result<(), String> {
    let mut i = start_idx;
    while i < args.len() {
        let arg = args[i].as_str();
        if value_flags.contains(&arg) {
            i += 2;
        } else if bool_flags.contains(&arg) {
            i += 1;
        } else if arg.starts_with("--") {
            return Err(format!("unknown option '{arg}'"));
        } else {
            i += 1;
        }
    }
    Ok(())
}

/// Reads email body from `--body-file <path>`, `--body -` (stdin), `--body <text>`,
/// or piped stdin when `--body` is omitted.
fn read_body_input(args: &[String]) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Some(file_path) = flag_val(args, "--body-file") {
        let content = fs::read_to_string(&file_path)
            .map_err(|e| format!("failed to read --body-file '{file_path}': {e}"))?;
        return Ok(Some(content));
    }
    if let Some(val) = flag_val(args, "--body") {
        if val == "-" {
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
            return Ok(Some(buf));
        }
        return Ok(Some(val));
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        if !buf.is_empty() {
            return Ok(Some(buf));
        }
    }
    Ok(None)
}

/// Strictly resolves identity.json from `--config <path>` (or `AGPOP_CONFIG`),
/// defaulting to `./.agpop/identity.json` in the current working directory.
/// Never falls back to shared global `$HOME` or `/tmp` paths to prevent multi-Agent collisions.
fn resolve_config_path(args: &[String]) -> PathBuf {
    if let Some(p) = flag_val(args, "--config").or_else(|| std::env::var("AGPOP_CONFIG").ok()) {
        return PathBuf::from(p);
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".agpop")
        .join("identity.json")
}

fn load_identity(path: &Path) -> Result<LocalIdentity, &'static str> {
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

fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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
/// - Primary filename uses server-assigned `received_at_ms` and unique server `msg_id`:
///   `mail-{server_received_at_ms}-id{msg_id}.json`.
/// - Uses `create_new(true)` (`O_CREAT | O_EXCL`). If the file already exists:
///   * If its SHA-256 matches `bytes`, treats the write as an idempotent retry and succeeds.
///   * Otherwise, appends a random suffix (`mail-{ts}-id{msg_id}-{rand}.json`) with `create_new(true)`.
fn write_new_private_mail_file(
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

fn create_exclusive_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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
enum SecurityStateError {
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

struct StateLockGuard {
    lock_path: PathBuf,
}

impl Drop for StateLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn acquire_state_file_lock(
    dir: &Path,
    lock_name: &str,
) -> Result<StateLockGuard, SecurityStateError> {
    acquire_state_file_lock_with_retries(dir, lock_name, 400)
}

fn acquire_state_file_lock_with_retries(
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

    // Never steal or unlink an existing lock file based on age: only the process
    // that created `lock_path` via `create_new(true)` may unlink it on drop.
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

fn write_private_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), SecurityStateError> {
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

fn load_known_peers_checked(peers_path: &Path) -> Result<BTreeMap<String, String>, SecurityStateError> {
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

/// Trust-On-First-Use (TOFU) peer public key pinning in `.agpop/known_peers.json`.
/// - Distinguishes first-time missing file (`NotFound`) from read/parse corruption (fail-closed).
/// - Uses an exclusive lockfile + atomic temp-file rename so concurrent send/receive processes
///   never overwrite each other's pins, and fails closed if saving fails.
fn verify_or_pin_peer_key(
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

/// Verifies or pins a sender's Ed25519 identity key on inbound messages:
/// - Internal user messages on `own_domain` (excluding `mailer-daemon@<own_domain>`) MUST carry
///   a verified Ed25519 public key and signature.
/// - Any sender address whose `ed25519:<from>` key was previously pinned in `known_peers.json`
///   can NEVER downgrade to an unsigned message (`sender_ed25519_pubkey == None`).
fn verify_or_pin_sender_identity(
    config_path: &Path,
    own_domain: &str,
    from_addr: &str,
    sender_ed25519_pubkey: Option<&str>,
) -> Result<(), SecurityStateError> {
    let from_clean = from_addr.trim().to_ascii_lowercase();
    let own_dom_clean = own_domain.trim().to_ascii_lowercase();
    let is_internal_user = from_clean.ends_with(&format!("@{own_dom_clean}"))
        && !from_clean.starts_with("mailer-daemon@");
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

/// Client-side E2EE nonce anti-replay cache in `.agpop/seen_nonces.json`.
/// Maps `"{ephemeral_pubkey}:{nonce}" -> msg_id`.
/// - First sight: records `msg_id` atomically and returns `Ok(())`.
/// - Same `msg_id`: allows idempotent redelivery if a prior DELETE ACK did not complete.
/// - Different `msg_id`: rejects as a cryptographic replay attack!
/// - Corrupt/unreadable file or write error: fails closed with `SecurityStateError::StateIo`.
fn check_and_record_seen_nonce(
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

fn escape_curl_config_str(s: &str) -> String {
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

fn save_identity(path: &Path, id: &LocalIdentity) -> Result<(), Box<dyn std::error::Error>> {
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

async fn raw_http_req(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let allow_insecure_http = addr.ip().is_loopback()
        || std::env::var("AGPOP_INSECURE_HTTP")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    if !allow_insecure_http {
        // Non-loopback connections MUST use HTTPS and NEVER downgrade to plaintext HTTP
        // (protecting Bearer tokens and payloads against network interception).
        let mut last_err: Option<Box<dyn std::error::Error>> = None;
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

    let mut last_err: Option<Box<dyn std::error::Error>> = None;
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

fn curl_https_req(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    use std::process::Stdio;

    let host = SERVER_HOST
        .get()
        .map(String::as_str)
        .unwrap_or("mail.sealedbyte.com");
    let is_domain = host.parse::<std::net::IpAddr>().is_err() && host != "localhost";
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
    cmd.arg("-sS")
        .arg("--proto")
        .arg("=https")
        .arg("--tlsv1.2")
        .arg("--max-time")
        .arg("10")
        .arg("-X")
        .arg(method)
        .arg("-w")
        .arg("\n__HTTP_CODE__:%{http_code}");

    if use_stdin_cfg {
        // Pass both Authorization header and request body via stdin (`--config -`)
        // so neither Bearer token nor mail payload ever appears in `ps aux` argv.
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
                cfg_buf.push_str(&format!("header = \"Authorization: Bearer {safe_tok}\"\n"));
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

async fn raw_http_req_once(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    const MAX_HTTP_RESP_BYTES: usize = 2 * 1024 * 1024;

    timeout(Duration::from_secs(10), async {
        let mut stream = TcpStream::connect(addr).await?;
        let host_hdr = match SERVER_HOST.get().map(String::as_str) {
            Some(h) if !h.is_empty() && h.parse::<std::net::IpAddr>().is_err() => {
                format!("{h}:{}", addr.port())
            }
            _ => addr.to_string(),
        };
        let auth_hdr = auth
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
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
    .map_err(|_| -> Box<dyn std::error::Error> { "http request timed out".into() })?
}

fn sync_default_allow_list_from_email(ident: &mut LocalIdentity, email: &str) {
    let Some(idx) = email.rfind('@') else {
        return;
    };
    let actual_dom = &email[idx..];
    if actual_dom.len() <= 1 {
        return;
    }
    let placeholder_host = SERVER_HOST
        .get()
        .map(|h| format!("@{h}"))
        .unwrap_or_else(|| "@mail.sealedbyte.com".to_string());
    match ident.allow_list.as_mut() {
        None => {
            ident.allow_list = Some(vec![actual_dom.to_string()]);
        }
        Some(list) if list.len() == 1 && (list[0] == placeholder_host || list[0] == "@mail.sealedbyte.com") => {
            list[0] = actual_dom.to_string();
        }
        _ => {}
    }
}

fn build_register_payload(
    prefix: &str,
    pubkey_hex: &str,
    is_pro: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let (pow_ts, pow_nonce) = if is_pro {
        (0u64, 0u64)
    } else {
        let pk_vec = hex::decode(pubkey_hex.trim())?;
        let pk_bytes: [u8; 32] = pk_vec
            .try_into()
            .map_err(|_| "invalid 32-byte pubkey_hex")?;
        let ts = now_ms();
        let nonce = solve_register_pow(&pk_bytes, ts, REGISTER_POW_BITS);
        (ts, nonce)
    };
    Ok(serde_json::json!({
        "prefix": prefix,
        "pubkey": pubkey_hex,
        "pow_ts": pow_ts,
        "pow_nonce": pow_nonce,
    })
    .to_string())
}

/// Automatically claims a pending ticket if `id` is still None.
async fn load_and_auto_claim(
    server_addr: SocketAddr,
    config_path: &Path,
    wait_until_ready: bool,
) -> Result<LocalIdentity, Box<dyn std::error::Error>> {
    let mut ident = load_identity(config_path)?;
    if ident.id.is_some() && ident.token.is_some() {
        return Ok(ident);
    }

    while let Some(ticket) = ident.ticket.clone() {
        let (code, body) = raw_http_req(
            server_addr,
            "GET",
            &format!("/v1/register/{ticket}"),
            None,
            None,
        )
        .await?;
        if code == 201 {
            let ready: AccountReadyResponse = serde_json::from_str(&body)?;
            sync_default_allow_list_from_email(&mut ident, &ready.email);
            ident.id = Some(ready.id);
            ident.email = Some(ready.email);
            ident.token = Some(ready.token);
            ident.ticket = None;
            save_identity(config_path, &ident)?;
            return Ok(ident);
        } else if code == 202 {
            if !wait_until_ready {
                return Ok(ident);
            }
            let tk: TicketResponse = serde_json::from_str(&body)?;
            tokio::time::sleep(Duration::from_secs(tk.ready_in_secs.clamp(1, 15))).await;
        } else if code == 404 {
            let payload = build_register_payload(&ident.prefix, &ident.pubkey_hex, false)?;
            let (rcode, rbody) =
                raw_http_req(server_addr, "POST", "/v1/register", None, Some(&payload)).await?;
            if rcode == 202 {
                let tk: TicketResponse = serde_json::from_str(&rbody)?;
                ident.ticket = Some(tk.ticket);
                save_identity(config_path, &ident)?;
                if !wait_until_ready {
                    return Ok(ident);
                }
                tokio::time::sleep(Duration::from_secs(tk.ready_in_secs.clamp(1, 15))).await;
            } else {
                return Err(
                    format!("ticket expired and re-register failed ({rcode}): {rbody}").into(),
                );
            }
        } else {
            return Err(format!("claim ticket failed ({code}): {body}").into());
        }
    }

    Ok(ident)
}

async fn cmd_init(
    server_addr: SocketAddr,
    config_path: &Path,
    prefix: &str,
    wait: bool,
    force: bool,
    pro_key: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ident = if !force {
        if let Ok(existing) = load_identity(config_path) {
            if let (Some(_), Some(_)) = (existing.id, existing.token.as_ref()) {
                let out = serde_json::json!({
                    "status": "ready",
                    "email": existing.email.as_deref().unwrap_or(""),
                    "key_id": existing.key_id.as_deref().unwrap_or(""),
                    "config": config_path.display().to_string(),
                });
                println!("{out}");
                return Ok(());
            }
            existing
        } else {
            create_fresh_identity(config_path, prefix)?
        }
    } else {
        create_fresh_identity(config_path, prefix)?
    };

    if ident.ticket.is_none() {
        let payload = build_register_payload(&ident.prefix, &ident.pubkey_hex, pro_key.is_some())?;

        let (code, body) =
            raw_http_req(server_addr, "POST", "/v1/register", pro_key, Some(&payload)).await?;
        if code == 201 {
            let ready: AccountReadyResponse = serde_json::from_str(&body)?;
            sync_default_allow_list_from_email(&mut ident, &ready.email);
            ident.id = Some(ready.id);
            ident.email = Some(ready.email.clone());
            ident.token = Some(ready.token);
            save_identity(config_path, &ident)?;
            let out = serde_json::json!({
                "status": "ready",
                "email": ready.email,
                "key_id": ident.key_id.as_deref().unwrap_or(""),
                "config": config_path.display().to_string(),
            });
            println!("{out}");
            return Ok(());
        } else if code == 202 {
            let tk: TicketResponse = serde_json::from_str(&body)?;
            ident.ticket = Some(tk.ticket.clone());
            save_identity(config_path, &ident)?;
            if !wait {
                let out = serde_json::json!({
                    "status": "pending",
                    "ticket": tk.ticket,
                    "ready_in_secs": tk.ready_in_secs,
                    "config": config_path.display().to_string(),
                });
                println!("{out}");
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(tk.ready_in_secs.clamp(1, 15))).await;
        } else {
            return Err(format!("register failed ({code}): {body}").into());
        }
    }

    let claimed = load_and_auto_claim(server_addr, config_path, wait).await?;
    if let (Some(_), Some(email)) = (claimed.id, claimed.email) {
        let out = serde_json::json!({
            "status": "ready",
            "email": email,
            "key_id": claimed.key_id.as_deref().unwrap_or(""),
            "config": config_path.display().to_string(),
        });
        println!("{out}");
    } else if let Some(ticket) = claimed.ticket {
        let out = serde_json::json!({
            "status": "pending",
            "ticket": ticket,
            "config": config_path.display().to_string(),
        });
        println!("{out}");
    }
    Ok(())
}

fn create_fresh_identity(
    config_path: &Path,
    prefix: &str,
) -> Result<LocalIdentity, Box<dyn std::error::Error>> {
    let mut sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_bytes);
    let sk = StaticSecret::from(sk_bytes);
    let pk = PublicKey::from(&sk);
    let (key_id, ed25519_pk) = derive_ed25519_identity(&sk_bytes);
    sk_bytes.zeroize();
    let default_dom = SERVER_HOST
        .get()
        .filter(|h| h.parse::<std::net::IpAddr>().is_err() && h.as_str() != "localhost")
        .map(|h| format!("@{h}"))
        .unwrap_or_else(|| "@mail.sealedbyte.com".to_string());
    let fresh = LocalIdentity {
        prefix: prefix.to_string(),
        privkey_hex: hex::encode(sk.to_bytes()),
        pubkey_hex: hex::encode(pk.as_bytes()),
        key_id: Some(key_id),
        ed25519_pubkey_hex: Some(ed25519_pk),
        ticket: None,
        id: None,
        email: None,
        token: None,
        allow_list: Some(vec![default_dom]),
    };
    save_identity(config_path, &fresh)?;
    Ok(fresh)
}

/// Sends a 32-byte stateless UDP probe (`[id: 8B][ts_ms: 8B][mac: 16B]`) to check mail count.
/// Only when `count > 0` does it perform HTTP `GET /v1/messages/{id}?probe=1`, decrypt locally,
/// and immediately `DELETE /v1/messages/{id}` to free server RAM slots!
#[allow(clippy::too_many_arguments)]
async fn cmd_wait_or_pop(
    server_addr: SocketAddr,
    config_path: &Path,
    timeout_secs: Option<u64>,
    forever: bool,
    inbox_dir: Option<PathBuf>,
    webhook_url: Option<String>,
    webhook_token: Option<String>,
    on_mail_cmd: Option<String>,
) -> Result<Vec<CleartextMailPayload>, Box<dyn std::error::Error>> {
    let ident = load_and_auto_claim(server_addr, config_path, true).await?;
    let id = ident.id.ok_or("account not ready yet (run `agpop init --wait`)")?;
    let token = ident.token.as_ref().ok_or("missing token")?;
    let token_hash = hash_token(token);

    let mut privkey_vec = hex::decode(&ident.privkey_hex)?;
    let mut privkey_bytes: [u8; 32] = privkey_vec
        .as_slice()
        .try_into()
        .map_err(|_| "bad privkey")?;
    privkey_vec.zeroize();
    let (key_id, ed25519_pubkey) = derive_ed25519_identity(&privkey_bytes);

    let dir = inbox_dir.unwrap_or_else(|| default_inbox_dir(config_path));
    let _ = ensure_private_dir(&dir);
    let resolved_inbox_dir = dir;

    let udp_sock = UdpSocket::bind("0.0.0.0:0").await?;
    let start = Instant::now();

    loop {
        let ts = now_ms();
        let mac = compute_udp_probe_mac(&token_hash, id, ts);
        let mut req = [0u8; UDP_PROBE_REQ_BYTES];
        req[0..8].copy_from_slice(&id.to_le_bytes());
        req[8..16].copy_from_slice(&ts.to_le_bytes());
        req[16..32].copy_from_slice(&mac);

        let udp_target = if !server_addr.ip().is_loopback() && server_addr.port() == 443 {
            SocketAddr::new(server_addr.ip(), 19080)
        } else {
            server_addr
        };
        let _ = udp_sock.send_to(&req, udp_target).await;
        let mut resp = [0u8; UDP_PROBE_RESP_BYTES];

        let (should_fetch, is_probe_confirmed) =
            match timeout(Duration::from_millis(800), udp_sock.recv_from(&mut resp)).await {
                Ok(Ok((UDP_PROBE_RESP_BYTES, _))) => {
                    let has = resp[0] == 1 && resp[1] > 0;
                    (has, has)
                }
                _ => (true, false),
            };

        if should_fetch {
            let fetch_path = if is_probe_confirmed {
                format!("/v1/messages/{id}?probe=1")
            } else {
                format!("/v1/messages/{id}")
            };
            match raw_http_req(
                server_addr,
                "GET",
                &fetch_path,
                Some(token),
                None,
            )
            .await
            {
                Ok((200, body)) => {
                    if let Ok(poll_resp) = serde_json::from_str::<PollResponse>(&body) {
                        if !poll_resp.messages.is_empty() {
                            let mut persisted = Vec::with_capacity(poll_resp.messages.len());
                            let mut ack_msg_ids = Vec::with_capacity(poll_resp.messages.len());
                            let mut disk_write_err: Option<std::io::Error> = None;

                            let own_domain = ident
                                .email
                                .as_deref()
                                .and_then(|e| e.rsplit_once('@').map(|(_, d)| d))
                                .unwrap_or("mail.sealedbyte.com")
                                .to_ascii_lowercase();

                            // 1. Decrypt, verify E2EE anti-replay + TOFU, and durably save each message
                            //    to local disk (0600 + create_new + fsync) BEFORE acknowledging/deleting!
                            for sealed in &poll_resp.messages {
                                if let Ok(mut clear) = unseal_message(&privkey_bytes, sealed) {
                                    // Verify or pin sender Ed25519 identity key (mandatory for internal users
                                    // and any previously-pinned sender; fail-closed on state file corruption/write error)
                                    match verify_or_pin_sender_identity(
                                        config_path,
                                        &own_domain,
                                        &clear.from,
                                        clear.sender_ed25519_pubkey.as_deref(),
                                    ) {
                                        Ok(()) => {}
                                        Err(SecurityStateError::Rejected(_)) => {
                                            ack_msg_ids.push(sealed.msg_id);
                                            continue;
                                        }
                                        Err(SecurityStateError::StateIo(e)) => {
                                            disk_write_err = Some(std::io::Error::other(e));
                                            continue;
                                        }
                                    }

                                    // Reject replayed (ephemeral_pubkey, nonce) under a different msg_id
                                    match check_and_record_seen_nonce(
                                        config_path,
                                        &sealed.ephemeral_pubkey,
                                        &sealed.nonce,
                                        sealed.msg_id,
                                    ) {
                                        Ok(()) => {}
                                        Err(SecurityStateError::Rejected(_)) => {
                                            ack_msg_ids.push(sealed.msg_id);
                                            continue;
                                        }
                                        Err(SecurityStateError::StateIo(e)) => {
                                            disk_write_err = Some(std::io::Error::other(e));
                                            continue;
                                        }
                                    }

                                    clear.received_at_ms = sealed.received_at_ms;
                                    let json_bytes = match serde_json::to_vec_pretty(&clear) {
                                        Ok(b) => b,
                                        Err(e) => {
                                            disk_write_err = Some(std::io::Error::other(e));
                                            continue;
                                        }
                                    };
                                    match write_new_private_mail_file(
                                        &resolved_inbox_dir,
                                        sealed.received_at_ms,
                                        sealed.msg_id,
                                        &json_bytes,
                                    ) {
                                        Ok(rel_path) => {
                                            let content_sha256 = sha256_hex(&json_bytes);
                                            ack_msg_ids.push(sealed.msg_id);
                                            persisted.push((
                                                sealed.msg_id,
                                                rel_path,
                                                content_sha256,
                                                clear,
                                            ));
                                        }
                                        Err(e) => {
                                            // Do NOT add to `ack_msg_ids` so message stays on server!
                                            disk_write_err = Some(e);
                                        }
                                    }
                                }
                            }

                            // 2. Only DELETE messages from server RAM that were successfully synced to disk!
                            if !ack_msg_ids.is_empty() {
                                let del_body =
                                    serde_json::json!({ "msg_ids": ack_msg_ids }).to_string();
                                let _ = raw_http_req(
                                    server_addr,
                                    "DELETE",
                                    &format!("/v1/messages/{id}"),
                                    Some(token),
                                    Some(&del_body),
                                )
                                .await;
                            }

                            // 3. Emit event notifications / webhooks / local hooks for persisted messages
                            for (msg_id, rel_path, content_sha256, m) in &persisted {
                                let (
                                    body_excerpt,
                                    body_total_bytes,
                                    excerpt_bytes,
                                    body_truncated,
                                ) = utf8_safe_excerpt(&m.text, EXCERPT_MAX_BYTES);

                                let now_event_ms = now_ms();
                                let event_id = generate_uuid_v7(now_event_ms);
                                let occurred_at = format_rfc3339_utc(now_event_ms);
                                let received_at = format_rfc3339_utc(m.received_at_ms);

                                let mut envelope = WebhookEnvelope {
                                    envelope_version: ENVELOPE_VERSION.to_string(),
                                    event_id: event_id.clone(),
                                    event_type: "mail.received".to_string(),
                                    data_schema_version: "mail.received.v1".to_string(),
                                    occurred_at,
                                    attempt: 1,
                                    key_id: key_id.clone(),
                                    ed25519_pubkey: ed25519_pubkey.clone(),
                                    data: EventData::MailReceived(MailReceivedData {
                                        msg_id: *msg_id,
                                        from: m.from.clone(),
                                        to: m.to.clone(),
                                        subject: m.subject.clone(),
                                        body_excerpt,
                                        body_total_bytes,
                                        excerpt_bytes,
                                        body_truncated,
                                        rel_path: rel_path.clone(),
                                        content_sha256: content_sha256.clone(),
                                        received_at,
                                        received_at_ms: m.received_at_ms,
                                    }),
                                };

                                if forever {
                                    if let Ok(line) = serde_json::to_string(&envelope) {
                                        println!("{line}");
                                    }
                                }

                                // 1. Native HTTP Webhook callback with retry & dead-letter
                                if let Some(ref wh_url) = webhook_url {
                                    let _ = deliver_webhook(
                                        wh_url,
                                        webhook_token.as_deref(),
                                        &privkey_bytes,
                                        &mut envelope,
                                        &resolved_inbox_dir,
                                    )
                                    .await;
                                }

                                // 2. Local command hook (--exec / --on-mail)
                                if let Some(ref cmd_str) = on_mail_cmd {
                                    let env_json =
                                        serde_json::to_string(&envelope).unwrap_or_default();
                                    let sig = sign_ed25519(&privkey_bytes, env_json.as_bytes());
                                    #[cfg(not(windows))]
                                    let mut hook_cmd = {
                                        let mut c = std::process::Command::new("sh");
                                        c.arg("-c")
                                            .arg(cmd_str)
                                            .arg("agpop-hook")
                                            .arg(rel_path)
                                            .arg(&m.from)
                                            .arg(&m.subject)
                                            .arg(&event_id)
                                            .arg(content_sha256);
                                        c
                                    };
                                    #[cfg(windows)]
                                    let mut hook_cmd = {
                                        let mut c = std::process::Command::new("cmd.exe");
                                        c.arg("/C").arg(cmd_str);
                                        c
                                    };
                                    let _ = hook_cmd
                                        .env("AGPOP_REL_PATH", rel_path)
                                        .env("AGPOP_FILE", rel_path)
                                        .env("AGPOP_SHA256", content_sha256)
                                        .env("AGPOP_EVENT_ID", &event_id)
                                        .env("AGPOP_KEY_ID", &key_id)
                                        .env("AGPOP_SIGNATURE", &sig)
                                        .env("AGPOP_ENVELOPE", &env_json)
                                        .env("AGPOP_FROM", &m.from)
                                        .env("AGPOP_TO", &m.to)
                                        .env("AGPOP_SUBJECT", &m.subject)
                                        .env("AGPOP_TEXT", &m.text)
                                        .env(
                                            "AGPOP_RECEIVED_AT_MS",
                                            m.received_at_ms.to_string(),
                                        )
                                        .status();
                                }
                            }

                            let batch_msgs = match finalize_batch_persistence_result(
                                persisted,
                                disk_write_err,
                                &resolved_inbox_dir,
                            ) {
                                Ok(msgs) => msgs,
                                Err(err_msg) => {
                                    privkey_bytes.zeroize();
                                    return Err(err_msg.into());
                                }
                            };

                            if !forever && !batch_msgs.is_empty() {
                                privkey_bytes.zeroize();
                                return Ok(batch_msgs);
                            }
                        }
                    }
                }
                Err(e) if !forever => {
                    privkey_bytes.zeroize();
                    return Err(e);
                }
                _ => {}
            }
        }

        if let Some(limit) = timeout_secs {
            if limit == 0 || start.elapsed().as_secs() >= limit {
                privkey_bytes.zeroize();
                return Ok(Vec::new());
            }
        }

        let wait_s = u16::from_le_bytes([resp[2], resp[3]]).clamp(1, 15) as u64;
        let sleep_s = if wait_s <= 1 && forever { 5 } else { wait_s };
        tokio::time::sleep(Duration::from_secs(sleep_s)).await;
    }
}

/// Evaluates the outcome of a fetched message batch after any successfully persisted messages
/// have been acknowledged on the server and emitted to hooks:
/// - If any state file (`known_peers.json` / `seen_nonces.json`) or inbox file write failed,
///   always emits a visible diagnostic on `stderr` and returns `Err(...)` (in both one-shot
///   and daemon modes, and even if earlier messages in the same batch succeeded).
fn finalize_batch_persistence_result(
    persisted: Vec<(u64, String, String, CleartextMailPayload)>,
    disk_write_err: Option<std::io::Error>,
    resolved_inbox_dir: &Path,
) -> Result<Vec<CleartextMailPayload>, String> {
    if let Some(err) = disk_write_err {
        let msg = format!(
            "local state or inbox persistence failed in '{}': {err} (unpersisted messages retained on server)",
            resolved_inbox_dir.display()
        );
        eprintln!("agpop error: {msg}");
        return Err(msg);
    }
    Ok(persisted.into_iter().map(|(_, _, _, m)| m).collect())
}

/// Delivers `WebhookEnvelope` via HTTP POST with:
/// - Body: JSON-serialized `WebhookEnvelope`
/// - Headers: `X-Agpop-Event`, `X-Agpop-Event-Id`, `X-Agpop-Attempt`, `X-Agpop-Key-Id`, `X-Agpop-Signature`
/// - Semantics:
///   * `200..=299` (including `202 Accepted`): success
///   * `400..=499` (except `408` and `429`): permanent failure, no retry, write to dead-letter
///   * `408`, `429`, `500..=599`, or network error: retry up to 5 times (`[1, 2, 4, 8, 16]`s, honoring `Retry-After`)
async fn deliver_webhook(
    url: &str,
    webhook_token: Option<&str>,
    privkey_bytes: &[u8; 32],
    envelope: &mut WebhookEnvelope,
    inbox_dir: &Path,
) -> Result<(), String> {
    for retry_idx in 0..=RETRY_BACKOFF_SECS.len() {
        envelope.attempt = (retry_idx + 1) as u32;
        let body_bytes = serde_json::to_vec(envelope).map_err(|e| e.to_string())?;
        let signature = sign_ed25519(privkey_bytes, &body_bytes);

        let (status_code, retry_after_opt, resp_body) =
            post_webhook_once(url, webhook_token, envelope, &signature, &body_bytes);

        // 2xx (including 202 Accepted) -> Success!
        if (200..=299).contains(&status_code) {
            return Ok(());
        }

        // 4xx (except 408 Request Timeout and 429 Too Many Requests) -> Permanent failure!
        if (400..=499).contains(&status_code) && status_code != 408 && status_code != 429 {
            append_dead_letter(inbox_dir, envelope, status_code, &resp_body, "permanent_4xx");
            return Err(format!("webhook permanent failure ({status_code}): {resp_body}"));
        }

        // Transient failure (408, 429, 5xx, or network error status_code == 0)
        if let Some(&default_wait) = RETRY_BACKOFF_SECS.get(retry_idx) {
            let wait_secs = retry_after_opt
                .map(|s| s.clamp(1, 60))
                .unwrap_or(default_wait);
            tokio::time::sleep(Duration::from_secs(wait_secs)).await;
        } else {
            append_dead_letter(
                inbox_dir,
                envelope,
                status_code,
                &resp_body,
                "retries_exhausted",
            );
            return Err(format!(
                "webhook retries exhausted after {} attempts (last status={status_code})",
                envelope.attempt
            ));
        }
    }
    Ok(())
}

fn post_webhook_once(
    url: &str,
    webhook_token: Option<&str>,
    envelope: &WebhookEnvelope,
    signature: &str,
    body_bytes: &[u8],
) -> (u16, Option<u64>, String) {
    use std::process::Stdio;

    let mut cmd = std::process::Command::new(CURL_BIN);
    cmd.arg("-sS")
        .arg("--max-time")
        .arg("10")
        .arg("-D")
        .arg("-")
        .arg("-w")
        .arg("\n__WH_CODE__:%{http_code}")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json; charset=utf-8")
        .arg("-H")
        .arg(format!("X-Agpop-Event: {}", envelope.event_type))
        .arg("-H")
        .arg(format!("X-Agpop-Event-Id: {}", envelope.event_id))
        .arg("-H")
        .arg(format!("X-Agpop-Attempt: {}", envelope.attempt))
        .arg("-H")
        .arg(format!("X-Agpop-Key-Id: {}", envelope.key_id))
        .arg("-H")
        .arg(format!("X-Agpop-Signature: {signature}"))
        .arg("--config")
        .arg("-")
        .arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let Ok(mut child) = cmd.spawn() else {
        return (0, None, "failed to invoke curl".to_string());
    };
    if let Some(mut stdin) = child.stdin.take() {
        let mut cfg_buf = String::new();
        if let Some(tok) = webhook_token {
            let safe_tok: String = tok
                .chars()
                .filter(|c| !matches!(c, '"' | '\\' | '\r' | '\n'))
                .collect();
            cfg_buf.push_str(&format!("header = \"X-Wake-Token: {safe_tok}\"\n"));
        }
        let body_str = String::from_utf8_lossy(body_bytes);
        let escaped_body = escape_curl_config_str(&body_str);
        cfg_buf.push_str(&format!("data-binary = \"{escaped_body}\"\n"));
        let _ = stdin.write_all(cfg_buf.as_bytes());
        cfg_buf.zeroize();
    }
    let Ok(out) = child.wait_with_output() else {
        return (0, None, "failed to wait on curl".to_string());
    };
    if !out.status.success() && out.stdout.is_empty() {
        return (
            0,
            None,
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        );
    }

    let raw_full = String::from_utf8_lossy(&out.stdout);
    let (raw, code_marker) = raw_full
        .rsplit_once("\n__WH_CODE__:")
        .unwrap_or((&raw_full, "0"));
    let raw = raw.strip_suffix('\r').unwrap_or(raw);
    let mut rem = raw;
    while rem.starts_with("HTTP/") {
        let first_line = rem.lines().next().unwrap_or("");
        let is_interim = first_line
            .split_whitespace()
            .nth(1)
            .is_some_and(|c| c.starts_with('1'));
        if is_interim {
            if let Some((_, after)) = rem.split_once("\r\n\r\n") {
                rem = after;
                continue;
            }
        }
        break;
    }
    let (hdr_part, body_part) = rem
        .split_once("\r\n\r\n")
        .or_else(|| rem.split_once("\n\n"))
        .unwrap_or((rem, ""));
    let code = code_marker
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|&c| c > 0)
        .unwrap_or_else(|| {
            hdr_part
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|c| c.parse::<u16>().ok())
                .unwrap_or(0)
        });

    let retry_after = hdr_part.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("retry-after") {
            v.trim().parse::<u64>().ok()
        } else {
            None
        }
    });

    (code, retry_after, body_part.to_string())
}

fn append_dead_letter(
    inbox_dir: &Path,
    envelope: &WebhookEnvelope,
    last_status: u16,
    last_response: &str,
    reason: &str,
) {
    let _ = ensure_private_dir(inbox_dir);
    let dl_path = inbox_dir.join("dead-letter.jsonl");
    #[cfg(unix)]
    let file_res = {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let r = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&dl_path);
        let _ = fs::set_permissions(&dl_path, fs::Permissions::from_mode(0o600));
        r
    };
    #[cfg(not(unix))]
    let file_res = OpenOptions::new().create(true).append(true).open(&dl_path);

    if let Ok(mut f) = file_res {
        let entry = serde_json::json!({
            "failed_at": format_rfc3339_utc(now_ms()),
            "reason": reason,
            "last_status": last_status,
            "last_response": last_response,
            "envelope": envelope,
        });
        let _ = writeln!(f, "{entry}");
    }
}

fn parse_entry_args(entries: &[String]) -> Vec<String> {
    let mut clean = Vec::new();
    let mut skip_next = false;
    for s in entries {
        if skip_next {
            skip_next = false;
            continue;
        }
        if s.starts_with("--") {
            skip_next = true;
            continue;
        }
        let trimmed = s.trim().to_ascii_lowercase();
        if !trimmed.is_empty() && !clean.contains(&trimmed) {
            clean.push(trimmed);
        }
    }
    clean
}

async fn cmd_allow(
    server_addr: SocketAddr,
    config_path: &Path,
    action: &str,
    entries: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ident = load_and_auto_claim(server_addr, config_path, true).await?;
    let id = ident.id.ok_or("account not ready")?;
    let token = ident.token.clone().ok_or("missing token")?;
    let path = format!("/v1/whitelist/{id}");

    // Sync local allow_list with server truth before mutating
    if let Ok((200, body)) = raw_http_req(server_addr, "GET", &path, Some(&token), None).await {
        if let Ok(wl) = serde_json::from_str::<WhitelistResponse>(&body) {
            if !wl.entries.is_empty() {
                ident.allow_list = Some(wl.entries);
                let _ = save_identity(config_path, &ident);
            } else if ident.allow_list.is_none() {
                let initial = if wl.active_slots > 0 {
                    let default_dom = ident
                        .email
                        .as_deref()
                        .and_then(|e| e.rfind('@').map(|idx| e[idx..].to_string()))
                        .unwrap_or_else(|| "@mail.sealedbyte.com".to_string());
                    vec![default_dom]
                } else {
                    Vec::new()
                };
                ident.allow_list = Some(initial);
                let _ = save_identity(config_path, &ident);
            }
        }
    }

    let (code, body) = match action {
        "add" => {
            let to_add = parse_entry_args(entries);
            if to_add.is_empty() {
                return Err("missing entries to add (e.g. `agpop allow add @github.com`)".into());
            }
            let mut current = ident.allow_list.clone().unwrap_or_default();
            for item in to_add {
                if !current.contains(&item) {
                    current.push(item);
                }
            }
            let payload = serde_json::json!({ "entries": current }).to_string();
            let (c, b) =
                raw_http_req(server_addr, "PUT", &path, Some(&token), Some(&payload)).await?;
            if c == 200 {
                ident.allow_list = Some(current);
                let _ = save_identity(config_path, &ident);
            }
            (c, b)
        }
        "rm" | "remove" | "del" => {
            let to_rm = parse_entry_args(entries);
            if to_rm.is_empty() {
                return Err("missing entries to remove (e.g. `agpop allow rm @github.com`)".into());
            }
            let mut current = ident.allow_list.clone().unwrap_or_default();
            current.retain(|item| !to_rm.contains(item));
            let payload = serde_json::json!({ "entries": current }).to_string();
            let (c, b) =
                raw_http_req(server_addr, "PUT", &path, Some(&token), Some(&payload)).await?;
            if c == 200 {
                ident.allow_list = Some(current);
                let _ = save_identity(config_path, &ident);
            }
            (c, b)
        }
        "set" => {
            let clean = parse_entry_args(entries);
            let payload = serde_json::json!({ "entries": clean }).to_string();
            let (c, b) =
                raw_http_req(server_addr, "PUT", &path, Some(&token), Some(&payload)).await?;
            if c == 200 {
                ident.allow_list = Some(clean);
                let _ = save_identity(config_path, &ident);
            }
            (c, b)
        }
        "clear" => {
            let (c, b) = raw_http_req(server_addr, "DELETE", &path, Some(&token), None).await?;
            if c == 200 {
                ident.allow_list = Some(Vec::new());
                let _ = save_identity(config_path, &ident);
            }
            (c, b)
        }
        _ => raw_http_req(server_addr, "GET", &path, Some(&token), None).await?,
    };

    if code == 200 {
        let mut wl: WhitelistResponse = serde_json::from_str(&body)?;
        if wl.entries.is_empty() && wl.active_slots > 0 {
            if let Some(ref local_list) = ident.allow_list {
                if !local_list.is_empty() {
                    wl.entries = local_list.clone();
                    if wl.active_slots == local_list.len() {
                        let sync_payload = serde_json::json!({ "entries": local_list }).to_string();
                        let _ = raw_http_req(
                            server_addr,
                            "PUT",
                            &path,
                            Some(&token),
                            Some(&sync_payload),
                        )
                        .await;
                    }
                }
            }
        } else if !wl.entries.is_empty() {
            ident.allow_list = Some(wl.entries.clone());
            let _ = save_identity(config_path, &ident);
        }
        println!("{}", serde_json::to_string(&wl)?);
        Ok(())
    } else {
        Err(format!("whitelist request failed ({code}): {body}").into())
    }
}

async fn cmd_send(
    server_addr: SocketAddr,
    config_path: &Path,
    to: &str,
    subject: &str,
    text: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ident = load_and_auto_claim(server_addr, config_path, true).await?;
    let id = ident.id.ok_or("account not ready")?;
    let token = ident.token.as_ref().ok_or("missing token")?;

    let to_clean = to
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_ascii_lowercase();
    if to_clean.is_empty()
        || !to_clean.contains('@')
        || !to_clean
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b'-' | b'_' | b'+'))
    {
        return Err("invalid recipient email address".into());
    }
    let own_domain = ident
        .email
        .as_deref()
        .and_then(|e| e.rsplit_once('@').map(|(_, d)| d))
        .unwrap_or("mail.sealedbyte.com")
        .to_ascii_lowercase();
    let is_internal = to_clean.ends_with(&format!("@{own_domain}"));

    let mut payload = if is_internal {
        // Zero-Trust Client-Side E2EE for same-domain Agent-to-Agent messages:
        // 1. Fetch recipient's X25519 public key (authenticated & whitelist-gated)
        let pk_path = format!("/v1/pubkey/{id}?to={to_clean}");
        let (pk_code, pk_body) =
            raw_http_req(server_addr, "GET", &pk_path, Some(token), None).await?;
        if pk_code != 200 {
            return Err(format!("send failed ({pk_code}): {pk_body}").into());
        }
        let pk_res: PubkeyLookupResponse = serde_json::from_str(&pk_body)?;
        let resp_to = pk_res.to.trim().to_ascii_lowercase();
        if resp_to != to_clean {
            return Err(format!(
                "server pubkey response recipient mismatch: requested '{to_clean}', got '{resp_to}'"
            )
            .into());
        }
        let resp_from = pk_res.sender_email.trim().to_ascii_lowercase();
        if let Some(ref own_email) = ident.email {
            let own_primary = own_email.trim().to_ascii_lowercase();
            if resp_from != own_primary {
                return Err(format!(
                    "server pubkey response sender_email mismatch: got '{resp_from}'"
                )
                .into());
            }
        }
        // Enforce TOFU public key pinning bound strictly to the locally requested `to_clean`
        verify_or_pin_peer_key(config_path, &to_clean, &pk_res.pubkey)
            .map_err(|e| e.to_string())?;
        let pk_vec = hex::decode(pk_res.pubkey.trim())?;
        let rcpt_pubkey: [u8; 32] = pk_vec
            .try_into()
            .map_err(|_| "invalid 32-byte recipient pubkey from server")?;

        let mut sk_vec = hex::decode(&ident.privkey_hex)?;
        let mut sender_privkey: [u8; 32] = sk_vec
            .as_slice()
            .try_into()
            .map_err(|_| "invalid local privkey")?;
        sk_vec.zeroize();

        // 2. Sign with sender's Ed25519 identity and seal locally in client RAM
        //    with `sender_email` bound as ChaCha20-Poly1305 AAD
        let mut cleartext = CleartextMailPayload {
            from: resp_from.clone(),
            to: to_clean.clone(),
            subject: subject.chars().take(256).collect(),
            text: text.to_string(),
            received_at_ms: now_ms(),
            sender_ed25519_pubkey: None,
            sender_signature: None,
        };
        sign_cleartext_mail(&sender_privkey, &mut cleartext);
        sender_privkey.zeroize();
        let mut plaintext_bytes = serde_json::to_vec(&cleartext)?;
        cleartext.subject.zeroize();
        cleartext.text.zeroize();
        if plaintext_bytes.len() > pk_res.max_msg_bytes {
            plaintext_bytes.zeroize();
            return Err(format!(
                "message exceeds recipient size limit ({} bytes)",
                pk_res.max_msg_bytes
            )
            .into());
        }
        let (ephemeral_pubkey, nonce, ciphertext_b64) =
            seal_and_zeroize(&rcpt_pubkey, &mut plaintext_bytes, &resp_from)?;

        // 3. Upload ONLY ciphertext (zero plaintext ever leaves this machine)
        serde_json::json!({
            "to": to_clean,
            "ephemeral_pubkey": ephemeral_pubkey,
            "nonce": nonce,
            "ciphertext_b64": ciphertext_b64,
        })
        .to_string()
    } else {
        // External SMTP recipient: server signs with DKIM and delivers via STARTTLS
        serde_json::json!({
            "to": to_clean,
            "subject": subject,
            "text": text,
        })
        .to_string()
    };

    let req_res = raw_http_req(
        server_addr,
        "POST",
        &format!("/v1/send/{id}"),
        Some(token),
        Some(&payload),
    )
    .await;
    payload.zeroize();
    let (code, body) = req_res?;

    if code == 200 {
        let res: SendResponse = serde_json::from_str(&body)?;
        let from_addr = if !res.from.is_empty() {
            res.from
        } else {
            ident.email.unwrap_or_default()
        };
        let out = serde_json::json!({
            "status": res.status,
            "msg_id": res.msg_id,
            "from": from_addr,
            "to": to,
            "subject": subject,
        });
        println!("{}", serde_json::to_string(&out)?);
        Ok(())
    } else {
        Err(format!("send failed ({code}): {body}").into())
    }
}

fn default_inbox_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new(".agpop"))
        .join("inbox")
}

/// Loads local archived messages from `inbox_dir`, sorted newest-first (`received_at_ms` descending).
fn load_local_inbox(inbox_dir: &Path) -> Vec<(String, CleartextMailPayload)> {
    let mut items = Vec::new();
    let Ok(rd) = fs::read_dir(inbox_dir) else {
        return items;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let Some(fname) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !fname.starts_with("mail-") || !fname.ends_with(".json") {
            continue;
        }
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(msg) = serde_json::from_str::<CleartextMailPayload>(&raw) {
                items.push((fname.to_string(), msg));
            }
        }
    }
    items.sort_by_key(|b| std::cmp::Reverse(b.1.received_at_ms));
    items
}

fn resolve_inbox_message(
    inbox_dir: &Path,
    target: &str,
) -> Result<(String, CleartextMailPayload), Box<dyn std::error::Error>> {
    let items = load_local_inbox(inbox_dir);
    if items.is_empty() {
        return Err(format!("no messages found in '{}'", inbox_dir.display()).into());
    }
    if target.eq_ignore_ascii_case("latest") {
        return Ok(items.into_iter().next().unwrap());
    }
    if let Ok(idx) = target.parse::<usize>() {
        if idx >= 1 && idx <= items.len() {
            return Ok(items.into_iter().nth(idx - 1).unwrap());
        }
    }
    let target_lower = target.to_ascii_lowercase();
    if let Some(found) = items.into_iter().find(|(fname, msg)| {
        let from_lower = msg.from.to_ascii_lowercase();
        fname == target
            || fname.contains(target)
            || from_lower == target_lower
            || from_lower.starts_with(&target_lower)
            || from_lower.contains(&target_lower)
    }) {
        return Ok(found);
    }
    Err(format!("message '{target}' not found in '{}'", inbox_dir.display()).into())
}

fn cmd_inbox(
    inbox_dir: &Path,
    action: &str,
    target: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        "read" | "show" | "get" => {
            let tgt = target.unwrap_or("latest");
            let (fname, msg) = resolve_inbox_message(inbox_dir, tgt)?;
            let out = serde_json::json!({
                "file": fname,
                "from": msg.from,
                "to": msg.to,
                "subject": msg.subject,
                "text": msg.text,
                "received_at": format_rfc3339_utc(msg.received_at_ms),
                "received_at_ms": msg.received_at_ms,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        _ => {
            let items = load_local_inbox(inbox_dir);
            let list: Vec<serde_json::Value> = items
                .into_iter()
                .enumerate()
                .map(|(i, (fname, m))| {
                    let (excerpt, _, _, _) = utf8_safe_excerpt(&m.text, 120);
                    serde_json::json!({
                        "index": i + 1,
                        "file": fname,
                        "from": m.from,
                        "subject": m.subject,
                        "excerpt": excerpt,
                        "received_at": format_rfc3339_utc(m.received_at_ms),
                        "received_at_ms": m.received_at_ms,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string(&list)?);
        }
    }
    Ok(())
}

async fn cmd_reply(
    server_addr: SocketAddr,
    config_path: &Path,
    inbox_dir: &Path,
    target: &str,
    body: &str,
    subject_override: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_, orig) = resolve_inbox_message(inbox_dir, target)?;
    let reply_subject = if let Some(s) = subject_override {
        s.to_string()
    } else if orig.subject.to_ascii_lowercase().starts_with("re:") {
        orig.subject.clone()
    } else {
        format!("Re: {}", orig.subject)
    };
    cmd_send(
        server_addr,
        config_path,
        &orig.from,
        &reply_subject,
        body,
    )
    .await
}

#[cfg(not(windows))]
fn is_pid_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn is_pid_alive(pid: u32) -> bool {
    let filter = format!("PID eq {pid}");
    let needle = format!("\"{pid}\"");
    std::process::Command::new("tasklist")
        .args(["/FI", &filter, "/NH", "/FO", "CSV"])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).contains(&needle))
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn stop_pid(pid: u32) {
    let _ = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();
}

#[cfg(windows)]
fn stop_pid(pid: u32) {
    let _ = std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn cmd_daemon_ctl(
    _server_addr: SocketAddr,
    config_path: &Path,
    action: &str,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| Path::new(".agpop"))
        .to_path_buf();
    let pid_path = config_dir.join("daemon.pid");
    let log_path = config_dir.join("daemon.log");
    let inbox_dir = flag_val(args, "--inbox-dir")
        .map(PathBuf::from)
        .or_else(|| std::env::var("AGPOP_INBOX_DIR").ok().map(PathBuf::from))
        .unwrap_or_else(|| default_inbox_dir(config_path));

    let existing_pid = fs::read_to_string(&pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());

    match action {
        "status" => {
            if let Some(pid) = existing_pid {
                if is_pid_alive(pid) {
                    let out = serde_json::json!({
                        "status": "running",
                        "pid": pid,
                        "config": config_path.display().to_string(),
                        "inbox_dir": inbox_dir.display().to_string(),
                        "log": log_path.display().to_string(),
                    });
                    println!("{out}");
                    return Ok(());
                }
                let _ = fs::remove_file(&pid_path);
            }
            let out = serde_json::json!({
                "status": "stopped",
                "config": config_path.display().to_string(),
                "inbox_dir": inbox_dir.display().to_string(),
            });
            println!("{out}");
        }
        "stop" => {
            if let Some(pid) = existing_pid {
                if is_pid_alive(pid) {
                    stop_pid(pid);
                }
                let _ = fs::remove_file(&pid_path);
                let out = serde_json::json!({
                    "status": "stopped",
                    "pid": pid,
                });
                println!("{out}");
            } else {
                let out = serde_json::json!({
                    "status": "not_running",
                });
                println!("{out}");
            }
        }
        "start" => {
            if !config_path.exists() {
                return Err(
                    "identity not initialized in current directory (run `agpop init` first)"
                        .into(),
                );
            }
            if let Some(pid) = existing_pid {
                if is_pid_alive(pid) {
                    let out = serde_json::json!({
                        "status": "already_running",
                        "pid": pid,
                        "config": config_path.display().to_string(),
                        "inbox_dir": inbox_dir.display().to_string(),
                        "log": log_path.display().to_string(),
                    });
                    println!("{out}");
                    return Ok(());
                }
                let _ = fs::remove_file(&pid_path);
            }

            let _ = ensure_private_dir(&config_dir);
            let _ = ensure_private_dir(&inbox_dir);
            #[cfg(unix)]
            let log_out = {
                use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .open(&log_path)?;
                let _ = fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600));
                f
            };
            #[cfg(not(unix))]
            let log_out = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)?;
            let log_err = log_out.try_clone()?;

            let exe = std::env::current_exe()?;
            let mut cmd = std::process::Command::new(exe);
            cmd.arg("wait")
                .arg("--forever")
                .arg("--config")
                .arg(config_path)
                .arg("--inbox-dir")
                .arg(&inbox_dir);

            if let Some(srv) = flag_val(args, "--server") {
                cmd.arg("--server").arg(srv);
            }
            if let Some(wh) = flag_val(args, "--webhook-url")
                .or_else(|| flag_val(args, "--callback-url"))
            {
                cmd.arg("--webhook-url").arg(wh);
            }
            if let Some(tok) = flag_val(args, "--webhook-token")
                .or_else(|| std::env::var("AGPOP_WEBHOOK_TOKEN").ok())
            {
                cmd.env("AGPOP_WEBHOOK_TOKEN", tok);
            }
            if let Some(ex) = flag_val(args, "--exec").or_else(|| flag_val(args, "--on-mail")) {
                cmd.arg("--exec").arg(ex);
            }

            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }

            let child = cmd
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::from(log_out))
                .stderr(std::process::Stdio::from(log_err))
                .spawn()?;

            let pid = child.id();
            fs::write(&pid_path, pid.to_string())?;
            let out = serde_json::json!({
                "status": "started",
                "pid": pid,
                "config": config_path.display().to_string(),
                "inbox_dir": inbox_dir.display().to_string(),
                "log": log_path.display().to_string(),
            });
            println!("{out}");
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mail_file_never_overwrites_and_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("agpop_test_inbox_{}", OsRng.next_u64()));
        let _ = fs::remove_dir_all(&dir);

        let body1 = b"{\"subject\":\"msg 1\"}";
        let body2 = b"{\"subject\":\"msg 2 colliding timestamp/id\"}";

        let f1 = write_new_private_mail_file(&dir, 1700000000000, 42, body1).unwrap();
        assert_eq!(f1, "mail-1700000000000-id42.json");

        // Idempotent retry with identical payload returns same filename without error
        let f1_retry = write_new_private_mail_file(&dir, 1700000000000, 42, body1).unwrap();
        assert_eq!(f1_retry, f1);
        assert_eq!(fs::read(dir.join(&f1)).unwrap(), body1);

        // Colliding timestamp + id with different payload NEVER overwrites `f1`; allocates suffixed file
        let f2 = write_new_private_mail_file(&dir, 1700000000000, 42, body2).unwrap();
        assert_ne!(f2, f1);
        assert_eq!(fs::read(dir.join(&f1)).unwrap(), body1);
        assert_eq!(fs::read(dir.join(&f2)).unwrap(), body2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tofu_key_pinning_and_nonce_anti_replay() {
        let dir = std::env::temp_dir().join(format!("agpop_test_tofu_{}", OsRng.next_u64()));
        let _ = fs::remove_dir_all(&dir);
        let cfg = dir.join("identity.json");

        // First sight pins key
        assert!(verify_or_pin_peer_key(&cfg, "alice-k9x2@mail.sealedbyte.com", "aa11bb22").is_ok());
        // Subsequent sight of same key succeeds
        assert!(verify_or_pin_peer_key(&cfg, "alice-k9x2@mail.sealedbyte.com", "AA11BB22").is_ok());
        // Key substitution (MITM) is rejected
        assert!(verify_or_pin_peer_key(&cfg, "alice-k9x2@mail.sealedbyte.com", "cc33dd44").is_err());

        // Nonce anti-replay: first sight succeeds, same msg_id is idempotent, different msg_id is rejected
        assert!(check_and_record_seen_nonce(&cfg, "eph1", "nonce1", 101).is_ok());
        assert!(check_and_record_seen_nonce(&cfg, "eph1", "nonce1", 101).is_ok());
        assert!(matches!(
            check_and_record_seen_nonce(&cfg, "eph1", "nonce1", 102),
            Err(SecurityStateError::Rejected(_))
        ));

        // Sender identity enforcement:
        // 1. Unsigned internal user mail is rejected
        assert!(matches!(
            verify_or_pin_sender_identity(&cfg, "mail.sealedbyte.com", "alice-k9x2@mail.sealedbyte.com", None),
            Err(SecurityStateError::Rejected(_))
        ));
        // 2. Signed internal user mail pins Ed25519 key; subsequent downgrade to unsigned is rejected
        assert!(verify_or_pin_sender_identity(
            &cfg,
            "mail.sealedbyte.com",
            "alice-k9x2@mail.sealedbyte.com",
            Some("ed25519pk_alice"),
        )
        .is_ok());
        assert!(matches!(
            verify_or_pin_sender_identity(&cfg, "mail.sealedbyte.com", "alice-k9x2@mail.sealedbyte.com", None),
            Err(SecurityStateError::Rejected(_))
        ));
        // 3. `mailer-daemon@<own_domain>` and unpinned external SMTP senders are permitted without Ed25519 key
        assert!(verify_or_pin_sender_identity(
            &cfg,
            "mail.sealedbyte.com",
            "mailer-daemon@mail.sealedbyte.com",
            None,
        )
        .is_ok());
        assert!(verify_or_pin_sender_identity(
            &cfg,
            "mail.sealedbyte.com",
            "ext@github.com",
            None,
        )
        .is_ok());

        // 4. Corrupted known_peers.json or seen_nonces.json fails closed with StateIo (never resets to empty)
        fs::write(dir.join("known_peers.json"), b"{corrupt json").unwrap();
        assert!(matches!(
            verify_or_pin_peer_key(&cfg, "bob-rye5@mail.sealedbyte.com", "11223344"),
            Err(SecurityStateError::StateIo(_))
        ));
        fs::write(dir.join("seen_nonces.json"), b"[corrupt json").unwrap();
        assert!(matches!(
            check_and_record_seen_nonce(&cfg, "eph2", "nonce2", 200),
            Err(SecurityStateError::StateIo(_))
        ));

        // 5. Lock file is never stolen while held, and cleanly releases on drop
        let guard = acquire_state_file_lock_with_retries(&dir, "known_peers", 5).unwrap();
        assert!(matches!(
            acquire_state_file_lock_with_retries(&dir, "known_peers", 3),
            Err(SecurityStateError::StateIo(_))
        ));
        drop(guard);
        let guard2 = acquire_state_file_lock_with_retries(&dir, "known_peers", 3).unwrap();
        drop(guard2);

        // 6. Batch persistence error is always surfaced even when earlier messages in the batch succeeded
        let dummy_msg = CleartextMailPayload {
            from: "alice-k9x2@mail.sealedbyte.com".into(),
            to: "bob-rye5@mail.sealedbyte.com".into(),
            subject: "Persisted #1".into(),
            text: "ok".into(),
            received_at_ms: 1700000000000,
            sender_ed25519_pubkey: None,
            sender_signature: None,
        };
        let partial_err = finalize_batch_persistence_result(
            vec![(1, "mail-1.json".into(), "sha256".into(), dummy_msg)],
            Some(std::io::Error::other("corrupted known_peers.json")),
            &dir,
        );
        assert!(partial_err.is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_reply_always_uses_primary_short_tag_email() {
        use tokio::net::TcpListener;

        // Unknown flags in `send` / `reply` are rejected rather than silently ignored
        let bad_send_args: Vec<String> = vec![
            "agpop".into(),
            "send".into(),
            "--to".into(),
            "alice-k9x2@mail.sealedbyte.com".into(),
            "--body".into(),
            "hi".into(),
            "--legacy-flag".into(),
        ];
        assert!(
            check_allowed_flags(
                &bad_send_args,
                2,
                &["--to", "--subject", "--body", "--body-file", "--server", "--config"],
                &[],
            )
            .is_err()
        );

        let dir = std::env::temp_dir().join(format!("agpop_test_reply_{}", OsRng.next_u64()));
        let _ = fs::remove_dir_all(&dir);
        let cfg = dir.join("identity.json");
        let inbox_dir = dir.join("inbox");

        let mut ident = create_fresh_identity(&cfg, "bob").unwrap();
        ident.id = Some(100_000);
        ident.email = Some("bob-rye5@mail.sealedbyte.com".into());
        ident.token = Some("tok_bob_test".into());
        save_identity(&cfg, &ident).unwrap();

        // Simulate an inbox message (even if original `to` had a numeric suffix, reply must use primary email)
        let incoming = CleartextMailPayload {
            from: "alice-k9x2@mail.sealedbyte.com".into(),
            to: "bob-100000@mail.sealedbyte.com".into(),
            subject: "Hello".into(),
            text: "Ping".into(),
            received_at_ms: 1700000000000,
            sender_ed25519_pubkey: None,
            sender_signature: None,
        };
        write_new_private_mail_file(
            &inbox_dir,
            incoming.received_at_ms,
            1,
            &serde_json::to_vec(&incoming).unwrap(),
        )
        .unwrap();

        let sk_alice = StaticSecret::from([42u8; 32]);
        let pk_alice = PublicKey::from(&sk_alice);
        let pk_alice_hex = hex::encode(pk_alice.as_bytes());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = listener.local_addr().unwrap();

        let srv_task = tokio::spawn(async move {
            // 1. Handle GET /v1/pubkey/100000?to=alice-k9x2@mail.sealedbyte.com
            let (mut s1, _) = listener.accept().await.unwrap();
            let mut buf1 = [0u8; 2048];
            let n1 = s1.read(&mut buf1).await.unwrap();
            let req1 = String::from_utf8_lossy(&buf1[..n1]);
            let first_line1 = req1.lines().next().unwrap_or("");
            assert_eq!(
                first_line1,
                "GET /v1/pubkey/100000?to=alice-k9x2@mail.sealedbyte.com HTTP/1.1"
            );
            let resp1_body = serde_json::json!({
                "pubkey": pk_alice_hex,
                "sender_email": "bob-rye5@mail.sealedbyte.com",
                "to": "alice-k9x2@mail.sealedbyte.com",
                "max_msg_bytes": 65536,
            })
            .to_string();
            let resp1 = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{resp1_body}",
                resp1_body.len()
            );
            s1.write_all(resp1.as_bytes()).await.unwrap();

            // 2. Handle POST /v1/send/100000
            let (mut s2, _) = listener.accept().await.unwrap();
            let mut buf2 = [0u8; 8192];
            let n2 = s2.read(&mut buf2).await.unwrap();
            let req2 = String::from_utf8_lossy(&buf2[..n2]);
            let (_, body2) = req2.split_once("\r\n\r\n").unwrap();
            let send_json: serde_json::Value = serde_json::from_str(body2).unwrap();
            assert_eq!(send_json.as_object().unwrap().len(), 4);
            let sealed: SealedMessage = serde_json::from_value(serde_json::json!({
                "msg_id": 7,
                "received_at_ms": 1700000005000u64,
                "expires_at_ms": 1700060005000u64,
                "ephemeral_pubkey": send_json["ephemeral_pubkey"],
                "nonce": send_json["nonce"],
                "ciphertext_b64": send_json["ciphertext_b64"],
                "verified_from": "bob-rye5@mail.sealedbyte.com",
            }))
            .unwrap();
            let clear = unseal_message(&sk_alice.to_bytes(), &sealed).unwrap();
            assert_eq!(clear.from, "bob-rye5@mail.sealedbyte.com");
            assert_eq!(clear.to, "alice-k9x2@mail.sealedbyte.com");
            assert_eq!(clear.subject, "Re: Hello");
            assert_eq!(clear.text, "Reply from primary short tag");

            let resp2_body = serde_json::json!({
                "status": "delivered",
                "msg_id": 7,
                "from": "bob-rye5@mail.sealedbyte.com",
            })
            .to_string();
            let resp2 = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{resp2_body}",
                resp2_body.len()
            );
            s2.write_all(resp2.as_bytes()).await.unwrap();
        });

        cmd_reply(
            srv_addr,
            &cfg,
            &inbox_dir,
            "latest",
            "Reply from primary short tag",
            None,
        )
        .await
        .unwrap();

        srv_task.await.unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}




