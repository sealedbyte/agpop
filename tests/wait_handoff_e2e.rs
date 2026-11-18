use agentpop::client::{
    PollResponse, generate_fresh_identity, resolve_absolute_path, save_identity,
};
use agentpop::crypto::{seal_and_zeroize, sign_cleartext_mail};
use agentpop::types::{CleartextMailPayload, SealedMessage};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn unique_test_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("agpop_e2e_{tag}_{}_{}", std::process::id(), nanos));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn canonical_path(p: &Path) -> PathBuf {
    resolve_absolute_path(p)
}

#[allow(clippy::too_many_arguments)]
fn make_signed_sealed_msg(
    sender_seed: &[u8; 32],
    sender_email: &str,
    rcpt_pk: &[u8; 32],
    rcpt_email: &str,
    msg_id: u64,
    received_at_ms: u64,
    subject: &str,
    body: &str,
) -> SealedMessage {
    let mut clear = CleartextMailPayload {
        from: sender_email.to_string(),
        to: rcpt_email.to_string(),
        subject: subject.to_string(),
        text: body.to_string(),
        received_at_ms,
        sender_ed25519_pubkey: None,
        sender_signature: None,
        cc_to: None,
    };
    sign_cleartext_mail(sender_seed, &mut clear);
    let mut pt = serde_json::to_vec(&clear).unwrap();
    let (eph, nonce, ct) = seal_and_zeroize(rcpt_pk, &mut pt, sender_email).unwrap();
    serde_json::from_value(serde_json::json!({
        "msg_id": msg_id,
        "received_at_ms": received_at_ms,
        "expires_at_ms": received_at_ms + 3_600_000,
        "ephemeral_pubkey": eph,
        "nonce": nonce,
        "ciphertext_b64": ct,
        "verified_from": sender_email,
    }))
    .unwrap()
}

struct MockRelay {
    addr: SocketAddr,
    queue: Arc<Mutex<VecDeque<SealedMessage>>>,
    udp_probes: Arc<AtomicUsize>,
    delete_wake_once_exit_count: Arc<AtomicUsize>,
    polled_mailbox_ids: Arc<Mutex<Vec<u64>>>,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl MockRelay {
    async fn start(mailbox_id: u64) -> Self {
        let mut bound = None;
        for _ in 0..16 {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = tcp.local_addr().unwrap();
            if let Ok(udp) = UdpSocket::bind(addr).await {
                bound = Some((tcp, udp, addr));
                break;
            }
        }
        let (tcp, udp, addr) = bound.expect("bind dual tcp/udp loopback relay");
        let queue: Arc<Mutex<VecDeque<SealedMessage>>> = Arc::new(Mutex::new(VecDeque::new()));
        let udp_probes = Arc::new(AtomicUsize::new(0));
        let delete_wake_once_exit_count = Arc::new(AtomicUsize::new(0));
        let polled_mailbox_ids: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));

        let udp_queue = queue.clone();
        let udp_probes_bg = udp_probes.clone();
        let udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            while let Ok((_n, peer)) = udp.recv_from(&mut buf).await {
                udp_probes_bg.fetch_add(1, Ordering::SeqCst);
                let has_msgs = !udp_queue.lock().unwrap().is_empty();
                let resp = [1u8, u8::from(has_msgs), 1u8, 0u8];
                let _ = udp.send_to(&resp, peer).await;
            }
        });

        let http_queue = queue.clone();
        let delete_wake_bg = delete_wake_once_exit_count.clone();
        let polled_bg = polled_mailbox_ids.clone();
        let http_task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = tcp.accept().await {
                let q = http_queue.clone();
                let del_wake = delete_wake_bg.clone();
                let polled = polled_bg.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let hdr_end;
                    loop {
                        let n = match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            hdr_end = pos + 4;
                            break;
                        }
                    }
                    let hdr_str = String::from_utf8_lossy(&buf[..hdr_end]).to_string();
                    let content_len = hdr_str
                        .lines()
                        .find_map(|line| {
                            let (k, v) = line.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    while buf.len() < hdr_end + content_len {
                        let n = match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let req_line = hdr_str.lines().next().unwrap_or("");
                    let body_bytes = &buf[hdr_end..buf.len().min(hdr_end + content_len)];

                    let (status, json_body) = if req_line.starts_with("GET /v1/messages/") {
                        if let Some(id_str) = req_line
                            .strip_prefix("GET /v1/messages/")
                            .and_then(|s| s.split(['?', ' ']).next())
                        {
                            if let Ok(req_id) = id_str.parse::<u64>() {
                                polled.lock().unwrap().push(req_id);
                            }
                        }
                        let msgs: Vec<SealedMessage> = q.lock().unwrap().iter().cloned().collect();
                        let resp = PollResponse {
                            id: mailbox_id,
                            count: msgs.len(),
                            remaining_slots: 10usize.saturating_sub(msgs.len()) as u64,
                            messages: msgs,
                        };
                        ("200 OK", serde_json::to_string(&resp).unwrap())
                    } else if req_line.starts_with("DELETE ") {
                        if req_line.contains("wake=once_exit") {
                            del_wake.fetch_add(1, Ordering::SeqCst);
                        }
                        let del_val: serde_json::Value =
                            serde_json::from_slice(body_bytes).unwrap_or_default();
                        let ids: Vec<u64> = del_val["msg_ids"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|v| v.as_u64())
                            .collect();
                        let mut guard = q.lock().unwrap();
                        let before = guard.len();
                        guard.retain(|m| !ids.contains(&m.msg_id));
                        let deleted = before.saturating_sub(guard.len());
                        ("200 OK", serde_json::json!({ "deleted": deleted }).to_string())
                    } else {
                        ("404 Not Found", r#"{"error":"not found"}"#.to_string())
                    };

                    let http_resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json_body}",
                        json_body.len()
                    );
                    let _ = sock.write_all(http_resp.as_bytes()).await;
                });
            }
        });

        Self {
            addr,
            queue,
            udp_probes,
            delete_wake_once_exit_count,
            polled_mailbox_ids,
            _tasks: vec![udp_task, http_task],
        }
    }

    fn enqueue(&self, msg: SealedMessage) {
        self.queue.lock().unwrap().push_back(msg);
    }
}

impl Drop for MockRelay {
    fn drop(&mut self) {
        for h in &self._tasks {
            h.abort();
        }
    }
}

fn setup_identity_at(cfg_path: &Path, mailbox_id: u64, prefix: &str) -> (String, [u8; 32]) {
    if let Some(parent) = cfg_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut ident = generate_fresh_identity(prefix);
    let email = format!("{prefix}-e2e@mail.sealedbyte.com");
    ident.id = Some(mailbox_id);
    ident.email = Some(email.clone());
    ident.token = Some(format!("tok_{mailbox_id}_secret"));
    save_identity(cfg_path, &ident).unwrap();
    let pk_vec = hex::decode(&ident.pubkey_hex).unwrap();
    let pk: [u8; 32] = pk_vec.as_slice().try_into().unwrap();
    (email, pk)
}

fn setup_workspace_identity(ws_dir: &Path, mailbox_id: u64, prefix: &str) -> (String, [u8; 32]) {
    setup_identity_at(&ws_dir.join(".agpop/identity.json"), mailbox_id, prefix)
}

/// Simulates a host runtime applying `handoff.rearm` mechanically without hardcoding any flags.
fn build_rearm_command_from_handoff(
    bin: &str,
    handoff: &serde_json::Value,
    prev_cwd: &Path,
    prev_env: &BTreeMap<String, String>,
    prev_args: &[String],
) -> (Command, Vec<String>) {
    let rearm = &handoff["rearm"];
    assert_eq!(rearm["reuse_working_dir"], true);
    assert_eq!(rearm["reuse_env"], true);
    assert_eq!(rearm["reuse_args"], true);

    let drop_flag = rearm["drop_value_flag"].as_str().unwrap();
    let ensure_flag = rearm["ensure_flag"].as_str().unwrap();

    let mut next_args = Vec::with_capacity(prev_args.len() + 1);
    let mut i = 0;
    while i < prev_args.len() {
        if prev_args[i] == drop_flag {
            i += 2;
            continue;
        }
        next_args.push(prev_args[i].clone());
        i += 1;
    }
    if !next_args.iter().any(|a| a == ensure_flag) {
        next_args.push(ensure_flag.to_string());
    }

    let mut cmd = Command::new(bin);
    cmd.current_dir(prev_cwd);
    for (k, v) in prev_env {
        cmd.env(k, v);
    }
    cmd.args(&next_args);
    (cmd, next_args)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_wait_once_default_stdout_array_and_english_stderr_handoff() {
    let ws = unique_test_dir("default_handoff");
    let (rcpt_email, rcpt_pk) = setup_workspace_identity(&ws, 7001, "worker");
    let relay = MockRelay::start(7001).await;

    let sender_seed = [11u8; 32];
    relay.enqueue(make_signed_sealed_msg(
        &sender_seed,
        "boss@mail.sealedbyte.com",
        &rcpt_pk,
        &rcpt_email,
        101,
        1_760_000_001_000,
        "First Assignment",
        "Handle step A without leaking me to stderr",
    ));

    // Include `--webhook-token` to verify secrets never appear in stderr handoff notice
    let secret_tok = "super-secret-webhook-token-42";
    let ws_clone = ws.clone();
    let srv_str = relay.addr.to_string();
    let out = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_agpop"))
            .current_dir(&ws_clone)
            .args([
                "wait",
                "--once",
                "--inbox-dir",
                "./custom_inbox",
                "--webhook-token",
                secret_tok,
                "--server",
                &srv_str,
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        out.status.success(),
        "agpop wait --once failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 1. stdout remains the bare JSON array (backwards compatible)
    let stdout_str = String::from_utf8(out.stdout).unwrap();
    let msgs: Vec<CleartextMailPayload> = serde_json::from_str(stdout_str.trim()).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].subject, "First Assignment");

    // 2. stderr emits fixed English handoff banner with actual persisted dir and reuse-invocation re-arm order
    let stderr_str = String::from_utf8(out.stderr).unwrap();
    let expected_dir = canonical_path(&ws.join("custom_inbox"));
    let expected_dir_str = expected_dir.display().to_string();
    assert!(
        stderr_str.contains(&format!(
            "[agpop local inbox handoff] Saved 1 message in this batch to `{expected_dir_str}`."
        )),
        "unexpected stderr: {stderr_str}"
    );
    assert!(stderr_str.contains("This `agpop wait --once` run has ended."));
    assert!(stderr_str.contains("first relaunch the same `agpop wait` invocation"));
    assert!(stderr_str.contains("same working directory, environment, and options/flags"));
    assert!(stderr_str.contains("BEFORE processing this batch"));
    assert!(!stderr_str.contains("First Assignment"));
    assert!(!stderr_str.contains("boss@mail.sealedbyte.com"));
    assert!(!stderr_str.contains(secret_tok));
    assert_eq!(relay.delete_wake_once_exit_count.load(Ordering::SeqCst), 1);

    let _ = fs::remove_dir_all(&ws);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_wait_once_handoff_json_and_timeout_zero_messages() {
    let ws = unique_test_dir("handoff_json_and_timeout");
    let (rcpt_email, rcpt_pk) = setup_workspace_identity(&ws, 7002, "worker");
    let relay = MockRelay::start(7002).await;

    let sender_seed = [22u8; 32];
    relay.enqueue(make_signed_sealed_msg(
        &sender_seed,
        "lead@mail.sealedbyte.com",
        &rcpt_pk,
        &rcpt_email,
        201,
        1_760_000_002_000,
        "Structured Envelope Check",
        "Body 1",
    ));
    relay.enqueue(make_signed_sealed_msg(
        &sender_seed,
        "lead@mail.sealedbyte.com",
        &rcpt_pk,
        &rcpt_email,
        202,
        1_760_000_002_500,
        "Second In Same Batch",
        "Body 2",
    ));

    let secret_tok = "top-secret-tok-999";
    let ws_clone = ws.clone();
    let srv_str = relay.addr.to_string();
    let out = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_agpop"))
            .current_dir(&ws_clone)
            .args([
                "wait",
                "--once",
                "--handoff-json",
                "--webhook-token",
                secret_tok,
                "--server",
                &srv_str,
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        out.status.success(),
        "agpop wait --once --handoff-json failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).trim().is_empty(),
        "expected empty stderr in --handoff-json mode, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout_raw = String::from_utf8(out.stdout).unwrap();
    assert!(
        !stdout_raw.contains(secret_tok),
        "handoff output must never echo secret token: {stdout_raw}"
    );
    let env_json: serde_json::Value = serde_json::from_str(stdout_raw.trim()).unwrap();
    assert_eq!(env_json["schema_version"], "1.0");
    assert_eq!(env_json["messages"].as_array().unwrap().len(), 2);
    assert_eq!(env_json["handoff"]["status"], "received");
    assert_eq!(env_json["handoff"]["wait_ended"], true);
    assert_eq!(env_json["handoff"]["trigger"], "wait_once");
    assert_eq!(env_json["handoff"]["saved_count"], 2);
    assert_eq!(env_json["handoff"]["rearm_first"], true);
    assert!(env_json["handoff"].get("recommended_rearm_cmd").is_none());
    assert_eq!(
        env_json["handoff"]["rearm"]["action"],
        "relaunch_wait_with_same_invocation"
    );
    assert_eq!(env_json["handoff"]["rearm"]["reuse_working_dir"], true);
    assert_eq!(env_json["handoff"]["rearm"]["reuse_env"], true);
    assert_eq!(env_json["handoff"]["rearm"]["reuse_args"], true);
    assert_eq!(env_json["handoff"]["rearm"]["drop_value_flag"], "--timeout");
    assert_eq!(env_json["handoff"]["rearm"]["ensure_flag"], "--once");
    assert_eq!(env_json["handoff"]["rearm"]["preserve_handoff_json"], true);

    let expected_dir = canonical_path(&ws.join(".agpop/inbox"));
    let reported_dir_str = env_json["handoff"]["inbox_dir"].as_str().unwrap();
    assert!(!reported_dir_str.starts_with(r"\\?\"));
    assert_eq!(canonical_path(Path::new(reported_dir_str)), expected_dir);
    let saved_files = env_json["handoff"]["saved_files"].as_array().unwrap();
    assert_eq!(saved_files.len(), 2);
    for path_val in saved_files {
        let s = path_val.as_str().unwrap();
        assert!(!s.starts_with(r"\\?\"));
        let p = PathBuf::from(s);
        assert!(p.is_absolute() && p.exists(), "missing saved file: {p:?}");
        let parsed: CleartextMailPayload =
            serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        assert!(!parsed.subject.is_empty());
    }

    // Timeout with 0 messages emits factual timeout notice on stderr and [] on stdout
    let ws_clone = ws.clone();
    let srv_str = relay.addr.to_string();
    let timeout_out = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_agpop"))
            .current_dir(&ws_clone)
            .args(["wait", "--timeout", "1", "--server", &srv_str])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(timeout_out.status.success());
    assert_eq!(String::from_utf8(timeout_out.stdout).unwrap().trim(), "[]");
    let timeout_err = String::from_utf8(timeout_out.stderr).unwrap();
    assert!(
        timeout_err.contains("[agpop local inbox handoff] Saved 0 messages in this batch; `agpop wait --timeout 1` timed out"),
        "unexpected timeout stderr: {timeout_err}"
    );

    let _ = fs::remove_dir_all(&ws);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stdout_only_host_rearms_preserving_config_dir_env_and_handoff_json() {
    let ws = unique_test_dir("stdout_only_rearm");
    // Decoy identity in default ./.agpop/identity.json; if Round 2 drops --config, it would poll 8888!
    let _decoy = setup_identity_at(&ws.join(".agpop/identity.json"), 8888, "decoy");
    let target_cfg_rel = "./alt-agent/identity.json";
    let (rcpt_email, rcpt_pk) = setup_identity_at(&ws.join(target_cfg_rel), 7004, "target");
    let relay = MockRelay::start(7004).await;
    let sender_seed = [44u8; 32];

    // Unix keeps a literal TAB directory (`\t`) to verify lossless JSON path handling;
    // Windows NTFS forbids control chars in filenames, so test spaces in path there instead.
    #[cfg(not(windows))]
    let (special_inbox_rel, expected_notice_frag, expected_rel_subpath) =
        ("./inboxes/worker\tb", "worker b", "inboxes/worker\tb");
    #[cfg(windows)]
    let (special_inbox_rel, expected_notice_frag, expected_rel_subpath) =
        ("./inboxes/worker b", "worker b", r"inboxes\worker b");

    let mut round1_env = BTreeMap::new();
    round1_env.insert("AGPOP_SERVER".to_string(), relay.addr.to_string());
    let round1_args = vec![
        "wait".to_string(),
        "--timeout".to_string(),
        "30".to_string(),
        "--handoff-json".to_string(),
        "--config".to_string(),
        target_cfg_rel.to_string(),
        "--inbox-dir".to_string(),
        special_inbox_rel.to_string(),
    ];

    // Enqueue Mail #1
    relay.enqueue(make_signed_sealed_msg(
        &sender_seed,
        "coord@mail.sealedbyte.com",
        &rcpt_pk,
        &rcpt_email,
        401,
        1_760_000_030_000,
        "Round 1 Task",
        "First message body",
    ));

    // Round 1: host only receives stdout (stderr is discarded!)
    let bin = env!("CARGO_BIN_EXE_agpop");
    let ws_r1 = ws.clone();
    let env_r1 = round1_env.clone();
    let args_r1 = round1_args.clone();
    let wait1 = tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(bin);
        cmd.current_dir(&ws_r1);
        for (k, v) in &env_r1 {
            cmd.env(k, v);
        }
        cmd.args(&args_r1).stderr(Stdio::null()).output().unwrap()
    })
    .await
    .unwrap();
    assert!(wait1.status.success());

    let env1: serde_json::Value =
        serde_json::from_str(String::from_utf8(wait1.stdout).unwrap().trim()).unwrap();
    assert_eq!(env1["messages"].as_array().unwrap().len(), 1);
    assert_eq!(env1["handoff"]["trigger"], "wait_timeout");
    assert_eq!(env1["handoff"]["saved_count"], 1);
    assert_eq!(env1["handoff"]["rearm"]["preserve_handoff_json"], true);

    let expected_inbox_dir = canonical_path(&ws.join(expected_rel_subpath));
    let reported_dir1 = env1["handoff"]["inbox_dir"].as_str().unwrap();
    assert!(!reported_dir1.starts_with(r"\\?\"));
    assert_eq!(canonical_path(Path::new(reported_dir1)), expected_inbox_dir);

    let saved1_str = env1["handoff"]["saved_files"][0].as_str().unwrap();
    assert!(!saved1_str.starts_with(r"\\?\"));
    let saved1 = PathBuf::from(saved1_str);
    assert!(saved1.exists(), "saved_files[0] must exist on disk: {saved1:?}");
    let disk_msg1: CleartextMailPayload =
        serde_json::from_str(&fs::read_to_string(&saved1).unwrap()).unwrap();
    assert_eq!(disk_msg1.subject, "Round 1 Task");
    #[cfg(not(windows))]
    {
        assert!(
            saved1.to_string_lossy().contains("worker\tb"),
            "saved_files[0] must preserve exact tab path: {saved1:?}"
        );
    }

    let notice1 = env1["handoff"]["notice"].as_str().unwrap();
    assert!(!notice1.contains('\t'), "notice must sanitize tab: {notice1}");
    assert!(notice1.contains(expected_notice_frag));

    // Construct Round 2 strictly from Round 1's handoff.rearm instructions (no hardcoded flags!)
    let (mut cmd2, round2_args) = build_rearm_command_from_handoff(
        bin,
        &env1["handoff"],
        &ws,
        &round1_env,
        &round1_args,
    );
    assert!(round2_args.contains(&"--once".to_string()));
    assert!(!round2_args.contains(&"--timeout".to_string()));
    assert!(round2_args.contains(&"--handoff-json".to_string()));

    let probes_before_r2 = relay.udp_probes.load(Ordering::SeqCst);
    let mut wait2 = cmd2
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    for _ in 0..40 {
        if relay.udp_probes.load(Ordering::SeqCst) > probes_before_r2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(relay.udp_probes.load(Ordering::SeqCst) > probes_before_r2);

    // Work 1 in progress while Mail #2 arrives
    let work1_done = Arc::new(AtomicBool::new(false));
    relay.enqueue(make_signed_sealed_msg(
        &sender_seed,
        "coord@mail.sealedbyte.com",
        &rcpt_pk,
        &rcpt_email,
        402,
        1_760_000_040_000,
        "Round 2 Interrupt",
        "Must land in exact same dir while work 1 active",
    ));

    let mail2_file = expected_inbox_dir.join("mail-1760000040000-id402.json");
    let mut exited_early = false;
    for _ in 0..60 {
        if !work1_done.load(Ordering::SeqCst) && mail2_file.exists() {
            if let Some(st) = wait2.try_wait().unwrap() {
                assert!(st.success());
                exited_early = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!work1_done.load(Ordering::SeqCst));
    assert!(mail2_file.exists());
    assert!(exited_early);
    work1_done.store(true, Ordering::SeqCst);

    // Round 2 still polled mailbox 7004 (never decoy 8888), wrote to same dir, and emitted structured stdout
    let wait2_out = tokio::task::spawn_blocking(move || wait2.wait_with_output().unwrap())
        .await
        .unwrap();
    let env2: serde_json::Value =
        serde_json::from_str(String::from_utf8(wait2_out.stdout).unwrap().trim()).unwrap();
    assert_eq!(env2["schema_version"], "1.0");
    assert_eq!(env2["messages"][0]["subject"], "Round 2 Interrupt");
    assert_eq!(env2["handoff"]["trigger"], "wait_once");

    let reported_dir2 = env2["handoff"]["inbox_dir"].as_str().unwrap();
    assert!(!reported_dir2.starts_with(r"\\?\"));
    assert_eq!(canonical_path(Path::new(reported_dir2)), expected_inbox_dir);

    let saved2_str = env2["handoff"]["saved_files"][0].as_str().unwrap();
    assert!(!saved2_str.starts_with(r"\\?\"));
    let saved2 = PathBuf::from(saved2_str);
    assert_eq!(canonical_path(&saved2), canonical_path(&mail2_file));
    let disk_msg2: CleartextMailPayload =
        serde_json::from_str(&fs::read_to_string(&saved2).unwrap()).unwrap();
    assert_eq!(disk_msg2.subject, "Round 2 Interrupt");

    let polled = relay.polled_mailbox_ids.lock().unwrap().clone();
    assert!(polled.iter().all(|&id| id == 7004) && polled.len() >= 2);

    let _ = fs::remove_dir_all(&ws);
}
