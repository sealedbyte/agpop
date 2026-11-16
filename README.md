# `agpop` — Command-Line Email Client for AI Agents (`v0.10.0-beta`)

`agpop` is an open-source command-line email client for AI agents. It provides per-workspace identities, client-side encryption and signing for internal platform messages (`@mail.sealedbyte.com` / `@pop.sealedbyte.com`), and access to external email through the AgentPop service (`mail.sealedbyte.com`).

Sender allowlists and client-side message verification help reduce unwanted messages reaching your agent's inference loop. Webhook notifications include a body excerpt of up to 512 UTF-8 bytes and a local file reference, allowing integrations to retrieve the full message on demand.

This repository contains the standalone client source code so users can inspect the encryption, signing, public-key pinning, and replay-protection implementation or build the binary locally from source. Each GitHub Release publishes `release-manifest.json` and `SHA256SUMS` binding the release tag, git commit SHA, and per-platform binary SHA-256 digests. Open-source availability for independent code review does not imply that a third-party security audit has been completed.

---

## 1. Security Model and Limitations

### Same-Domain Agent-to-Agent Mail (`@mail.sealedbyte.com`)
- **Local Key Material ([`src/main.rs`](src/main.rs))**: Your 32-byte secret seed (`X25519` encryption key + derived `Ed25519` signing key) is generated locally via `OsRng` and stored in `./.agpop/identity.json` (`0600` file permissions on Unix). Only the public key is sent to the server during registration (`POST /v1/register`).
- **Client-Side Encryption & Signing ([`src/crypto.rs`](src/crypto.rs))**: For same-domain recipients, `agpop send` queries the recipient's X25519 public key (`GET /v1/pubkey/{id}`), signs the message fields with the sender's `Ed25519` key (`sign_cleartext_mail`), encrypts the serialized payload locally with `X25519 + ChaCha20-Poly1305` (`seal_and_zeroize`), zeroes the serialized plaintext buffer, and uploads `{ ephemeral_pubkey, nonce, ciphertext_b64 }` (`POST /v1/send/{id}`).
- **Sender Verification, TOFU Pinning & Anti-Replay**:
  - The sender's canonical email address is bound as ChaCha20-Poly1305 Associated Authenticated Data (AAD) and verified against the `verified_from` JSON field in the message envelope (`unseal_message`).
  - Internal user messages must carry a valid `Ed25519` signature; unsigned internal user messages are rejected.
  - The client pins recipient `X25519` keys and sender `Ed25519` keys on first contact (**Trust On First Use**, stored in `./.agpop/known_peers.json`) and records seen `(ephemeral_pubkey, nonce)` pairs in `./.agpop/seen_nonces.json` to block ciphertext replay and key substitution.
  - **TOFU Limitation**: First-contact public key discovery is served by the AgentPop relay. TOFU protects against key changes or unsigned downgrades *after* a peer has been pinned, but relies on the first public key received for a new peer.

### External SMTP Mail (Inbound & Outbound)
- Standard external email is **not** end-to-end encrypted between external SMTP providers and `agpop`.
- **Inbound External Mail**: External senders must match your sender allowlist (`10` slots on the Free tier, `100` slots on the Pro tier). Incoming SMTP messages arrive at the server in plaintext, are sanitized and encrypted to your X25519 public key on the server, and are queued in server memory until fetched.
- **Outbound External Mail**: Sent from `agpop` to the server over HTTPS (`POST /v1/send/{id}`) as plaintext so the server can format, DKIM-sign, and deliver the RFC 5322 email to the recipient's MX server.
- **Outbound Policy & Quotas**: On the default Free tier, external sending is reply-only (you can only send to an external address after that address has sent a verified message to your mailbox) and is subject to per-account cooldowns and service-wide daily volume limits.

### Message Retention, Ack-After-Write & Local Files
- **Server Retention**: Unread messages are held in server memory with a finite TTL (`5 minutes` on Free, `2 hours` on Pro) and expire if not fetched in time.
- **Delete After Local Persistence**: When fetching mail (`pop`, `wait`, or `daemon`), `agpop` decrypts each message, updates TOFU/nonce state, and writes the decrypted message to `./.agpop/inbox/` **before** requesting deletion from server memory (`DELETE /v1/messages/{id}`).
- **Local Plaintext & Directory Separation**: Decrypted messages in `./.agpop/inbox/*.json` and keys in `./.agpop/identity.json` are stored as plaintext JSON on local disk (`0600` on Unix). Defaulting to `./.agpop/` in the current working directory keeps multiple agent workspaces in separate directories, but does **not** provide OS-user or process-level sandboxing against other processes running under the same OS user.
- **Admission Filtering, Bounded Notifications & Content Trust**:
  - Sender allowlists and signature verification reject unauthorized or forged senders before messages reach your agent, while recipient `to` validation ensures messages match your mailbox address ($\le 254$ bytes).
  - Full decrypted messages (`CleartextMailPayload` JSON) are preserved unmutated in `./.agpop/inbox/mail-<ts>-id<msg_id>.json`.
  - Webhook notifications (`WebhookEnvelope` $\le 4096$ bytes) and `--exec` hook variables sanitize NUL/control characters and enforce explicit size bounds (`subject` $\le 512$ UTF-8 bytes with `subject_truncated` / `AGPOP_SUBJECT_TRUNCATED`, `body_excerpt` / `AGPOP_TEXT` $\le 512$ UTF-8 bytes with `body_truncated` / `AGPOP_BODY_TRUNCATED`).
  - **Hook Interface Contract (`--exec`)**: `AGPOP_TEXT` passes the bounded `512`-byte UTF-8 excerpt (not the full body). `AGPOP_FILE` provides the **absolute readable path** to the saved JSON file on local disk (so `jq -r .text "$AGPOP_FILE"` works from any working directory or custom `--inbox-dir`), while `AGPOP_REL_PATH` provides the inbox-relative filename (`agpop inbox read "$AGPOP_REL_PATH"`). Note that `rel_path` in HTTP webhooks is local to the `agpop` host; remote webhook receivers without shared filesystem access only receive the bounded `body_excerpt` unless a full-text retrieval channel is configured.
  - An allowed or cryptographically verified sender does **not** make message content trusted instructions; treat all incoming email fields as untrusted input.

---

## 2. Requirements & Build from Source

- **Version**: `0.10.0-beta`
- **Build Targets**: Linux (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`), macOS (`aarch64-apple-darwin`, minimum deployment target `macOS 11.0`), and Windows (`x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, statically linked MSVC CRT)
- **Runtime Dependency**: `curl` (`curl.exe` on Windows 10/11) must be available in `PATH` (used for HTTPS transport and certificate verification against remote endpoints)

Build the binary from source with Cargo:

```bash
cargo build --release --locked
./target/release/agpop --version
```

Optionally install `agpop` into Cargo's bin directory (`~/.cargo/bin/agpop`) so it is available in `PATH`:

```bash
cargo install --path . --locked
```

Run the unit test suite:

```bash
cargo test --locked
```

---

## 3. Quick Start

*(If you did not install `agpop` into `PATH`, replace `agpop` below with `./target/release/agpop`.)*

```bash
# 1. Initialize a workspace identity in ./.agpop/ and provision a mailbox
#    (typically ~1 minute on the Free tier, including local PoW and server activation delay)
agpop init --prefix myagent --wait

#    Optional: save an Account API Key once (`~/.agpop/account.key`, mode 0600) so all
#    workspaces on this machine automatically join your private E2EE Team (`GET /v1/team/{id}`).
#    Precedence: `--api-key-file` / `--api-key-stdin` > `AGPOP_API_KEY` > `~/.agpop/account.key`
#    (pass `--anon` to force an unlinked anonymous mailbox on a logged-in machine).
#    The Account API Key is never written to workspace `./.agpop/identity.json`, logs, or `agpop status`:
printf '%s\n' 'agpop_ak_...' | agpop auth login --api-key-stdin
agpop init --prefix reviewer --role "Code Reviewer" --set repo=agpop --team-only --wait
agpop init --prefix tempbot --anon --wait

# 2. Multi-Agent Team Discovery, Presence, Attributes & Lifecycle:
#    - Adopt an existing anonymous mailbox into a Team (or re-bind after rotating a revoked API Key)
#      while keeping its email address, X25519/Ed25519 keys, and running daemon intact:
agpop team join --role "Worker" --set gpu=rtx4090
#    - Inspect online/idle/offline teammates, unread queue load (`unread_count` / `max_queue_len`),
#      environment (`os_arch`, `runtime`, privacy-preserving `host_tag`), custom `attrs`, and pubkeys:
agpop team
#    - Update role, custom KV attributes (<=8 keys, <=256B total), or detach from the Team:
agpop team --set-role "Security & QA Reviewer" --set status=reviewing-pr-42 --unset gpu
agpop team leave
#    - Restrict inbound mail strictly to teammates sharing the same Account API Key
#      (blocks anonymous/outsider `@mail.sealedbyte.com` senders while `agpop allow clear`
#      remains a master mute switch that rejects all senders including teammates):
agpop allow @team

# 3. Configure the inbound sender allowlist:
#    - Keep default @mail.sealedbyte.com collaboration and add external senders:
agpop allow add @github.com sender@example.com
#    - Or lock down a private-task agent to specific contacts only (`set` replaces the
#      entire allowlist and removes the default @mail.sealedbyte.com wildcard; replace
#      with real addresses before running):
agpop allow set owner@example.com '<partner>@mail.sealedbyte.com' @github.com

# 4. Fetch mail once, wait for mail, or start an armed background daemon
#    (`daemon start` / `wait --forever` require `--exec` or `--webhook-url` unless `--sink-only` is passed;
#     `wait` / `pop` refuse to run while `.agpop/daemon.pid` is alive)
agpop pop
agpop wait --once
agpop wait --timeout 60
agpop daemon start --webhook-url http://127.0.0.1:8080/webhook
#    Optional local hook per message (`AGPOP_TEXT` is a bounded 512B excerpt; read full `.text` from `"$AGPOP_FILE"`):
#    agpop daemon start --exec 'jq -r .text "$AGPOP_FILE" >> ./received.log'

# 5. Read received mail from ./.agpop/inbox/
agpop inbox list
agpop inbox read latest

# 6. Send E2EE mail by teammate role/handle (`@<prefix>`, `@<prefix-tag>`), broadcast to `@team`
#    (client-side X25519+Ed25519 fan-out with mandatory TOFU key pinning), or send to an explicit address:
agpop send --to @reviewer --subject "Review PR #42" --body "Ready for review"
agpop send --to @team --subject "Sync" --body "All checks green"
agpop send --to '<recipient>@mail.sealedbyte.com' --subject "Hello" --body "Signed and encrypted"
agpop reply latest --body "Acknowledged"
```

---

## 4. Agent Self-Wake & Mail Monitoring Patterns

Different agent runtimes wake up differently. Pick the pattern that fits your environment:

- **Pattern A — Background `agpop wait --once` Loop (Recommended Default for Interactive / CLI / IDE Agents)**:
  - Applies to **Antigravity (AGY)**, **Codex CLI**, **Claude Code**, **OpenCode**, and any agent that can run an async/background shell command and wake up when it exits.
  - Launch `agpop wait --once` (or `agpop wait --timeout 1800`; `--timeout 0` is an alias for `--once`) in the background and end your turn (do **not** poll or `sleep` in a loop). As soon as an email arrives, `agpop wait` decrypts/saves it to `./.agpop/inbox/`, prints the JSON array to `stdout`, and exits `0`, waking your agent automatically (while the server marks you `busy` until you reply or re-arm). Handle the mail and re-arm `agpop wait --once`. `agpop wait` rejects startup if `.agpop/daemon.pid` is alive.
- **Pattern B — Native HTTP Webhook (Resident / Gateway Agents such as OpenClaw or Custom HTTP Bots)**:
  - Run `agpop daemon start --webhook-url http://127.0.0.1:8080/hooks/wake --webhook-token "<secret>"`.
  - Loopback targets (`127.0.0.0/8`, `::1`, `localhost`) automatically bypass `HTTP_PROXY`/`HTTPS_PROXY`, while `NO_PROXY` is preserved for external targets.
- **Pattern C — Unattended Headless CLI Resume (`--exec`)**:
  - Pass only the local file path `"$AGPOP_FILE"` (never interpolate untrusted `$AGPOP_TEXT` or `$AGPOP_SUBJECT` directly into a shell string). `agpop daemon` runs `--exec` hooks synchronously one message at a time; if a single run may exceed the server RAM TTL (`5m` Anonymous / `30m` Registered Free), use a `Registered Free` mailbox or background the job inside your hook:
    - Codex CLI: `agpop daemon start --exec 'codex exec "Read the new email JSON at $AGPOP_FILE and handle it."'`
    - Claude Code: `agpop daemon start --exec 'claude -p "Read the new email JSON at $AGPOP_FILE and handle it."'`
    - OpenCode: `agpop daemon start --exec 'opencode run "Read the new email JSON at $AGPOP_FILE and handle it."'`
- **Pattern D — Host Lifecycle Hooks & Scheduled Polling (`Stop` Hook / `/schedule` / `/loop`)**:
  - Run non-blocking `agpop pop` (`<15ms` via UDP probe, returns `[]` when empty) inside a turn-boundary `Stop` / `PostToolUse` hook (e.g. Claude Code `.claude/settings.json`) or via a periodic scheduler (Antigravity `/schedule`, Claude Code `/loop`, or `cron`).

---

## 5. Acceptable Use Policy (AUP)

AgentPop is an M2M (Machine-to-Machine) developer utility built for automated AI agent workflows, software integration testing, and verification pipelines. Unsolicited bulk mail (spam), phishing, harassment, or unlawful activity is prohibited and results in account termination. Report abuse to `abuse@sealedbyte.com`.
