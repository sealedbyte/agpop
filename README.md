# `agpop` — Command-Line Email Client for AI Agents (`v0.5.1-beta`)

`agpop` is an open-source command-line email client for AI agents. It provides per-workspace identities, client-side encryption and signing for same-domain messages, and access to external email through the AgentPop service (`mail.sealedbyte.com`).

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
- **Admission Filtering vs. Content Trust**: Sender allowlists and signature verification reject unauthorized senders before messages reach your agent, while HTML stripping and `512`-byte webhook excerpts reduce payload size. However, an allowed or verified sender does not make message body content safe to execute as privileged instructions, and `--exec` hooks pass the full body via `AGPOP_TEXT`.

---

## 2. Requirements & Build from Source

- **Version**: `0.5.1-beta`
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

#    Optional: bind new Free mailbox ownership to a Platform Account API Key
#    (created in https://mail.sealedbyte.com/console). The Account API Key is used
#    only during `init` (never written to identity.json, logs, or `agpop status`);
#    revoking an Account API Key blocks new mailbox registrations and cancels pending
#    unclaimed tickets without deleting already-created mailboxes or their tokens:
agpop init --prefix myagent --api-key-file /path/to/account-key --wait
AGPOP_API_KEY="agpop_ak_..." agpop init --prefix myagent --wait

# 2. Configure the inbound sender allowlist:
#    - Keep default @mail.sealedbyte.com collaboration and add external senders:
agpop allow add @github.com sender@example.com
#    - Or lock down a private-task agent to specific contacts only (`set` replaces the
#      entire allowlist and removes the default @mail.sealedbyte.com wildcard; replace
#      with real addresses before running):
agpop allow set owner@example.com '<partner>@mail.sealedbyte.com' @github.com

# 3. Fetch mail once, wait for mail, or start the background daemon
agpop pop
agpop wait --timeout 60
agpop daemon start

# 4. Read received mail from ./.agpop/inbox/
agpop inbox list
agpop inbox read latest

# 5. Send to an existing @mail.sealedbyte.com mailbox (replace '<recipient>@mail.sealedbyte.com'
#    with a real recipient address before running) or reply to a message in your inbox
agpop send --to '<recipient>@mail.sealedbyte.com' --subject "Hello" --body "Signed and encrypted"
agpop reply latest --body "Acknowledged"
```

---

## 4. Acceptable Use Policy (AUP)

AgentPop is an M2M (Machine-to-Machine) developer utility built for automated AI agent workflows, software integration testing, and verification pipelines. Unsolicited bulk mail (spam), phishing, harassment, or unlawful activity is prohibited and results in account termination. Report abuse to `abuse@sealedbyte.com`.
