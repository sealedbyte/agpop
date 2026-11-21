# AgentPop Team Convention (`agpop` v0.10.0+)

Follow these 5 lightweight rules when collaborating in an AgentPop Team with a human Owner (`agpop-gui`):

1. **Report Current Step (`attrs.step`)**
   Update your live breadcrumb when starting or switching tasks (truncated to 64 chars, merges cleanly):
   ```bash
   agpop team --set step="running cargo test"
   ```

2. **Prefix Human-Facing Subjects (`[ASK]` / `[BLOCKED]` / `[DONE]` / `[FYI]`)**
   - `[ASK] ...` — Need human decision/approval (triggers strong desktop alert).
   - `[BLOCKED] ...` — Stuck or failed; cannot proceed without human help (triggers strong desktop alert).
   - `[DONE] ...` — Task completed (light notification).
   - `[FYI] ...` — Status note only (silent archive).

3. **Provide One-Click Approval Choices (```` ```agpop-options ````)**
   When asking the Owner to pick between options, include a fenced `agpop-options` block:
   ````markdown
   ```agpop-options
   [{"label": "Approve Plan A", "reply": "Approved Plan A. Proceed."},
    {"label": "Abort & Rollback", "reply": "Abort and revert changes."}]
   ```
   ````

4. **CC Owner Handled Automatically**
   When `/console` designates an authoritative `CC Owner`, `agpop send` automatically sends a best-effort silent E2EE copy to the Owner's Live Feed while online (bypass with `--no-cc` if needed).

5. **Reply Receipts (`--seen` / `--accept`)**
   需要明确告知对方“看到了”时，回复加 `--seen`；明确承诺接手时加 `--accept`；直接交付结果、普通讨论、收到回执，都不用额外确认。
   ```bash
   agpop reply "$AGPOP_FILE" --seen
   agpop reply "$AGPOP_FILE" --accept --body "我来复核，下午给结果"
   ```
   When processing messages in batch or via `wait --exec` / daemon workflows, pass the current local mail file path (for example `"$AGPOP_FILE"`) or its `message_id` instead of `latest`, so a newer arrival never shifts the receipt target. (`--accept` already implies seen; do not combine `--seen` and `--accept`.)
