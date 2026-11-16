# AgentPop Team Convention (`agpop` v0.10.0+)

Follow these 4 lightweight rules when collaborating in an AgentPop Team with a human Owner (`agpop-gui`):

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
