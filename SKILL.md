# AgentPop Team Convention (`agpop` v0.10.0+)

Follow these 6 lightweight rules when collaborating in an AgentPop Team with a human Owner (`agpop-gui`):

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
   When `/console` designates an authoritative `CC Owner`, both `agpop send` and `agpop reply` automatically send a best-effort silent E2EE copy to the Owner's Live Feed while online. Owner CC is controlled centrally in `/console` and cannot be bypassed by the sender (`--no-cc` is not supported).

5. **Reply Receipts (`--seen` / `--accept`)**
   需要明确告知对方“看到了”时，回复加 `--seen`；明确承诺接手时加 `--accept`；直接交付结果、普通讨论、收到回执，都不用额外确认。
   ```bash
   agpop reply "$AGPOP_FILE" --seen
   agpop reply "$AGPOP_FILE" --accept --body "我来复核，下午给结果"
   ```
   When processing messages in batch or via `wait --exec` / daemon workflows, pass the current local mail file path (for example `"$AGPOP_FILE"`) or its `message_id` instead of `latest`, so a newer arrival never shifts the receipt target. (`--accept` already implies seen; do not combine `--seen` and `--accept`.)

6. **Next-Step Declaration (`--next <continue|handoff|blocked|done|fyi>`)**
   `--next` **永远以发件人自己为主语**，仅声明“发完这封信后，**我**对这封信所涉事项接下来怎么处理”——**绝不**用于指令收件人做什么，也不会自动修改成员卡的全局 `attrs.work`。

   | 枚举 | 准确语义（GUI 显示） | 常见误用 / 不应推断 |
   |---|---|---|
   | `continue` | **我继续处理** | 发件人同步阶段进展，事项仍在发件人手里继续推进（**切勿误用于“请对方继续推进或补充信息”**；要对方接手/解锁应选 `handoff` 或 `blocked`）。 |
   | `handoff` | **请求对方接手** | 派单、提审、交付下游。**发信成功不等于对方已接手**，仅对方回 `--accept` 才确认接手；向 `@team` 广播时仅显示“向团队请求接手”。 |
   | `blocked` | **我受阻，需要协助** | 发件人当前卡住，等待对方拍板、解锁或补充信息（不代表对方已自动接管全部任务）。 |
   | `done` | **我这边已完成** | 仅声明发件人这一侧收尾，**不代表对方已验收或整个事项已关闭**（仍需对方复核/验收请标 `handoff`）。 |
   | `fyi` | **仅告知** | 纯信息同步，不改变已有承诺（**不要用 `--next fyi` 替代回执**；确认收到/接手请用 `agpop reply --seen` 或 `--accept`）。 |

   ```bash
   agpop send --to @reviewer --subject "[ASK] Review PR #42" --next handoff --body "Ready for review"
   agpop reply "$AGPOP_FILE" --next continue --body "已定位根因，继续修补中，稍后交付结果"
   ```
   - **默认可选**：不传即为“未标注”，绝不默认为 `fyi`。
   - **团队可选严格模式**：设置 `AGPOP_REQUIRE_NEXT=1` 后，向团队内部单发或 `@role` / `@team` 发送普通信件时强制携带 `--next`；纯回执（`--seen` / `--accept`）与外部 SMTP 豁免。
   - **互斥限制**：`--next` 不可与 `--seen` / `--accept` 同时使用，也不可用于外部 SMTP 邮件。
