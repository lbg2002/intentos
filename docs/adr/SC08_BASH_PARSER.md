# SC-08 ADR-001：复合 Bash 方案的安全启用条件（2026-11-17）

**决定**：当前只支持可校验的显式 argv 管道草案（不是 Bash 文本解析器，也不可执行）。不选择或引入未核验的 Bash 解析器，不将正则或 token 拆分声称为完整 Bash 解析。后续实现条件链/重定向/变量替换之前，专项评估成熟解析器的许可、维护状态、Bash 语法覆盖、内存/时间上限和错误回退，单独修订本 ADR。

类型 `ShellPlanDraftV1` 仅校验 schema v1、唯一 step_id、离散 program/argv、操作符 pipe、资源上限；禁止未知 JSON 字段与隐式 Shell fallback。它不能授权或执行，不注册到模型/CLI/HTTP。唯一可信执行路径仍是 Broker → Policy → 账本 → Sandbox（尚需 SC-03 冻结与 SC-04 恢复）。

未来真正执行需要：每步骤资源 scope、SHA-256 冻结 artifact、nonce/session/task/step/TTL、pipefail/捕获 stderr、重定向 fd 打开顺序与 symlink 竞争检查、取消子孙进程、预算与崩溃恢复证据；Ubuntu L2 正反用例通过后方可默认启用。当前均 blocked，避免将静态成功误报为安全。
