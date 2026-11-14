# 实现任务书三（Agent-3）：E2 沙箱暂存、授权包络、项目记忆与技能驱动模块 (`execution_hub`)

> **角色定位**：IntentOS 受控执行、安全包络与长期知识引擎架构师（Agent-3）  
> **参考设计方案**：`docs/IntentOS_设计方案_v0.3.md` §7.4–§7.6、§8.4（E2 沙箱暂存执行）、§9.1–§9.3、§10.3（授权包络与渐进信任）、§11.2–§11.5（项目记忆、候选提议、技能与工作流学习）、§13.1–§13.4（Task & Drive Engine）  
> **解决核心痛点**：解决现有系统「只能执行固定单步命令、缺少 E2 沙箱暂存差异预览与提交、多步操作弹窗繁琐缺少 GrantEnvelope 包络审批与渐进信任、缺少项目级记忆与从历史任务提取工作流（Workflow）、缺少事件与定时触发器」的问题。

---

## 1. 严格的文件读写边界（防冲突红线）

- ✅ **你唯一允许新建和修改的目录**：
  `crates/intentosd/src/execution_hub/`
- ❌ **严禁修改任何其他目录或文件**：
  严禁修改 `Cargo.toml`、`crates/protocol/`、`crates/intentosd/src/lib.rs`、`crates/intentosd/src/core.rs`、`crates/intentosd/src/broker.rs` 等任何外部文件！（主干已在 `lib.rs` 和 `core.rs` 中挂载了 `pub mod execution_hub;` 并转发了 `domain = "execution_hub"` 的 `ModuleRpc` 请求）。

---

## 2. 模块内部文件规划（功能模块化拆分）

请在 `crates/intentosd/src/execution_hub/` 下按以下职责拆分子模块，并在 `mod.rs` 中组织导出：

```text
crates/intentosd/src/execution_hub/
├── mod.rs              # 模块入口与 handle_module_rpc 分发器
├── e2_staging.rs       # E2 沙箱暂存执行器：隔离运行命令/脚本 → 计算暂存目录与真实目录的文件树 Diff → 预览 → 经 SafeFsEngine 提交为可撤销 ChangeSet（§8.4）
├── grant_envelope.rs   # GrantEnvelope 授权包络管理、包络边界校验（能力/范围/效应/操作数/网络）与渐进信任长期规则提议器（§10.3）
├── project_memory.rs   # Git 仓库自动发现与项目登记（R-05）、项目级记忆（M-04）、记忆候选提议与确认（M-05）、召回来源追溯（M-06）
├── skill_workflow.rs   # Skill & Workflow 注册表（加载 skills/ 下 SKILL.md）、从已完成 Task 提取可复用 Workflow（M-07）与漂移检测
└── drive_scheduler.rs  # Drive Engine（§13.3–§13.4）：定时触发器、文件系统事件触发规则（含防抖、频率限制、L1 决策过滤）、自主性等级（L0/L1/L2）
```

---

## 3. 核心功能实现要求

### 3.1 E2 沙箱暂存执行与差异提交 (`e2_staging.rs`，对标 §8.4)
1. **暂存工作区构建 (`stage_run`)**：
   - 当智能体或用户请求执行组合命令/脚本（如批量重命名、批量图片/文档处理、代码格式化）时，在 `${runtime_dir}/e2_staging_<id>` 创建隔离暂存区。
   - 将目标授权目录（只读或快照副本）映射到暂存区，调用 `intentos_sandbox::build_sandboxed_command` 在默认无外网（`allow_tcp_network = false`）条件下运行命令。
2. **文件树差异计算 (`compute_staging_diff`)**：
   - 对比暂存区执行前后状态，精确计算出：
     - `added_files`: 新增文件列表（路径、大小、SHA-256、文本预览）
     - `modified_files`: 修改文件列表（路径、前后大小、Unified Diff 文本预览）
     - `deleted_files`: 删除文件列表
   - 若仅在暂存输出区生成新产物（artifact），无需审批即可保存；若涉及修改真实授权目录，生成 `StagedProposal` 供前端展示文件树差异卡片。
3. **原子提交与一键撤销 (`commit_staged_proposal`)**：
   - 用户批准后，通过 `core.fs_engine`（`openat2` 原生安全文件操作）将暂存变更写入真实授权目录，自动备份被覆盖/删除文件到 `undo/` 备份区，并写入一条包含全部子操作的 `ChangeSet` 到 `state_db`，支持一键整体撤销！

### 3.2 授权包络 (`GrantEnvelope`) 与渐进信任 (`grant_envelope.rs`，对标 §10.3)
1. **授权包络生命周期**：
   - 为多步任务生成 `GrantEnvelope`（包含 `envelope_id`, `task_id`, `capabilities`, `resource_scope`, `max_effect`, `max_operations`, `network`, `expires_at`, `nonce`, `policy_version`）。
   - 提供 `check_within_envelope(envelope_id, call)`：只要子步骤在包络的能力、目录范围、最高效应和操作次数内，直接放行不再逐个弹窗；越出包络立即触发重新审批。
2. **渐进信任规则提议 (`ProgressiveTrust`)**：
   - 统计用户对同类 `(capability_id, target_dir)` 的连续批准次数；当连续批准 ≥ 3 次时，自动生成一条狭窄的长期规则提议 `RuleProposal`（如：「允许在 `~/Downloads` 内执行 `file.move`，单次最多 50 个文件，最高效应 `write.reversible`」），供用户在前端确认生效或随时撤销（绝不覆盖 `confirm_each` 类高危效应）。
   - 统计审批疲劳指标（平均决策耗时、批准率、拒绝率）。

### 3.3 项目登记与记忆候选系统 (`project_memory.rs`，对标 §11.2–§11.5 & §12.3 R-05)
1. **Git 项目自动发现与登记 (`discover_and_list_projects`)**：
   - 扫描授权目录（1~3 层深度）内含 `.git`、`Cargo.toml`、`package.json`、`pyproject.toml` 的目录，登记为 `ProjectRecord`（`project_id`, `name`, `root_path`, `tech_stack`, `git_branch`, `last_active`）。
2. **项目记忆与记忆候选 (`MemoryCandidate`)**：
   - 支持按 `scope = "personal"` 或 `scope = "project:<id>"` 管理记忆。
   - 实现 `propose_memory_candidates_from_task(task)`：从已验证完成的任务或会话中提取值得保留的偏好/项目约定候选（不自动写库，放入待确认队列，由用户一键「确认写入记忆」或「忽略」，M-05）。

### 3.4 技能与工作流管理及学习 (`skill_workflow.rs`，对标 §7.1, §11.4, M-07)
1. **技能扫描与解析**：
   - 扫描 `skills/builtin/` 与 `${data_dir}/skills/user/` 下的 `SKILL.md`，解析 YAML frontmatter（`id`, `name`, `summary`, `triggers`, `trust_level`）与 Markdown 正文。
2. **从已完成任务学习工作流 (`learn_workflow_from_task`)**：
   - 将一个已成功执行的 `Task` 的 `steps` 提炼为参数化的可复用工作流 `WorkflowSpec`（保存为标准 `SKILL.md` 文件），支持通过触发短语（如「开始做 IntentOS」「整理每周下载」）一键重放执行（执行时每步仍经 Policy 校验，遇到资源漂移安全失败）。

### 3.5 事件与定时驱动引擎 (`drive_scheduler.rs`，对标 §13.3–§13.4)
1. 管理自动化触发器规则 `DriveTriggerRule`：
   - 支持 `Schedule`（Cron / 定时）与 `FilesystemEvent`（如监控 `~/Downloads` 下新创建的 `*.pdf`，含 `settle_seconds` 防抖、忽略 `.crdownload`/`.part`、`max_runs_per_hour` 限流）。
   - 支持 `simulate_trigger_event` 接口：在收到事件时先调用 `core.decision` 进行低成本二元过滤（如「该文件是否像学术论文」），根据自主性等级（`L0 手动` / `L1 仅提建议` / `L2 授权自动执行可逆工作流`）生成建议卡片或自动触发任务。

---

## 4. `ModuleRpc` 接口契约（必须在 `mod.rs` 的 `handle_module_rpc` 中实现）

前端与其他模块将通过 `domain: "execution_hub"` 调用以下 `action`：

| `action` 名称 | 输入 `payload` | 功能说明与返回结构 |
|---|---|---|
| `"stage_e2_command"` | `{ "command": "...", "work_dir": "...", "task_id": "..." }` | 在隔离暂存区执行命令并计算文件树 Diff，返回 `StagedProposal`（含 `proposal_id`, `stdout`, `stderr`, `diffs`） |
| `"commit_e2_proposal"` | `{ "proposal_id": "..." }` | 将暂存变更经 `SafeFsEngine` 原子应用到真实目录并生成可撤销 `ChangeSet` |
| `"discard_e2_proposal"` | `{ "proposal_id": "..." }` | 丢弃并清理暂存目录 |
| `"create_grant_envelope"` | `{ "task_id": "...", "capabilities": [...], "resource_scope": [...], "max_effect": "write.reversible", "max_operations": 50 }` | 创建并激活任务授权包络 |
| `"list_envelopes_and_rules"` | `{}` | 返回当前活动授权包络、长期信任规则、待确认的渐进信任规则提议及审批疲劳统计 |
| `"confirm_rule_proposal"` | `{ "proposal_id": "..." }` | 确认将渐进信任提议转为长期规则 |
| `"revoke_grant_or_rule"` | `{ "id": "..." }` | 撤销指定授权包络或长期规则 |
| `"list_projects"` | `{ "rescan": false }` | 列出已发现/登记的 Git 项目及技术栈元数据 |
| `"list_memory_candidates"` | `{}` | 列出待用户确认的记忆候选（M-05） |
| `"confirm_memory_candidate"` | `{ "candidate_id": "..." }` | 确认将记忆候选写入 `state_db` |
| `"list_skills_and_workflows"` | `{}` | 列出全部内置与用户自定义技能（Skill）及工作流（Workflow） |
| `"learn_workflow_from_task"` | `{ "task_id": "...", "name": "...", "trigger_phrase": "..." }` | 从指定历史任务提取步骤并保存为用户可复用工作流（M-07） |
| `"run_workflow"` | `{ "workflow_id": "..." }` | 按序受控执行指定工作流 |
| `"list_drive_triggers"` | `{}` | 列出定时与文件事件触发规则及自主性等级 |
| `"upsert_drive_trigger"` | `{ "rule": {...} }` | 新增或更新定时/事件触发规则 |
| `"delete_drive_trigger"` | `{ "rule_id": "..." }` | 删除触发规则 |
| `"trigger_dry_run"` | `{ "rule_id": "...", "sample_path": "~/Downloads/paper.pdf" }` | 模拟触发一次事件，展示 L1 决策过滤结果与生成的建议/任务 |

---

## 5. 验收与自测标准

1. 所有代码必须包含 `#![forbid(unsafe_code)]`。
2. 在 `crates/intentosd/src/execution_hub/` 内编写完整的单元测试 `#[cfg(test)] mod tests`，覆盖：
   - E2 暂存执行 → 文件新增/修改 Diff 计算 → 提交生成 `ChangeSet` → 撤销还原闭环；
   - `GrantEnvelope` 包络内放行与越界（超出目录/超出效应/超操作数）拦截测试；
   - Git 项目自动发现、从 `Task` 提取 `Workflow` 并持久化为 `SKILL.md` 测试；
   - Drive Engine 事件触发防抖（忽略 `.crdownload`）与 L1 过滤测试。
3. 运行 `cargo test -p intentosd execution_hub` 与 `cargo clippy -p intentosd -- -D warnings` 必须 100% 通过且零警告。
