# 实现任务书二（Agent-2）：全要素 11 域配置中心与大脑网关管理模块 (`config_center`)

> **角色定位**：IntentOS 系统配置中心与 Model Gateway 架构师（Agent-2）  
> **参考设计方案**：`docs/IntentOS_设计方案_v0.3.md` §4.7、§5.1–§5.6、§6.4、§8.7、§9.2、§10.2–§10.4、§14.2、§16.1  
> **解决核心痛点**：解决现有系统「配置内容要素太少（只有 3 个简陋输入框）、无法管理多供应商与 5 大模型角色、无连接与工具能力实测、无外发矩阵配置、无自定义站点/搜索模板增删改、无 11 页完整设置体系」的问题。

---

## 1. 严格的文件读写边界（防冲突红线）

- ✅ **你唯一允许新建和修改的目录**：
  `crates/intentosd/src/config_center/`
- ❌ **严禁修改任何其他目录或文件**：
  严禁修改 `Cargo.toml`、`crates/protocol/`、`crates/intentosd/src/lib.rs`、`crates/intentosd/src/core.rs`、`crates/intentosd/src/config.rs` 等任何外部文件！（主干已在 `lib.rs` 和 `core.rs` 中挂载了 `pub mod config_center;` 并转发了 `domain = "config_center"` 的 `ModuleRpc` 请求）。

---

## 2. 模块内部文件规划（功能模块化拆分）

请在 `crates/intentosd/src/config_center/` 下按以下职责拆分子模块，并在 `mod.rs` 中组织导出：

```text
crates/intentosd/src/config_center/
├── mod.rs              # 模块入口与 handle_module_rpc 分发器
├── schema.rs           # 11 大配置域的完整强类型数据结构定义、默认值与校验器
├── store.rs            # 配置持久化管理（读写 config.toml / brain.toml / advanced_config.json 及 state_db 联动）
├── brain_manager.rs    # 多供应商 CRUD、5 大模型角色（Main/Fast/Decision/Vision/Memory）、推理参数与预算管理
├── provider_tester.rs  # 供应商连接测试（B-03：区分认证失败/不可达/超时/模型不存在）、工具调用实测（B-04）与模型列表拉取（B-02）
├── egress_matrix.rs    # 外发矩阵（DataClass × ProviderTrust）自定义配置、敏感目录列表与 Forbidden 路径规则检查器（§5.4）
└── web_and_sites.rs    # 搜索引擎 CRUD、内置+自定义网站别名与站内搜索模板 CRUD、浏览器与书签/历史授权配置（§4.7）
```

---

## 3. 核心功能实现要求（对标设计方案 §5.1–§5.6 与 §14.2 的 11 大配置域）

### 3.1 域 1：概览 (`overview`)
- 聚合守护进程运行状态、版本、运行时健康度、索引统计、存储占用（`state.db` / `index.db` / `undo/` 备份区字节数）、CLI 依赖探测（`wpctl`, `gsettings`, `nmcli`, `rg`, `fd`, `bwrap`, `git`, `secret-tool` 等是否存在及版本号，§8.7）。

### 3.2 域 2：大脑与模型网关 (`brain`，对标 §5.1 B-01 ~ B-12)
1. **多供应商管理 (`providers` CRUD，B-01 & B-02)**：
   - 字段：`id`, `name`, `kind` (`openai-compatible` / `anthropic` / `gemini` / `ollama-local`), `base_url`, `credential_ref` (`secret-service://intentos/<id>`), `trust` (`trusted` / `standard` / `untrusted`), `enabled`, `available_models: Vec<String>`, `notes`。
   - 支持设置 API Key（优先调用 `secret-tool store --label="IntentOS" service intentos provider <id>`，若无桌面 keyring 则安全保存在内存/受控 `0600` 凭据槽中，**绝不写入 `brain.toml` 或日志**，§5.6）。
2. **连接检测 (`test_provider_connection`，B-03) 与工具能力实测 (`test_provider_tools`，B-04)**：
   - 连接测试：真实发起请求（或对本地 mock/端点探测），精确区分 `ok`、`auth_failed (401/403)`、`unreachable`、`timeout`、`model_not_found (404)`，返回延迟毫秒数 `latency_ms`。
   - 工具能力测试：向该供应商发送一条带最小 `tools` schema（如 `ping_tool`）的请求，验证其是否真实支持结构化 `tool_calls` 返回（§5.1 B-04）。
3. **5 大模型角色配置 (`profiles`，B-05 & B-06)**：
   - 完整支持 5 个角色：`main`（复杂推理与规划）、`fast`（L1 结构化解析与摘要）、`decision`（L1 类型化决策，`kind: "emulated" | "native"`，阈值 `direct_threshold`, `margin_threshold`, `clarify_threshold`）、`vision`（截图与视觉理解，P2）、`memory`（记忆提取与会话压缩）。
   - 每个角色的推理参数（B-06）：`provider`, `model`, `inherit`（可继承其它角色）、`context_budget`（如 `65536`）、`max_output_tokens`（如 `4096`）、`thinking`（`"off" | "low" | "medium" | "high"`）、`temperature`（`0.0 ~ 2.0`）。
4. **外发矩阵 (`egress_matrix`，B-10，§5.4)**：
   - `DataClass` (`public`, `personal`, `sensitive`, `forbidden`) × `ProviderTrust` (`trusted`, `standard`, `untrusted`) 的可配置策略表（值为 `"allow"` | `"confirm"` | `"deny"`，其中 `forbidden` 强制锁定为 `"deny"` 不可放宽）。
   - 支持配置用户自定义的 `sensitive_directories: Vec<String>`（标记为敏感的目录）和只读展示 `forbidden_rules`（`~/.ssh`, `~/.gnupg`, 密钥环等）。
5. **运行时与调用预算 (`runtime_limits` & `routing`，B-07 ~ B-09)**：
   - `runtime` (`"pi"` | `"native"`), `l0_enabled`, `l1_enabled`, `fallback_enabled`（B-07：故障切换开关及备用 `fallback_provider`）。
   - `max_tool_calls`, `max_runtime_seconds`, `max_concurrent_sessions`, `session_idle_timeout_minutes`, `single_task_cost_limit`, `daily_cost_limit`, `daily_token_limit`。

### 3.3 域 3 ~ 域 11 全要素配置支持（对标 §14.2 全部 11 页）
- **域 3 记忆 (`memory_config`)**：会话压缩阈值、会话结束时是否提议记忆候选开关、按作用域（个人/项目）过滤记忆。
- **域 4 能力与模块 (`capabilities_config`)**：按模块（`applications`, `filesystem`, `system`, `devtools`, `web`）展示启用状态、各能力启用/禁用开关、CLI 依赖探测详情、MCP Server 接入列表配置。
- **域 5 资源与项目 (`resources_config`)**：授权目录列表（增删改）、敏感目录列表、排除规则（如 `node_modules`, `target`, `.git`）、inotify 实时增量索引开关、手动重建索引。
- **域 6 网站与搜索 (`web_config`，§4.7)**：
  - 默认搜索引擎选择 + 自定义搜索引擎 CRUD（`id`, `name`, `url` 含 `{query}` 校验）；
  - 网站别名与站内搜索模板 CRUD（`id`, `names: Vec<String>`, `url`, `search: Option<String>`，校验只允许 `http://` 或 `https://`）；
  - 默认打开浏览器（`default`, `firefox`, `google-chrome`, `chromium`, `brave`）；
  - 浏览器书签索引授权开关（`bookmark_index_enabled`）与浏览器历史本地匹配授权开关（`history_index_enabled`）。
- **域 7 权限与安全 (`permissions_config`)**：小规模可逆写免审批阈值（默认 `max_auto_reversible_files = 20`, `max_auto_backup_mb = 200`，§10.2）、渐进信任提议开关、审计日志保留天数（默认 90 天）。
- **域 8 撤销与备份 (`undo_config`)**：备份区容量上限（`quota_gb`，默认 4 GB）、保留天数（`retention_days`，默认 30 天）、大文件单文件占比阈值（默认 25%）、一键清理过期备份。
- **域 9 自动化与驱动 (`automation_config`)**：全局自主性等级（`L0_Manual` / `L1_Suggest` / `L2_Authorized_Auto`，§13.4）、锁屏时暂停后台任务开关、每小时最大自动触发次数。
- **域 10 交互与快捷键 (`interaction_config`)**：全局唤起快捷键（默认 `<Super><Shift>space`）与**系统/输入法快捷键冲突检测器**（§3.1）、默认界面模式（`floating` 浮层 vs `workspace` 工作区）、外观主题（`system` / `dark` / `light`）、UI 缩放比例（`85% ~ 135%`）、失去焦点自动收起开关、语音输入 ASR 模式（`disabled` / `local_cpu` / `gateway_cloud`）。
- **域 11 维护与调试 (`maintenance_config`)**：开发者调试转录开关（`record_transcripts`，开启后顶栏提示、保留 7 天自动清理，§6.4）、日志级别、**导出无密钥配置包 (`export_config_bundle`)** 与 **导入配置包 (`import_config_bundle`)**、恢复出厂默认配置。

---

## 4. `ModuleRpc` 接口契约（必须在 `mod.rs` 的 `handle_module_rpc` 中实现）

前端与设置中心将通过 `domain: "config_center"` 调用以下 `action`：

| `action` 名称 | 输入 `payload` | 功能说明与返回结构 |
|---|---|---|
| `"get_all_domains"` | `{}` | 一次性返回全部 11 个配置域的完整结构化数据与实时统计指标 |
| `"update_domain"` | `{ "domain_key": "brain \| resources \| web \| permissions \| undo \| automation \| interaction \| maintenance \| memory \| capabilities", "data": {...} }` | 校验并持久化更新指定配置域，同步更新 `core` 中的 `config.toml` / `brain.toml` |
| `"upsert_provider"` | `{ "provider": { "id": "...", "kind": "...", "base_url": "...", "trust": "...", "enabled": true }, "api_key": "sk-..." }` | 新增或编辑模型供应商，安全存储 API Key（绝不写进 TOML） |
| `"delete_provider"` | `{ "provider_id": "..." }` | 删除指定供应商（保护最后一个或被 main 引用的供应商提示） |
| `"test_provider_connection"` | `{ "provider_id": "..." }` | 执行 B-03 连接测试，返回 `{ "status": "ok \| auth_failed \| unreachable \| timeout", "latency_ms": 42, "message": "..." }` |
| `"test_provider_tools"` | `{ "provider_id": "...", "model": "..." }` | 执行 B-04 结构化工具调用测试，返回 `{ "supported": true, "latency_ms": 120, "details": "..." }` |
| `"update_model_profiles"` | `{ "profiles": { "main": {...}, "fast": {...}, "decision": {...}, "vision": {...}, "memory": {...} } }` | 更新 5 大模型角色及推理参数（温度、上下文预算、思考强度） |
| `"update_egress_matrix"` | `{ "matrix": {...}, "sensitive_directories": [...] }` | 更新外发矩阵与敏感目录（强制校验 `forbidden` 永远为 `deny`） |
| `"upsert_site_shortcut"` | `{ "site": { "id": "...", "names": [...], "url": "...", "search": "..." } }` | 新增或修改网站别名与站内搜索模板（强制校验 `http/https`） |
| `"delete_site_shortcut"` | `{ "site_id": "..." }` | 删除站点别名 |
| `"upsert_search_engine"` | `{ "engine": { "id": "...", "name": "...", "url": "..." }, "set_default": true }` | 新增/修改搜索引擎并可选设为默认 |
| `"check_hotkey_conflict"` | `{ "hotkey": "<Super>space" }` | 检测是否与 Ubuntu/IBus/Fcitx5 默认快捷键冲突（如 `<Super>space` 提示与中文输入法切换冲突，推荐 `<Super><Shift>space`） |
| `"export_config_bundle"` | `{}` | 导出不含任何 API Key/凭据的完整 TOML/JSON 配置包（§5.6, M-08） |
| `"import_config_bundle"` | `{ "bundle": {...} }` | 校验并导入配置包 |
| `"reset_to_defaults"` | `{ "domain_key": "all \| ..." }` | 将指定域或全部配置恢复为安全默认值 |

---

## 5. 验收与自测标准

1. 所有代码必须包含 `#![forbid(unsafe_code)]`。
2. 安全红线：任何 API Key 绝不能写入 `brain.toml`、`config.toml` 或任何明文配置文件；`forbidden` 数据分级在 `egress_matrix` 中无论如何修改都必须锁定为 `deny`；自定义站点 URL 严禁 `javascript:` / `file:` / `data:` 协议。
3. 在 `crates/intentosd/src/config_center/` 内编写完整的单元测试 `#[cfg(test)] mod tests`，覆盖：
   - 11 大配置域读取、修改与持久化回读一致性；
   - 多供应商 CRUD 与 5 大模型角色保存；
   - 外发矩阵 `forbidden` 不可放宽校验与危险 URL 拦截校验；
   - 快捷键冲突检测（`<Super>space` 报警）与无密钥配置导出脱敏测试。
4. 运行 `cargo test -p intentosd config_center` 与 `cargo clippy -p intentosd -- -D warnings` 必须 100% 通过且零警告。
