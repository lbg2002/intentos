# IntentOS Wave 2 — 基于 `gnome-quick-chat` 范式的悬浮对话窗、记忆与数据管理层、软件指令转译层总架构

## 1. 核心设计哲学变革

基于作者的 `https://github.com/lbg2002/gnome-quick-chat`（✦ Quick Chat · 随问）演进为真正的 **Ubuntu 原生 AI 操作系统（AIOS）**：

1. **极简单一悬浮对话窗口（Single Floating Chat Dialog，告别复杂网页仪表盘）**：
   - 不再是复杂的多栏多标签网页后台，也不局限于通知栏内部，而是**浮在桌面窗口之上的单一极简对话框**（GNOME 桌面悬浮窗 / GTK4 无边框圆角悬浮窗 / Web 居中悬浮对话卡三端体验一致）。
   - 对话框内部继承并升华 `gnome-quick-chat` 的交互精髓：
     - **顶部极简栏**：`✦ IntentOS` + **内联模型与后端切换胶囊 (`▾`)**（一键切换 `ZCode | Codex | Pi | OpenAI API`、模型、思考强度 `默认/快/标准/深入`）+ `📋` 剪贴板/选区随问 + `🧠` 记忆快照浮层 + `+` 新建/切换对话 + `⚙` 设置抽屉（默认完全收起，不干扰主对话）。
     - **流式 Markdown 气泡 + 20px 横向彩色圆点轨迹栏 (`Trace Dots`)**：
       - 灰色圆点 `●` (`thinking`)：深度思考链路（点击展开/收起）
       - 紫色圆点 `●` (`memory`)：记忆与数据层召回（点击查看命中的「之前说的文件 / 长期高频文件 / 本机已安装与常用软件」）
       - 青色圆点 `●` (`adapter`)：软件指令转译层调用（点击查看 `MPRIS2 / D-Bus / URI / Headless / AT-SPI / CLI` 转译详情）
       - 橙黄圆点 `●` (`approval`)：待确认分级范围权限（气泡内联 `[批准本次] [本会话放行该范围] [拒绝]`）
       - 翠绿圆点 `●` (`tool_ok`)：已验证完成的系统能力（点击查看耗时、参数与内联 `[↶ 撤销]`）
       - 红色圆点 `●` (`tool_err`)：已拒绝或失败的操作
     - **底部极简输入框**：单框多行自适应输入（`Enter` 发送、`Shift+Enter` 换行、`↑/↓` 历史提问回溯、`Esc` 中止当前回合或收起悬浮窗、输入 `@` 快速引用记忆中的文件与软件）。

2. **记忆与数据管理层（`crates/intentosd/src/memory_hub/`）**：
   - 彻底解决「记不住之前说的文件、不知道长期使用的文件、不知道电脑上有哪些软件和常用软件」的问题。
   - 独立 SQLite 库 `${data_dir}/memory_hub.db`（WAL 模式）：
     - **会话提及实体图谱 (`conversational_mentions`)**：自动从每轮对话与工具调用中提取并持久化提到的文件路径、文件名、目录、软件名及上下文摘要，支持查询「我之前说的那个文件」「上次聊到的方案」。
     - **长期文件使用画像 (`file_usage_habits`)**：深度解析 Ubuntu 系统 `~/.local/share/recently-used.xbel`（GTK 全局最近使用记录、访问次数与关联打开软件）+ 授权目录扫描 + IntentOS 操作计数，计算 Frecency 长期热度分，识别「长期高频使用的文件」。
     - **本机软件全量资产与常用画像 (`software_inventory`)**：扫描 `/usr/share/applications`、`~/.local/share/applications`、Snap 与 Flatpak `.desktop` 描述，提取中英文名、分类、MIME 支持、URI Scheme、`DBusActivatable` 与历史使用频次，回答「我装了哪些软件」「我最常用的软件有哪些」。
     - **持久多轮会话与自动 RAG 注入 (`session_rag`)**：持久化对话历史（隐私模式除外），并在每轮大模型调用前自动生成精炼的 `[Personal OS Memory Context]` 注入系统上下文。

3. **软件指令接口转译层（`crates/intentosd/src/app_adapter/`）**：
   - 解决「许多桌面 GUI 软件不支持终端命令行驱动，需要做指令接口适配」的核心痛点。
   - 五通道渐进式软件控制转译：
     1. **MPRIS2 / Session D-Bus 驱动 (`mpris_dbus.rs`)**：通过 `gdbus` / D-Bus 控制无 CLI 接口的音乐播放器（QQ音乐、网易云、Spotify、VLC、浏览器媒体：`PlayPause`、`Next`、`Previous`、`Volume`、读取当前播放曲目）、文件管理器（`org.freedesktop.FileManager1.ShowItems` 高亮定位文件）与 `DBusActivatable` 应用。
     2. **URI Scheme & `.desktop` Desktop Actions 驱动 (`uri_desktop.rs`)**：将高层意图转译为 `vscode://file/...`、`obsidian://open?...`、`mailto:...`、`tg://...` 及 `.desktop` 内定义的 `[Desktop Action ...]`（如新建无痕窗口、新建文档）。
     3. **Headless 后台静默转换驱动 (`headless_bridge.rs`)**：将办公/多媒体软件的隐藏无头接口（如 `libreoffice --headless --convert-to pdf`、图片转换等）封装为可撤销的结构化能力。
     4. **AT-SPI2 无障碍树与窗口焦点适配驱动 (`gui_bridge.rs`)**：面向既无 CLI 也无 D-Bus 接口的纯 GUI 软件，提供窗口枚举/聚焦、AT-SPI2 控件树探测与受控快捷键/UI 动作适配（高风险动作走分级审批）。
     5. **声明式软件适配器注册表 (`registry.rs`)**：内置 15+ 常见 Linux 软件适配器并支持 `${config_dir}/adapters/*.toml` 用户扩展。

4. **多智能后端自动探测与统一回合桥接层（`crates/intentosd/src/backend_bridge/`）**：
   - 复刻并升级 `gnome-quick-chat` 的四后端自动探测与隔离机制：
     - 只读扫描 `~/.zcode/v2/provider_config.json`（ZCode CLI，通过 `0600` 临时文件覆盖模型，绝不污染原文件）、`~/.codex/config.toml`（Codex CLI）、`~/.pi/agent/models.json`（Pi CLI）、本地 Ollama (`127.0.0.1:11434`) 与自定义 OpenAI 兼容 API（`0600` 密钥库 / GNOME Keyring）。
     - 统一输出标准化的对话回合结构（包含 `reply_markdown`、`thinking`、`trace_dots`、`memory_hits`、`adapter_actions`、`pending_approval`、`session_id`）。

---

## 2. 跨模块统一 RPC 契约（`UiRpcRequest::ModuleRpc`）

### A. `domain = "memory_hub"`
- `get_memory_dashboard` -> `{ mentioned_files: [...], frequent_files: [...], frequent_apps: [...], installed_apps_summary: {...}, sessions: [...] }`
- `record_conversation_turn` `{ session_id, user_text, assistant_text, tool_steps, incognito }` -> 自动提取提及的文件/软件并更新长期使用画像
- `query_personal_memory` `{ query, kind: "all" | "mentioned_files" | "frequent_files" | "software", limit }` -> `{ hits: [...], context_markdown: "..." }`
- `sync_system_usage` `{}` -> 重新同步 `~/.local/share/recently-used.xbel` 与 `.desktop` 软件库
- `list_sessions` / `get_session` / `create_session` / `delete_session`

### B. `domain = "app_adapter"`
- `list_adapters` `{ query?: string }` -> `{ adapters: [...] }`（列出支持转译控制的软件及其适配通道 `dbus_mpris | uri_scheme | desktop_action | headless | gui_atspi | cli`）
- `translate_and_execute` `{ app_hint: string, intent_action: string, params: object, approved?: bool }` -> `{ ok, channel_used, app_id, summary, verification, trace_dot, changeset_id? }`
- `probe_live_controllable_apps` `{}` -> `{ mpris_players: [...], running_windows: [...], dbus_activatable_count: number }`

### C. `domain = "backend_bridge"`
- `get_backends_catalog` `{}` -> `{ active: { backend, provider, model, reasoning_effort }, backends: { zcode: {...}, codex: {...}, pi: {...}, openai: {...} } }`
- `set_active_backend` `{ backend, provider, model, reasoning_effort, base_url?, api_key? }` -> `{ saved: true, active: {...} }`
- `send_quick_chat_turn` `{ session_id?, text, clipboard_context?, incognito?, reasoning_effort? }` ->
  ```json
  {
    "turn_id": "turn_...",
    "session_id": "ses_...",
    "backend_used": "zcode | codex | pi | openai | fallback",
    "model_used": "...",
    "thinking": "...",
    "reply_markdown": "...",
    "trace_dots": [
      { "kind": "thinking", "color": "gray", "title": "深度思考", "detail": "..." },
      { "kind": "memory", "color": "purple", "title": "记忆召回: 3 项文件/软件", "detail": "..." },
      { "kind": "adapter", "color": "cyan", "title": "转译层: MPRIS 音乐控制", "detail": "..." },
      { "kind": "tool_ok", "color": "green", "title": "display.brightness.set", "detail": "...", "changeset_id": "..." }
    ],
    "pending_approval": null
  }
  ```

---

## 3. 严格文件所有权边界（零冲突并行规则）

1. **`memhub` 智能体**：仅创建/修改 `crates/intentosd/src/memory_hub/` 下的文件。
2. **`adapter` 智能体**：仅创建/修改 `crates/intentosd/src/app_adapter/` 下的文件。
3. **`llmbridge` 智能体**：仅创建/修改 `crates/intentosd/src/backend_bridge/` 下的文件。
4. **`chatweb` 智能体**：仅创建/修改 `crates/intentosd/src/web_ui/` 下的文件（将 Web 界面重构为 `gnome-quick-chat` 风格的极简单一悬浮对话窗 + `Trace Dots` + 内联模型切换器 + `@` 记忆引用 + 抽屉式设置）。
5. **`floatui` 智能体**：仅创建/修改 `desktop/` 下的文件（将 `desktop/gtk-fallback/intentos-launcher.py`、`launcher_style.css` 与 `desktop/gnome-extension/extension.js`、`stylesheet.css` 升级为浮在桌面窗口之上的极简悬浮聊天对话窗，支持 `Super+Shift+Q` 呼出、`Super+Shift+Y` 剪贴板随问、`Trace Dots` 与内联模型切换）。
6. **`qa` 首席联调与审查智能体**：待前 5 位完成后，负责串联 `core.rs` / `runtime.rs`（让 `submit_intent` 与 `send_quick_chat_turn` 自动读写 `memory_hub` 并挂载 `app_adapter` 工具），运行 `cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace`、`node --check` 与 `python3 -m py_compile` 全量门禁验证。
