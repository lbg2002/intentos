# IntentOS 研发进度记录（Progress Log）

> 严格遵循《IntentOS 设计方案（终版 Rev.4）》分阶段推进。


## 软件兼容与受控命令主线更新（2026-11-17）

- 顶层架构改为软件动作兼容、系统基础控制、Bash 分层执行与危险操作审批，见 [系统操控架构](docs/AIOS_SYSTEM_CONTROL_ARCHITECTURE.md)。
- 新增 `terminal.execute.command` 字面量单命令输入，编译为现有 program/argv，复用分级、审批、审计和沙箱；完整复合 Bash 仍待交付。
- 修正软件分类受父目录名称干扰的问题，以及 systemd 的 `--web-listen` 参数。
- 新增三项回归测试通过，最终 Clippy/格式通过；全量 219/232 通过，13 项未通过；分类修复追加单元与端到端验证通过，详细口径见架构文档验证章节。

---

## AIOS 目标验收与可信入口加固（本轮）

- 方案：[AIOS 代码审查与目标交付方案](docs/AIOS_REVIEW_AND_DELIVERY_PLAN.md)，按目标证据、隐私生命周期和渐进交付重新排序 S0–S4。
- 代码：`f06ad28` 修正 task.verify 误判和外层协议状态，限制本地 Web Host/Origin 与监听地址；新增四项回归测试。
- 质量：`b67d992` 保持行为不变地适配当前 Clippy；`efae7d1` 修正红队 Node 定位、真实监听端口和探针失败/超时语义。
- 最终结果：215/230 测试通过；新增四项全通过；语料 324/325、撤销 6/6、红队 16/16；全量测试及延迟门禁仍未通过，GTK 冒烟因无显示服务跳过。详见 [验证报告](docs/AIOS_VALIDATION_REPORT.md)。
- M3/M4 仍属后续计划；未宣称整套 AIOS 已完成，也未覆盖原有历史基准。

---

## ✅ 已完成里程碑一：阶段一 `v0.0 PoC`（Tag: `v0.1.0-poc`）

- **交付时间**：2026-11-13
- **核心目标**：打通「意图输入 → L0/L2 路由 → Policy 污点与权限仲裁 → E1/E3 受控执行 → 读回验证 → ChangeSet 一键撤销」完整闭环。
- **关键成果**：
  1. 冻结协议 `crates/protocol`、`state.db`（WAL + 脱敏审计）与 `index.db`（WAL + FTS5 + 自动重建）。
  2. 原生安全文件事务 `crates/fsops`（`SYS_openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` + `renameat2(RENAME_NOREPLACE)` + 4 GiB 备份配额 + 冲突检测回滚）。
  3. 三层自适应无外网进程沙箱 `crates/sandbox` + `agent/pi-adapter` 网关代理 Worker。
  4. 首批 29 个 YAML 能力单源构建；`126/126` 基准评测 `100%` 通过，`10/10` 安全红队通过。

---

## ✅ 已完成里程碑二：阶段二 `v0.1 Intent Shell`（首个可日用正式版，Tag: `v0.1.0`，§18.2）

- **交付时间**：2026-11-13
- **核心目标**：完成全部桌面壳层交互、87 项单源系统能力、L1 类型化决策模型路由、显式记忆与无痕隐私会话、四页设置中心、公开非特权 D-Bus 接口及 `.deb` / 免编译压缩包交付。
- **已完成工作包清单（WP04–WP16 全量收官）**：
  - [x] **WP10 L1 类型化决策模型适配器（`crates/intentosd/src/decision.rs`）**：实现 `binary` / `choice` / `score` 三原语、Fast LLM 网关结构化评估与本地校准回退、决策校准表持久化（`decision_calibrations`）及单向权限/污点升级不变量。
  - [x] **WP04 全量 87 项内置 YAML 能力描述与单源文档（`modules/builtin/` & `docs/capabilities.md`）**：
    - 应用与窗口：`window.list`、`window.focus`、`app.quit`（优雅关闭不强杀）
    - 文件与归档：`file.copy`、`file.rename`、`file.trash`、`file.recent`、`file.reveal`、`clipboard.copy`、`archive.create`、`archive.extract`（内置 Zip-Slip / Tar-Slip 路径穿越硬拦截与 `ChangeSet` 一键撤销）
    - 声音与媒体：`sound.mic.volume.set`、`sound.mic.mute.set`、`sound.output.list`、`sound.output.set`、`media.control`、`screenshot.take`
    - 显示与外观字体：`display.night_light.set`、`display.night_light.temperature`（步长 `500K`）、`display.idle_delay.set`、`appearance.accent_color.set`、`appearance.font.{list,interface.set,document.set,monospace.set}`（`fc-list` 已安装字体严格白名单校验与相近字体建议 `A11c`）、`appearance.cursor_size.set`、`appearance.animations.set`、`appearance.wallpaper.set`（授权目录校验）、`appearance.clock.set`
    - 锁屏、网络蓝牙、电源与输入设备：`screen.lock`、`screen.autolock.set`、`network.wifi.{power,list,connect}`（未保存热点零密码索取并自动移交系统面板 `A11f`）、`network.status`、`bluetooth.{power,connect,disconnect}`、`network.airplane.set`、`power.profile.{get,set}`、`power.battery.status`、`power.session`（挂起/重启/关机/注销逐次确认）、`input.mouse.speed`、`input.touchpad.{speed,natural_scroll,tap_to_click}`、`input.keyboard.repeat`、`input.source.switch`
    - 组合场景（`scene.apply` & 自定义保存 `A11e`）：内置「护眼模式」「演示模式」「安静模式」「会议模式」「专注模式」及「把现在的设置保存为 XXX」，单 `ChangeSet` 原子记录与一键整体回退
    - 开发者诊断与命令移交：`disk.usage`、`network.ip`、`process.list`、`process.terminate`、`terminal.open_at`、`terminal.handoff`、`package.search`、`git.{status,log,diff}`、`project.open` 及内置技能 `skills/builtin/{git-guide,linux-diagnose}/SKILL.md`
  - [x] **WP05 扩展资源索引**：支持 Chromium / Google Chrome `Bookmarks` 只读书签检索、`fc-list` 字体缓存索引及 `$ ` 命令直通历史管理（`index.db`）。
  - [x] **WP11 / M-01..M-03 显式记忆与临时隐私会话**：
    - `incognito = true` 隐私会话零 SQLite 落盘（任务、历史、记忆均不写库）
    - 显式偏好记忆 CRUD + 「记住 docx 用 WPS 打开」自动路由联动（`A22`）+ 密钥/口令写入实时拦截（`M-02`）+ 删除指纹墓碑防复活（`M-03`）
  - [x] **WP12–WP14 桌面壳层、四页设置中心与公共 D-Bus 服务**：
    - 公共非特权 D-Bus 服务 `org.intentos.Core1`（`crates/intentosd/src/dbus_bridge.rs`，严格隔离审批/授权/记忆管理接口并拦截外部 `$ ` 直通）
    - GNOME Shell 扩展升级（隐私会话开关 + 命令移交一键填入）
    - GTK4 独立降级唤起窗（`desktop/gtk-fallback/intentos-launcher.py`）与 GTK4 四页设置中心（`desktop/settings/intentos-settings.py`）
    - Web Shell `v0.1` 升级（内嵌四页设置中心模态框、场景快捷应用、记忆中心管理、隐私会话开关与 `$ ` 命令移交审阅条）
  - [x] **WP15–WP16 Debian `.deb` 打包与 325 条语料 + 16 项红队 Release 门禁验证**：
    - 实时候选刷新延迟：**P50 = `2.58 ms`，P95 = `5.99 ms`**（冻结目标 P50 ≤ 12 ms, P95 ≤ 30 ms）
    - L0 确定性执行延迟：**P50 = `2.96 ms`，P95 = `9.17 ms`**（冻结目标 P50 ≤ 120 ms, P95 ≤ 300 ms）
    - 日常意图 L0 覆盖率：**`100.0%`（284/284）**（冻结目标 ≥ 85%）
    - 325 条评测集总体准确率：**`99.4%`（323/325，含 100 条系统设置）**（冻结目标 ≥ 88%）
    - 虚假成功率：**`0`**；6 类可逆变更集一键撤销成功率：**`100.0%`（6/6）**；红队安全与沙箱逃逸门禁：**`16/16` 全通过**
    - Workspace `cargo clippy --workspace --all-targets -- -D warnings`：**0 警告**；`26/26` 单元与端到端集成测试全部通过。

---

## ✅ 已完成里程碑三：阶段三 `v0.3 Modular Architecture & Full Feature Upgrade`（模块化重构与全功能升级）

- **交付时间**：2026-11-13
- **核心目标**：按照《IntentOS 设计方案 v0.3》完成全功能模块化重构，解决「路由死板、界面单调、交互不灵活、配置要素少」四大核心痛点，并通过 `UiRpcRequest::ModuleRpc { domain, action, payload }` 统一模块总线实现解耦。
- **已完成 5 大功能模块与验收门禁**：
  - [x] **模块一 `intent_engine`（`crates/intentosd/src/intent_engine/`，TASK 01）**：
    - 通用模式编译器（`pattern_compiler.rs`）与拼音全拼/首字母 + 口语模糊评分器（`fuzzy_scorer.rs`）
    - 全量 87 项 YAML 能力的通用槽位提取器（`slot_extractor.rs`，覆盖相对/绝对数值、布尔、颜色、字体、路径、枚举）
    - 多轮会话与工作上下文指代消解器（`context_resolver.rs`，消解「它」「那个文件」「刚下载的」「上次打开的」）
    - 分组候选引擎与 `Alt+Enter` 上下文动作菜单（`grouped_candidates.rs`，5 大分组 + R0-R3 徽章）
    - 复合多步意图拆解与顺序执行器（`compound_splitter.rs`，支持「先…再…」「…然后…」「…并…」跨步路径传递）
  - [x] **模块二 `config_center`（`crates/intentosd/src/config_center/`，TASK 02）**：
    - §14.2 完整 11 域配置 Schema 与持久化存储（`schema.rs`、`store.rs`，配置落盘 `0600` 原子替换且零明文 API Key）
    - 多模型大脑与网关管理器（`brain_manager.rs`，支持 OpenAI/Anthropic/Gemini/DeepSeek/Qwen/Ollama/vLLM 多 Provider CRUD 与 `Main/Fast/Decision/Vision/Memory` 5 角色路由 + Fallback 链 + 推理参数 + 运行时预算）
    - B-03 连通性测试器与 B-04 Tool-Calling 能力自检器（`provider_tester.rs`）
    - B-10 `DataClass × ProviderTrust` 出网矩阵仲裁器（`egress_matrix.rs`，硬性保证 `Forbidden -> deny` 不变量）
    - 自定义网站快捷方式与搜索引擎模板 CRUD（`web_and_sites.rs`，拦截 `javascript:`/`data:`/`file:`/`vbscript:` 危险协议）
    - 快捷键冲突检测与不含密钥的配置包导入导出
  - [x] **模块三 `execution_hub`（`crates/intentosd/src/execution_hub/`，TASK 03）**：
    - E2 受控沙箱暂存执行与 Diff 预览提交器（`e2_staging.rs`，在隔离 staging 目录生成 unified diff / hex 摘要，提交后自动生成可逆 `ChangeSet`）
    - 细粒度授权信封与渐进信任引擎（`grant_envelope.rs`，校验目录/命令/域名/文件数/字节数/TTL 边界，3 次重复自动建议信任规则）
    - Git 项目自动发现与三态记忆候选管理（`project_memory.rs`）
    - 重复动作工作流学习与 Skill 生成器（`skill_workflow.rs`，含执行前资源漂移检测）
    - 主动建议与自动化驱动调度器（`drive_scheduler.rs`，支持文件事件防抖、忽略 `.part`/`.crdownload`、全屏/会议勿扰抑制）
  - [x] **模块四 `web_ui`（`crates/intentosd/src/web_ui/`，TASK 04）**：
    - 100% 离线模块化前端资源（`assets/index.html` + 4 个自适应毛玻璃 CSS + 7 个原生 ES Module JS）
    - Spotlight 紧凑浮层与 Intent Workspace 工作区双模态切换、全键盘导航引擎（`Alt+Enter` 动作抽屉、`Tab` 分组切换、空输入 `↑` 历史召回、`Ctrl+Z` 30 秒倒计时撤销横幅）、声明式视图与 11 页可视化设置中心
  - [x] **模块五 `desktop`（`desktop/`，TASK 05）**：
    - GNOME Shell 46 扩展（`extension.js`、`stylesheet.css`）支持分组候选、`Alt+Enter` 子菜单、内联审批卡片与顶栏状态胶囊
    - GTK4 独立唤起器（`intentos-launcher.py`、`launcher_style.css`）与 GTK4 11 页原生设置中心（`intentos-settings.py`）
  - [x] **Workspace 质量与安全门禁**：
    - 全仓强制 `#![forbid(unsafe_code)]`
    - `cargo clippy --workspace --all-targets -- -D warnings`：**0 警告，0 错误**
    - `cargo test --workspace`：**`45/45` 单元测试与端到端测试 100% 通过**
    - 前端 7 个 ES Module `node --check` 与桌面 Python 脚本 `py_compile`：**0 错误**

---

## ✅ 已完成里程碑四：阶段四 `v0.4 Desktop-Floating Quick-Chat AIOS + Memory Hub + App Translation Layer`（桌面悬浮「随问」单对话框 + 个人记忆数据管理层 + 软件指令转译层）

- **交付时间**：2026-11-14
- **核心目标**：对标 `gnome-quick-chat`（`✦ Quick Chat · 随问`）极简交互范式并升级为真正的桌面级 AI 操作系统，彻底重构为**浮在桌面之上的单一极简对话框**，同时补齐**个人记忆与数据管理层（`memory_hub`）**、**非 CLI 桌面软件指令接口转译层（`app_adapter`）**与**本机多后端只读自动发现（`backend_bridge`）**。
- **已完成核心模块与验收门禁**：
  - [x] **单一桌面悬浮「随问」对话框（原生 GTK4 + GNOME Shell 46–50 扩展 + Web 悬浮单窗）**：
    - 原生 GTK4 桌面悬浮窗（`desktop/gtk-fallback/intentos-launcher.py`、`launcher_style.css`）：无边框毛玻璃 `480×640` 悬浮窗、拖拽顶栏、`📌` 置顶、内联折叠 `▾` 引擎/模型/思考强度切换条（`自动 / ZCode / Codex / Pi / OpenAI API` + `默认/快/标准/深入`）、`📋` 剪贴板一键随问（`--clipboard-ask`）、`🧠` 记忆与软件转译抽屉、`20px` 六色 `Trace Dots`（`●`）及自动兼容 Conda 环境切换系统 `/usr/bin/python3`。
    - GNOME Shell 46–50 桌面悬浮窗扩展（`desktop/gnome-extension/extension.js`、`stylesheet.css`）：脱离通知栏，通过 `Main.layoutManager.addTopChrome` 挂载可拖拽桌面居中悬浮窗，支持 `<Super><Shift>q` 唤起与 `<Super><Shift>y` 选中文本随问。
    - Web 单一悬浮对话框重构（`crates/intentosd/src/web_ui/assets/index.html`、`quick-chat-dialog.css`、`main.js`、`trace-dots.js`、`markdown-renderer.js`、`memory-adapter-popover.js`）：砍掉繁杂后台多面板，聚焦单一 `✦ IntentOS · 随问` 悬浮窗，支持 `@` 引用记忆文件/软件、代码块一键复制、`↻` 重试与点击圆点展开工具/审批/撤销详情（11 页设置中心隐藏在右上角 `⚙`）。
  - [x] **记忆与个人数据管理层 `memory_hub`（`crates/intentosd/src/memory_hub/`）**：
    - 独立 WAL 库 `memory_hub.db`（`schema_and_db.rs`，含密钥脱敏与 `incognito` 零落盘保证）。
    - 对话提及文件与跨轮实体记忆（`conversational_entities.rs`）：自动提取并升级对话中出现的路径、裸文件名、`《文档名》`、目录与软件，支持「打开/复制我之前说的那个文件」跨会话消解。
    - 长期高频文件与本机软件全量画像（`long_term_habits.rs`）：解析 Ubuntu `~/.local/share/recently-used.xbel` 与 Frecency 频次统计长期常用文件；全量扫描系统/用户/Snap/Flatpak `.desktop` 构建本机已安装软件与常用软件目录。
    - 自动上下文注入与 4 项大模型记忆工具（`session_rag.rs`）：推理前自动注入 `[Personal OS Memory]`，并向大模型暴露 `memory_recall_mentioned_files`、`memory_get_frequent_files`、`memory_get_software_catalog`、`memory_search_past_chats`。
  - [x] **非 CLI 桌面软件指令接口转译层 `app_adapter`（`crates/intentosd/src/app_adapter/`）**：
    - 内置 **24 个 Linux 桌面软件适配 Profile**（QQ 音乐、网易云音乐、Spotify、Rhythmbox、VLC、Nautilus、VS Code、ZCode、Cursor、Chrome、Firefox、LibreOffice、WPS、Obsidian、Evince、Telegram 等）并支持 `${config_dir}/adapters/*.{toml,json}` 扩展（`registry.rs`）。
    - 五级无 CLI 转译通道：`MPRIS2 / Session D-Bus` 媒体与文件管理器控制（`mpris_dbus.rs`）、`URI Scheme` 深链与 `.desktop` `[Desktop Action]` 动作解析（`uri_desktop.rs`）、受控后台文档/图片无头转换（`headless_bridge.rs`，绑定可逆 `ChangeSet`）、以及 `AT-SPI2 / 窗口级 GUI 动作`（`gui_bridge.rs`，强制审批门禁）。
    - 向大模型暴露 3 项软件转译工具：`app_adapter_invoke`、`app_adapter_list`、`app_adapter_now_playing`。
  - [x] **本机多后端只读自动发现与统一对话回合引擎 `backend_bridge`（`crates/intentosd/src/backend_bridge/`）**：
    - 零外部侵入只读探测本机 `ZCode`（`~/.zcode/v2/`）、`Codex`（`~/.codex/config.toml`）、`Pi`（`~/.pi/agent/models.json`）、`Ollama`（`127.0.0.1:11434`）与 `OpenAI API` 凭据库（`detector.rs`），支持 `<think>` 提取、7 项新 AIOS 工具循环调用、6 色 `Trace Dots` 生成及回合幂等取消（`turn_engine.rs`）。
  - [x] **Workspace 质量与端到端门禁**：
    - `cargo clippy --workspace --all-targets -- -D warnings`：**0 警告，0 错误**
    - `cargo test --workspace -- --test-threads=1`：**`64/64` 单元测试与端到端集成测试（含 `tests/e2e_wave2.rs`）100% 通过**
    - 前端 10 个 JS 模块 + GNOME 扩展 `node --check` 与 GTK4 Python 脚本 `py_compile`：**0 错误**

---

## ✅ 已完成里程碑五：阶段五 `v0.5 Trustworthy Permission Guard, Outline Memory, Live /v1/models & Dynamic App Adapter`（全局路径与敏感审批防护 + 三层渐进式章节记忆 + 接口实时拉取模型 + 个性化软件转译 + 深浅色主题适配）

- **交付时间**：2026-11-14
- **核心目标**：针对真实桌面实测暴露的 5 大核心痛点（设置中心 GTK4 崩溃、模型未走 `/v1/models` 实时查询、中文目录阻断与敏感权限缺交互式审批、记忆盲目塞入无关文件且只给裸路径无法定位论文第四章、`SodaM` 托盘类个性化软件关不掉及浅色主题黑底按钮对比度异常）完成系统级优化。
- **已完成核心升级与验收门禁**：
  - [x] **1. 设置中心修复与实时 `/v1/models` 模型接口自动拉取（`desktop/settings/intentos-settings.py`、`backend_bridge/detector.rs`）**：
    - 修复 `gi.require_version("Gdk", "4.0")` 警告与全部 `TextView.set_min_content_height` 崩溃，新增 `--smoke-ui` 真机 GTK4 全 11 页构建门禁（0 警告、0 异常）。
    - `detector.rs` 自动并发请求各后端/网关（如本机 `http://localhost:8317/v1/models`、OpenAI/Anthropic 兼容端点）拉取全量实时聊天模型（自动过滤 embedding/rerank/image 工具模型，内置 300 秒缓存与 `refresh_models` 强制刷新），同时在 `turn_engine.rs` 原生支持 Anthropic `/v1/messages` 工具调用与重复工具调用死循环熔断。
    - 悬浮窗 `▾`、Web 端与设置中心第 2 页同步提供 **`↻ 刷新接口模型`**、**模型实时搜索过滤框**与可滚动全量模型列表（本机实测自动拉取 36 个实时模型）。
  - [x] **2. 四级全局路径可见性与敏感权限内联审批防护（`crates/fsops/src/lib.rs`、`policy.rs`、`config.rs`、`core.rs`）**：
    - 自动解析 `~/.config/user-dirs.dirs`（原生覆盖中文 `桌面/文档/下载` 与用户主目录常规空间）：常规用户空间读取与打开（`file.open`）全局免阻断；AI 发起的文件修改（`move/copy/rename/trash/write`）强制走可逆变更集审批。
    - 敏感隐藏配置目录（`~/.config`、`~/.local` 等）与外部/系统路径不再粗暴报错「路径超出授权目录范围」，而是自动升级为 **`RequiresApproval` 内联安全审批卡片**（在悬浮窗气泡内自动展开，清晰展示 `R1/R2/R3` 风险等级、目标路径/PID、是否可一键撤销，提供 **`[✓ 批准本次]` · `[⏱ 本会话放行此范围]` · `[✕ 拒绝]`**），同时对 `~/.ssh` 私钥与 `/etc/shadow` 保持绝对硬拦截（`Deny`）。
    - 顶栏新增 **`🛡` 防护姿态胶囊**，支持一键切换 `严格逐次审批 / 平衡防护(默认) / 开发者模式` 并随时撤回会话授权。
  - [x] **3. 意图门控 Token 预算记忆召回与三层文档章节大纲索引（`memory_hub/document_outline.rs`、`session_rag.rs`）**：
    - **零噪声意图门控与严格 Token 预算（`<= 950 chars` / ~280 tokens）**：执行纯应用/系统控制（如「打开 QQ」「调低音量」）时注入 **0 条无关文件记忆**，彻底杜绝把 `.deb`/`.docx` 盲目塞进上下文。
    - **三层渐进式文档记忆（`L0 语义索引卡 -> L1 章节大纲表 -> L2 按需章节精读工具 memory_inspect_document`）**：自动提取 `.docx`（`word/document.xml`）、`.md`、`.txt`、`.tex`、`.pdf` 的内部标题与章节结构（如英文文件名 `paper_main.docx` 内的中文标题「硕士学位论文」及「第四章 …」），说「打开我的硕士论文第四章」时既能精准打开文件，又能按需提取第四章标题与摘要而不撑爆上下文。
  - [x] **4. 个性化无接口软件动态转译与 `SodaM` 真实闭环关闭校验（`app_adapter/dynamic_profiler.rs`、`broker.rs`）**：
    - 自动扫描全量 `.desktop`（含 `Keywords=music;qishui;soda;sodam;`、`StartupWMClass`、`Exec`）、运行态 `/proc/<pid>` 与 Session D-Bus，为任意用户个性化软件自动生成转译 Profile，并支持在设置中心第 5 页自定义无接口软件动作映射（`custom_apps.json`）。
    - 重构 `app.quit` 为四阶段真实转译关闭与读回校验：`MPRIS2 Stop+Quit` → 窗口优雅关闭 → 针对最小化到托盘的应用（如 `SodaM` 汽水音乐）发送同 UID 优雅 `SIGTERM` → 轮询 `/proc/<pid>/status` 实锤校验进程退出（若僵死未退绝不假报成功，自动弹出内联审批询问是否强制结束）。
  - [x] **5. 原生 GTK4 / GNOME 扩展 / Web 深浅色高对比度主题重构**：
    - 彻底清除 GTK4 Adwaita 深色 `background-image` 在浅色模式下的残留（解决黑底黑字问题），启动时自动跟随 Ubuntu 系统深浅色并在切换 `◑` 时同步全套高对比度组件样式，同时将超过 6 步的 `Trace Dots` 自动折叠为紧凑 `+N` 胶囊。
  - [x] **Workspace 全量门禁验证**：
    - `cargo clippy --workspace --all-targets -- -D warnings`：**0 警告，0 错误**
    - `cargo test --workspace -- --test-threads=1`：**`79/79` 单元测试与端到端测试（含 `tests/e2e_wave3.rs`）100% 通过**
    - `intentos-settings.py --smoke-ui`（11 页实测）与 `intentos-launcher.py --smoke-ui`（36 个实时模型实测）：**0 警告，0 错误**


### 里程碑 6：Wave 4 — 通用个性化软件自动嗅探与转译引擎 + 净环境真实校验启动（已完成）
- **通用托盘菜单与桌面无接口软件自省引擎 (`crates/intentosd/src/app_adapter/sni_dbusmenu.rs` & `gui_bridge.rs`)**：
  - 自动嗅探 Session D-Bus 上的所有 `org.kde.StatusNotifierItem-*` 与 `org.freedesktop.StatusNotifierItem-*` 托盘实例（如 `SodaM 汽水音乐`、`WPS 云盘`、`FlClash`、`QQ`、`微信`、`飞书`、`轻笺 BetterNotes` 等无 CLI / 无 MPRIS2 的个性化桌面应用），实时解析 `Id`/`Title`（如正在播放曲目）与 `com.canonical.dbusmenu.GetLayout` 完整菜单树（`显示主窗口`、`暂停`、`上一首`、`下一首`、`退出` 等），并通过 `AboutToShow` + `Event(clicked)` + 读回比对完成闭环验证控制。
  - 修复 `gui_bridge.rs`：在真实桌面会话（`DISPLAY` / `WAYLAND_DISPLAY`）下彻底杜绝伪造 `"（无头/仿真环境预演）"`，默认调用宿主机 `/usr/bin/python3`（`Atspi 2.0` + `Wnck 3.0`）与托盘 `Activate` 实现真实窗口枚举与聚焦，进程未运行时诚实返回 `VerificationFailed`。
  - 新增第 9 个 AIOS 大模型工具 **`app_adapter_inspect_app`**（`5 memory_hub + 4 app_adapter`），支持对任意未知/个性化软件按需实时探测 `.desktop`、运行 PID、托盘菜单项、MPRIS2、URI Scheme 与 AT-SPI 控件。
- **中英文/拼音双向 `.desktop` 解析、净环境启动与编译期 RPATH (`.cargo/config.toml`、`resource.rs`、`broker.rs`)**：
  - 新增本地编译期 RPATH 配置支持，`intentosd` 与 `intentosctl` 直接运行无需再手动携带 `LD_LIBRARY_PATH`。
  - 派生桌面子进程时自动剥离 Conda `LD_LIBRARY_PATH`、`CONDA_*`、`PYTHONPATH`、`PYTHONHOME`，彻底消除对 Electron / Qt / 系统 `/usr/bin/python3` GUI 软件的动态库污染。
  - `resource.rs` 支持中文口令转拼音反向匹配 `.desktop` `Keywords=`（如 `"汽水音乐"` -> `"qishui"` 命中 `/usr/share/applications/sodam.desktop`，大小写不敏感匹配 `"SodaM"` -> `"sodam.desktop"`），`app.launch` 自动唤醒已驻留托盘实例或通过 `gio launch <精确路径>` 启动并轮询 `/proc` 校验真实 PID。
- **诚实状态圆点与「个性化软件实时转译工作台」(`desktop/` & `crates/intentosd/src/web_ui/`)**：
  - 区分已校验成功（翠绿 `#10b981`）与仅发送请求待响应（天蓝 `#38bdf8` `RequestedUnverified`），拒绝虚假绿点。
  - 悬浮窗 `🧠` 抽屉与 11 页设置中心第 5 页新增实时托盘扫描、一键触发托盘菜单、任意软件深度探测与零 JSON 口令绑定。
- **Wave 4 质量门禁**：
  - 零环境变量 `cargo clippy --workspace --all-targets -- -D warnings`：**0 警告，0 错误**
  - 零环境变量 `cargo test --workspace -- --test-threads=1`：**`93/93` 测试（含 `tests/e2e_wave4.rs`）100% 通过**
  - `intentos-settings.py --smoke-ui`、`intentos-launcher.py --smoke-ui` 与全量 JS 语法检查：**0 警告，0 错误**

### 里程碑 7：Wave 5 — 审批续接会话闭环、本机软件 9 大类深度转译、非线性时间衰减压缩与本地离线语音识别（已完成）
- **敏感权限审批无缝续接大模型会话 (`backend_bridge/turn_engine.rs`、`policy.rs`、`core.rs`)**：
  - 修复点击「批准本次 / 本会话放行此范围 / 拒绝」无视觉响应且未进入会话的问题：触发 `RequiresApproval` 时保存 `SuspendedTurnCheckpoint`；用户点击审批按钮后立即隐藏按钮并提示执行进度，通过 `backend_bridge.resume_approved_turn` 执行已授权能力（含授权目录实时补扫），将完整 `step.data`（如检索到的真实文件列表）回填给大模型继续推理生成自然语言回答，自动写入当前会话与长期记忆库，且「本会话放行此范围」在有效期内同目录不再重复弹窗。
- **本机全量软件深度扫描与 9 大分类丰富接口转译层 (`app_adapter/local_scanner.rs`、`registry.rs`)**：
  - 扫描系统 `/usr/share/applications`、Snap、Flatpak、`~/.local/share/applications` 与 17 类伴生命令行工具，实测识别本机 **100 款可见桌面软件**，自动归入 **9 大分类**（影音娱乐、社交通讯与会议、办公文档与笔记、云盘互传、网络代理与浏览器、AI 编程与开发逆向、图形创意与光盘刻录、远程桌面与虚拟化、硬件外设与系统工具），内置 **70 款精调软件画像**并自动合成 **730 项可转译接口**（涵盖腾讯会议房间号直连、LibreOffice 无头转 PDF、Evince 页码跳转检索、draw.io 导出、FlClash 代理探测与托盘控制、VirtualBox 虚拟机管控、RustDesk 远控、Fcitx5 中英切换、NVIDIA 显存功耗遥测、LocalSend 局域网发文件等）。
- **非线性时间衰减会话上下文压缩 (`memory_hub/context_compressor.rs`)**：
  - 自动剥离历史回合中的工具调用记录（`tool_calls` / `role: tool`）与 `<think>` 思考过程，**仅保留用户提问与 AI 回答**；按 $w(d,\Delta t)=\exp(-\lambda d^\gamma)/(1+0.06\ln(1+\Delta t/30))$ 四区段非线性时间衰减（近期完整保留 → 中期保留问题与核心结论/折叠代码块 → 远期问答微摘要 → 超远期滚动归并摘要锚点），严格锁定单会话上下文预算（默认 `6000` Tokens），并在设置中心第 3 页开放可视化调节。
- **本地离线语音识别 (ASR) 模型下载中心与随问麦克风输入 (`speech_hub/`、`scripts/intentos_asr_runner.py`)**：
  - 新增 `speech_hub` 模块，支持在设置中心第 1 页一键下载管理 **SenseVoiceSmall INT8**（ModelScope 国内高速直连，中英粤日韩极速识别）与 **Whisper Tiny / Base / Small Q8** 四款离线 ONNX 模型（实时进度条、测速、取消与删除）及开启/关闭语音输入功能；悬浮窗输入框新增 `🎙` 录音按钮，基于 `pw-record` + `onnxruntime` 本地离线转写并填入/自动发送。
- **Wave 5 质量门禁**：
  - 零环境变量 `cargo clippy --workspace --all-targets -- -D warnings`：**0 警告，0 错误**
  - 零环境变量 `cargo test --workspace -- --test-threads=1`：**`115/115` 测试（含 `tests/e2e_wave5.rs`）100% 通过**
  - `intentos-settings.py --smoke-ui`、`intentos-launcher.py --smoke-ui` 与全量 JS 语法检查：**0 警告，0 错误**

---

### 里程碑 8：`v0.2-M1: 统一智能体核心与可信底座加固`（GitHub Milestone #1，Issues `#1`–`#5` 全量收官）
- **交付时间**：2026-11-15
- **路线图与工程治理 (`docs/ROADMAP_v0.2.md`、`README.md`)**：
  - 建立 `IntentOS v0.2 — Cognitive Shell` 五层认知壳层路线图、4 个 GitHub 里程碑（`v0.2-M1` 至 `v0.2-M4`）与 16 个结构化架构 Issue（`#1`–`#16`）。
- **模块化智能体回合运行时与多后端受控 `CapabilityBroker` 桥接 (`backend_bridge/{turn_engine,turn_checkpoint,broker_bridge,providers_http,providers_cli}.rs`，Closes `#1`, `#2`)**：
  - 将原 4,995 行单文件 `turn_engine.rs` 拆分为 5 个高内聚子模块，`turn_engine.rs` 精简至 **1,303 行**（`< 1,500` 行目标达成），并保留 100% 向后兼容重导出。
  - 统一 `BackendExecutionMode`（`managed_broker` / `cli_broker_bridged` / `external_chat_only` / `offline_core`）；升级 `ZCode` / `Codex` / `Pi` CLI 后端通过 `<intentos_tool_call>` 受控协议接入 `CapabilityBroker`（最多 4 轮工具闭环），产出真实 `TraceDot`、`changeset_ids` 并与 HTTP 后端共享完全一致的 `PendingApproval` 挂起与 `resume_approved_turn` 续接闭环。
- **`TurnEffectLedger` 副作用账本与失败回退防重放保证 (`turn_checkpoint.rs`、`turn_engine.rs`，Closes `#3`)**：
  - 每次能力调用生成确定性 `step_id` 与 canonical JSON SHA-256 `idempotency_key`；当 HTTP/CLI 后端在第 1 轮已提交任意副作用（`effect > Effect::Observe`）后第 2 轮发生网络/5xx 故障时，硬性阻断向次级 CLI 或 `core.submit_intent` 回退重放（`side_effect_replay_prevented: true`），完整保留首轮 `changeset_ids` 供用户一键 `Undo`。
- **三级隐私会话记忆隔离与全链路 `SensitiveDataGuard` 落盘脱敏 (`security_guard.rs`、`db.rs`、`memory_hub/`、`runtime.rs`、`turn_engine.rs`，Closes `#4`)**：
  - 引入 `PrivacySessionPolicy`（`Standard` / `EphemeralReadOnly` / `StrictIsolated`），修复 `incognito: true` 泄露 `StateDb::list_active_memories()` 显式偏好的 P0 隐私缺陷，保证 Quick-Chat 与 Core L2 出网消息零偏好泄露、零会话/任务落盘。
  - 引入 `SensitiveDataGuard` 与 `UnifiedTaskStateMachine`，在 `state.db` 与 `memory_hub.db` SQLite 写入前统一完成密钥/口令/私钥正则脱敏（`[REDACTED_SECRET]`），经磁盘原始字节扫描验证零明文密钥残留。
- **认知型 L1 结构化目标识别 (`StructuredIntent`) 与复合意图子句完整性 (`intent_engine/{goal_schema,cognitive_parser,compound_splitter}.rs`、`decision.rs`、`router.rs`、`core.rs`，Closes `#5`)**：
  - 新增 `StructuredIntent` 与 `CognitiveIntentKind`（`DeterministicCommand`、`RelativeAdjustment`、`GoalWorkspace`、`SystemDiagnosis`、`ProceduralOrKnowledge`、`CompoundTask`），使「今天想专心写论文」「电脑最近有点卡」「每日天气穿衣+待办简报」等高层目标自动结构化升级至 L2 规划，并在 `turn_engine.rs` 注入紧凑认知目标提示块。
  - 修复 `split_compound_intent` 静默丢弃未解析子句缺陷：显式记录 `ClauseResolution` 与 `unresolved_clauses`，在线升级 L2 协同完成全部子句，离线诚实返回 `PartiallyCompleted` 并列出待办子目标；同时修复「查一下内网地址」「开启省电续航」「怎么批量查找日志」等路由盲区。
- **`v0.2-M1` 全量门禁验证**：
  - `cargo clippy --workspace --all-targets -- -D warnings`：**0 警告，0 错误**
  - `cargo test --workspace -- --test-threads=1`：**`142/142` 测试（含新增 `tests/e2e_v0_2_m1.rs` 5 项端到端验收套件）100% 通过**
  - 325 条基准评测准确率提升至 **`99.7%`（324/325）**，候选延迟 **P50 = `2.79 ms` / P95 = `5.92 ms`**，红队安全门禁 **`16/16` 全通过**。

---

### 里程碑 9：`v0.2-M1.1 全量底座加固与 v0.2-M2 动态能力发现、WorldState、受控终端及诊断/软件 Provider`（GitHub Milestone #2，Issues `#6`–`#9` 全量收官）
- **交付时间**：2026-11-15
- **`v0.2-M1.1` 十项底座可靠性、隐私、预算、性能与流式加固 (`H01`–`H10`，Commits `afd8c18`..`a862ba3`)**：
  - **并发回合隔离、语义幂等与持久化步骤 WAL (`H01`–`H03`，`afd8c18`, `7515373`, `a5ac6e7`)**：实现同 `session_id` 原子回合占用与请求级 `request_id` 幂等单飞；按 `CacheUntilStateChanged` / `AlwaysRefresh` / `IdempotentMutation` / `ExactlyOncePerStep` / `NeverReplay` 五类语义与 `state_epoch` 失效机制管理重放；新增 SQLite `turn_step_journal` 预写日志，对未决副作用标记 `RecoveryRequired` 并在重启后恢复，绝不盲目自动重跑。
  - **外部 CLI 真实沙箱隔离、三态隐私上下文与统一执行脊柱 (`H04`–`H06`，`85e7524`, `7fd5930`, `3b2b4e9`)**：实测探测 `codex` / `zcode` / `pi` CLI 能力并套入 `bubblewrap` 沙箱，通过 `stdin` 管道消除 `/proc/<pid>/cmdline` 提示词泄露，统一 `allow_broker_tools=false` 时的 `ExternalChatOnly` 硬阻断；将 `ExecutionContext`（`Standard` / `EphemeralReadOnly` / `StrictIsolated`）贯通全链路；收敛 Core L2 与 Quick-Chat 共用事务型 `CapabilityBroker` 分发器，修复 `pi-adapter` 崩溃回退 `native` 时的跨运行时重复副作用漏洞。
  - **五维全局预算、渐进式认知检索、版本化能力快照与真实 SSE 流式事件 (`H07`–`H10`，`0f46c11`, `9054506`, `31f2c38`, `a862ba3`)**：引入 `TaskBudgetTracker`（轮次/工具调用/耗时/审批暂停剔除/重试上限）；`H08` 对高确定性意图跳过 Fast LLM，仅在歧义时发送 Top-12 紧凑能力目录（`9,612 B -> 956 B`，**-90.05%**）；`H09` 引入 `CapabilitySnapshot` 预序列化缓存与 `CapabilitySearchIndex`，使 `build_quick_chat_openai_tools` 延迟从 `23.73 ms` 降至 **`0.29 ms`（提速 `83×`）**，`parse_structured_intent` 从 `23.22 ms` 降至 **`0.35 ms`（提速 `61×`）**；`H10` 建立单调递增序号 `AgentEvent` 流式总线、OpenAI/Anthropic 增量 SSE 解析器（含跨 chunk UTF-8 与密钥实时脱敏）及受限 TTL Warm Worker 复用池。
- **`v0.2-M2` 动态能力发现、环境状态理解、受控终端与诊断/软件语义能力 (`M2-A`–`M2-D`，Commits `ad5a8cb`..`8f17a02`，Closes `#6`, `#7`, `#8`, `#9`)**：
  - **`M2-A` 动态能力发现 6 元工具与渐进式 Schema 暴露 (`meta_tools.rs`、`capability_snapshot.rs`，`ad5a8cb`，Closes `#6`)**：新增 `capability.search`（P50 = `23.4 µs`）、`capability.describe`、`capability.invoke`（阻断递归元工具调用并完整穿过 `CapabilityBroker`）、`app.discover`、`resource.resolve`、`task.verify`；首轮仅暴露高置信度直接工具 + 6 个元工具，使 Quick-Chat 首轮 Schema 从 `15,672 B` 降至 **`3,474 B`（`-77.83%`）**，Core L2 首轮 Schema 从 `38,351 B` 降至 **`3,474 B`（`-90.94%`）**，并在回合中段动态解锁新发现能力。
  - **`M2-B` 统一 `ResourceResolver` 与隐私门控 `WorldState` (`world_state.rs`、`context_resolver.rs`，`9cdb9fb`, `8f17a02`，Closes `#7`)**：统一解析文件、目录、项目、应用、窗口、URL、日期对比实验结果（如「比较昨天与前天的实验结果」→ `MultipleComparative`），并在原生 Wayland 焦点不可见时诚实返回 `UnavailableOnWayland` 触发澄清询问（「把它关掉」绝不盲关后台窗口），`StrictIsolated` 下实现零项目/记忆泄露。
  - **`M2-C` `C0`–`C4` 受控终端 `CommandProposal` 分类器与 `bubblewrap` 沙箱执行器 (`terminal_agent.rs`、`crates/sandbox`、`973f452`，Closes `#8`)**：结构化 `CommandProposal` 强制非 Shell `Command::new(program).args(argv)` 执行，硬拦截 `bash -c` / `python3 -c` / 可执行符号链接伪装 / 数据符号链接越界 / `~/.ssh` 读取 / 未授权目录写入；`C0`/`C1` 在无外网 `bwrap` 沙箱内受限执行（独立进程组超时 `SIGKILL` + 64 KiB 截断 + `SensitiveDataGuard` 脱敏），`C3` 系统修改强制人工审批并诚实标记 `reversible: false`。
  - **`M2-D` Linux 统一诊断套件与 5 层多通道 `SoftwareCapabilityProvider` (`diagnostics.rs`、`app_adapter/provider.rs`，`0ae73e1`，Closes `#8`, `#9`)**：实现 `logs.query`、`dependency.inspect`（净环境 vs 当前环境双 `ldd` 精准定位缺失 `.so` 与 Conda `LD_LIBRARY_PATH` 冲突）、`service.status`、`package.inspect`、`network.diagnose`（真实网卡路由 + 本地代理端口活性探测 + FUSE/云盘挂载健康检查）、`system.bottleneck`、`repair.plan`、`repair.verify`；将桌面软件适配升级为 5 层严格优先级 `SoftwareCapabilityProvider`（`NativeApiOrDbus` → `CliOrHeadless` → `DirectDocumentFormat` → `GuiAtSpiSemantic` → `HonestGuidance`，含 `RequestedUnverified` 零盲目跨通道重放保证），打通 `.docx` 章节可逆编辑与字节级精确 `Undo`、多格式（`.pdf`/`.docx`/`.md`）文献综述编译、`git.inspect_repo` 及闭源软件诚实引导。
- **`v0.2-M2` 全量质量门禁与同机 `--release` 实测验收**：
  - `cargo fmt --all -- --check`：**0 差异**；`cargo clippy --workspace --all-targets -- -D warnings`：**0 警告**。
  - 无头净环境 `cargo test --workspace -- --test-threads=1`：**`226 / 226` 单元测试与端到端集成测试（含开放式论文研究工作区综合合成验收 `tests/e2e_v0_2_m2.rs`）100% 通过**。
  - 同机 `--release` `intentosctl eval`（325 条语料）：总体准确率 **`99.69%`（324/325）**，L0 覆盖率 **`100.0%`（284/284）**，候选延迟 **P50 = `2.84 ms` / P95 = `5.54 ms`**，`Undo` **`6/6`**，红队门禁 **`16/16` 全通过**；`intentosd` 静置内存 **`24.18 MiB`**（`<= 80 MiB`）、10s 静置 CPU **`0.00%`**；GTK4 设置中心与悬浮启动器 `--smoke-ui` 100% 通过。
