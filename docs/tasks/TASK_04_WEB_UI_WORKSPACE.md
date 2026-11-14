# 实现任务书四（Agent-4）：现代化模块化 Web Shell 与 Intent Workspace 前端 (`web_ui`)

> **角色定位**：IntentOS 桌面交互与前端视觉架构师（Agent-4）  
> **参考设计方案**：`docs/IntentOS_设计方案_v0.3.md` §3.1（UI-01 ~ UI-15、键盘约定与交互原型）、§3.2（状态机）、§3.4（Intent Workspace）、§5.6、§14.2（11 页设置中心）  
> **解决核心痛点**：彻底解决现有页面「丑陋单调、单文件 1300 行堆砌、操作不灵活、候选无分组、没有 `Alt+Enter` 动作菜单、没有多轮对话侧栏与动态声明式视图、设置界面只有几个简陋输入框」的问题。

---

## 1. 严格的文件读写边界（防冲突红线）

- ✅ **你唯一允许新建和修改的目录**：
  `crates/intentosd/src/web_ui/`
- ❌ **严禁修改任何其他目录或文件**：
  严禁修改 `crates/intentosd/src/web_shell.rs`、`crates/intentosd/src/web_shell.html`、`crates/intentosd/src/core.rs` 等外部文件！（主干 `web_shell.rs` 已自动配置为：当 `crates/intentosd/src/web_ui/assets/index.html` 存在时直接渲染该页面，并将 `/assets/{*path}` 映射到 `crates/intentosd/src/web_ui/assets/` 目录下）。

---

## 2. 模块内部文件规划（前端工程模块化拆分）

严禁再把所有代码塞进一个 HTML 文件！请按功能模块拆分为清晰的 HTML + CSS + ES Modules 结构：

```text
crates/intentosd/src/web_ui/
├── mod.rs                          # Rust 静态资源加载器与 web_ui 辅助 RPC（如 UI 状态快照、快捷工作区布局保存）
└── assets/
    ├── index.html                  # 主骨架 HTML（语义化布局：顶栏 Status Bar、Spotlight 浮层/工作区容器、动作菜单浮层、11页设置中心抽屉、30s 撤销 Toast）
    ├── styles/
    │   ├── design-tokens.css       # Ubuntu Yaru 现代配色 + 深浅色 + 毛玻璃（backdrop-filter）+ 动效曲线与字号缩放变量
    │   ├── launcher-spotlight.css  # Spotlight 浮层模式、分组候选列表、键盘快捷键角标、Alt+Enter 动作弹出菜单样式
    │   ├── workspace-surface.css   # Intent Workspace 双栏布局（左侧多轮会话流 + 右侧动态声明式结果面板 + 附件拖拽胶囊栏）
    │   └── settings-center.css     # 11 页设置中心（侧边导航栏 + 外发矩阵表格 + 模型角色卡片 + 进度条 + 审计筛选器）样式
    └── js/
        ├── main.js                 # 应用主入口，初始化各子模块与全局状态机（Hidden/Input/Routing/Running/Clarifying/Approval/Result/Undoing）
        ├── rpc-client.js           # 封装标准 RPC (`/api/rpc`) 与模块化 `module_rpc(domain, action, payload)` 调用
        ├── keyboard-engine.js      # 全键盘流控制器（Enter, Ctrl+Enter, Alt+Enter 动作菜单, Tab 分组切换/补全, ↑/↓ 导航与历史输入调出, Ctrl+C 复制, Ctrl+Z 撤销, Ctrl+, 设置）
        ├── candidate-view.js       # 分组即时候选渲染器（─ 最佳匹配 ─ / ─ 应用 ─ / ─ 文件 ─ / ─ 网站 ─ / ─ 系统设置 ─ / ─ 技能 ─）与 Alt+Enter 动作菜单
        ├── result-surfaces.js      # 可信声明式结果视图组件库（UI-14：文件列表卡片、Unified Diff 差异树、系统诊断仪表盘、任务步骤 DAG 进度条、PTY 终端面板）
        ├── workspace-panel.js      # 多轮会话流、上下文引用胶囊（拖拽文件、当前窗口/选区模拟引用、项目切换器）与快捷意图场景栏
        └── settings-11pages.js     # 完整 11 页设置中心渲染与交互逻辑（对接 `config_center` 与 `execution_hub`）
```

---

## 3. 核心视觉与交互设计要求

### 3.1 现代桌面级视觉美学 (`styles/*.css`)
1. **Ubuntu 26.04 Modern Glassmorphic 风格**：
   - 深色模式下采用深邃板岩蓝底色配半透明毛玻璃浮层（`backdrop-filter: blur(20px) saturate(160%)`）、细腻高光边框、Ubuntu 标志性暖橙/电光蓝双强调色与流畅微动效。
   - 顶栏（Top Bar，UI-09）实时展示：IntentOS 状态呼吸灯（`● 空闲` / `◌ 推理中` / `⚠ 待审批` / `🔒 隐私会话`）、当前路由层（`L0 <5ms` / `L1 Decision` / `L2 Agent`）、活跃项目徽章、一键切换「**浮层模式 (Spotlight)** ↔ **工作区模式 (Workspace)**」开关、快捷撤销按钮与「⚙ 11页设置中心」入口。

### 3.2 极致丝滑的全键盘流操作 (`keyboard-engine.js` & `candidate-view.js`，对标 §3.1)
1. **分组候选实时展示（UI-02）**：
   - 调用 `module_rpc("intent_engine", "query_grouped_candidates", ...)`（若后端未就绪则自动优雅兼容 `query_candidates` 并在前端按 `kind` 分组），按 `─ 最佳意图 ─`、`─ 应用 ─`、`─ 文件 ─`、`─ 网站与搜索 ─`、`─ 系统设置 ─`、`─ 命令与技能 ─` 分组展示，并在顶栏配有分类过滤胶囊（`全部` / `应用` / `文件` / `网站` / `设置`）。
2. **`Alt+Enter` 候选/结果动作菜单（UI-06）**：
   - 在任意候选或结果项上按 `Alt+Enter`（或点击右侧 `⋯ 动作` 按钮），弹出精致的上下文动作菜单：
     - 文件：`打开` / `用指定应用打开` / `打开所在文件夹` / `复制完整路径` / `重命名` / `移入回收站`
     - 应用：`启动或聚焦` / `新窗口启动` / `优雅退出`
     - 网站：`默认浏览器打开` / `复制链接` / `站内搜索`
     - 设置：`立即执行` / `恢复默认值` / `在系统控制中心打开`
3. **完整键盘快捷键矩阵**：
   - `Enter`：执行当前高亮候选
   - `Ctrl+Enter`：忽略 L0 候选，强制作为复杂意图交给 L1/L2 智能体
   - `Alt+Enter`：打开/关闭当前选中候选的上下文动作菜单
   - `Tab` / `Shift+Tab`：补全当前候选名称，或在候选分组标签间快速切换
   - `↑ / ↓`：上下移动候选；**当输入框为空时按 `↑` 自动调出上一条输入记录**
   - `Ctrl+C`（当焦点在候选列表上且未选中文本时）：一键复制选中文件的路径或网站的 URL 并弹出 Toast 提示
   - `Ctrl+Z`：一键撤销最近一次变更，并在每次可逆操作完成后底部弹出 **30 秒倒计时「↶ 撤销刚才的修改」浮动通知条（UI-08）**

### 3.3 Intent Workspace 意图工作区与声明式动态结果视图 (`workspace-panel.js` & `result-surfaces.js`，对标 §3.4 & UI-11~UI-14)
1. **多轮对话与上下文胶囊栏（UI-10, UI-13）**：
   - 支持新建会话、清空会话、隐私会话切换。
   - 输入框上方或下方支持添加「上下文附件胶囊」（支持拖入文件/输入文件路径引用、附加当前项目上下文、附加剪贴板/选区文本）。
2. **5 类可信声明式动态结果组件（UI-11, UI-12, UI-14）**：
   - **组件 1：文件与资源列表视图 (`ResourceListView`)**：表格/卡片切换，每行直接带「打开」「定位目录」「复制路径」「回收站」快捷按钮。
   - **组件 2：审批与文件树差异视图 (`ApprovalDiffCard`，UI-07)**：高亮展示前 → 后变更对比（绿色新增、红色删除、设置前后值对比），可展开查看原始命令/参数，提供「拒绝」「允许本次」「允许本任务（创建授权包络）」三按钮。
   - **组件 3：系统诊断仪表盘卡片 (`DiagnosticCard`)**：当执行磁盘、内存、端口、进程、IP、电池查询时，渲染带可视化进度条/徽章的结构化卡片，而非枯燥纯文本。
   - **组件 4：终端直通与命令交接面板 (`TerminalOutputPanel`，UI-11)**：等宽字体深色终端风格，显示 `cwd`、退出码、一键复制输出、「在系统终端中继续」按钮，以及「将此报错交给 L2 诊断」按钮。
   - **组件 5：多步任务与工作流进度视图 (`TaskStepsView`，UI-12)**：清晰展示每个 Step 的耗时、能力 ID、验证状态徽章（`✓ 已验证` / `↗ 已发出请求` / `✗ 验证失败`）及关联的 `changeset_id`。

### 3.4 11 页全要素可视化设置中心 (`settings-11pages.js`，对标 §5.6 & §14.2)
点击「⚙ 设置中心」（或按 `Ctrl+,`）打开左侧 11 栏导航的完整设置中心，对接 `config_center` 与 `execution_hub` 的 `module_rpc`：
1. **📊 1. 概览**：核心服务状态、Uptime、87+ 能力与沙箱探测状态、CLI 依赖健康度矩阵。
2. **🧠 2. 大脑与网关**：
   - **供应商管理列表**：新增/编辑/删除供应商、设置 API Key、点击「测试连接 (B-03)」与「测试工具调用 (B-04)」实时显示延迟与结果徽章；
   - **5 大模型角色配置卡**（`Main` / `Fast` / `Decision` / `Vision` / `Memory`）：配置模型 ID、上下文预算滑块、最大输出 Token、思考强度（`off/low/medium/high`）、温度；
   - **外发安全矩阵表（§5.4）**：可视化配置 `Public / Personal / Sensitive / Forbidden` × `Trusted / Standard / Untrusted` 的允许/确认/拒绝策略，以及敏感目录管理；
   - **运行时与预算限制**：单任务最大工具调用数、超时秒数、并发会话数、每日预算上限、故障切换开关。
3. **💡 3. 记忆与候选**：个人偏好记忆 CRUD、项目记忆筛选、待确认记忆候选队列（一键确认/忽略）。
4. **🧩 4. 技能与工作流**：内置与用户技能/工作流列表、从历史任务一键提炼保存为新工作流、一键运行工作流。
5. **🛠 5. 能力与模块**：按分类浏览/搜索全部 87+ 项系统能力、查看输入 Schema 与效应等级（R0–R3）、组合场景模式管理。
6. **📁 6. 资源与项目**：授权目录增删改、已自动发现的 Git 项目列表、手动重建索引。
7. **🌐 7. 网站与搜索**：默认搜索引擎与自定义引擎 CRUD、网站别名与站内搜索模板 CRUD、书签与历史授权开关。
8. **🛡 8. 权限与安全**：当前活动授权包络（`GrantEnvelope`）、渐进信任长期规则确认与撤销、脱敏安全审计日志查询。
9. **↶ 9. 撤销与备份**：备份区配额（4 GB / 30 天）设置与用量进度条、可撤销变更集时间轴与一键还原。
10. **⚡ 10. 自动化与驱动**：全局自主性等级（L0/L1/L2）切换、定时与文件事件触发规则管理及模拟测试按钮。
11. **⌨ 11. 交互与维护**：全局热键配置与冲突检测器、默认视图模式、UI 缩放滑块、开发者调试转录开关（7天自动清理）、无密钥配置一键导出/导入。

---

## 4. 验收与自测标准

1. 确保 `crates/intentosd/src/web_ui/assets/index.html` 及所有引用的 `/assets/styles/*.css`、`/assets/js/*.js` 路径准确无误，无任何外部 CDN 依赖（100% 离线可用）。
2. 在 `crates/intentosd/src/web_ui/mod.rs` 中编写单元测试，验证 `render_index_html` 和所有静态资源文件（CSS/JS）均可成功读取且 MIME 类型正确。
3. 运行 `cargo test -p intentosd web_ui` 与 `cargo clippy -p intentosd -- -D warnings` 必须 100% 通过且零警告。
