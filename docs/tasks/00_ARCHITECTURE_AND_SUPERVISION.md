# IntentOS v0.3 功能模块化重构与多智能体并行开发统筹规范

> **统筹架构师（Coordinator）制定**  
> 依据标准：`docs/IntentOS_设计方案_v0.3.md`  
> 目标：彻底解决现有版本「意图理解呆板（太笨）」「界面简陋不美观」「交互不灵活」「配置要素匮乏」四大痛点，采用**零冲突的功能模块化目录隔离设计**，支持 **5 个智能体（Agent-1 ~ Agent-5）同时并行编码**。

---

## 1. 现状诊断与核心差距分析

| 痛点维度 | 现有实现 (`v0.1.0`) 的问题 | `v0.3` 模块化升级目标 |
|---|---|---|
| **1. 太笨了（路由死板、能力割裂）** | `router.rs` 单文件 2500+ 行硬编码正则，稍微换种口语表达或复合句就失效；`decision.rs` 的槽位填充仅硬编码了 6 个能力；缺乏多轮指代（当前窗口、剪贴板、刚生成产物）与复合意图拆解；无 E2 沙箱暂存执行与项目级记忆/技能学习。 | 建立 **`intent_engine`** 与 **`execution_hub`** 两大模块：基于 Capability Descriptor 的 `l0_patterns` 动态模板引擎 + 拼音/同义词/编辑距离柔性匹配 + 通用 Schema 槽位提取器 + 复合意图自动拆解 + 异步 L1 决策校准 + E2 沙箱暂存差异提交 + GrantEnvelope 包络审批 + 项目记忆与技能工作流学习。 |
| **2. 页面不好看（单文件堆砌、视觉粗糙）** | `web_shell.html` 1300+ 行单文件内联样式，缺乏层次感与现代桌面质感；无流式对话抽屉、无动态声明式结果组件（文件树 Diff、诊断仪表盘、任务 DAG 进度、终端 PTY 面板）。 | 建立 **`web_ui`** 与 **`desktop`** 模块：采用 Ubuntu Yaru + Glassmorphism（毛玻璃拟态）设计系统，支持 **Spotlight 极简浮层模式** 与 **Intent Workspace 意图工作区模式** 一键切换，按功能拆分为独立的 HTML/CSS/ES Module 组件。 |
| **3. 操作不灵活（缺乏键盘流与上下文动作）** | 候选列表扁平无分组；缺少 §3.1 规定的 `Alt+Enter` 候选/结果上下文动作菜单（打开 / 用…打开 / 打开所在文件夹 / 复制路径 / 移动 / 回收站）；缺少 `Tab` 分组切换与补全、空输入 `↑` 调出历史、拖拽附件与选区引用卡片。 | 全量实现 §3.1 键盘优先（Keyboard-First）交互规范：分组候选（应用/文件/网站/设置/技能/命令）、`Alt+Enter` 动作菜单、`Tab` 补全与分组切换、`Ctrl+C` 快捷复制路径、30 秒浮动撤销横幅、拖拽文件/选区上下文胶囊。 |
| **4. 配置要素太少（仅 3 个输入框）** | 设置中心仅有「运行时 + 主模型名 + 授权目录 + 默认搜索引擎」4 项最简表单，缺失 §5 与 §14.2 设计的绝大部分核心配置要素。 | 建立 **`config_center`** 模块，完整落地 §5.1–§5.6 与 §14.2 的 **11 大配置域**：多供应商 CRUD、连接测试（B-03）与工具调用测试（B-04）、5 大模型角色（Main/Fast/Decision/Vision/Memory）及推理参数（B-06）、外发矩阵（`DataClass × ProviderTrust`，B-10）、预算与故障切换（B-07/B-08）、站点别名与站内搜索模板 CRUD、书签/历史授权开关、授权包络与渐进信任规则、备份配额与过期清理、自动化触发器、快捷键冲突检测、开发者调试转录（7天自动清理）与无密钥配置导入导出。 |

---

## 2. 功能模块化架构与多智能体零冲突文件边界

为确保 **5 个智能体在同一代码库中同时写代码互不覆盖、互不锁死编译**，主干已预先在 `crates/protocol/src/lib.rs`、`crates/intentosd/src/lib.rs`、`crates/intentosd/src/core.rs` 和 `crates/intentosd/src/web_shell.rs` 中打通了**模块化插件总线（`UiRpcRequest::ModuleRpc { domain, action, payload }`）**与静态资源路由（`/assets/{*path}`）。

### 2.1 五大并行任务书与专属目录归属表

| 智能体编号 | 任务书文件 | 负责的功能模块 | **允许新建/修改的专属目录（独占写权限）** | **严禁修改的文件（由统筹者统一维护）** |
|---|---|---|---|---|
| **Agent-1** | `docs/tasks/TASK_01_INTENT_ENGINE.md` | **柔性意图引擎与智能路由模块**（动态语法、模糊/拼音/同义词匹配、通用 Schema 槽位解析、多轮指代消歧、候选分组与动作菜单生成、复合意图拆解） | `crates/intentosd/src/intent_engine/**` | `Cargo.toml`, `crates/protocol/**`, `crates/intentosd/src/{lib,core,main,db,router,decision}.rs` |
| **Agent-2** | `docs/tasks/TASK_02_CONFIG_CENTER.md` | **全要素配置中心与大脑网关管理模块**（11 大配置域 Schema、多供应商 CRUD、连接与工具实测、5 大模型角色、外发矩阵、站点/搜索模板 CRUD、无密钥导入导出） | `crates/intentosd/src/config_center/**` | `Cargo.toml`, `crates/protocol/**`, `crates/intentosd/src/{lib,core,main,db,config,gateway}.rs` |
| **Agent-3** | `docs/tasks/TASK_03_EXECUTION_HUB.md` | **E2 沙箱暂存、授权包络、项目记忆与驱动引擎模块**（E2 沙箱暂存差异计算与提交、GrantEnvelope 包络审批与渐进信任、Git 项目发现与项目记忆、Skill/Workflow 学习、定时与事件触发器） | `crates/intentosd/src/execution_hub/**` | `Cargo.toml`, `crates/protocol/**`, `crates/intentosd/src/{lib,core,main,db,broker,policy,runtime}.rs` |
| **Agent-4** | `docs/tasks/TASK_04_WEB_UI_WORKSPACE.md` | **现代化模块化 Web Shell 与 Intent Workspace 前端**（Spotlight 浮层 + Workspace 双模式、分组候选、`Alt+Enter` 动作菜单、声明式动态视图组件、11 页全要素可视化设置中心） | `crates/intentosd/src/web_ui/**` | `crates/intentosd/src/web_shell.rs`, `crates/intentosd/src/web_shell.html`（保留作为回退） |
| **Agent-5** | `docs/tasks/TASK_05_DESKTOP_NATIVE_SHELL.md` | **Ubuntu 原生桌面壳层与 GTK4/libadwaita 11 页设置中心**（GNOME 扩展美化与动作菜单、GTK4 浮层启动器升级、GTK4 11 页全要素设置中心、快捷键冲突检测） | `desktop/gnome-extension/**`, `desktop/gtk-fallback/**`, `desktop/settings/**` | `crates/**` 下所有 Rust 文件 |

---

## 3. 模块化总线通信契约（`ModuleRpc` 统一规范）

前端（`web_ui` / `desktop`）及核心组件通过统一 JSON-RPC 调用各功能模块：

### 请求格式（经 `/api/rpc` 或 `${XDG_RUNTIME_DIR}/intentos/ui.sock`）
```json
{
  "id": "req_01",
  "method": "module_rpc",
  "params": {
    "domain": "intent_engine | config_center | execution_hub | web_ui",
    "action": "<具体动作名>",
    "payload": { ... }
  }
}
```

### 响应格式
```json
{
  "id": "req_01",
  "ok": true,
  "result": { ... },
  "error": null
}
```

---

## 4. 统筹监督与合入验收流程（Coordinator 职责）

1. **阶段一（并行开发）**：用户将 `TASK_01` ~ `TASK_05` 分别发给 5 个智能体同时执行。各智能体仅在各自独占目录内编写模块化代码与单元测试。
2. **阶段二（编译与单测门禁）**：每个智能体完成任务后，统筹者检查：
   - `#![forbid(unsafe_code)]` 合规性；
   - `cargo clippy --workspace --all-targets -- -D warnings` 零警告；
   - 各模块单元测试与 `module_rpc` 接口契约一致性。
3. **阶段三（主干深度集成与端到端联调）**：统筹者在 `core.rs` 中将 `intent_engine`、`config_center`、`execution_hub` 与主干 `submit_intent` 流水线深度串联，执行全量基准评测与红队安全回归测试。
