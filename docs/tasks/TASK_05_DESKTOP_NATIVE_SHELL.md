# 实现任务书五（Agent-5）：Ubuntu 原生桌面壳层（GNOME 扩展 + GTK4 启动器 + GTK4 11页设置中心）(`desktop/`)

> **角色定位**：Ubuntu Desktop / GNOME Shell (GJS) 与 GTK4/libadwaita 原生客户端架构师（Agent-5）  
> **参考设计方案**：`docs/IntentOS_设计方案_v0.3.md` §3.1–§3.3、§5.6、§14.1–§14.2、§15.3  
> **解决核心痛点**：解决现有原生桌面组件（`desktop/gnome-extension/`、`desktop/gtk-fallback/intentos-launcher.py`、`desktop/settings/intentos-settings.py`）界面粗糙、缺少候选分组与 `Alt+Enter` 动作菜单、缺少 30 秒撤销通知条、设置中心只有简陋 4 页且配置项极少的问题。

---

## 1. 严格的文件读写边界（防冲突红线）

- ✅ **你唯一允许新建和修改的目录**：
  - `desktop/gnome-extension/`
  - `desktop/gtk-fallback/`
  - `desktop/settings/`
- ❌ **严禁修改任何其他目录或文件**：
  严禁修改 `crates/` 下的任何 Rust 代码文件！所有后端交互均通过现有的 `${XDG_RUNTIME_DIR}/intentos/ui.sock` JSON-RPC 通道（支持原有方法及新增的 `method: "module_rpc"`）完成。

---

## 2. 模块内部文件规划

```text
desktop/
├── gnome-extension/
│   ├── metadata.json           # GNOME 46–49 兼容元数据与快捷键 schema
│   ├── extension.js            # 升级版 GNOME Shell 扩展（分组候选、Alt+Enter 动作菜单、顶栏状态呼吸指示器、30s 撤销横幅、命令交接与审批卡片）
│   └── stylesheet.css          # 现代化毛玻璃深浅色自适应样式表（圆角浮层、分组标题、风险徽章 R0-R3、差异高亮）
├── gtk-fallback/
│   ├── org.intentos.Launcher.desktop
│   ├── intentos-launcher.py    # 升级版 GTK4 原生浮层启动器（支持 Spotlight 紧凑模式 + 对话抽屉展开模式、分组候选、Alt+Enter 动作菜单、空输入 ↑ 调出历史、拖拽文件引用）
│   └── launcher_style.css      # GTK4 CSS 样式表（Ubuntu Yaru 风格美化）
└── settings/
    ├── org.intentos.Settings.desktop
    └── intentos-settings.py    # 升级版 GTK4/libadwaita 11 页全要素原生设置中心（对接 config_center / execution_hub RPC）
```

---

## 3. 核心功能实现要求

### 3.1 GNOME Shell 扩展升级 (`desktop/gnome-extension/`)
1. **视觉与样式升级 (`stylesheet.css`)**：
   - 采用现代圆角毛玻璃浮层设计，区分候选分组标题（`应用` / `文件` / `网站` / `系统设置` / `命令`）、快捷键提示角标（`Enter` / `Alt+Enter` / `Ctrl+Enter` / `Ctrl+Z`）与风险等级颜色徽章（`R0` 绿、`R1` 蓝、`R2` 橙、`R3` 红）。
2. **交互升级 (`extension.js`)**：
   - **分组候选与 `Tab` 切换**：调用 `module_rpc("intent_engine", "query_grouped_candidates")`（若返回未分组则自动兼容 `query_candidates`），支持 `Tab` 键在分组间切换或补全输入。
   - **`Alt+Enter` 动作菜单（UI-06）**：在选中候选上按 `Alt+Enter`，展开内联动作子菜单（如文件的「打开」「打开所在文件夹」「复制路径」「移入回收站」）。
   - **空输入框按 `↑` 调出历史输入**：记录本会话最近输入列表，空输入按 `↑` 快速回填。
   - **顶栏状态呼吸指示器（UI-09）**：显示当前状态（`● 空闲` / `◌ 运行中` / `⚠ 待审批` / `🔒 隐私模式`），菜单中支持一键打开 `intentos-settings` 设置中心、切换隐私会话、一键撤销、紧急停止全部任务。

### 3.2 GTK4 原生降级启动器升级 (`desktop/gtk-fallback/intentos-launcher.py`)
1. **引入自定义 GTK4 `CssProvider` (`launcher_style.css`)**：
   - 彻底告别默认灰扑扑的原生控件堆砌，提供高颜值输入框、分组候选行、徽章胶囊、等宽代码输出框和审批差异卡片。
2. **全键盘流与动作菜单**：
   - 完整支持：`Enter`（执行首选）、`Ctrl+Enter`（强制 L2 智能体）、`Alt+Enter`（弹出选中候选的动作列表，如打开所在目录、复制路径、用指定应用打开）、`Ctrl+C`（复制选中结果路径/链接）、`Ctrl+Z`（一键撤销）、` ↑`（空输入调出上一条指令）。
   - 支持点击顶栏「⚙ 设置」按钮直接拉起 `intentos-settings.py`，点击「展开工作区」显示最近任务、组合场景快捷按钮与变更集历史。
3. **命令行自检模式保持兼容**：
   - 保留 `--smoke-rpc` 参数，确保自动化冒烟测试与门禁脚本正常工作。

### 3.3 GTK4 11 页全要素设置中心 (`desktop/settings/intentos-settings.py`，对标 §14.2)
将原有的简陋 4 页 Notebook 升级为左侧 `Gtk.StackSidebar` + 右侧 `Gtk.Stack` 的 **11 页现代桌面设置中心**（兼容调用 `module_rpc("config_center", ...)` 与原有 `get_settings_overview` RPC）：
1. **1. 概览 (Overview)**：守护进程 PID、Uptime、索引统计、沙箱与系统后端探测状态、一键刷新索引。
2. **2. 大脑 (Brain & Gateway)**：
   - 供应商管理（添加/编辑供应商 ID、类型、Base URL、信任等级 `Trusted/Standard/Untrusted`、API Key 凭据录入、**「测试连接」与「测试工具调用」按钮**）；
   - 5 大模型角色（Main / Fast / Decision / Vision / Memory）模型名、上下文预算、思考强度与温度设置；
   - 外发矩阵（`DataClass × ProviderTrust`）可视化开关表；
   - 运行时限制（最大工具调用次数、超时秒数、并发会话数、每日预算）。
3. **3. 记忆 (Memories)**：显式偏好记忆列表、新增偏好、删除并写入墓碑（M-03）、待确认记忆候选列表。
4. **4. 技能与工作流 (Skills & Workflows)**：已加载技能与工作流列表、从最近任务提炼保存工作流。
5. **5. 能力与场景 (Capabilities & Scenes)**：组合场景模式（护眼/演示/安静/会议/专注 + 保存当前设置为自定义场景）、87+ 项系统能力浏览器。
6. **6. 资源与项目 (Resources & Projects)**：授权目录列表编辑、已发现的 Git 项目列表、重建索引。
7. **7. 网站与搜索 (Web & Search)**：默认搜索引擎切换、自定义站点别名与站内搜索模板添加/删除、默认浏览器与书签授权开关。
8. **8. 权限与安全 (Permissions & Trust)**：活动授权包络（GrantEnvelope）、渐进信任规则确认/撤销、安全审计日志查看器。
9. **9. 撤销与备份 (Undo & Backup)**：备份配额（GB）与保留天数设置、当前备份占用、可撤销变更集列表与一键撤销按钮。
10. **10. 自动化 (Automation)**：全局自主性等级（L0 手动 / L1 建议 / L2 授权自动）、文件事件与定时触发规则管理。
11. **11. 交互与维护 (Interaction & Maintenance)**：全局唤起热键配置与冲突检测（检测 `<Super>space` 输入法冲突）、开发者调试转录开关、无密钥配置一键导出/导入。
- 保留 `--dump-json` 命令行参数以兼容自动化测试。

---

## 4. 验收与自测标准

1. Python 脚本必须通过 `python3 -m py_compile desktop/gtk-fallback/intentos-launcher.py desktop/settings/intentos-settings.py` 语法与字节码编译检查。
2. GNOME 扩展 `desktop/gnome-extension/extension.js` 语法规范，严格使用异步 `Gio.SocketClient` 流，绝不阻塞 GNOME Shell 主线程。
3. 支持在无图形显示器（Headless）环境下通过 `--smoke-rpc` 和 `--dump-json` 正常执行 RPC 自检。
