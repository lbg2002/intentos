# ✦ IntentOS — 面向 Ubuntu 桌面的高可信意图原生 AIOS 壳层

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2022.04%20%7C%2024.04%20%7C%2026.04-E95420)](https://ubuntu.com/)
[![Rust](https://img.shields.io/badge/Rust-unsafe__forbid-orange.svg)](Cargo.toml)

**IntentOS** 是一个运行在 Ubuntu / GNOME 桌面之上的开源 **AI 操作系统智能壳层（AIOS Shell & Safe Execution Core）**。

它的交互灵感源自极简随问窗 [gnome-quick-chat](https://github.com/lbg2002/gnome-quick-chat) —— **桌面上只有一个轻盈、可自由拖拽置顶的悬浮对话框**，没有繁杂臃肿的后台网页感；但在极简对话框之下，内置了完整的 **个人数据与文档章节记忆层**、**无 CLI 个性化软件自动嗅探与接口转译层**、**四级敏感路径交互审批与一键回滚引擎**、**非线性时间衰减长会话压缩** 以及 **本地离线语音识别（ASR）中心**。

> 欢迎大家下载体验、提 Issue 反馈 Bug 或分享你希望适配的 Linux 桌面软件与新想法！

---

## ✨ 核心特性

### 1. 极简桌面悬浮随问窗（多端统一体验）
- **单悬浮窗设计**：支持 **GTK4 原生桌面悬浮窗**（X11 / Wayland 即开即用）、**GNOME Shell 46–49 顶栏扩展** 与 **本地离线 Web UI**（`127.0.0.1:8787`）。
- **实时模型自动探测**：自动发现本机 `ZCode`、`Codex`、`Pi`、OpenAI 兼容接口与 Anthropic `/v1/messages` 接口，实时拉取 `/v1/models` 全量可用模型列表，支持关键词搜索切换与推理强度调节。
- **诚实可观测轨迹点 (`●`)**：紫色（记忆召回）、青色（软件转译层）、绿色（已验证执行完成 + 一键 `↶ 撤销`）、天蓝色（已发请求待桌面响应）、琥珀色（敏感权限待审批）。

### 2. 本机全量软件深度扫描与 9 大类通用接口转译层 (`app_adapter`)
Linux 上大量第三方/国产桌面软件没有命令行参数或标准接口。IntentOS 自动扫描系统 `/usr/share/applications`、Snap、Flatpak、`~/.local/share/applications` 及伴生命令行，将软件归入 **9 大分类** 并通过多通道自动转译控制：
- **托盘协议实时自省 (`StatusNotifierItem` + `com.canonical.dbusmenu`)**：即使软件没有实现 `MPRIS2`（例如 **汽水音乐 SodaM**、**WPS 云盘**、**FlClash**、**QQ**、**微信**、**飞书**、**百度网盘**、**移动云盘**），也能自动嗅探其实时状态（如正在播放曲目）并点按托盘菜单（`显示主窗口`、`暂停`、`下一首`、`退出` 等），执行后自动读回校验。
- **丰富深度转译能力（内置 70+ 软件画像 + 通用 `.desktop` 自动合成）**：
  - 🎵 **影音娱乐**：汽水音乐、QQ音乐、VLC、Spotify 等播放控制与主窗口唤醒
  - 💬 **社交通讯与会议**：腾讯会议 `wemeet://` 房间号一键入会、飞书、QQ、微信聚焦与唤醒
  - 📄 **办公文档与笔记**：WPS 全家桶、永中 Office、LibreOffice 无头一键转 PDF、Evince/Papers 指定页码跳转与词条搜索、Typora、轻笺 `BetterNotes`
  - ☁ **云盘与局域网互传**：LocalSend 局域网发文件、百度网盘/移动云盘唤醒
  - 🌐 **网络代理与浏览器**：FlClash 代理端口探测与托盘切换、Tailscale 状态、Chrome/Brave 无痕与 App 模式
  - 💻 **开发与创意工具**：VS Code / ZCode / Trae CN 跳转 `文件:行号` 与双文件 `Diff`、`draw.io` 无头导出 PDF/PNG/SVG、VirtualBox 虚拟机管控、RustDesk 远控、Fcitx5 中英切换、NVIDIA GPU 实时遥测
- **零 JSON 个性化口令绑定**：在设置中心第 5 页可一键扫描本机软件能力，将任意托盘动作、URI 或快捷键绑定为你习惯的自然语言口令。

### 3. 个人文件记忆、文档章节大纲与非线性时间衰减压缩 (`memory_hub`)
- **跨会话个人记忆**：记住你之前对话提过的文件、解析 `~/.local/share/recently-used.xbel` 统计长期高频文件与常用软件，支持 `@` 快速引用；按意图精准按需注入（`<= 950` 字符预算），纯打开软件等无关指令零噪音。
- **文档章节大纲召回**：自动索引常用目录中的 `.docx`、`.md`、`.pdf`、`.txt` 章节标题树（如直接说 *「打开我的论文第四章」* 自动定位对应 `.docx` 与章节摘要）。
- **非线性时间衰减上下文压缩**：
  - 自动剥离历史回合中的工具调用记录（`tool_calls` / `role: tool`）与 `<think>` 思考块，**仅保留用户提问与 AI 回答**；
  - 越近的对话保留越完整，越早的对话按指数时间衰减浓缩摘要，超远期自动滚动归并，长会话永不撑爆模型上下文。

### 4. 可信四级路径边界、内联审批续接会话与可逆撤销 (`policy` & `fsops`)
- 基于 Linux `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` 内核级防符号链接逃逸，全核心 `#![forbid(unsafe_code)]`。
- **四级权限边界**：
  - **禁区（永不放行）**：`~/.ssh`、`~/.gnupg`、`/etc/shadow`、私钥凭据等硬性拦截；
  - **常规用户空间**：自动识别中英文 XDG 目录（`桌面/文档/下载` 等），读取/打开丝滑免打扰；
  - **敏感点目录与外部路径**（如 `~/.config`、`/home`、`/opt`）及 AI 发起的修改：自动弹出内联审批卡片（**`✓ 批准本次`** / **`⏱ 本会话放行此范围`** / **`✕ 拒绝`**），点击批准后**自动将工具真实结果回填大模型继续推理并写入当前会话**；
  - **可逆变更集 (`ChangeSet`)**：文件移动/重命名/回收站与系统设置修改均自动建立快照，支持一键 `↶ 撤销`。

### 5. 本地离线语音识别中心 (`speech_hub`)
- 在 **11 页设置中心 → 第 1 页** 内置离线 ONNX 语音识别模型下载器與总开关：
  - 支持一键下载 **阿里 FunASR `sensevoice-small-int8`**（ModelScope 国内高速直连，中英粤日韩极速识别）及 **OpenAI `whisper-tiny-q8` / `whisper-base-q8` / `whisper-small-q8`**；
  - 开启后悬浮窗输入框旁出现 **`🎙`** 麦克风按钮，点击录音、再点本地离线转写填入或自动发送。

---

## 🏗 架构概览

```text
intentos/
├── crates/
│   ├── intentosd/           # 核心守护进程 (Router + Broker + Policy + Gateway)
│   │   └── src/
│   │       ├── backend_bridge/  # 多引擎大模型桥接 (/v1/models 实时发现 + 审批断点续接)
│   │       ├── memory_hub/      # 个人记忆、文档章节大纲索引 & 非线性时间衰减上下文压缩
│   │       ├── app_adapter/     # 本机软件 9 大类深扫 + SNI/DBusMenu/MPRIS2/AT-SPI2 转译层
│   │       ├── speech_hub/      # 离线 ONNX 语音模型下载管理 + PipeWire/ALSA 录音转写
│   │       ├── config_center/   # 11 大配置域持久化与校验
│   │       ├── execution_hub/   # 会话授权信封、E2 暂存预演与工作流
│   │       └── web_ui/          # 100% 本地离线内嵌前端资源
│   ├── intentosctl/         # 命令行客户端、TUI 启动器与安全评测门禁
│   ├── fsops/               # openat2 防逃逸文件系统引擎与可逆备份还原
│   ├── sandbox/             # bwrap 无外网沙箱执行器
│   ├── capability-sdk/      # 能力模块 SDK
│   └── protocol/            # IPC / D-Bus 强类型协议定义
├── desktop/
│   ├── gtk-fallback/        # GTK4 桌面原生悬浮随问窗 (intentos-launcher.py)
│   ├── settings/            # GTK4 11 页可视化设置中心 (intentos-settings.py)
│   └── gnome-extension/     # GNOME Shell 46-49 原生桌面扩展
├── modules/builtin/         # 95+ 单源 YAML 系统能力声明描述
└── scripts/                 # 一键安装、本地运行与离线 ONNX 语音推理脚本
```

---

## 🚀 快速安装与启动（Ubuntu 22.04 / 24.04 / 26.04）

### 1. 安装系统基础依赖

```bash
sudo apt update
sudo apt install -y \
  build-essential pkg-config libssl-dev libsqlite3-dev \
  python3 python3-gi gir1.2-gtk-4.0 gir1.2-wnck-3.0 gir1.2-atspi-2.0 \
  libglib2.0-bin pipewire-bin ripgrep
```

*(如需启用本地离线语音识别推理，推荐在 Python 环境中安装 `pip install onnxruntime numpy`；如未安装 Rust 工具链，可通过 `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` 安装。)*

### 2. 克隆仓库并一键启动体验

```bash
git clone https://github.com/lbg2002/intentos.git
cd intentos

# 方式 A：免安装直接编译并启动守护进程 + 桌面悬浮窗
./scripts/run-local.sh --launcher
```

或者分终端独立运行守护进程、悬浮随问窗与 11 页设置中心：

```bash
# 终端 1：编译并启动后端守护进程
cargo build --release
./target/release/intentosd --web-listen 127.0.0.1:8787

# 终端 2：启动 GTK4 桌面悬浮随问窗
/usr/bin/python3 ./desktop/gtk-fallback/intentos-launcher.py

# （可选）打开 11 页可视化设置中心（配置模型 API / 下载语音识别模型 / 扫描本机软件）
/usr/bin/python3 ./desktop/settings/intentos-settings.py
```

### 3. 用户态安装到系统菜单与开机自启（可选，无需 root）

```bash
./scripts/install-ubuntu.sh
# 安装后可直接从系统应用菜单打开「IntentOS 随问」与「IntentOS 设置」，或命令行运行：
~/.local/bin/intentos-launcher
~/.local/bin/intentos-settings
```

---

## 🧪 运行测试与门禁检查

```bash
# 全仓零警告静态检查与 115 项单元/端到端集成测试
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1

# 桌面悬浮窗与 11 页设置中心 UI 冒烟自检
/usr/bin/python3 ./desktop/settings/intentos-settings.py --smoke-ui
/usr/bin/python3 ./desktop/gtk-fallback/intentos-launcher.py --smoke-ui
```

---

## 💬 参与共建与意见反馈

IntentOS 目前处于快速迭代演进阶段，非常欢迎任何使用反馈与建议！
- **遇到软件无法控制或转译不理想？** 欢迎提交 [Issue](https://github.com/lbg2002/intentos/issues)，附上软件名称与 `.desktop` 信息（或在悬浮窗点击 `🧠 → ⚡ 探测接口` 贴出探测结果），我们会持续扩充内置转译画像。
- **有新的 AIOS 交互点子或安全改进建议？** 欢迎直接发 Issue 讨论或提交 Pull Request！

## 📄 开源协议

本项目基于 [MIT License](LICENSE) 开源。
