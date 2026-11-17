# IntentOS 软件兼容、系统操控与 Bash 执行架构

2026-11-17，按用户最新目标调整。本文成为产品主线；个人记忆、工作区和主动任务降为支撑能力。沿用统一 Broker、Policy、账本和 ChangeSet。本轮包含代码增量，不代表下述所有规划已经交付。

## 1. 产品目标

用户通过自然语言或命令操控 Ubuntu：打开和控制软件、管理文件、调整系统设置、观察进程/服务/网络/磁盘，必要时执行经审批的 Bash 脚本。优先提升兼容动作的实际成功率及失败可恢复性。

首要场景：软件启动/聚焦/退出与文档打开；音量/显示/通知/输入/网络；文件搜索/复制/移动/归档；进程、服务和依赖诊断；批准后的安装、配置与修复。各能力必须区分已验证、已发送未验证、部分完成、不可用。

## 2. 三类命令通路

| 通路 | 适用内容 | 执行与审批 |
| --- | --- | --- |
| 已注册系统/软件动作 | 音量、窗口、文件移动、播放控制等 | 优先使用语义能力，经 Broker 策略与动作专属验证 |
| 单命令输入 | `df -h`、`systemctl restart example.service`、带引号路径 | 编译为 program/argv；本地分类器判断参数、路径、网络和效应；修改进入审批 |
| Bash 脚本与复合计划 | 工作区 `bash build.sh`；未来管道、重定向、多步骤组合 | 现有授权路径脚本按 C3 审批及 OS 沙箱；完整复合语法需下述新契约后开放 |

本轮新增 `terminal.execute.command` 输入，兼容原 program/argv；二者互斥。支持字面量单词、单双引号、转义和空参数。不解释环境变量、命令替换、通配符、重定向、管道、条件链和多行代码。遇到不支持语法明确拒绝并建议拆步/工作区脚本，不静默改变意思。解析不是 Bash 的完整 AST，也不是脚本安全证明。

审批使用规范化 program/argv 与原有参数摘要，批准后重新进行本地风险检查；输入 `expected_effect: observe` 不得将危险命令降级。现有 C4 禁令仍有效，直接 `bash -c` 不作为新增入口。

## 3. 危险操作审批模型

| 风险 | 默认行为 | 例子与边界 |
| --- | --- | --- |
| 已验证只读 | 授权范围内自动执行 | 磁盘、内存、进程状态；工具的危险参数仍需识别 |
| 可逆修改 | 显示差异后批准，可限定同一计划范围 | 文件移动/修改、系统设置；有真实快照才显示可撤销 |
| 不可逆/外部影响 | 每个任务明确批准，不长期静默放行 | 删除、网络发送、服务停止、安装和运行项目脚本 |
| 系统特权 | 专门的特权动作代理与系统认证，待实现 | root 安装、系统服务管理；不保存 sudo 密码、不在模型命令里裸放 sudo |
| 灾难性/凭据访问/绕过边界 | 拒绝并解释可替代路径 | 全盘格式化、根目录递归删除、读取私钥、绕过审批接口 |

审批卡必须展示：动作目的、完整命令/脚本、cwd、读取/写入范围、联网范围、执行身份、超时、预期变化、可恢复范围。改变任何批准参数必须使旧授权失效。批准按钮不能使系统自动获得 root 或不可访问路径。

“审批危险指令”与“执行能力存在”分开：当前终端仍受沙箱限制；批准 apt 或 systemctl 不意味着宿主系统管理员操作已经可执行。特权功能在完成可信代理前提示交给系统工具。

## 4. 完整 Bash 的后续设计

增加版本化 ShellPlan：原始源文本、语法版本、解析树摘要、步骤依赖、重定向目标、解释器身份、脚本内容摘要、cwd、只读/读写目录、网络策略、环境变量白名单、预算、验证条件。

必须条件：

1. 采用维护中的 Bash 解析器，支持矩阵逐项启用。AST 分类是风险提示，OS 沙箱才是实际执行边界；动态行为和未知外部程序一律高风险。
2. 管道以独立进程和显式 stdin/stdout 管道执行，明确 pipefail；`&&`/`||` 按退出状态推进。重定向通过安全文件句柄，不由字符串拼接打开路径。
3. 脚本内容在审批时冻结，摘要同时绑定解释器、参数与范围；执行批准后的不可变副本，阻断批准后改脚本。脚本引用的外部资源仍须限制可见范围。
4. 干净环境，禁用 profile/rc/BASH_ENV/ENV 等隐式初始化，不继承代理密钥、认证 socket 和用户凭据。
5. 无网络默认隔离；域名限制不能仅靠提示词，需出站代理/受控网络策略。缺少内核隔离时拒绝执行，不降级裸宿主 Shell。
6. 进程组取消、超时、输出上限、磁盘配额；失败留下“已发生/待核验”记录。包安装和脚本副作用不得宣称通用撤销。
7. 宿主修改交给明确受支持的系统/文件操作代理；系统特权通过有限动作及 Polkit 等认证机制，不给任意脚本全局 root。

交付顺序：先脚本冻结与审批摘要；再单管道/明确重定向；再条件计划；动态替换、循环和任意脚本只在隔离工作区经明确审批执行。每步具备红队和真机测试后再对模型开放。

## 5. 软件兼容架构

建立动作级兼容矩阵，而非软件名称支持列表：软件版本、发行方式（deb/Snap/Flatpak/AppImage）、桌面/显示协议、动作、通道、前置依赖、验证器、失败码和最近验证版本。

Provider 选择顺序由动作决定：可靠的 CLI/API、D-Bus/MPRIS/SNI、URI/.desktop、AT-SPI 语义操作、用户接管。启动成功不证明聚焦，进程存在不证明文档打开，托盘菜单存在不证明动作生效。副作用已发送后不得盲目切换通道重复执行。

第一批认证：Files/Nautilus、Firefox/Chromium、VS Code、LibreOffice/WPS、一个 MPRIS 音乐软件和一个 SNI 托盘软件。每个软件先完成启动/打开/聚焦/状态/退出中可可靠支持的动作；缺失能力明确标注。安装了但检测不到接口时给“仅能启动”，不冒充完全支持。

软件画像为声明式能力契约与隔离适配器，软件探测异步、缓存按版本失效。桌面包更新后重新验证；用户自定义快捷动作同样经过策略，不继承安装者信任。

## 6. 系统基础控制平面

将已存在的音量、显示、输入、通知、电源、网络、蓝牙、进程、服务、文件能力整理成统一 ControlAction：读取当前值、参数范围、权限等级、执行后读回、恢复方法和能力不可用原因。

只读诊断先行；会断网、停止当前会话、终止进程的动作显示真实影响。系统默认面板负责凭据输入。安全文件系统引擎负责路径和写入，不让 shell 的字符串解析成为唯一防线。

设置中心按“软件、系统、终端、安全、连接”组织用户任务；保留高级选项。命令面板同时显示原命令、风险原因、审批状态、输出、停止与恢复，不迫使用户理解 C0–C4 标签。

## 7. 交付工作包与验收

| 包 | 内容 | 当前状态/门槛 |
| --- | --- | --- |
| T0 | 单命令输入归一化 → 现有分类/审批/沙箱 | 本轮实现；引号、空参数、互斥、风险降级与硬禁令回归 |
| T1 | 脚本冻结、内容摘要绑定与命令计划预览 | 待实现；批准后脚本变化不得影响执行，授权不可重放 |
| T2 | 软件动作兼容矩阵和统一结果 | 待实施；至少 7 类代表软件在指定 Ubuntu 真机上逐动作验证 |
| T3 | 系统控制平面与有限特权代理 | 待实施；低权限无副作用，批准影响与真实效果一致 |
| T4 | 受控管道、重定向与条件计划 | 待实施；子进程、符号链接、路径竞争、网络和恢复测试 |
| T5 | 连续集成与性能/安装 | 分层 CI 和真实桌面 runner 待实施；本轮修正 systemd 参数 |

必须测试：引用含空格/中文路径；嵌套替换；重定向逃逸；PATH/环境注入；脚本批准后修改；进程组取消；错误码与部分执行；网络外发；系统恢复；Wayland 与 X11 可见性；Snap/Flatpak 沙箱。

性能目标沿用顶层规划，本地风险判定新增目标 P95 ≤10ms（不含首次可执行文件/路径扫描，需另报）；UI 首次反馈 ≤150ms。Shell 进程启动、软件启动、模型延迟和目标验证分别记录。当前环境缺少 bwrap userns 的限制不允许通过放宽安全断言消除。

## 8. 本轮兼容与限制

原 program/argv 协议保持兼容，能力描述版本升级为 2。command 经解析后复用现有执行器，不引入第二条权限路径。现有工作区脚本仍没有本方案要求的完整脚本冻结契约，必须作为后续高优先级工作；不要将本轮单命令输入宣传为完整 Bash 兼容。

本轮还修正 systemd 模板 `--listen` 为主程序实际支持的 `--web-listen`，但 Debian 安装路径和干净主机启动仍需单独验收。

软件兼容本轮修复：分类器不再将可执行文件的父目录当作应用身份。原实现会将 `/home/vlc/.../wps-mock` 中的 `vlc` 误当作软件特征，导致 WPS 分类错误；现在只使用 desktop ID、程序 basename、名称、WM class 等身份和元数据。新增不同安装目录下分类保持一致的回归测试。

## 9. 本轮验证记录

基线 `ece36ac`，云环境沿用上一轮工具链。实际运行：

- 命令解析与审批回归：`cargo test -p intentosd --lib command_line_ -- --test-threads=1`，2/2 通过。
- 分类修复：`cargo test -p intentosd --lib classifier_ -- --test-threads=1`，2/2 通过；对应 `e2e_wave5 wave5_test2`，1/1 通过。
- `cargo fmt --all -- --check`、`git diff --check`、最终 `cargo clippy --workspace --all-targets -- -D warnings` 通过；Cargo 仍提示已有 manifest 项。
- 无显示环境的全 workspace `--no-fail-fast` 回归：219/232 通过，13 失败。该次编译在软件分类修复前，分类修复后按上述单元和端到端用例补验，未声称最终源码全量重跑。
- systemd 参数已对照 `intentosd --help` 验证；未在真实 systemd 登录会话安装启动。
- 本轮未重跑语料性能评测和 GTK 真桌面验收，不沿用旧数字作为本轮成绩。内核隔离执行尚需支持 userns 的 Ubuntu 主机验证。

全量回归未通过项：

- `backend_bridge::providers_cli::tests::cli_bwrap_sandbox_blocks_workspace_write_secret_dir_and_cmdline_leak_while_bridging_broker`
- `backend_bridge::providers_cli::tests::cli_chat_only_mode_omits_protocol_and_strips_forced_tool_calls_with_zero_broker_exec`
- `backend_bridge::tests::test_m1_cli_broker_bridge_executes_tool_call_and_suspends_on_pending_approval`
- `diagnostics::tests::m2d_scenario1_real_proc_system_bottleneck_and_synthetic_swap_zombie_detection`
- `terminal_agent::tests::anti_bypass_blocks_shells_inline_code_flags_symlinks_secrets_unauth_writes_and_tcp`
- `terminal_agent::tests::c0_df_and_free_succeed_in_real_bwrap_readonly_sandbox`
- `terminal_agent::tests::c1_rg_find_and_git_status_succeed_inside_authorized_tempdir_in_bwrap`
- `terminal_agent::tests::c2_reversible_write_requires_approval_snapshots_changeset_and_undoes_plus_redacts`
- `m1_test1_turn_engine_modularized_and_cli_broker_bridge_unifies_execution`
- `p0_10_chat_only_allow_broker_tools_false_blocks_system_tools_identically_on_http_and_cli`
- `p0_11_real_cli_os_sandbox_blocks_unauthorized_write_forbidden_read_and_cmdline_leak`
- `p1_05_h10_warm_pi_worker_reuse_incognito_isolation_and_idle_eviction`
- `m2_test3_controlled_terminal_c0_c4_sandbox_and_anti_bypass`
