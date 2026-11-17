# 工作包清单

所有任务均待开发；条目中“现有”仅为复用入口。依赖与发布阻塞见 README。实现时若代码已覆盖需求，补充证据/缺失回归，不重复造功能。

## SC-01：验证环境与失败归因（P0）

- 依赖：无。范围：`rust-toolchain.toml`、workspace manifests、`.github/workflows/`（新建）、`scripts/`、现有 tests/eval。
- 先重跑当前基线，为上一轮 13 项失败标记产品缺陷/环境缺失/测试不稳定，并保存原断言与最小复现。不要把 13 当作永久固定数量。
- 固定可用工具链与依赖锁；为纯逻辑测试、真实内核隔离、GTK/桌面、Release 性能建立不同 job/runner 标签。runner 缺少 userns/Landlock 时 job 必须明确阻塞或失败，不能作为发布成功。
- 交付：环境探针、CI 配置、测试运行说明、结果模板；不得在未知自托管 runner 上开启不可信 PR 特权测试。
- 验收：新克隆可重复运行静态与纯逻辑检查；隔离 probe 与真实安全用例结论一致；每项基线失败有证据和后续归属。

## SC-02：用户安装与 Debian 发布一致性（P0）

- 依赖：无；退出需 SC-01 验证环境。范围：`packaging/systemd/`、`packaging/deb/build-deb.sh`、`scripts/install-ubuntu.sh`、`config.rs`、`main.rs`。
- `--web-listen` 已修复，不重复。当前 Debian 包放 `/usr/bin/intentosd`，共用服务模板却指 `%h/.local/bin/intentosd`，须独立确认并修正两种安装布局。
- 对齐 modules/skills/worker/UI 资源查找路径；从任意 cwd 和不含源码目录的干净系统启动。用户安装与系统安装各自生成正确服务配置。
- 交付：两种布局的路径契约、安装/升级/卸载说明、服务状态健康检查。失败必须清晰返回，不打印假成功。
- 验收：干净 VM 安装后实际启动、重登录、升级保留配置与数据、失败升级可恢复、卸载选择保留数据。单纯 --help 通过不算安装验收。

## SC-03：审批脚本冻结与身份绑定（P0）

- 依赖：SC-01 的基础回归；范围：`terminal_agent.rs`、`policy.rs`、`backend_bridge/turn_checkpoint.rs`、`crates/protocol`、`crates/fsops`，按职责新建小模块。
- 实施 CONTRACTS C1/C2/C5。沿用已有工作区脚本分类；增加受控 artifact 创建与摘要，不让审批后重新读取原脚本。
- 扩展 PendingApproval 时设计旧序列化数据读取；旧脚本审批缺少摘要时不得自动升级为已信任新计划。
- 交付：脚本 artifact 管理、审批摘要、一次性消费、清理生命周期和兼容说明；CLI/HTTP 两后端均走同一入口。
- 验收：批准后替换源脚本/替换为 symlink 不执行新内容；修改 argv/cwd/网络/写路径使授权失败；解释器环境注入不生效；脚本含密钥不泄露到日志；拒绝/过期无执行。
- 明确未做：任意宿主 Bash 和 root shell。已有 OS 隔离不可因审批而取消。

## SC-04：执行预算、取消与恢复（P0）

- 依赖：SC-03。范围：`crates/sandbox`、`terminal_agent.rs`、`backend_bridge/`、`db.rs` 与 AgentEvent。
- 统一超时、输出/磁盘预算、进程组取消、暂停审批和任务依赖；复用既有实现并补生命周期缺口。
- 崩溃注入在 prepared/executing/applied/verified 各点；恢复按证据核验，不重跑未知副作用。支持受限临时脚本不能恢复的明确提示。
- 验收：测试脚本派生孙进程后取消无残留写入；无限输出有界；超时保留已发生事实；恢复不重复追加文件；暂停审批不消耗执行时限；并发审批单不能串任务。

## SC-05：软件动作注册与兼容矩阵（P1）

- 依赖：SC-01 基础环境。范围：`app_adapter/{provider,registry,local_scanner}.rs`、`capability_snapshot.rs`、`meta_tools.rs`。
- 建立动作级版本化记录与查询接口，复用 provider 类型。发现状态与认证状态分离；保持未知版本可诚实降级。
- 将渠道选择、超时、验证器、不可重放规则收口；模型动态发现返回能力/限制，不返回假兼容标签。
- 交付：矩阵 schema 与 fixture、查询 RPC/tool、缓存失效、版本迁移；没有实测的条目状态为 unverified。
- 验收：未安装/版本改变/接口缺失/Flatpak 限制正确显示；RequestedUnverified 后不会第二次启动或写入；与已有工具 schema 预算兼容。

## SC-06：代表软件动作认证（P1）

- 依赖：SC-05；范围：app_adapter 各通道、资源解析与 tests。
- 先选 7 类代表：Nautilus、Firefox/Chromium、VS Code、LibreOffice、WPS、MPRIS 播放器、SNI 托盘软件。动作选择：启动/打开资源/聚焦/状态/优雅退出；不支持的项明示而不是补假实现。
- 至少一个 deb、一个 Flatpak/Snap 的可用真实环境；记录具体发行方式和版本。Wayland/X11 分开认证。
- 交付：每个动作证据、适配代码、失败恢复、兼容矩阵。浏览器打开 URL 不等于页面内容已加载；编辑器进程存在不等于定位到文件行。
- 验收：含空格/中文路径、多实例、软件已打开、依赖缺失、无窗口权限、托盘超时；退出不得误杀无关进程。

## SC-07：系统控制与有限特权动作（P0/P1）

- 依赖：SC-03/SC-04，真机验证依赖 SC-01。范围：`settings.rs`、`diagnostics.rs`、`broker.rs`、系统 YAML、必要的 helper/Polkit 包装。
- 梳理音量、亮度、通知、输入、网络、电源、进程/服务等现有动作；补充读取-变更-读回-恢复契约。
- 第一子包为非特权动作一致性；第二子包为一个有限特权服务动作，必须实现 CONTRACTS C4；包管理是后续子包，不捆绑裸 sudo 放行。
- 验收：范围外参数拒绝、无认证不执行、认证取消无变更、执行后读回一致；网络切断/会话结束事先说明；外部修改后的 undo 触发冲突而非覆盖。
- 发布门槛：privileged helper 的授权与参数验证需专项审查，未通过保持关闭。

## SC-08：受控 Bash 复合计划（P1）

- 依赖：SC-03/SC-04；范围：新计划解析模块、terminal_agent、sandbox、protocol/描述符。
- 先记录 ADR：选用解析器的 Bash 支持范围、维护状态、许可证、资源限制。禁止用正则/关键词过滤冒充完整 Bash 解析。
- 第一步支持显式 argv 管道与安全重定向；第二步支持 &&/||。定义 pipefail、stderr、重定向打开顺序、append/overwrite、失败后的步骤状态。
- 未支持语法返回结构化 unsupported_syntax，不能自动 fallback 到 bash -c。动态替换/循环/函数以冻结脚本的受控执行处理，不谎称可静态判定无害。
- 验收：嵌套替换、here-doc、重定向 symlink、文件竞争、管道中途失败、大输出、取消、重启；越界访问失败且未损害宿主 fixture 外文件。

## SC-09：审批、命令面板与结果体验（P1）

- 依赖：SC-03、SC-05；特权展示依赖 SC-07。范围：GTK launcher/settings、GNOME、Web UI、RPC/event。
- 统一呈现目的、完整命令、作用目录、读写/网络/身份、风险原因、恢复范围；技术分级放详情。长脚本需可展开完整内容，不能只展示省略摘要让用户盲批。
- 展示申请批准、执行、部分完成、失败、取消与待核验；用户能停止、拒绝、调整路径，审批后自动续接正确任务。
- 验收：键盘与读屏、缩放、中文输入法、双屏、快捷键冲突；不同客户端拒绝/批准行为一致；命令/文件名中的标记文本不得成为 HTML/markup 注入。

## SC-10：集成、安全与性能发布（P0 门槛）

- 依赖：所发布范围内全部包完成，未完成能力明确关闭。范围：集成 tests/eval、发布文档、安装包与 STATUS。
- 运行 ACCEPTANCE 的全矩阵；对目标成功率、未知状态和跳过项给出准确分母；Release 性能测试独占资源运行，记录 SHA/硬件/内核/桌面。
- 验收：没有未处理 P0；危险操作审批与拒绝测试全部通过；支持矩阵的目标动作真机通过；关键 SLO 达标或明确缩小发布范围。
- 交付：可复现发布报告、升级迁移/回退文档、已知限制；未验证的平台不可宣传全面支持。
