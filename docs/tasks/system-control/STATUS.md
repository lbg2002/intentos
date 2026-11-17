# 工作包状态与交付记录

初始化日期：2026-11-17；基线：`355ebac`。本文件由开发智能体随真实交付更新。

状态：todo → in_progress → implemented_unverified → verified；可标记 blocked（同时说明已完成部分和阻塞依赖）。只有满足 ACCEPTANCE 才标 verified。

| ID | 工作包 | 依赖 | 状态 | 实现提交 | 验证证据/阻塞 |
| --- | --- | --- | --- | --- | --- |
| SC-01 | 分层验证与失败归因 | 无 | implemented_unverified | c835c9b | CI/探针已写；历史13项未复测；L1/L2/L3/L4关键验证 blocked |
| SC-02 | 安装/打包一致性 | 退出需01 | implemented_unverified | 2ce685e | 路径静态修正；V16 干净 VM 安装/升级/卸载 blocked |
| SC-03 | 冻结脚本与审批摘要 | 01基础回归 | blocked | 8420a8b, 72b6812 | 未实现可信冻结 artifact；所有解释器/工作区脚本暂拒绝；V01–V05 blocked |
| SC-04 | 取消/预算/崩溃恢复 | 03 | blocked | c89fbba | 正常退出后孙进程清理补强；取消和崩溃恢复 V06/V07 未验证，依赖03冻结 |
| SC-05 | 软件动作契约/矩阵 | 01基础回归 | implemented_unverified | e08a959, a2e548f | schema v1、只读 RPC、未验证状态与单测；L1/L3 blocked |
| SC-06 | 代表软件真机认证 | 05 | blocked | 5e2b8fb | 7 类/35 动作只读探针与 3 项本地 Python 测试；L3 实际认证未执行 |
| SC-07 | 系统控制/有限特权代理 | 03/04 | blocked | e5f4a08 | 设置 ChangeSet Undo 外部变更冲突检测；特权 C4、L2/L3 blocked |
| SC-08 | Bash复合计划 | 03/04 | blocked | ef5f27f | 显式 argv 管道草案静态校验；不可执行，解析器/运行时受03/04阻塞 |
| SC-09 | 审批与结果体验 | 03/05，特权依赖07 | blocked | c103d40 | Web 标记注入与终端会话授权防护；全客户端 V14/V15 blocked |
| SC-10 | 集成/安全/性能发布 | 所发布范围全部包 | blocked | ac71df3, b5ab0d7 | 显式 release_allowed=false；现有 P0/真实 L2/L3/L4 未达标 |

## 每次交付追加模板

```text
任务ID/状态：
审查基线SHA/实现提交SHA/分支：
完成的用户行为：
修改的接口、配置或存储：
实际测试命令、日期、环境、构建SHA：
通过/失败/未执行数量及原因：
真实隔离、真桌面与性能证据链接：
安全/恢复语义与兼容迁移：
剩余风险和默认关闭功能：
下一步任务/解除阻塞的条件：
GitHub提交或PR链接：
```

不要写“全部完成”替代明细。代码提交、验证提交、文档提交可不同，测试报告须明确被测代码SHA，避免把最后文档提交误当作重新运行过测试。

## SC-01（2026-11-17）

- 基线 `d0b9f56e1b3f454e6bda380f7d2ebe7ca223362b`，分支 `sc/system-control-20261117`；实现 probe / L1-L4 workflow / 固定工具链 / 历史失败归因台账。
- 本地实测：探针脚本 bash -n PASS；L1 blocked (missing rustc)；L2 blocked (missing bwrap)。无 Cargo、L2 OS、L3 GUI、L4 Release 行为验证。
- 完整证据：`docs/validation/system-control-sc01.md`；未达到验收，不得宣称 verified。后续非依赖任务可继续。


## SC-02（2026-11-17）

- 修复 Debian 服务 /usr/bin/intentosd 与用户安装 ~/.local/bin/intentosd 的布局差异；修复用户模块、worker、skills 搜索路径以及开发机路径硬编码。
- 安装器检测 systemd 用户服务 active；当前无 systemd 用户管理器时返回非零，不报告假成功。
- 静态审查完成，实际 Ubuntu VM 安装/升级/卸载、Rust 编译及真桌面验证 blocked。SC-01 门槛未达，不能标记 verified。


## SC-03（2026-11-17）

- 已提交 **安全门禁增量**：在任何审批前拒绝未冻结的工作区可执行脚本和 Bash/Python/Node/Perl/Ruby/PHP/Lua 解释器执行，并补无需内核沙箱的分类负向回归。避免审批后重新读取源脚本造成 TOCTOU。
- 未实现真正 immutable artifact、script SHA-256 审批绑定、session/step 签名、旧 checkpoint 迁移、删除生命周期；不能将此项标记完成。
- 当前无 cargo，新增测试未执行；V01–V05 真实执行/攻击用例 **blocked**。脚本保持默认关闭，旧版本允许的脚本能力有意收紧。


## SC-04（2026-11-17）

- 局部修复：受控沙箱主进程正常退出后仍清理同进程组孙进程，防止短生命周期父进程遗留后台任务；增加异步真实沙箱负向测试。已有 timeout/output 上限、killpg 和账本代码未放宽。
- **未完成**：完整任务取消联动、硬性磁盘预算、prepared/executing/applied/verified 崩溃注入与恢复证明；依赖 SC-03 未完成。本次测试因无 cargo/bwrap 未执行，V06/V07 blocked，不能验收或开放未验证功能。


## SC-05（2026-11-17）

- 增加不授予执行能力的 `app_adapter.get_compatibility_matrix` 只读 RPC。按 action_id/channel/package_format 暴露 schema_version=1、发现状态、认证状态、版本未知、桌面/Flatpak/Snap 约束；不伪造认证记录。
- 对模型已有 `app.discover` 补充 `certification_state: unverified` 和版本未知提示；保持原 Broker/Policy/Provider 链路不变。无认证写入或持久化迁移，旧客户端忽略新增字段。
- 添加三个纯逻辑负向单测；当前无 cargo/rustc，尚未执行。V08/V10、历史 13 项回归和真实环境认证均 blocked，状态不能 verified。


## SC-06（2026-11-17）

- 提交只读七类代表软件探针 `scripts/sc06_certification_probe.py`，各类的 launch/open/focus/status/quit 仅收集桌面入口、打包线索与会话元信息，35 个结果全部明确 unverified；禁止将发现等同认证。
- 独立 Python fixture 测试（3/3 PASS，当前 Linux 容器）验证发现不自动认证、未发现状态、symlink 不接受；没有执行任何软件启动、退出或桌面控制。
- V08–V10 在 Ubuntu 24.04 GNOME Wayland/X11、deb 与 Flatpak/Snap 样本上的实测 **blocked**；未完善功能通道与 SDK 认证，SC-06 不能标 verified。


## SC-07（2026-11-17）

- 修改既有 SystemSettingsEngine/CapabilityBroker 的 ChangeSet 撤销路径：恢复前按记录 after 读回；外部修改则将变更集标记 Conflict，不再覆盖当前用户新值。先预检多个设置项并二次读回，减少部分撤销。保持统一 Broker/ChangeSet 通路。
- 新增模拟亮度值外部变化的针对性单测（未执行，当前无 Cargo）；读回与写入之间仍是非原子窗口，需 OS 驱动支持 compare-and-swap 才能严格消除竞态。
- SC-03/04 未解除，Polkit/受限特权代理、包管理系统动作未实现；V11/V12 真实机器与用户认证测试 **blocked**，特权默认关闭，不新增 sudo/root Shell。


## SC-08（2026-11-17）

- 增加独立的 ShellPlanDraftV1 **只校验不可执行**模块，支持显式 argv + pipe 拓扑的结构验证；未知字段、重复 step、动态 Shell 控制符/条件链返回结构化错误，不使用 `bash -c`。
- 未挂载工具、RPC 或任何执行入口；`executable=false` 固定值。无静态 Bash 语法解析器，也不声称支持 shell 文本/重定向/条件链，须待 ADR 评估与 SC-03/04 完成后继续。
- 三项纯逻辑回归未在当前容器编译，L2 文件/进程隔离 V13 blocked；能力默认关闭。


## SC-09（2026-11-17）

- Web 的审批 cap ID 和资源结果 cap ID 使用 textContent 替代字符串插入 innerHTML，避免来自模型/外部参数的标记注入。
- 浏览器隐藏终端“允许本任务/本会话”并阻止点击；**服务端** PolicyEngine 的 session grant、GrantEnvelope 的创建与消费、持久化审批续跑均拒绝对 terminal.execute 使用跨动作授权，防止只改 UI 的绕过。
- 不变更终端单次 nonce+digest 原有审批；真实 CLI/HTTP/GTK/GNOME 双端一致性、V14/V15 与脚本冻结依赖仍 blocked。静态/回归由 CI 核验，不因缺桌面而算通过。


## SC-10（2026-11-17）

- 增加 `scripts/sc10_release_gate.py`，逐包要求 STATUS=verified 且相应的 SHA、runner、命令与 L1/L2/L3 证据文件齐全；skipped/failed 不计 passed；默认阻断发布。没有扩展已启用能力。
- 本地隔离 fixture 的 3 个 Python 单元测试 PASS；缺实际 L1/L2/L3/L4 证据，当前批次 release_allowed=false。门禁仅能检查报告字段，不是签名证明或真实硬件认证的替代品。
- SC-03/04/06/07/08/09 关键验收未通过，SC-10 blocked。未运行 Release 性能 benchmark，不发布完整 Bash、特权代理或全面软件兼容声明。


### SC-05 查询语义补全（2026-11-17）

- 显式 app_id 查无 desktop entry 返回 `lookup_status=not_installed_or_not_detected`；找到但无动作返回 `no_declared_actions`；已发现且可列出动作也不会自动转为 certified。新增两条 Rust 状态边界测试及两条合成 fixture，仍不启用新执行通路。


### 跨包回归门禁补充（2026-11-17）

- L1 引入 SC-05/07/08/03/09 定向 Rust 测试、SC-06/10 Python fixture、Web JS 语法检查及不可发布断言；另设 Ubuntu 24.04 托管 runner 的全工作区 `--no-fail-fast` 回归，保留全部失败日志，不以 skip 或放宽断言代替合格 L2/L3。
- 完整运行结果待 CI 记录。L1 全量测试不是 OS 隔离认证；仍需专用 Ubuntu 真实 userns/bwrap 及 GNOME 登录会话。


### SC-10 发布门禁加固（2026-11-17）

- 对照 ACCEPTANCE.md 的 V01–V17 案例加入逐包必需案例 ID 检查；SC-10 强制 L4 性能证据，SC-01 强制 L2 环境证据，避免仅有若干 L1 成功日志就误过发布。添加一组**合成**正向与遗漏案例负向单测，合成证据不构成真实验收。


### 跨包 P0 沙箱缺陷（2026-11-17）

- 全工作区 Ubuntu L1 `44036688627` 中 `sandbox_enforces_readonly_workspace_private_tmpfs_and_credential_masking` 真正观测到 Landlock 模式 `SECRET_LEAKED`，不能仅解释为缺少 bwrap。已在通用 SandboxSpec 构造器中禁止无法提供凭据掩码和私有 tmpfs 的 Landlock/NodePermission 回退；保持原严格测试不变，新增拒绝降级的纯逻辑测试。
- 该行为是**默认禁用不合格执行路径**，可能影响无 bwrap 的 agent/CLI/terminal；须 Ubuntu L2 具备 bwrap userns 正反测试后恢复服务能力，未达标仍 blocked。旧测试在无 bwrap 的 L1 预期失败，不能宣布全部通过。


## 2026-11-17 本批实际 L1/全量回归报告（区分被测 SHA）

- 定向 L1 GitHub Runner `44037507542`，**被测 SHA `42a7729fe4ba3dcd5583ae34d789310e32b77e08`**：rustfmt、全 workspace Clippy `-D warnings`、协议/SDK 测试、`command_line_`、SC-03/05/07/08/09 定向 Rust 测试、Web JS 语法以及 SC-06/10 Python 8 项 **PASS**；SC-10 发布门禁 `release_allowed=false` 也符合预期。参见 `docs/validation/system-control-batch-20261117.md`。
- 全量 L1 GitHub Runner `44036688627`，**被测 SHA `b219cf863fe735c2fc590d65f0236347799fcb58`**：22 个 test target 合计 **235 PASS / 9 FAIL**，包括真凭据泄漏 `SECRET_LEAKED`、CLI 权限逃逸 `AUTH_CFG_WRITE_ESCAPED` 和环境缺少 bwrap/numpy 等。原断言全部保留，CI **FAIL**；未把环境不合格计通过。
- P0 防止 Landlock 回退泄漏：`4b692b1` 禁止无可信 bwrap 的通用沙箱执行；`2bfecaa` 加入定向测试和 CI。该代码后续流水线结果须核实，**不能用较早 SHA 的通过记录冒充此新修复已通过**。
- L2 实际 Bubblewrap/userns、L3 Ubuntu GNOME Wayland/X11、L4 独占性能均未执行（manual self-hosted runner 未就绪）；对应工作包仍 blocked/implemented_unverified，全部发布门槛未达。
