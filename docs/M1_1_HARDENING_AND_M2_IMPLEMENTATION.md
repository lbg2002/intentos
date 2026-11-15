# IntentOS v0.2-M1.1 代码审查、性能加固与 M2 实施任务书

> 本文是面向编码 Agent（Codex、Pi、ZCode 等）的可执行工程任务书，而非新的产品规划。必须依据实际源码、测试与运行结果实施；不得仅修改说明文档、伪造测试结果或为了满足指标降低安全性。

- 审查基线：[`61619ce`](https://github.com/lbg2002/intentos/commit/61619ce389adaa0fed1365ba6e4bcde97d4b164f)（2026-11-14）。
- 上一基线：[`b7b4745`](https://github.com/lbg2002/intentos/commit/b7b4745e44b61e52303e6911053b15f3548aa955)。
- 现有总体路线：[ROADMAP_v0.2.md](ROADMAP_v0.2.md)。本文补充 M1.1 加固任务，并细化 M2，原则上不改变 M3/M4 的总体方向。
- 核心目标：**统一、动态、闭环**。统一 Agent 执行与安全边界；动态发现能力；保证真实任务的完整执行、验证、取消与恢复。
- 本次审查为静态源码审查；性能数字来自仓库报告，未在实际 Ubuntu/GNOME 环境重新运行。下述风险需要回归测试和真实环境验证，不能作为已复现漏洞或已达到性能目标的结论。

---

## 0. Agent 执行纪律

1. 开工前读取当前 main、本文、ROADMAP_v0.2.md、PROGRESS.md、Cargo.toml、相关测试及已有架构设计。如果当前代码已修复本文问题，先补充证据或回归测试，不重复实现。
2. 优先完成 M1.1 P0 项，再完成 P1 性能与体验项，最后进入 M2。每个任务独立提交，明确涉及的模块、行为改变、测试和遗留风险。
3. 复用现有 Rust 核心、CapabilityBroker、PolicyEngine、ModelGateway、ChangeSet、SQLite、现有 app_adapter/memory_hub/execution_hub；不要新建平行体系或引入重型数据库。
4. 全部实际操作必须经过可信执行边界；模型不拥有提升权限、绕过审批、任意 Shell、直接接触密钥的权力。工具输出和外部文件仍为不可信数据。
5. 不以消除测试失败为目的放宽测试断言、硬编码用户示例、隐藏错误或改变评测口径。不要把 Mock 通过等同于真实环境验证通过。
6. 保持 Ubuntu 22.04/24.04/26.04 及 GNOME/GTK/Web 的现有接口兼容；涉及接口改变时给出兼容迁移和端到端测试。GNOME 50 的实际兼容性需专项验证，不能仅依赖声明。
7. 所有新增执行能力均应包含参数 Schema、权限、超时、结果验证、失败与撤销语义（无法撤销则明确标注）。
8. 完成后运行实际可用的 cargo fmt、clippy、workspace 测试、评测及桌面 smoke tests，并记录命令、环境、结果和未执行原因。禁止编造运行结果。每个任务的 Definition of Done 必须有源码与测试支撑。
9. 任何性能重构前建立同环境基线；关键事务、安全审批、隐私隔离不可为性能让步。

## 1. 更新评价与基准

M1 已完成 turn_engine 模块拆分、CLI Broker 协议、TurnEffectLedger、PrivacySessionPolicy/SensitiveDataGuard、StructuredIntent 与复合子句追踪，并新增 e2e_v0_2_m1.rs。但上述基础设施尚未在所有执行路径统一生效。

| 指标 | 旧版报告 | M1 报告 |
|---|---:|---:|
| 候选刷新 P50 | 2.50 ms | 2.79 ms |
| 候选刷新 P95 | 5.56 ms | 5.92 ms |
| L0 执行 P50 | 2.53 ms | 6.35 ms |
| L0 执行 P95 | 8.72 ms | 61.23 ms |
| 325 条意图评测准确率 | 97.2% (316/325) | 99.7% (324/325) |
| 红队门禁 | 16/16 | 16/16 |

来源：[旧报告](https://github.com/lbg2002/intentos/blob/b7b4745e44b61e52303e6911053b15f3548aa955/eval/latest_report.md)、[M1 报告](https://github.com/lbg2002/intentos/blob/61619ce389adaa0fed1365ba6e4bcde97d4b164f/eval/latest_report.md)。L0 P95 报告值约增至原来的 7.02 倍，但两份报告运行环境未确认一致，不能直接将全部差异归因于代码。现有评测主要验证路由、能力和参数，且含模拟环境；99.7% 不代表真实开放式任务成功率。

### M1.1 实施总表

| ID | 优先级 | 任务 | 主要代码 |
|---|---|---|---|
| H01 | P0 | 并发 turn 去重与请求绑定 | backend_bridge/turn_checkpoint.rs |
| H02 | P0 | 按工具语义实施幂等 | backend_bridge/broker_bridge.rs |
| H03 | P0 | 持久化副作用日志与恢复 | turn_checkpoint.rs、db.rs、fsops |
| H04 | P0 | 所有外部 Agent 的真实执行隔离 | providers_cli.rs、sandbox |
| H05 | P0 | 三态隐私策略全链路传递 | security_guard.rs、core.rs、runtime.rs、backend_bridge |
| H06 | P0 | 统一 Core L2 与 Quick Chat 执行路径 | runtime.rs、backend_bridge、core.rs |
| H07 | P1 | 全局预算与诚实任务状态 | providers_http.rs、providers_cli.rs、turn_checkpoint.rs |
| H08 | P1 | 渐进式语义决策 | intent_engine、decision.rs、core.rs |
| H09 | P1 | 能力与后端缓存、数据库/I/O 性能 | intent_engine、broker_bridge、detector、db.rs |
| H10 | P1 | 流式任务事件与轻量 Worker | backend_bridge、runtime、desktop、web_ui |

P0 项需全部通过回归测试才进入增加新副作用能力的 M2；H01/H02/H03/H06 可共享设计，但要分别验收。

---

## 2. M1.1 P0 实施细则

### H01 并发请求去重：禁止同一 turn 同时运行两次

定位：[turn_checkpoint.rs#L325](https://github.com/lbg2002/intentos/blob/61619ce389adaa0fed1365ba6e4bcde97d4b164f/crates/intentosd/src/backend_bridge/turn_checkpoint.rs#L325)。

现状：begin_turn 仅对已经取消的 active handle 返回 PreCancelled；已存在且正常运行的相同 turn_id 可被新的 handle 替换，两个调用各自持有独立 Ledger。complete_turn 的 remove 与 completed cache 插入亦分属不同锁，需审查竞态。当前缓存按 turn_id 读取，没有完整绑定请求内容及隐私策略。

实现要求：
- 原子地注册/获取 turn，生命周期统一为 Running、Paused、Finished、Cancelled 等；同一个标识仅允许一个有效 owner。
- 新增 AlreadyRunning/Conflict 等明确结果：同请求重复提交订阅现有事件或返回正在执行，不创建新的 Agent；相同标识但不同内容拒绝。
- 将 turn identity 绑定 session_id、规范化请求摘要、模型/执行模式、隐私策略（及实际调用者作用域），禁止跨会话缓存混用。
- 完成、取消、审批挂起、重连状态原子更新；防止旧 handle 删除新实例，明确缓存 TTL 与容量、审批状态的重放规则。
- 普通会话支持跨进程恢复的唯一标识约束；严格隔离会话只保留允许的内存状态。

验收：10 个并发相同 turn_id 请求只触发一次实际副作用；相同 ID 不同 payload/session 被拒绝；取消与完成竞争、重连、超时重试、跨会话缓存隔离均有测试。

### H02 幂等语义：区分重复步骤与相同参数

定位：[broker_bridge.rs#L419](https://github.com/lbg2002/intentos/blob/61619ce389adaa0fed1365ba6e4bcde97d4b164f/crates/intentosd/src/backend_bridge/broker_bridge.rs#L419)，turn_checkpoint.rs 的 TurnEffectLedger。

现状：幂等键为 turn_id + capability_id + canonical_args，所有重复参数可能被拦截。读状态在修改后可能取旧缓存；连续两次下一首、相对音量调整等合法步骤可能被吞掉。缓存失败/拒绝结果时 duplicate 分支仍返回 is_error=false。

实现要求：
- 为能力描述或可信执行器增加幂等策略，如 AlwaysRefresh、CacheUntilStateChanged、IdempotentMutation、ExactlyOncePerStep、NeverReplay。
- 明确 call_id（传输调用）、step_id（逻辑步骤）、attempt_id（尝试）区别。模型无权伪造可信步骤身份来绕过限制。
- 普通查询允许刷新；有时效要求的查询不得返回过期缓存；变更后使关联状态缓存失效。
- 绝对设置可以按操作语义安全去重；相对、增量、追加、下一首等只能对同一逻辑步骤的重放去重，不阻止新的合法步骤。
- 缓存输出必须保留原始成功/错误/拒绝/验证状态；不允许将失败缓存标记成功。可重试读取与未知副作用区分处理。
- 规范化参数、路径身份、作用域与实际 effect；不要仅凭未经验证的模型 tool_name 或参数 JSON 作为安全判定。

验收：读取→修改→再次读取取得新值；连续两次下一首均执行；重复提交同一步骤只执行一次；失败查询允许受控重试；拒绝结果仍是拒绝；JSON 键顺序变化不绕过去重。

### H03 可恢复的副作用事务

定位：[turn_checkpoint.rs#L119](https://github.com/lbg2002/intentos/blob/61619ce389adaa0fed1365ba6e4bcde97d4b164f/crates/intentosd/src/backend_bridge/turn_checkpoint.rs#L119)、broker_bridge.rs、db.rs、fsops。

现状：Ledger 与 suspended checkpoints 主要驻留内存；mutated_state 依赖 effect > Observe 且返回成功，不能覆盖“副作用发生但验证失败/函数报错/进程崩溃”的情况。SQLite 已有 Task、ChangeSet 等持久化能力，应复用。

实现要求：
- 新增最小化步骤执行日志及迁移：task_id、step_id、idempotency_key、attempt_id、effect、状态、预期变更、关联 changeset、验证结果、时间与恢复策略；敏感信息先脱敏，不保存不必要的原始工具输入。
- 变更执行前持久化 Prepared → Executing；操作之后进入 Applied 或 Unknown；验证成功后 Verified/Committed；失败按能力语义执行恢复、回滚或标记 RecoveryRequired。
- 对有副作用的调用，若执行已开始且结果不确定，默认阻断整任务重放。先检查真实环境、原 ChangeSet 与预期状态，再决定是否允许重试。禁止把工具 Err 等同于未变更。
- 普通任务可跨重启恢复；审批恢复必须重新校验授权、参数摘要和资源身份，不能复用过期/被撤销的授权。
- SQLite 事务只能确保日志自身的原子性，不能声称外部 OS 操作具有数据库级原子性。跨文件系统、进程、网络等必须采用补偿、验证和保守恢复。
- 严格无痕与临时只读会话不持久化私有任务记录；明确不支持跨重启的私有任务恢复，关键安全策略仍生效。

验收：注入工具修改后返回错误、验证失败、修改后进程崩溃、审批暂停重启、回滚失败等故障；不重复执行已发生的动作，保留已确认变更与恢复提示，不伪报整体成功。

### H04 外部 CLI 后端真实隔离与统一执行模式

定位：[providers_cli.rs#L271](https://github.com/lbg2002/intentos/blob/61619ce389adaa0fed1365ba6e4bcde97d4b164f/crates/intentosd/src/backend_bridge/providers_cli.rs#L271)、sandbox、ModelGateway。

现状：CLI Broker XML 协议已接入，但普通 Command::new 启动并不保证外部 Agent 无法使用原生工具。ZCode 依赖 --disallowed-tools；Codex 分支未显式指定统一只读沙箱；Pi 分支未显式禁用自身工具。Mock CLI 测试只证明协议可工作。allow_broker_tools 当前主要传给 CLI 分支，不应作为跨后端的可靠“仅聊天”开关。

实现要求：
- 明确 Managed（受控模型/Agent）、ExternalReadOnly（限制读取、分析）、ExternalDelegated（用户明确授权的独立外部执行）三种模式；不支持真实隔离的后端不得标记 Managed。
- Managed 模式通过可信 Broker bridge 执行；外部 Agent 原生 Bash/Edit/Write 等工具必须真实禁用，并采用可验证的 OS 沙箱、只读目录、最小环境与网络/凭据边界。
- 根据真实 CLI/SDK 版本检测支持的隔离参数；无法验证安全限制时降级为受限对话或明确拒绝，不能静默以普通权限运行。
- 优先考虑 Pi 的成熟 Agent SDK 或受控 Worker；Codex/ZCode 可作为独立编码任务的委托后端，权限、资源范围和实际副作用明确展示。
- 所有后端统一执行 allow_broker_tools 或等效策略，HTTP 仅对话时不提供系统工具，也拒绝工具请求；审批、验证与撤销的语义一致。
- CLI prompt、环境变量、配置覆盖文件、临时输出、日志和外发数据按 PrivacySessionPolicy、SensitiveDataGuard 和 egress policy 管理；避免命令行参数暴露私有 prompt，尽可能使用 stdin/受控 IPC。

验收：真实后端版本实测尝试直接写文件/执行未授权命令/读取禁区路径/外发敏感数据均被阻止；仅对话模式 HTTP/CLI 一致；已授权 Broker 操作仍正常。Mock 测试保留，但不能替代真实后端测试。

### H05 三态隐私策略全链路贯通

定位：[security_guard.rs#L403](https://github.com/lbg2002/intentos/blob/61619ce389adaa0fed1365ba6e4bcde97d4b164f/crates/intentosd/src/security_guard.rs#L403)、[turn_engine.rs#L452](https://github.com/lbg2002/intentos/blob/61619ce389adaa0fed1365ba6e4bcde97d4b164f/crates/intentosd/src/backend_bridge/turn_engine.rs#L452)、core.rs、runtime.rs、db.rs、memory_hub。

现状：已定义 Standard、EphemeralReadOnly、StrictIsolated。但 Quick Chat 将策略重新压缩为 incognito = !allows_memory_read()，EphemeralReadOnly 因允许读取而变为 false，后续按布尔值判断写入可能导致持久化。

实现要求：
- 核心内部统一使用 ExecutionContext { session_id, task_id, privacy, trust, budget } 或等效结构，传递完整 PrivacySessionPolicy，不再以 bool 代替三态。
- 分别检查 memory_read、memory_write、task_persistence、audit/log、cache、模型外发与 CLI 私有数据处理策略；不能因允许读取而默认允许写入。
- StrictIsolated：不查询长期记忆、不写历史/任务/习惯；EphemeralReadOnly：允许授权范围内读取，禁止持久化会话/记忆/任务；Standard：正常但仍脱敏。
- 审批恢复、工具调用、候选搜索、后端缓存、错误日志、自动技能学习和主动调度沿用原策略。不能依据模型提供的 session_id 擅自切换作用域。
- 将敏感数据保护覆盖所有持久化出口、临时文件、异常日志与模型外发；记录最少必要安全事件，不将隐私承诺与实际实现混淆。

验收：三态分别覆盖 Quick Chat/Core L2/CLI/HTTP/审批恢复/工具调用；通过 SQLite 内容及文件检查验证读写隔离与敏感数据零不必要明文残留；使用虚构测试凭据，避免真实密钥。

### H06 统一所有执行入口与任务状态机

定位：[runtime.rs#L350](https://github.com/lbg2002/intentos/blob/61619ce389adaa0fed1365ba6e4bcde97d4b164f/crates/intentosd/src/runtime.rs#L350)、core.rs、backend_bridge。

现状：Quick Chat 使用新 Broker Bridge/Ledger，Core L2 AgentCoordinator 仍独立运行 Pi Worker/Native loop；Pi 失败后直接 fallback native，缺少与 Quick Chat 同样的显式副作用熔断。

实现要求：
- 建立单一 AgentExecutor 或复用并重构现有协调器，统一 submit_goal、execute_step、checkpoint、resume、verify、cancel。
- GTK、GNOME、Web、D-Bus、CLI 与将来的事件任务共享执行与状态语义；所有 provider 只负责模型协议、流式通信和受控工具请求。
- 将原生 Agent、Pi Worker、HTTP、CLI 的步骤执行收口到同一可信 ledger、policy、budget、privacy 和 task manager；禁止另起平行执行内核。
- 后端切换只在确定无副作用且授权/隐私允许时自动进行；执行开始或结果未知时先恢复/验证，不重放用户整个目标。
- 保持 L0 直接能力快速路径，但其实际变更同样经过可信 Broker、变更日志和正确状态管理。
- 逐步迁移并删除冗余循环；保留兼容接口，不需要一次重写全部 Rust 守护进程。

验收：同一任务经各入口具有一致的工具权限、审批、验证、取消、错误、回滚语义；Pi Worker 中途失败不重复写操作；旧 E2E 与新增测试均通过。

---

## 3. M1.1 P1 功能与性能任务

### H07 全局预算、诚实完成状态

定位：[providers_http.rs#L249](https://github.com/lbg2002/intentos/blob/61619ce389adaa0fed1365ba6e4bcde97d4b164f/crates/intentosd/src/backend_bridge/providers_http.rs#L249)、[turn_checkpoint.rs#L615](https://github.com/lbg2002/intentos/blob/61619ce389adaa0fed1365ba6e4bcde97d4b164f/crates/intentosd/src/backend_bridge/turn_checkpoint.rs#L615)、providers_cli.rs、core.rs。

- 分离 max_model_rounds、max_tool_calls、max_wall_time、max_input/output_tokens、max_retries、max_cost（提供商支持时）。一轮多工具必须逐次计数，避免 max_tool_calls 被误作轮数限制。
- 预算跨模型切换、审批、恢复共享；禁止通过 max(2) 等恢复逻辑重新获得已耗尽的预算。区分审批等待时间与执行时间，保留实际全局上限。
- 执行耗尽预算时返回准确的部分结果、已执行副作用与可恢复原因。
- 将请求生命周期与任务目标状态分开，例如 request_status=finished, task_status=partially_completed, completed_steps, unresolved_goals, recovery_required。不能把 HTTP/RPC completed 当作目标全部完成。
- 更新现有 M1 第二组测试：第一轮变更、第二轮 502，应保留变更、熔断回退，并明确任务部分完成/需恢复；保持前端兼容。
- 复合任务必须保留所有子目标；最终根据执行证据判定完成、失败、部分完成或未知，不能仅根据模型回复判定。

### H08 渐进式认知解析

定位：[cognitive_parser.rs](https://github.com/lbg2002/intentos/blob/61619ce389adaa0fed1365ba6e4bcde97d4b164f/crates/intentosd/src/intent_engine/cognitive_parser.rs)、decision.rs、core.rs、turn_engine.rs。

现状：六类 StructuredIntent 已实现，但 core 主路由和 Quick Chat 主要调用同步本地解析；Fast LLM 路径已存在却主要为可选入口。不要继续堆叠专用关键词直到认知解析器变成第二个 router。

- L0：明确、完整、低风险单步指令保持本地快速执行；先区分“询问怎么做”与“要求执行”，不能把知识问题误作操作。
- L1：本地结构化目标、实时资源/项目/前台上下文、必要时 Fast LLM；仅在歧义或本地置信不足时额外调用模型。
- L2：复杂诊断、工作空间、复合目标可直接交由主 Agent 规划，避免重复调用 Fast LLM。
- 将 StructuredIntent 真正接入统一执行入口，输出 goal、子目标、约束、资源、候选能力及澄清需求；模型建议必须经 Schema、Policy 和真实状态校验。
- 目前 Fast LLM prompt 可包含最多 96 项能力描述，M2 后改为按目标检索少量候选能力。
- 不把启发式置信分数或模型自报概率当作已校准概率；利用实际用户纠正、拒绝、任务结果建立校准与回归集。
- 对“打开计算器”“音量调到20”保持 L0；“声音有点吵”先读取状态并合理调节；“继续昨天的工作”使用上下文；“修复软件启动异常”交 L2 并用证据验证。

### H09 缓存与性能剖析

定位：intent_engine/mod.rs、core.rs、broker_bridge.rs#L312、backend_bridge/detector.rs、turn_engine.rs#L485、db.rs、app_adapter、memory_hub。

1. **能力快照**：缓存 CapabilitySnapshot（版本、共享 descriptors、PatternCompiler、ToolSchemaCache、检索索引），在能力目录变更时更新。避免每次 RPC/复合分析/工具选取重新编译正则、克隆全部描述或先构建全量 Schema。
2. **后端快照**：当前 Quick Chat 每轮 await discover_backends_catalog。先测其中是否已有缓存以及命中情况；将阻塞式探测移出请求热路径。配置/程序路径变化刷新，模型列表 TTL + 手动刷新，API 健康检查异步运行，失败按需重探。防止后台探测风暴。
3. **文件/软件索引**：复用现有索引，采用增量扫描、事件失效、合理 TTL；不在每次输入时完整扫描或启动多个重复扫描。
4. **SQLite/I/O**：分析同步锁、事务次数、持久化脱敏、文件解析耗时；关键日志可靠写入，非关键统计可批量处理；阻塞 I/O 使用有界 worker/spawn_blocking，避免占用 Tokio 调度线程。保留 SensitiveDataGuard 的 OnceLock 正则缓存，不为性能跳过脱敏。
5. **基准**：先在同一机器、相同构建配置、同样数据/硬件模拟配置下运行旧基线和当前版；分别测冷启动与热启动、候选/解析/真实执行/数据库/模型探测/索引开销，输出 P50/P95/P99、样本量、RSS、CPU、工具 Schema Token、模型轮数和端到端完成时间。

### H10 统一流式协议与轻量运行时

定位：providers_http.rs、providers_cli.rs、runtime.rs、desktop/gnome-extension、desktop/gtk-fallback、web_ui。

- 统一 AgentEvent：Started、GoalResolved、MessageDelta、ToolStarted、ToolCompleted、AwaitingApproval、Progress、Completed、Failed、Cancelled 等。前端订阅真实事件，不模拟工具已经执行的假进度。
- HTTP 支持真实流式响应及工具调用增量解析；非流式 provider 允许诚实降级。统一取消、连接重建、事件序号、背压、重放保护与敏感数据处理。
- CLI 当前每轮重启子进程并重复传输 prompt 历史；优先使用支持持续会话的 SDK/协议或受控 Worker，避免不必要的重复启动。使用按需启动、空闲回收，不让所有后端长期驻留。
- 三端统一任务协议和显示状态；GNOME Shell 内不得进行阻塞索引、扫描、模型请求等工作，交给守护进程。
- 测量首个真实事件/首 token、端到端任务耗时、CLI 启动次数、上下文大小与空闲资源。

---

## 4. M2 实施任务：真正提升开放式任务能力

现有 [ROADMAP_v0.2.md](ROADMAP_v0.2.md) 的 Issue #6–#9 为主线。完成 H01–H06 的关键安全边界后逐项接入，禁止创建与统一执行器并行的新 Agent。

### M2-A 动态能力发现（#6）

- 提供 capability.search、capability.describe、capability.invoke、app.discover、task.verify 等元工具，并补充 resource.resolve。
- 初始只暴露少量元工具和高频必要工具；检索返回候选 ID、摘要、适用范围、风险与可用性；需要具体能力时按需读取 Schema。
- 既支持运行中重新发现能力，也支持逐渐扩展工具集合，不受初始 Top 12 + 固定工具限制。
- 统一 Core L2、Quick Chat、CLI Bridge 的工具目录和检索；使用现有 capability-sdk/YAML、app_adapter 的真实能力，避免重复注册。
- capability.invoke 不能成为万能逃逸入口；解析 canonical ID、校验 Schema、权限、参数、作用域、effect、幂等、预算、审批与验证。
- 对工具检索和描述缓存版本化，限制结果规模，避免将敏感资源数据作为目录内容自动发给外部模型。
- 验收：一个任务先找文件，途中才发现需 PDF 解析及生成清单能力，能够动态获取、调用并验证；初始工具 Schema Token 相比旧基线目标下降至少 50%，同时评估额外检索轮数、总体任务成功率与耗时。

### M2-B 通用资源解析与 WorldState

- 在 resource.rs、memory_hub、intent_engine/context_resolver.rs 上复用统一 ResourceResolver，返回 ResourceRef（稳定 ID、kind、URI、display_name、project_id、source、confidence、last_verified_at）。
- 解析当前窗口、选中文本、当前工作目录、文件/文档、活跃应用、项目、最近实验结果和会话指代；对多个匹配项给出合理候选而非随意选择。
- 引入轻量 WorldState：desktop、active_project、running_apps、resources、system_health、network、pending_tasks、updated_at；采用事件驱动更新与按需刷新，附来源与数据时效。
- 不持续收集所有窗口内容、剪贴板或输入；只在用户授权和实际任务需要时获取，隐私策略贯穿。
- 可通过现有 GNOME 扩展/D-Bus/资源索引提供状态；Wayland 环境无法读取的状态明确 unavailable，不伪造焦点或位置。
- M3 继续扩展项目记忆、工作空间、技能复用，M4 复用 WorldState 做主动调度，避免各模块重复探测。
- 验收：“把它关掉”定位真实前台对象并按风险处理；“比较昨天与前天的实验结果”解析两个真实资源；状态过期时刷新，资源歧义时澄清。

### M2-C 受控通用终端（#7）

- CommandProposal：program、argv、cwd、purpose、expected_effect、required_paths、network_access、timeout 等；使用参数数组而不是拼接 shell 字符串。
- C0 只读系统诊断；C1 范围受限读取；C2 可逆修改（预览/审批/备份）；C3 系统修改（单独审批/受控 Polkit）；C4 禁止（无边界 root、凭据/禁区等）。
- 不只检查命令名：可信本地风险分类须审查参数、路径、子命令、可执行文件身份、环境、网络、重定向、解释器与间接执行。不能把 bash -c、任意 Python/Node 代码、构建脚本等无条件列为只读。
- 采用真实 OS sandbox、最小文件/网络权限、超时、输出上限、进程树取消及结果验证；高风险变更不能通过模型自报 effect 降级。
- 常用功能继续使用原生能力；长尾问题由受控通用终端补充；复杂领域任务采用专门 Provider。避免为每条 Linux 命令写 YAML。
- 验收：只读 df/free/限定目录的 rg 等可用；已授权目录诊断正常；危险参数、符号链接逃逸、间接执行、未授权网络/写入被阻止。包安装/服务变更必须审批并验证，不宣称所有系统修改可撤销。

### M2-D 真实系统诊断（#8）与软件 Provider（#9）

- 诊断能力优先复用已有实现，统一暴露 system/process/logs/dependency/service/package/network inspect、repair.plan、repair.verify 等能力。
- 诊断任务走“获取真实证据 → 分析原因 → 生成方案 → 授权修改 → 验证结果 → 记录经验”；不能仅返回猜测，不能在用户只问原因时擅自修改。
- 软件 Provider 从 app launch/focus 转向真正的工作能力。优先使用原生 API、CLI/headless、D-Bus/MPRIS/SNI、URI/.desktop、文件格式直接处理、AT-SPI 等适用通道；无可靠通道时诚实引导。根据实际软件能力选择通道，不能假设 WPS 等提供全部接口。
- 每种通道定义 capability availability、执行前提、参数、权限、结构化结果、验证和撤销。执行成功但无法确认时返回 RequestedUnverified，不能盲目换通道重试产生副作用。
- GUI 操作优先语义控件树；不将全屏截图+像素坐标盲点作为主方案，Wayland 权限明确。
- 重点完成六个真实任务场景：电脑卡顿诊断、应用启动/依赖故障、个人文件整理、Git 项目辅助、网络/代理/云盘诊断、论文文档与研究资料处理。每个用真实环境状态定义成功条件。

---

## 5. 测试矩阵与验收标准

新增 M1.1 专项集，例如 crates/intentosd/tests/e2e_v0_2_m1_1.rs；单元测试按模块放置，实际命令和文件名由实现者结合现有结构确定。

| 用例 | 预期 |
|---|---|
| 同一 turn_id 10 次并发 | 实际执行一次 |
| 同一 ID 不同请求/会话 | 拒绝冲突，不共享私有结果 |
| 修改后进程崩溃 | 恢复检查识别已发生变更，不盲目重放 |
| 读取→修改→读取 | 第二次获得真实新状态 |
| 连续两次相对修改/下一首 | 两个逻辑步骤均执行 |
| 同一步骤重复提交 | 去重且保留真实结果 |
| 工具执行后验证失败 | Unknown/RecoveryRequired，不谎报无副作用 |
| EphemeralReadOnly | 允许授权记忆读取、零私有任务/历史持久化 |
| StrictIsolated | 零长期记忆读写；恢复/缓存/外发不泄露 |
| HTTP/CLI 仅对话 | 不允许系统工具 |
| 真实 CLI 原生工具绕过测试 | 未授权写入、命令、禁区、网络被阻止 |
| Pi Worker 中途失败 | 不重复执行已完成操作 |
| 多工具一轮、跨多次审批 | 工具/轮次/时间预算持续计数 |
| 先变更再 HTTP 502 | 部分完成/恢复提示，保留 ChangeSet |
| 复合指令含无法解析子句 | 保留未决子目标，不静默丢步 |
| 动态工具中途发现 | 新能力可正确调用且通过策略 |
| WorldState 状态失效/资源歧义 | 刷新或澄清，不凭空选择 |
| 多前端流式与取消 | 真实状态一致，停止后无新副作用 |

建议测试层次：纯单元测试 → Mock provider E2E → 故障注入/并发 → 真实 CLI/模型 → Ubuntu/GNOME 桌面实机。Mock 和模拟硬件结果必须单独报告。

### 建议性能门禁（目标值，不是已测结果）

| 指标 | 建议目标 |
|---|---:|
| 本地候选 P95 | ≤ 10 ms |
| L0 意图解析 P95 | ≤ 10 ms |
| 常见本地设置执行 P95 | ≤ 50 ms |
| 快捷键唤醒至可输入 | ≤ 100 ms |
| 已缓存能力检索 P95 | ≤ 15 ms |
| 模型切换 UI 响应 | ≤ 100 ms（异步加载列表） |
| Rust 守护进程空闲 RSS | ≤ 80 MB |
| 原生悬浮窗空闲 RSS | ≤ 80 MB |
| 空闲 CPU 平均 | ≤ 0.5%（明确采样区间和 CPU 口径） |
| 初始工具 Schema Token | 比旧基线减少 ≥ 50% |
| 重复副作用/未授权高危执行 | 0 |

指标需按硬件、冷/热状态、构建配置、是否真实设备、文件规模分别记录；真实 OS 调用/模型网络延迟单独分项，不与纯解析延迟混淆。门禁不达标时先定位原因，记录取舍，不虚构结果或损害安全。

建议命令（按仓库实际配置执行）：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
/usr/bin/python3 desktop/settings/intentos-settings.py --smoke-ui
/usr/bin/python3 desktop/gtk-fallback/intentos-launcher.py --smoke-ui
```

并按 intentosctl 的实际 CLI/help 运行现有 eval suite 与新增基准，不猜测未存在的参数；补充真实后端隔离验证、并发、故障注入以及 GNOME 50/Wayland smoke 测试。

---

## 6. 后续 M3/M4 与长期纪律

沿用 ROADMAP_v0.2.md，不提前大规模实现。M2 结束后：
- M3：M0–M4 记忆与重要性/项目作用域驱动召回，个人工作空间增量恢复，成功轨迹沉淀技能；不自动继承历史授权。将 WorldState 与项目记忆区分：一个是当前环境事实，一个是持久历史与用户偏好。
- M4：真实事件总线、持久化调度、防抖、去重、低功耗自动任务；修复 drive_scheduler.rs 中真实 settle_seconds 防抖逻辑；设置中心从 11 页收敛为 5 个核心域+高级折叠。
- AgentBench：以环境状态验证的 Goal Success Rate 为主指标，覆盖语义理解、复杂任务、个人智能、安全/恢复。增加未解析子目标、无效工具、恢复率、误操作、无关记忆、重复副作用、首响应、总耗时与资源占用。
- 暂不开发自有模型、Linux 内核、桌面合成器、重型多 Agent 群聊、重型数据库、全屏视觉盲点操作或重复办公软件。保持轻量、极简、用户态可卸载。

## 7. 建议提交顺序与交付清单

- [x] H01：原子 turn 注册、请求身份绑定、并发测试。
- [x] H02：工具幂等策略、读取刷新与相对操作测试。
- [x] H03：持久化步骤日志、未知副作用、崩溃恢复测试。
- [x] H04：真实 CLI/SDK 隔离、统一只对话策略、实测证明。
- [x] H05：完整三态 privacy context 与全链路测试。
- [x] H06：收敛全部 Agent 执行入口、旧路径迁移与故障注入。
- [x] H07：全局预算、部分完成与目标验证、协议兼容。
- [x] H08：渐进式认知决策，减少重复推理与硬编码。
- [x] H09：性能基线、能力快照、模型发现缓存、I/O 优化。
- [x] H10：真实流式事件、Worker 按需复用、三端交互。
- [x] M2-A：动态能力元工具、渐进 Schema 暴露。
- [x] M2-B：ResourceResolver + WorldState。
- [x] M2-C：受控终端执行。
- [x] M2-D：系统诊断与软件 Provider 六种真实任务闭环。
- [x] 更新 PROGRESS.md、评测报告与实际验收结果；公开未完成项、已知限制和回归风险。

**最终交付要求**：不仅能识别用户指令，还能实际完成“恢复论文工作环境、检查昨天的实验结果、整理新增文献、给出今天优先事项”等复杂目标；每项子任务有实际证据、明确的部分失败语义、可控权限与适用的撤销/恢复机制。此验收场景不应被硬编码成专用关键词或虚假成功路径。

---

## 8. 实施完成状态、提交记录与同机性能对照实测

### 8.1 线性提交记录（`H01`–`H10` 与 `M2-A`–`M2-D`）

所有加固与 Milestone 2 架构任务已按线性顺序合入 `main` 分支，全量遵守 `#![forbid(unsafe_code)]` 且所有能力执行 100% 经过 `CapabilityBroker` + `PolicyEngine` + `TurnEffectLedger` + `ChangeSet`：

| 阶段 / 编号 | Commit SHA | 提交摘要与核心闭环内容 |
|---|---|---|
| 基线 (`Baseline`) | `cf9e649` | `docs: add M1.1 hardening and M2 agent implementation task specification` |
| `H01` | `afd8c18` | `fix(h01): atomic turn registration, request identity binding, and concurrency guard` |
| `H02` | `7515373` | `fix(h02): capability-semantic idempotency policies, read invalidation, and step identity` |
| `H03` | `a5ac6e7` | `fix(h03): persistent step execution ledger, unknown side-effect halt, and restart recovery` |
| `H04` | `85e7524` | `fix(h04): real OS sandbox isolation for external CLI agents, stdin prompt pipe, and unified chat-only enforcement` |
| `H05` | `7fd5930` | `fix(h05): propagate three-state ExecutionContext privacy policy end-to-end` |
| `H06` | `3b2b4e9` | `refactor(h06): unify Core L2 and Quick-Chat execution spine with shared ledger and P0 fault-injection suite` |
| `H07` | `0f46c11` | `feat(h07): global multi-dimensional budget tracker and honest partial/recovery task status` |
| `H08` | `9054506` | `feat(h08): progressive L0/L1/L2 cognitive decision, compact Fast-LLM retrieval, and calibration` |
| `H09` | `31f2c38` | `perf(h09): versioned CapabilitySnapshot, non-blocking BackendCatalog cache, and I/O hot-path optimization` |
| `H10` | `a862ba3` | `feat(h10): unified AgentEvent streaming protocol, SSE incremental parser, and warm worker reuse` |
| `M2-A` (`#6`) | `ad5a8cb` | `feat(m2-a): dynamic capability discovery meta-tools and progressive schema exposure` |
| `M2-B` (`#7`) | `9cdb9fb` | `feat(m2-b): unified ResourceResolver and privacy-gated WorldState with Wayland honesty` |
| `M2-C` (`#8`) | `973f452` | `feat(m2-c): C0-C4 controlled terminal CommandProposal classifier and sandboxed executor` |
| `M2-D` (`#8`, `#9`) | `0ae73e1` | `feat(m2-d): real Linux diagnostic capability suite and 5-tier SoftwareCapabilityProvider` |
| `M2-E2E` | `4896679` | `test(m2): add comprehensive M2 and open-ended research synthesis E2E suite` |
| `M2-B Fix` | `8f17a02` | `fix(m2-b): exclude clipboard destination phrases from read-from-clipboard deictic check` |

### 8.2 验证覆盖矩阵（严格区分仿真/Mock 测试与宿主机真机实测）

1. **Workspace 自动化测试全量通过（`226 / 226`，`0 failed`）**：
   - 单元测试（`174` 项）：`intentos_capability_sdk` (`2`)、`intentos_fsops` (`6`)、`intentos_protocol` (`4`)、`intentos_sandbox` (`4`)、`intentosd` (`158`)。
   - 集成与端到端测试（`52` 项）：`e2e_poc` (`2`)、`e2e_v0_1` (`5`)、`e2e_wave2` (`2`)、`e2e_wave3` (`4`)、`e2e_wave4` (`4`)、`e2e_wave5` (`4`)、`e2e_v0_2_m1` (`8`)、`e2e_v0_2_m1_1_p0` (`12`，覆盖并发防串扰、语义幂等、步骤 WAL 崩溃恢复、CLI 沙箱与 `ExternalChatOnly`、三态隐私零落盘、跨运行时 `TurnEffectLedger` 防重放)、`e2e_v0_2_m1_1_p1` (`6`，覆盖 `AgentEvent` SSE 流、UTF-8 多字节流式分片、密钥实时脱敏、流中断取消、Warm Worker 复用与隔离)、`e2e_v0_2_m2` (`5`，覆盖动态能力中段解锁、`WorldState` Wayland 诚实消解与双资源对比、`C0`–`C4` 受控终端、6 类真实诊断/软件任务闭环及开放式论文研究工作区综合目标 + `Undo` 回退 + 部分失败诚实语义)。
   - **诚实边界说明**：端到端套件中的大模型多轮推理采用本地隔离 HTTP/SSE 网关（Deterministic Mock Upstream）驱动多轮 `tool_calls`，以确保离线 CI 可重现；而所有底层系统效应（`SYS_openat2` 文件事务、`bubblewrap 0.11.1` 命名空间隔离、`/proc` 采样、双环境 `ldd` 动态库冲突分析、`git` 仓库状态、TCP 代理活性探测、`.docx` ZIP/XML 章节读写与字节级 `Undo` 还原）均为 **100% 宿主机真实执行，零假成功返回**。
2. **宿主机真机实测环境**：
   - 硬件与内核：`AMD Ryzen 7 4800H (8C/16T)`，`30,941 MiB RAM`，`Ubuntu 26.04.1 LTS (Linux 7.0.0-43-generic x86_64)`。
   - 桌面与沙箱：`Wayland` + `GNOME Shell 50.1`，`bubblewrap 0.11.1`（非特权 User/Mount/Net/PID Namespace 实测可用），`rustc 1.96.0`，`Python 3.14.4`（系统 GTK4 / Libadwaita）。

### 8.3 同机 `--release` 性能基线与交付后实测对照（`cf9e649` vs `v0.2-M2` `8f17a02`）

#### （1）首轮工具 Schema 与认知提示词开销对照（M2-A 渐进式暴露 + H08 紧凑检索）

> 注：在已注册能力规模从 `cf9e649` 的 **96 项**（`87 YAML + 9 AIOS`）扩展至 **119 项可发现能力**（`95 YAML + 9 AIOS + 15 SoftwareCapabilityProvider + 6 Meta-Tools`）的前提下，首轮上下文开销实现大幅下降：

| 指标项（代表性复合语句：`帮我查找文档里的周报并把音量调到30%`） | `cf9e649` 基线 | `v0.2-M2` (`8f17a02`) | 变化幅度 |
|---|---:|---:|---:|
| Quick-Chat 首轮 OpenAI `tools` JSON 字节数 | `15,672 B` (`29` tools) | **`3,474 B`** (`11` tools: `5` direct + `6` meta) | **`-77.83%`** (目标 `>= 50%`) |
| Quick-Chat 首轮 OpenAI `ceil(B/4)` / BPE 近似 Token | `3,918` / `6,783` tok | **`869` / `1,717` tok** | **`-77.82%` / `-74.69%`** |
| Quick-Chat 325 条语料首轮 OpenAI `tools` 平均字节数 | `15,747.8 B` | **`3,218.1 B`** (`min 2,061 B, max 5,076 B`) | **`-79.56%`** |
| Quick-Chat 首轮 Anthropic `tools` JSON 字节数 | `14,831 B` | **`3,155 B`** | **`-78.73%`** |
| CLI 受控桥接 `<intentos_tool_call>` 协议提示词字节数 | `5,929 B` | **`2,393 B`** | **`-59.64%`** |
| Core L2 首轮 OpenAI `tools` JSON 字节数（vs 全量 96 工具） | `38,351 B` (`96` tools) | **`3,474 B`** (`11` tools) | **`-90.94%`** |
| Core L2 首轮 OpenAI `tools`（vs 原生循环 36 工具过滤） | `17,804 B` (`36` tools) | **`3,474 B`** (`11` tools) | **`-80.49%`** |
| Core L2 `pi-adapter` `RunRequest.tools` JSON 字节数 | `35,375 B` | **`3,133 B`** | **`-91.14%`** |
| Fast LLM `cognitive_parser` `cap_catalog` JSON 数组 | `9,612 B` (`87` caps) | **`956 B`** (`Top-12` caps) | **`-90.05%`** |
| Fast LLM `cognitive_parser` 完整 `messages` 载荷字节数 | `11,811 B` | **`2,066 B`** | **`-82.51%`** |

#### （2）热路径阶段延迟、官方 325 条基准评测与守护进程资源占用对照（`--release`）

| 维度 / 实测指标 | `cf9e649` 基线 (`--release`) | `v0.2-M2` (`8f17a02`, `--release`) | 门禁 / 对照结论 |
|---|---:|---:|---|
| `build_quick_chat_openai_tools` P50 / P95 / P99 (Cold) | `23.73 / 27.05 / 41.62 ms` | **`0.32 / 0.47 / 0.66 ms`** | **`-98.6%` (`73.6×` 提速)** |
| `build_quick_chat_openai_tools` P50 / P95 / P99 (Warm) | `24.00 / 31.86 / 41.60 ms` | **`0.29 / 0.42 / 0.56 ms`** | **`-98.8%` (`83.3×` 提速)** |
| `parse_structured_intent` 本地结构化解析 P50 / P95 / P99 | `23.22 / 28.41 / 45.95 ms` | **`0.38 / 0.67 / 1.08 ms`** (Warm `0.35 / 0.65 / 0.78 ms`) | **`-98.4%` (`61.5×` 提速，消除重复编译)** |
| `CapabilitySnapshot::search` 动态检索 P50 / P95 / P99 | N/A（新增动态检索索引） | **`0.024 / 0.052 / 0.064 ms`** (Warm `23.4 / 47.1 / 61.5 µs`) | 远优于 `< 0.5 ms` 目标 |
| `router.route_text` L0 解析路由 P50 / P95 / P99 (Warm) | `2.04 / 4.96 / 7.01 ms` | **`1.88 / 5.26 / 5.77 ms`** | 保持 ~`2 ms` 亚感知水平 |
| 实时候选刷新 `query_candidates` P50 / P95 / P99 (Warm) | `2.70 / 5.52 / 8.32 ms` | **`2.53 / 5.82 / 6.22 ms`** | 远优于冻结门禁 (`P50 <= 12 ms, P95 <= 30 ms`) |
| 官方 `intentosctl eval` 总体准确率 (`N=325`) | `99.69%` (`324/325`) | **`99.69%` (`324/325`)** | 零回归（远高于 `>= 88%` 门禁） |
| 官方 `intentosctl eval` 日常 L0 覆盖率 (`N=284`) | `100.0%` (`284/284`) | **`100.0%` (`284/284`)** | 零回归（`>= 85%` 门禁） |
| 官方 `intentosctl eval` L0 执行延迟 P50 / P95 (Cold) | `6.25 / 69.02 ms` | **`6.52 / 75.93 ms`** | 远优于冻结门禁 (`P50 <= 120 ms, P95 <= 300 ms`) |
| 可逆变更集 `Undo` / 虚假成功数 / 红队门禁 (`RT-01`..`16`) | `6/6` / `0` / `16/16` | **`6/6` / `0` / `16/16`** | 100% 通过 |
| `intentosd` 独立守护进程冷启动 / 热启动就绪耗时 | `229.43 / 233.44 ms` (`96` caps) | **`235.70 / 253.13 ms`** (`104` caps) | 保持 ~`240 ms` 极速就绪 |
| `intentosd` 空闲常驻物理内存 `VmRSS`（静置 3s） | `23,268 kB` (`22.72 MiB`) | **`24,760 kB` (`24.18 MiB`, `RssAnon 6.0 MiB`)** | 远低于 `<= 80 MiB` 预算 |
| `intentosd` 10 秒静置 CPU 占用率 | `0.00%` (`0` ticks / `10s`) | **`0.00%` (`0` ticks / `10.01s`)** | 远低于 `<= 0.5%` 预算 |
| GTK4 `intentos-settings.py --smoke-ui` 冷 / 热耗时 | `483.12 / 455.22 ms` | **`424.73 / 402.42 ms`** (`VmRSS ~92.4 MiB`, `11` 页 `0` 警告) | 全 11 页构建与 CSS 校验通过 |
| GTK4 `intentos-launcher.py --smoke-ui` 冷 / 热耗时 | `399.55 / 379.99 ms` | **`379.16 / 361.50 ms`** (`VmRSS ~85.4 MiB`, `36` 实时模型) | 主题/审批续接/语音按钮校验通过 |

### 8.4 未完成项（后续 `M3`/`M4` 规划）、已知限制与回归风险披露

1. **Wayland 活动窗口焦点读取边界**：在 Ubuntu 26.04 原生 Wayland 会话下，若 GNOME Shell 扩展未上报近期（`<= 15s` TTL）焦点窗口提示，合成器安全隔离禁止任意后台进程静默嗅探全局前台窗口；此时 `WorldState` 诚实返回 `FocusWindowConfidence::UnavailableOnWayland` 并触发澄清询问，绝不猜测或误关后台应用。
2. **闭源桌面软件内部动作边界**：针对微信、QQ、百度网盘等无公开 D-Bus / CLI 接口且 AT-SPI 无障碍树未暴露语义控件的内部操作，`SoftwareCapabilityProvider` 严格停留在第 5 级 `HonestGuidance`（返回可操作的人工步骤说明，`action_executed: false`），绝不采用全屏截图视觉坐标盲点点击。
3. **L0 尾部执行延迟构成**：`intentosctl eval` 的 L0 执行 P95（`~75.9 ms`）主要由外部系统工具子进程（如 `powerprofilesctl`、`apt-cache`、`ss`）的 OS 调度开销决定，Rust 核心路由与策略仲裁本身小于 `3 ms`。
4. **后续 `v0.2-M3` / `v0.2-M4` 待推进事项**：
   - `M3`：分层长期记忆（`M0`–`M4`）重要性与项目作用域检索、跨天工作区增量恢复快照、经成功验证轨迹的候选技能沉淀（不自动继承历史高危授权）。
   - `M4`：低功耗事件总线、持久化定时/事件防抖调度（完善 `drive_scheduler.rs` 真实 `settle_seconds` 等待语义）、设置中心从 11 页向「5 核心域 + 高级折叠」收敛及 `IntentOS-AgentBench` 全量评测集建设。
