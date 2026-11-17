# 接口与安全契约

本文件定义目标契约，不声称以下类型已经存在。开发者须先对照 `crates/protocol/src/lib.rs` 与现有接口复用/增量扩展，禁止创建同义平行类型。

## C1：命令和脚本身份

现有 `terminal.execute` 的 `command` 与 `program/argv` 互斥，command 只支持字面量单命令。保留现有客户端兼容；不得默默将不支持语法发送给 `bash -c`。

建议 `ExecutionPlanV1` 最小字段：version、plan_id、origin、steps、cwd、resource_scope、network_policy、timeout/output/disk_budget、verification_requirements。每步包含稳定 step_id、program_identity、argv 或 script_artifact_id、依赖和重定向。模型可提交提案，不得提交可信审批身份。

审批摘要必须绑定：规范化计划、执行身份、完整 argv、cwd、脚本字节 SHA-256、解释器身份、只读/读写路径、网络授权、预算、验证要求、过期时间与策略版本。摘要的序列化规则与字段排序固定；用户界面显示同一对象，避免展示和执行不一致。

脚本 artifact：从授权路径通过安全文件句柄读取、有大小上限、内容摘要和长度；存储在守护进程专用目录，以原子写入和拒绝 symlink 的方式建立。执行不可变副本，不重新读取原路径。不可变是针对模型/worker 权限边界，不夸称可抵御任意同 UID 宿主恶意进程。

解释器及 PATH 必须来自可信解析器；剥离 BASH_ENV、ENV、LD_PRELOAD、用户 rc/profile、认证 socket 和无关密钥。脚本依赖文件仍须受资源 scope 限制。批准后源文件改变不应改变执行内容；若计划选择“必须源文件未变”策略则拒绝执行并要求新批准，不得混用。

## C2：授权、取消与恢复

沿用 `PendingApproval` 的 nonce、digest、TTL 与单次消费机制。授权作用域绑定 session/task/step，UI 不能把模型传来的 approved=true 当作授权。拒绝、过期、重复消费、参数变化均无执行副作用。

状态遵循现有 Task/StepExecState：prepared → awaiting_approval → executing → applied/verified/failed/unknown/cancelled 的语义映射由协议变更说明明确。禁止借新增字段绕开旧状态机。

取消先阻断未启动依赖步骤，再终止受控进程组，等待退出与资源清理；已发生副作用记录为待核验。崩溃恢复不得自动重放 unknown 的写步骤。撤销只限真实记录的 ChangeSet，不能把任意 Shell 视为可逆事务。

脚本或网络修改不能静默得到会话永久授权。自动后台任务不扩大用户批准的范围。授权撤销必须影响尚未开始的动作。

## C3：软件动作契约

复用 `ProviderCapabilitySpec`、`CapabilityAvailability`、`ProviderExecutionOutcome` 与 `ExecutionChannel`。增量字段建议：app_id、package_format、observed_version、action_id、channel、environment_requirements、effect、approval_policy、verifier_id、undo_support、last_verified_build。

动作目录明确 launch/open/focus/status/quit 等各动作能力。发现软件、可请求动作、动作已发送、环境已验证是不同状态；不得只靠名称匹配或 exit=0 宣称目标完成。

通道重试只允许无副作用失败；收到 RequestedUnverified 后先核验，不盲切备用通道。所有通道同样经过 Broker。探测超时和失败不阻塞主 UI。

错误码至少区分：not_installed、unsupported_action、permission_required、sandbox_unavailable、desktop_unobservable、dependency_missing、timeout、verification_failed。用户消息可本地化，机器码稳定。

## C4：系统特权代理

优先通过已有系统 D-Bus/Polkit 动作，确需 helper 时采用固定动作白名单和强类型参数；绝不接受任意 shell、program 路径或未校验的 service/package 参数。

调用方需要独立认证，模型/worker 不可直接访问认证凭据或特权 socket。UI 意愿批准与 OS 身份认证是两层条件。动作与参数摘要都必须一致；重放、过期及伪造调用者必须被拒绝。

初版只选择一个真实需求动作做端到端，如“重启明确白名单的测试服务”。包安装另行设计可信仓库、包名、模拟影响和交互认证，不能通过批准任意 apt argv 一次解决。

## C5：验证、持久化与数据处理

证据记录：目标资源身份、检查器版本、预期谓词、观察值、时间、来源、结果与不可观察原因。模型描述不是证据。对路径检查与读取使用安全句柄降低 TOCTOU；校验输出大小、内容及文件类型，不只检查存在。

新增表/JSON 必须版本化和原子迁移；持久化错误上报。隐私模式在任务账本、脚本 artifact、输出、UI 历史和日志一致处理。脚本可能含凭据：审批可临时显示必要内容，禁止原文进入日志或遥测。脱敏不得改写实际执行字节；无法安全持久化则采用受限临时 artifact 并禁用跨重启恢复。

artifact 清理策略包含拒绝、过期、取消、完成、崩溃后回收；只清理专属目录且不跟随 symlink。运行中引用不得被后台清理删除。
