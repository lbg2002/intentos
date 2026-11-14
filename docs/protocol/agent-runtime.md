# IntentOS 可插拔智能体运行时契约 (`AgentRuntime` v1)

> 冻结依据：设计方案终版 §5.3、§6.3、§10.6、§24.4

## 1. 安全沙箱不变量

1. **零内置宿主工具**：`agent/pi-adapter` 不加载任何内置 `bash` / `edit` / `write` 工具，仅接收 `CapabilityBroker` 动态导出的结构化 `ToolSpec`。
2. **零 API Key**：Worker 环境变量经过 `env_clear()` 清洗，绝不注入任何云端模型密钥。
3. **零外网 TCP 权限**：
   - Ubuntu 桌面优先使用 `bwrap --unshare-net`（配合 AppArmor `userns` 配置）；
   - 容器或受限环境自动降级至 Linux 6.8+ **Landlock ABI v4**（拦截全部 `ConnectTcp` / `BindTcp` 并限制文件系统仅可见代码只读目录、`scratch_dir` 与 `gateway/` 目录）。
4. **唯一出网桥接**：Worker 仅通过 `INTENTOS_GATEWAY_SOCK`（HTTP over Unix Domain Socket）访问 `POST /v1/chat/completions`，并携带单次任务租约头 `X-IntentOS-Run-Token`。

## 2. Core → Worker（stdin JSON-RPC）

- `initialize`: 握手校验协议版本与特性列表
- `run`: 启动单轮规划，传入 `RunRequest`（含 `run_token`、裁剪后内存历史 `history`、带 `Taint` 与 `DataClass` 的 `context_blocks`、白名单 `tools` 与 `budget`）
- `tool_result`: 回传由 Rust `CapabilityBroker` 经策略引擎与 `openat2` 安全校验后执行的真实结果
- `cancel`: 立即取消指定 `run_id`

## 3. Worker → Core（stdout `RuntimeEvent` 流）

- `run.started`
- `usage.updated`（输入/输出 Token 计量）
- `tool.requested`（请求 Core 仲裁并执行结构化能力）
- `message.delta`
- `run.finished` / `run.failed` / `run.cancelled`
