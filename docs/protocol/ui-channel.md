# IntentOS 私有可信 UI 通道契约 (`ui-channel` v1)

> 冻结依据：设计方案终版 §10.5、§15.3、§24.4

## 1. 通道物理与身份隔离

- **Socket 路径**：`${XDG_RUNTIME_DIR}/intentos/ui.sock`（权限 `0600`，父目录 `0700`）
- **对端内核鉴权**：
  1. `intentosd` 对每条连接执行 `SO_PEERCRED`，校验对端 `uid == geteuid()`；
  2. 读取 `/proc/<pid>/cmdline` 与 `/proc/<pid>/exe`，硬拒绝任何来自 `pi-adapter` / `worker.js` / `intentos-agent` 的连接；
  3. Agent Worker 沙箱仅挂载 `${XDG_RUNTIME_DIR}/intentos/gateway/gateway.sock` 子目录，从文件系统层彻底不可见 `ui.sock`。
- **公共 D-Bus 边界**：`org.intentos.Core1` 仅暴露 `SubmitIntent`、`QueryCandidates`、`GetTask`、`ListTasks`、`GetStatus`；**绝不暴露** `approve`、`deny`、`undo`、`run_passthrough` 与凭据配置接口。

## 2. 报文封装（NDJSON）

每行一条 UTF-8 JSON 对象：

### 请求 `UiRpcEnvelope`

```json
{
  "id": "rpc_7f9c12ab",
  "method": "query_candidates",
  "params": { "query": "打开 vsc" }
}
```

### 响应 `UiRpcResponse`

```json
{
  "id": "rpc_7f9c12ab",
  "ok": true,
  "result": { "...": "..." },
  "error": null
}
```

## 3. 方法清单

| `method` | 用途 | 特权级 |
|---|---|---|
| `query_candidates` | 实时 `<30ms` 候选刷新（按键即查） | UI |
| `submit_intent` | 提交自然语言意图（支持可信 `$ ` 直通识别与消歧项选择） | UI |
| `approve` | 携带 `approval_id` + 一次性 `nonce` + 参数 `digest` 确认审批 | **仅私有通道** |
| `deny` | 拒绝并作废待审批单 | **仅私有通道** |
| `undo` | 按 `ChangeSet` 一键回滚文件或系统设置修改 | **仅私有通道** |
| `run_passthrough` | 执行用户亲手输入的终端命令直通 | **仅私有通道** |
| `list_tasks` / `get_task` | 查询任务状态机与步骤 | UI |
| `list_changesets` | 查询可撤销变更集列表 | UI |
| `get_status` / `probe_capabilities` | 查询守护进程健康度、索引统计与本机硬件后端能力 | UI |
| `reindex_resources` | 触发应用与授权目录文件增量重扫 | UI |
| `stop_all` | 紧急中断全部会话并吊销模型网关运行租约 | **仅私有通道** |
