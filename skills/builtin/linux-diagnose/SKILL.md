---
id: linux-diagnose
name: Linux 系统资源与端口诊断向导
version: "0.1.0"
trust: builtin
effects:
  - observe
allowed_capabilities:
  - disk.free
  - disk.usage
  - process.list
  - port.inspect
  - network.status
  - network.ip
  - power.battery.status
  - terminal.handoff
---

# Linux 系统资源与端口诊断向导 (`linux-diagnose`)

## 定位与安全约束 (§11.4)
- 优先使用结构化确定性能力完成本地诊断：
  - 端口占用：`port.inspect`
  - 磁盘剩余与目录体积：`disk.free`、`disk.usage`
  - 高内存/CPU 进程采样：`process.list`
  - 网络连通性与本机 IP：`network.status`、`network.ip`
- 当用户需要需要管理员权限或复杂管道日志过滤（如 `journalctl`、`dmesg`、`systemctl status`）时，必须通过 `terminal.handoff` 返回建议命令与中文风险解释，**绝不代用户执行特权命令或索取 `sudo` 密码**。
