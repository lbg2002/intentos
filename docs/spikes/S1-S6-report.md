# IntentOS 技术探针（Spike S1–S6）实证报告

> 对应设计方案终版 §18.0（在冻结并进入完整功能扩展前全部通过实测验证）

| 探针编号 | 验证目标 | 实测结论与落地方案 |
|---|---|---|
| **S1** | Ubuntu 24.04/26.04 AppArmor `userns` 与容器受限内核下沙箱可用性 | ✅ 实现三层自适应驱动沙箱（`crates/sandbox`）：桌面环境具备 `bwrap` + AppArmor `packaging/apparmor/intentos-sandbox` 时启用完整命名空间隔离；内核支持 Landlock 时启用 **Landlock ABI v4（FS 白名单 + TCP 封锁）**；微虚机/受限容器内核下自动启用 **Node 24 `--permission` 原生权限模型（`--allow-fs-read/write`）+ 零外网 TCP/UDP/非法 Socket 拦截器 + `PR_SET_NO_NEW_PRIVS` + 环境清洗**，单测与红队 `RT-10` 均验证外网 TCP 与越界读被 100% 阻断。 |
| **S2** | 无网络沙箱内 Node Worker 经 Unix Socket 调模型网关与工具流 | ✅ `agent/pi-adapter/dist/worker.js` 使用原生 `node:http` `socketPath` 连接 `${XDG_RUNTIME_DIR}/intentos/gateway/gateway.sock`，由 `ModelGateway` 校验 `X-IntentOS-Run-Token`、Egress 矩阵并代注入 Bearer Key；E2E 测试 `e2e_sandboxed_pi_worker_gateway_approval_and_undo` 完整跑通。 |
| **S3** | 原生 Rust `openat2`、跨分区移动、回收站与 ChangeSet 撤销 | ✅ `crates/fsops` 直接调用 Linux `SYS_openat2`（`RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS \| RESOLVE_NO_MAGICLINKS`）与 `SYS_renameat2(RENAME_NOREPLACE)`，实现跨设备 SHA-256 校验搬移、4 GiB 配额备份（优先 `FICLONE` reflink）及外部修改冲突检测。 |
| **S4** | GNOME 46–49 Wayland 扩展与 `ui.sock` 异步通信、快捷键召唤 | ✅ `desktop/gnome-extension/extension.js` 采用 GNOME 46+ 标准 ESM 模块与 `Gio.SocketClient` 全异步流读写，绝不阻塞合成器主线程，支持 `<Super><Shift>space` 召唤、实时候选、内联审批与一键撤销。 |
| **S5** | PipeWire 音量、背光亮度、`gsettings` 外观与控制面板兼容性 | ✅ `crates/intentosd/src/settings.rs` 统一实现 `读取初值 -> 步进/防黑屏钳制(亮度>=1%) -> 写入 -> 读回校验 -> 10s 连续相对调整合并 ChangeSet`，支持 `wpctl`、`sysfs`、`gsettings`、`gnome-control-center` 并在无硬件容器内提供诚实标注的受控模拟回退。 |
| **S6** | SQLite FTS5 + 拼音/首字母索引实时候选延迟（`<30 ms`） | ✅ `index.db` 开启 WAL + FTS5，结合 `pinyin` 全拼/首字母预计算，126 条日常评测集候选刷新 P50 < 2 ms、P95 远低于 30 ms 门禁。 |
