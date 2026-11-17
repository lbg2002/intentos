# P0 沙箱 Landlock 凭据泄漏与默认拒绝（2026-11-17）

原始证据：GitHub Actions `44036688627`，被测代码 `b219cf863fe735c2fc590d65f0236347799fcb58`，L1 full workspace。

原始安全测试 `crates/sandbox/src/lib.rs::tests::sandbox_enforces_readonly_workspace_private_tmpfs_and_credential_masking` 实测 `driver=Landlock` 时输出 `SECRET_LEAKED`，证明对 mock_home 父目录授予 Landlock READ 会暴露 `.ssh/id_ed25519` 子文件。该模式不能提供挂载命名空间中的私有 /tmp 或目录内凭据 bind-mount 遮蔽。**这是已观察的安全缺陷，非 skipped / 环境缺失。**

安全修复：现有通用 `build_sandboxed_command_with_mounts` 在未通过 Bubblewrap userns 探针时直接 `SandboxError::Setup`，不降级到 Landlock、NodePermission 或 ProcessCleanEnv。终端执行复用此构造器，保持相同拒绝边界。旧 Legacy fallback 代码暂保留但不执行，不提供外部开启开关。新增 `sc10_landlock_does_not_silently_downgrade_credential_isolation` 负向纯逻辑测试。**不修改旧安全测试断言**；原测试缺 bwrap 环境依然不能获得成功结论。

尚无真实 bwrap/userns Ubuntu L2 正向对照，本 P0 不视为 fully verified。对受影响的 worker/CLI 功能降级为拒绝执行并提示安装/启用 Bubblewrap；用户应在可恢复 Ubuntu VM 验证正常工作区访问、越界密钥拦截、文件写与 TCP 隔离、禁用认证 socket、临时目录隔离及取消后孙进程情况。