# SC-09 审批安全体验增量

基线 c89fbbac，分支 sc/system-control-05-10-20261117。变化：Web ResultSurfaces 中审批 capability ID/资源 capability ID 改用 DOM textContent，diff_preview 原有 textContent 保留；终端批准只允许本次，既隐藏批量批准按钮，也在服务端 PolicyEngine/GrantEnvelope/恢复 RPC 做强制拒绝，旧持久化 wildcard envelope 对 terminal.execute 无效。

本次未运行 GNOME Wayland/X11、GTK 读屏/键盘/双屏/缩放测试，未对含凭据脚本的 DB/event/export 运行 V15，故 **blocked**。政策单测追加 wildcard/directory grant 不得覆盖 terminal.execute（需 Cargo CI）；不能以 UI 隐藏按钮代替服务端安全验证。

风险：续跑检查仅覆盖会话模式入口；旧任务与所有客户端需完整回归。SC-03 冻结能力未交付，脚本默认拒绝。