# SC-03 脚本安全门禁（2026-11-17）

基线 d0b9f56；SC-01/02 后分支 sc/system-control-20261117。因未实现冻结脚本 artifact，批准后源脚本可变是关键安全缺口。本提交不声称完成冻结；采取 fail-closed：阻断工作区脚本与解释器直接执行，使新批准无法启用未冻结脚本。

新增分类负向测试 `sc03_unfrozen_scripts_fail_closed_before_any_approval`，覆盖 bash 脚本、直接工作区脚本、python -m。**未执行**：环境无 cargo/rustc。V01–V05、隔离、密钥日志及旧审批兼容 **blocked**。不放宽已有安全断言。恢复原脚本执行能力的前置条件是实现可信不可变 artifact、完整审批摘要绑定、清理/隐私/迁移，并在合格 Ubuntu VM 跑过红队矩阵。