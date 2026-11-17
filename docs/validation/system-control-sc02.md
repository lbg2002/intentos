# SC-02 实际验证记录

日期：2026-11-17。起点 d0b9f56；分支 sc/system-control-20261117。

修复用户安装与 Debian 安装之间 daemon、模块、技能与 worker 的路径不一致；移除对开发机绝对路径依赖。代码审查不等于安装验收。

当前执行环境没有 cargo、rustc、完整 Ubuntu systemd 登录会话，无法完成 V16 干净安装、重登录、升级中断、回退、保留数据卸载，全部标记 **blocked**，没有测试成功计数。

下一步在 Ubuntu 24.04 VM 执行 cargo fmt/clippy/test、bash -n 两个安装脚本、dpkg-deb 检查、从非源码 cwd 启动，systemctl --user is-active 验证、升级故障注入与卸载数据保留。