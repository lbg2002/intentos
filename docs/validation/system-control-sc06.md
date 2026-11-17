# SC-06 代表软件认证探针报告

时间：2026-11-17；基线 c89fbbac，依赖 SC-05 的动作矩阵。实现仅提供 **只读证据采集工具**，不是软件认证成功记录。

`python3 -m unittest -v scripts/test_sc06_probe.py`：当前 Linux 容器实测 3/3 PASS（Python 3，有系统显示变量但不是可信 GNOME 用户会话）。`python3 scripts/sc06_certification_probe.py --desktop-dir /tmp`：产生 7 类 x 5 动作共 35 条，tested=0/passed=0，均标 blocked 或 not_installed_or_not_detected、unverified。该运行未打开任何应用或操作 GUI。

**真实场景均 blocked**：缺 Ubuntu 24.04/22.04/26.04 目标桌面、Wayland/X11 身份、最少 deb + Flatpak/Snap 样本、安装版本及窗口/资源操作证据。需逐动作认证：中文与空格路径、多实例、后台软件、MPRIS/SNI 超时、退出不误杀其他进程、显式正向对照。记录真实发行格式、软件版本、desktop_id、动作、目标证据与时间；未验证不得写入 certified。

`scripts/sc06_certification_probe.py` 不需要提权，`--output` 仅写指定报告文件。原应用执行仍必须使用 Broker/Policy，不通过探针启用动作。
