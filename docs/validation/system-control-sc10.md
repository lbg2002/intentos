# SC-10 发布门禁与真实阻塞报告

日期 2026-11-17；基线 c89fbbac；开发分支 sc/system-control-05-10-20261117。新增 stdlib Python fail-closed 发布证据 gate，检查 STATUS 和每包 docs/validation/release/scNN.json 的声明：tested_sha、runner、command、测试层及 pass 标签。此 gate 不信任 skipped 标签，不产生授权，不做实际系统变更。

当前 Linux 容器实测：`python3 -m unittest -v scripts/test_sc10_release_gate.py` 对应 fixture 3/3 PASS；直接检查实际 STATUS 预期输出 release_allowed=false，退出码 2，不能称发布通过。证据 schema 仅做格式一致性检查，不能证明日志真实性或硬件条件；真实结果必须由可信 Ubuntu VM/GNOME runner 与人工审查支持。

本轮未运行 Release 独占性能、干净安装/升级、全套 V01–V17、L2/L3，也未消除原有 13 项测试失败。SC-03/04 仍受阻，SC-06 7 类软件认证为 unverified，SC-07 privileged helper 禁用，SC-08 仅静态草案，SC-09 跨客户端真机认证缺失。当前全功能发布 **BLOCKED**。

解除阻塞条件：SC-01/02 恢复并通过，逐项完成 SC-03/04；对发布范围执行全部安全红队与正向对照；每个候选软件/动作真机逐项录证；通过性能 SLO；维护者核查真实任务日志，再在 STATUS 标注 verified。不得通过删减测试/伪造证据让门禁通过。

发布门禁补强：每包必需 L1/L2/L3/L4 分层及对应 V01–V17 验收编号；SC-10 必须带 L4。合成的全绿 fixture 仅证明门禁并非永远拒绝，不能证明真实安全；还需对 runner 与实际日志人工审查。真实发布仍被 blocked。
