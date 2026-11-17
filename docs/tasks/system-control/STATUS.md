# 工作包状态与交付记录

初始化日期：2026-11-17；基线：`355ebac`。本文件由开发智能体随真实交付更新。

状态：todo → in_progress → implemented_unverified → verified；可标记 blocked（同时说明已完成部分和阻塞依赖）。只有满足 ACCEPTANCE 才标 verified。

| ID | 工作包 | 依赖 | 状态 | 实现提交 | 验证证据/阻塞 |
| --- | --- | --- | --- | --- | --- |
| SC-01 | 分层验证与失败归因 | 无 | implemented_unverified | SC-01 分支提交 | CI/探针已写；历史13项未复测；L1/L2/L3/L4关键验证 blocked |
| SC-02 | 安装/打包一致性 | 退出需01 | implemented_unverified | SC-02 分支提交 | 路径静态修正；V16 干净 VM 安装/升级/卸载 blocked |
| SC-03 | 冻结脚本与审批摘要 | 01基础回归 | todo | — | 已有单命令输入不等于脚本冻结 |
| SC-04 | 取消/预算/崩溃恢复 | 03 | todo | — | 复用已有进程组和账本，补生命周期 |
| SC-05 | 软件动作契约/矩阵 | 01基础回归 | todo | — | 已有Provider需增量演进 |
| SC-06 | 代表软件真机认证 | 05 | todo | — | 需要实际软件版本与桌面会话 |
| SC-07 | 系统控制/有限特权代理 | 03/04 | todo | — | 分非特权与特权子包；特权默认关闭 |
| SC-08 | Bash复合计划 | 03/04 | todo | — | 不允许退化为裸bash -c |
| SC-09 | 审批与结果体验 | 03/05，特权依赖07 | todo | — | GTK/GNOME/Web逐项验收 |
| SC-10 | 集成/安全/性能发布 | 所发布范围全部包 | todo | — | 不将环境跳过计为通过 |

## 每次交付追加模板

```text
任务ID/状态：
审查基线SHA/实现提交SHA/分支：
完成的用户行为：
修改的接口、配置或存储：
实际测试命令、日期、环境、构建SHA：
通过/失败/未执行数量及原因：
真实隔离、真桌面与性能证据链接：
安全/恢复语义与兼容迁移：
剩余风险和默认关闭功能：
下一步任务/解除阻塞的条件：
GitHub提交或PR链接：
```

不要写“全部完成”替代明细。代码提交、验证提交、文档提交可不同，测试报告须明确被测代码SHA，避免把最后文档提交误当作重新运行过测试。

## SC-01（2026-11-17）

- 基线 `d0b9f56e1b3f454e6bda380f7d2ebe7ca223362b`，分支 `sc/system-control-20261117`；实现 probe / L1-L4 workflow / 固定工具链 / 历史失败归因台账。
- 本地实测：探针脚本 bash -n PASS；L1 blocked (missing rustc)；L2 blocked (missing bwrap)。无 Cargo、L2 OS、L3 GUI、L4 Release 行为验证。
- 完整证据：`docs/validation/system-control-sc01.md`；未达到验收，不得宣称 verified。后续非依赖任务可继续。


## SC-02（2026-11-17）

- 修复 Debian 服务 /usr/bin/intentosd 与用户安装 ~/.local/bin/intentosd 的布局差异；修复用户模块、worker、skills 搜索路径以及开发机路径硬编码。
- 安装器检测 systemd 用户服务 active；当前无 systemd 用户管理器时返回非零，不报告假成功。
- 静态审查完成，实际 Ubuntu VM 安装/升级/卸载、Rust 编译及真桌面验证 blocked。SC-01 门槛未达，不能标记 verified。
