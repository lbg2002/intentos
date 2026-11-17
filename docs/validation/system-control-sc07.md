# SC-07 系统控制恢复冲突防护（2026-11-17）

基线：前批 c89fbbac + SC-05/06 分支。修复：之前 `CapabilityBroker::undo_changeset` 对 Setting 直接写回 before，若用户在之后改动该设置，Undo 会覆盖外部新值。现在对 ChangeOp::Setting 的记录 after 进行读回冲突检查，Conflict 状态保留，不写旧值。对多设置项先进行 preflight，再通过 settings checked-undo 二次检查。

单测 `sc07_conflicting_external_setting_is_not_overwritten_on_undo`：模拟先写 35 再写 80，旧 changeset Undo 必须拒绝，不覆盖 80。**尚未运行（本地缺 Cargo）**，GitHub L1 CI 结果另行查验；真实系统 V12 外部竞态及 V11 OS 认证需要 L2/L3。该 optimistic readback 无系统级原子 compare-and-swap，不能声称完全避免检查之后的竞态。

特权 helper 未实现，未开放 host sudo/root 操作，涉及重启服务/包安装仍保持禁止。无存储 schema 迁移；老 ChangeSet 内已有 before/after 字段，旧客户端读法不变。