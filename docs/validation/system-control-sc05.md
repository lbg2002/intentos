# SC-05 软件动作矩阵增量验证（2026-11-17）

基线：上一批 c89fbbac；实现分支 sc/system-control-05-10-20261117。新增接口：`module_rpc(domain=app_adapter, action=get_compatibility_matrix, payload={query?,app_id?,limit?,force_refresh?})`。返回 schema_version=1, actions[], count, source。查询不会执行动作，也不接受任意扫描目录或客户端提交认证标签。

设计：枚举桌面项与动作声明不等于软件动作完成。所有记录认证初始为 `unverified`，版本缺失为 `null`；Snap/Flatpak 额外保留接口授权待核验限制；旧客户端只读响应字段兼容且无新数据库表。动作执行继续使用原 Broker/Policy/Provider，不增加直接执行入口。

新增 3 个 Rust 测试：发现不自动认证、Flatpak/Snap 约束、schema JSON 兼容。**测试结果：blocked / 未执行**（当前执行容器缺 cargo/rustc，GitHub CI 状态另行检查）。V08/V10 真机与 RequestedUnverified 通道回退仍需 Ubuntu 24.04 + Wayland/X11 验证。任何动作不得仅依据矩阵 `unverified` 宣传“已认证”。