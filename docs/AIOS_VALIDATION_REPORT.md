# AIOS 本轮代码验证报告

本轮审查起点：`c34047f`。核心修复：`f06ad28`；稳定工具链整理：`b67d992`；最终评测脚本：`efae7d1`。方案见 [AIOS 代码审查与目标交付方案](AIOS_REVIEW_AND_DELIVERY_PLAN.md)。

## 环境与结论

Linux 6.18.57 云环境；Rust/Cargo 1.100.0；Node v24.22.1；使用既有本地工具链和 SQLite 库；无 DISPLAY/WAYLAND_DISPLAY；Bubblewrap 已安装但 userns 不可用，Landlock 探测不可用。评测使用 Debug 构建，与回归任务有资源竞争，不作为发布性能基准。

**本轮修复和新增回归验证通过，整体发布门禁未通过。** 不能用红队 16/16 掩盖真实 CLI/终端内核隔离用例失败；RT-10 本机驱动为 NodePermission，仅证明所运行探针的结果，不能代替 Bubblewrap/Landlock 强隔离认证。

## 命令与实际结果

命令在仓库根目录运行，并使用工作区既有工具链环境。

| 检查 | 实际结果 |
| --- | --- |
| `cargo fmt --all -- --check`、`git diff --check` | 通过 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 通过；Cargo 自身仍提示旧 manifest 的未使用依赖和未继承的 workspace `rust-version` |
| 最终评测调整后 `cargo clippy -p intentosctl --all-targets -- -D warnings`、`cargo build -p intentosctl` | 通过 |
| `cargo test -p intentosd --lib task_verify -- --test-threads=1`（无桌面环境变量） | 3/3，包括两项新增验证回归和原有多轮检索/写入/归档任务 |
| `cargo test -p intentosd --lib local_origin_tests -- --test-threads=1` | 2/2，包括来源矩阵和真实 HTTP 路由/公开监听拒绝 |
| `env -u DISPLAY -u WAYLAND_DISPLAY cargo test --workspace --no-fail-fast -- --test-threads=1` | 最终 **215/230 通过，15 失败**；进程退出 101，5 个测试目标失败 |
| 最终 `intentosctl eval --corpus eval/intents/v0_1_shell_300.json` | **324/325**，L0 覆盖 **284/284**，虚假成功计数 **0**，撤销 **6/6**，红队 **16/16**；延迟门禁失败，进程退出 1 |
| 两项 `/usr/bin/python3 desktop/... --smoke-ui`（无桌面环境变量） | 脚本明确返回 `skipped: no DISPLAY or WAYLAND_DISPLAY`；**未完成真实 GTK 验收** |

最终评测完整数据见 [Debug 评测报告](validation/aios-eval-debug.md)。候选刷新 P50/P95 为 48.29/241.83 ms，L0 执行 P50/P95 为 83.01/342.14 ms。未命中项为 `D5-14`「打开壁纸设置」的参数期望；总体门禁 FAIL。

初始核心库运行为 149 通过/9 失败，最终核心库为 153 通过/9 失败，新增 4 项全部通过，失败名称与初始库运行一致。初次完整运行为 214/230；最终为 215/230。`wave5_test2_deep_local_software_scan_9_categories_and_rich_translation` 首轮办公分类计数为零、第二轮通过，未改其断言或扫描实现，作为不稳定性保留排查。

## 未通过用例

下列用例全部保留原始断言，没有为了通过测试放松沙箱、权限、性能或验证条件。

- `backend_bridge::detector::tests::h09_discover_backends_catalog_fast_sub_ms_warm_coalesces_probes_and_invalidates_on_config_change`
- `backend_bridge::providers_cli::tests::cli_bwrap_sandbox_blocks_workspace_write_secret_dir_and_cmdline_leak_while_bridging_broker`
- `backend_bridge::providers_cli::tests::cli_chat_only_mode_omits_protocol_and_strips_forced_tool_calls_with_zero_broker_exec`
- `backend_bridge::tests::test_m1_cli_broker_bridge_executes_tool_call_and_suspends_on_pending_approval`
- `diagnostics::tests::m2d_scenario1_real_proc_system_bottleneck_and_synthetic_swap_zombie_detection`
- `terminal_agent::tests::anti_bypass_blocks_shells_inline_code_flags_symlinks_secrets_unauth_writes_and_tcp`
- `terminal_agent::tests::c0_df_and_free_succeed_in_real_bwrap_readonly_sandbox`
- `terminal_agent::tests::c1_rg_find_and_git_status_succeed_inside_authorized_tempdir_in_bwrap`
- `terminal_agent::tests::c2_reversible_write_requires_approval_snapshots_changeset_and_undoes_plus_redacts`
- `m1_test1_turn_engine_modularized_and_cli_broker_bridge_unifies_execution`
- `p0_10_chat_only_allow_broker_tools_false_blocks_system_tools_identically_on_http_and_cli`
- `p0_11_real_cli_os_sandbox_blocks_unauthorized_write_forbidden_read_and_cmdline_leak`
- `p1_05_h10_warm_pi_worker_reuse_incognito_isolation_and_idle_eviction`
- `p1_06_h07_h08_h09_end_to_end_synergy_and_sub_millisecond_warm_latency`
- `m2_test3_controlled_terminal_c0_c4_sandbox_and_anti_bypass`

## 后续验证与风险

- 在允许 userns 的 Ubuntu 主机重跑 Bubblewrap/CLI/终端安全用例；核实可信可执行路径、诊断 `df` 证据与 Warm Worker 行为。当前拒绝执行是安全边界生效，不能以移除边界来修复测试。
- 在独占资源、Release 构建下重测性能；当前两项严格时延断言失败，尚无证据断言 Release 达标，也不宣称本轮提速。
- 独立排查 `D5-14` 参数期望与软件扫描用例不稳定性；这些仍是待处理问题，不全部归因于沙箱。
- 在真实 GNOME/Wayland/X11/GTK 环境验证来源保护后的前端、审批、续接与撤销。HTTP 集成测试通过不等于真实桌面全平台通过。
- 本轮只落地方案 S0 的可信验证和入口/评测加固。M3/M4 的记忆生命周期、工作空间恢复、技能学习及后台事件总线仍按方案分阶段交付，没有标记已完成。
