# SC-01 分层验证与历史失败归因台账（2026-11-17）

基线：`d0b9f56e1b3f454e6bda380f7d2ebe7ca223362b`。旧记录：219/232 通过、13 项失败，来自 `docs/AIOS_SYSTEM_CONTROL_ARCHITECTURE.md` 的早期版本；**没有在本次最新版源码上重跑，未证明其中任何一项已修复或仅属环境问题。**

本次环境：普通 Linux 容器，无 rustc/cargo/bwrap/GNOME 登录会话。实际执行：`bash -n` 返回 0，探针 L1 返回 2（missing rustc），L2 返回 2（missing bwrap）。不计为回归通过。

## 13 项保留原断言的待归因失败

| # | 原始失败测试 | 当前结论 |
| --- | --- | --- |
| 1 | `backend_bridge::providers_cli::tests::cli_bwrap_sandbox_blocks_workspace_write_secret_dir_and_cmdline_leak_while_bridging_broker` | blocked；原因归属待原测试复现 |
| 2 | `backend_bridge::providers_cli::tests::cli_chat_only_mode_omits_protocol_and_strips_forced_tool_calls_with_zero_broker_exec` | blocked；原因归属待原测试复现 |
| 3 | `backend_bridge::tests::test_m1_cli_broker_bridge_executes_tool_call_and_suspends_on_pending_approval` | blocked；原因归属待原测试复现 |
| 4 | `diagnostics::tests::m2d_scenario1_real_proc_system_bottleneck_and_synthetic_swap_zombie_detection` | blocked；原因归属待原测试复现 |
| 5 | `terminal_agent::tests::anti_bypass_blocks_shells_inline_code_flags_symlinks_secrets_unauth_writes_and_tcp` | blocked；原因归属待原测试复现 |
| 6 | `terminal_agent::tests::c0_df_and_free_succeed_in_real_bwrap_readonly_sandbox` | blocked；原因归属待原测试复现 |
| 7 | `terminal_agent::tests::c1_rg_find_and_git_status_succeed_inside_authorized_tempdir_in_bwrap` | blocked；原因归属待原测试复现 |
| 8 | `terminal_agent::tests::c2_reversible_write_requires_approval_snapshots_changeset_and_undoes_plus_redacts` | blocked；原因归属待原测试复现 |
| 9 | `m1_test1_turn_engine_modularized_and_cli_broker_bridge_unifies_execution` | blocked；原因归属待原测试复现 |
| 10 | `p0_10_chat_only_allow_broker_tools_false_blocks_system_tools_identically_on_http_and_cli` | blocked；原因归属待原测试复现 |
| 11 | `p0_11_real_cli_os_sandbox_blocks_unauthorized_write_forbidden_read_and_cmdline_leak` | blocked；原因归属待原测试复现 |
| 12 | `p1_05_h10_warm_pi_worker_reuse_incognito_isolation_and_idle_eviction` | blocked；原因归属待原测试复现 |
| 13 | `m2_test3_controlled_terminal_c0_c4_sandbox_and_anti_bypass` | blocked；原因归属待原测试复现 |

在具备依赖的 Ubuntu VM 运行 `cargo test --workspace --locked --no-fail-fast -- --test-threads=1` 并保留原断言；逐项以 `cargo test -p intentosd <test-filter> -- --nocapture --test-threads=1`（集成测试额外指定 `--test`）做最小复现，随后依据日志标记 `product_defect`、`environment_missing` 或 `flaky`。记录 SHA、runner、内核、userns/bwrap、stdout/stderr、退出码和复测次数。

分层：L1 静态与纯逻辑；L2 真实进程/文件/网络隔离（必须正向对照，不可仅跑探针）；L3 GNOME Wayland/X11 分别验证，不把 skipped 记 PASS；L4 独占 Release 性能。可信 L2/L3/L4 只允许手动 workflow_dispatch 与带专用标签 runner，不能让不可信 PR 触发提权/桌面测试。缺 runner 即 blocked。当前尚无 L2/L3/L4 证据；安全功能不能默认开启。
