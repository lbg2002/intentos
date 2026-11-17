# IntentOS SC-05～SC-10 2026-11-17 实际验证与阻塞总账

## 源码与被测版本

- 审查起点：`main d0b9f56e1b3f454e6bda380f7d2ebe7ca223362b`；接续前批 `c89fbbac`。
- 本批开发分支：`sc/system-control-05-10-20261117`，草稿 PR：https://github.com/lbg2002/intentos/pull/17 ；**未合并到 main**。
- GitHub Ubuntu 24.04 L1 定向成功：`42a7729fe4ba3dcd5583ae34d789310e32b77e08`，https://github.com/lbg2002/intentos/actions/runs/44037507542
- GitHub Ubuntu 24.04 L1 全量失败：`b219cf863fe735c2fc590d65f0236347799fcb58`，https://github.com/lbg2002/intentos/actions/runs/44036688627
- 安全修复 `4b692b1` 与 CI 补测 `2bfecaa` 晚于上述被测版本，不能视为已由上述运行验证。后续 CI 应另列 SHA/URL。

## 真实执行结果

| 环境/命令 | 被测提交 | 结果 | 解释 |
| --- | --- | --- | --- |
| `cargo fmt --all -- --check` | `42a7729` | PASS | GH L1 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | `42a7729` | PASS | GH L1 |
| 协议 + SDK `cargo test` | `42a7729` | PASS | GH L1 |
| `command_line_` 及 SC-03/05/07/08/09 定向 Rust `cargo test` | `42a7729` | PASS | 分别 2、5、1、3、1、1 项（详见原始 GitHub 日志） |
| SC-09 Web JS 语法检查 | `42a7729` | PASS | 只做语法解析，非真实桌面 |
| `python3 -m unittest discover -s scripts -p 'test_sc*.py' -v` | `42a7729` | 8 PASS | SC-06 3 + SC-10 5，均为 fixture/门禁逻辑 |
| SC-10 release gate | `42a7729` | 预期拒绝 | `release_allowed=false`，不表示发布成功 |
| `cargo test --workspace --locked --no-fail-fast -- --test-threads=1` | `b219cf8` | **235 PASS / 9 FAIL** | 22 个 target，4 个失败 target，CI EXIT 101 |
| L2 正/反隔离测试 | — | **BLOCKED** | 可信 userns/bwrap VM 不可用 |
| L3 GNOME Wayland/X11 | — | **BLOCKED** | 无已授权真实登录桌面 runner |
| L4 Release 独占性能/安装升级 | — | **BLOCKED** | 无专用参考设备 |

## 全工作区实际失败 9 项

| 测试 | 观测证据 | 初步归因与后续 |
| --- | --- | --- |
| `sandbox::sandbox_enforces_readonly_workspace_private_tmpfs_and_credential_masking` | `driver=Landlock` + `SECRET_LEAKED` | **P0 产品安全缺陷**：子路径凭据可读，已新增 fail-closed 安全门禁，待 L2 正向重测 |
| `app_adapter::local_scanner::test_host_deep_scan_discovers_rich_apps_if_present` | 扫描结果小于原断言 10 个 | GitHub Runner 软件桌面缺失，环境不满足；不降低断言 |
| `backend_bridge::providers_cli::cli_bwrap_sandbox_blocks_workspace_write_secret_dir_and_cmdline_leak_while_bridging_broker` | `AUTH_CFG_WRITE_ESCAPED` | **P0 边界问题**，Landlock 回退未满足只读 overlay，fail-closed 后需再测 |
| `speech_hub::test_asr_runner_script_self_test_passes` | `ModuleNotFoundError: numpy` | 环境依赖缺失；另跑真实 Python ASR 自测 |
| `terminal_agent::anti_bypass_blocks_shells_inline_code_flags_symlinks_secrets_unauth_writes_and_tcp` | 期待 `RequiresApproval` 实为硬拒绝 | 与 SC-03 为防 TOCTOU 主动关闭未冻结脚本的行为冲突；不得改断言绕过，需补真正冻结 |
| `terminal_agent::c0_df_and_free_succeed_in_real_bwrap_readonly_sandbox` | `bwrap_path=None` | L2 环境不合格，按 blocked 保留 |
| `terminal_agent::c1_rg_find_and_git_status_succeed_inside_authorized_tempdir_in_bwrap` | 实际 `C4Forbidden`，期待 `C1ScopedRead` | 待最小复现确定具体路径与策略；不能仅归因环境 |
| `e2e_v0_2_m2::m2_test3_controlled_terminal_c0_c4_sandbox_and_anti_bypass` | 断言 bwrap_userns_ok 失败 | L2 环境不合格，按 blocked 保留 |
| `e2e_wave5::wave5_test4_speech_hub_config_streaming_model_download_and_asr_runner_selftest` | `ModuleNotFoundError: numpy` | 与 ASR 依赖缺失相同，不表示本轮功能成功 |

相比早期“13 项历史失败”必须以本轮实际 9 项作为**新基线失败清单**，但未出现在本次失败清单中的旧断言不能未经对照宣称被功能修复。现有测试中由于环境不可用而未真正触及受保护内核操作的路径，同样不形成 L2 证据。

## 安全与发版结论

- **全功能发布：BLOCKED**，关键安全验收未通过。未冻结工作区脚本、host privileged helper、复合 Bash 执行、未认证软件动作不能默认启用。
- 即使 L1 定向所有用例通过，也不等于 L2 沙箱、L3 桌面或 L4 性能通过；未执行的测试不计入成功分母。
- P0 安全修复为拒绝不安全回退（功能降级），不是已经证明隔离正确；等可恢复 Ubuntu VM 启用可信 bwrap/userns 后执行正/负用例。
- 保留原始 GitHub Actions 日志、错误和测试断言；任何人工解除 gate 必须引用可信机器的独立证据，禁止篡改 STATUS 为 verified 代替测试。
