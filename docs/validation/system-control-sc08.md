# SC-08 安全草案验证

新增测试：`sc08_valid_pipeline_is_still_not_executable`、`sc08_rejects_conditional_and_shell_escape_as_unsupported_syntax`、`sc08_rejects_duplicate_step_ids_and_extra_redirection_fields`。

**本地测试 blocked**：当前容器无 rustc/cargo；后续 GitHub L1 CI 可验证。无实际 Shell 执行、pipefail、重定向、文件越界、取消或恢复测试，V13 blocked。草案无注册入口，默认不可执行。