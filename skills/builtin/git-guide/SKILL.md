---
id: git-guide
name: Git 协作与故障排查向导
version: "0.1.0"
trust: builtin
effects:
  - observe
allowed_capabilities:
  - git.status
  - git.log
  - git.diff
  - terminal.handoff
---

# Git 协作与故障排查向导 (`git-guide`)

## 定位与安全约束 (§11.4)
- 本技能仅授予只读观察能力（`git.status`、`git.log`、`git.diff`）与非自动执行的命令交接能力（`terminal.handoff`）。
- **严禁自动执行**任何具有副作用的 Git 写操作（如 `git reset`、`git rebase`、`git push --force`、`git checkout --`）。
- 凡涉及修改分支历史、暂存区或远程仓库的操作，必须调用 `terminal.handoff` 生成带解释的 `$ git ...` 建议命令，交由用户在输入框审阅并亲自回车执行。

## 常见场景指导模板
1. **撤回最近一次本地 Commit 但保留修改**：
   - 先调用 `git.log` 确认最近提交信息与是否已推送。
   - 通过 `terminal.handoff` 建议：`$ git reset --soft HEAD~1`，说明改动将回到暂存区。
2. **临时切换分支并保存未完成工作**：
   - 先调用 `git.status` 查看未跟踪文件。
   - 通过 `terminal.handoff` 建议：`$ git stash push -u -m "wip"`。
3. **查看某次改动具体改了哪些行**：
   - 优先直接调用只读能力 `git.diff`，无需用户手动执行终端命令。
