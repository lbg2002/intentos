#![forbid(unsafe_code)]

//! E2 Sandboxed Staged Execution & Atomic ChangeSet Commit (`docs/IntentOS_设计方案_v0.3.md` §8.4).
//!
//! Workflow:
//! 1. Create an isolated staging workspace under `${runtime_dir}/e2_staging_<id>`.
//! 2. Copy/stage authorized directory files into `staged_work_dir` and record pre-execution hashes/snapshots.
//! 3. Execute the command inside `intentos_sandbox::build_sandboxed_command` with `allow_tcp_network = false` by default.
//! 4. Compute exact file tree diffs (`added_files`, `modified_files` with unified diff & SHA-256, `deleted_files`, `artifacts`).
//! 5. On user approval (`commit_e2_proposal`), apply staged changes to the real authorized directory via `SafeFsEngine`
//!    (`openat2` native operations + Undo backup) and persist a single reversible `ChangeSet` to `state_db`.

use crate::core::IntentOsCore;
use chrono::{DateTime, Duration, Utc};
use intentos_protocol::{ChangeOp, ChangeSet, ChangeSetStatus};
use intentos_sandbox::{SandboxSpec, build_sandboxed_command};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use walkdir::WalkDir;

const MAX_STAGED_FILE_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB per file cap for staging copy
const MAX_PREVIEW_CHARS: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSnapshot {
    pub rel_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub is_binary: bool,
    pub text_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddedFileDiff {
    pub path: String,
    pub rel_path: String,
    pub target_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub is_binary: bool,
    pub text_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModifiedFileDiff {
    pub path: String,
    pub rel_path: String,
    pub target_path: String,
    pub old_size_bytes: u64,
    pub new_size_bytes: u64,
    pub old_sha256: String,
    pub new_sha256: String,
    pub is_binary: bool,
    pub unified_diff: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedFileDiff {
    pub path: String,
    pub rel_path: String,
    pub target_path: String,
    pub old_size_bytes: u64,
    pub old_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedArtifact {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StagingDiffSummary {
    pub added_files: Vec<AddedFileDiff>,
    pub modified_files: Vec<ModifiedFileDiff>,
    pub deleted_files: Vec<DeletedFileDiff>,
    pub artifacts: Vec<StagedArtifact>,
    pub total_changes: usize,
    pub only_artifacts: bool,
    pub unified_diff_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedProposal {
    pub proposal_id: String,
    pub task_id: String,
    pub command: String,
    pub work_dir: String,
    pub staging_dir: String,
    pub staged_work_dir: String,
    pub artifacts_dir: String,
    pub sandbox_driver: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub diffs: StagingDiffSummary,
    pub requires_approval: bool,
    pub status: String,
    pub changeset_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

static PROPOSALS_REGISTRY: OnceLock<Mutex<HashMap<PathBuf, BTreeMap<String, StagedProposal>>>> =
    OnceLock::new();

fn registry() -> &'static Mutex<HashMap<PathBuf, BTreeMap<String, StagedProposal>>> {
    PROPOSALS_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn expand_home(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        return PathBuf::from(home).join(rest);
    }
    if trimmed == "~" {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        return PathBuf::from(home);
    }
    PathBuf::from(trimmed)
}

fn resolve_authorized_work_dir(
    core: &IntentOsCore,
    requested: Option<&str>,
) -> anyhow::Result<PathBuf> {
    let roots = core.fs_engine.authorized_roots();
    if let Some(req) = requested
        && !req.trim().is_empty()
    {
        let candidate = expand_home(req);
        if core.fs_engine.is_forbidden(&candidate) {
            anyhow::bail!(
                "E2 沙箱拒绝挂载受保护路径 (forbidden): {}",
                candidate.display()
            );
        }
        if !candidate.is_absolute() {
            anyhow::bail!("E2 工作目录必须为绝对路径: {}", candidate.display());
        }
        let in_scope = roots.iter().any(|r| candidate.starts_with(r));
        if !in_scope {
            anyhow::bail!("E2 工作目录超出授权目录范围: {}", candidate.display());
        }
        std::fs::create_dir_all(&candidate)?;
        return Ok(candidate);
    }

    let first = roots
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("未配置任何授权目录"))?;
    std::fs::create_dir_all(&first)?;
    Ok(first)
}

/// Stage and run a command inside an isolated E2 sandbox workspace and compute file tree diffs (§8.4).
pub async fn stage_e2_command(
    core: &IntentOsCore,
    command: &str,
    work_dir: Option<&str>,
    task_id: Option<&str>,
    allow_tcp_network: bool,
) -> anyhow::Result<StagedProposal> {
    let cmd_trimmed = command.trim();
    if cmd_trimmed.is_empty() {
        anyhow::bail!("E2 暂存执行命令不能为空");
    }

    let real_work_dir = resolve_authorized_work_dir(core, work_dir)?;
    let proposal_id = format!("e2_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let task_id_str = task_id
        .filter(|s| !s.trim().is_empty())
        .map(String::from)
        .unwrap_or_else(|| format!("task_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));

    std::fs::create_dir_all(&core.paths.runtime_dir)?;
    let staging_dir = core
        .paths
        .runtime_dir
        .join(format!("e2_staging_{}", proposal_id));
    let staged_work_dir = staging_dir.join("work");
    let artifacts_dir = staging_dir.join("artifacts");
    let tmp_dir = staging_dir.join("tmp");

    std::fs::create_dir_all(&staged_work_dir)?;
    std::fs::create_dir_all(&artifacts_dir)?;
    std::fs::create_dir_all(&tmp_dir)?;

    // 1. Snapshot & copy authorized work_dir into staged_work_dir
    let pre_snapshot = stage_directory_tree(&real_work_dir, &staged_work_dir)?;

    // 2. Build sandboxed command with no TCP network by default
    let mut env_vars = BTreeMap::new();
    env_vars.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    env_vars.insert(
        "HOME".to_string(),
        staged_work_dir.to_string_lossy().to_string(),
    );
    env_vars.insert("TMPDIR".to_string(), tmp_dir.to_string_lossy().to_string());
    env_vars.insert(
        "INTENTOS_ARTIFACTS_DIR".to_string(),
        artifacts_dir.to_string_lossy().to_string(),
    );
    env_vars.insert("LANG".to_string(), "C.UTF-8".to_string());

    let bash_path = if Path::new("/bin/bash").exists() {
        PathBuf::from("/bin/bash")
    } else {
        PathBuf::from("/bin/sh")
    };

    let spec = SandboxSpec {
        program: bash_path,
        args: vec!["-c".to_string(), cmd_trimmed.to_string()],
        readonly_paths: vec![],
        readwrite_paths: vec![staging_dir.clone()],
        env_vars,
        work_dir: staged_work_dir.clone(),
        allow_tcp_network,
    };

    let (mut cmd, driver) = build_sandboxed_command(&spec)?;
    let output = tokio::time::timeout(std::time::Duration::from_secs(15), cmd.output())
        .await
        .map_err(|_| anyhow::anyhow!("E2 沙箱命令执行超时 (15s)"))??;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code();

    // 3. Compute file tree diffs between pre_snapshot and staged_work_dir
    let diffs = compute_staging_diff(
        &real_work_dir,
        &staged_work_dir,
        &artifacts_dir,
        &pre_snapshot,
    )?;

    let requires_approval = diffs.total_changes > 0 && !diffs.only_artifacts;
    let status = if diffs.total_changes == 0 && diffs.artifacts.is_empty() {
        "no_changes".to_string()
    } else if diffs.only_artifacts {
        "artifacts_ready".to_string()
    } else {
        "staged".to_string()
    };

    let proposal = StagedProposal {
        proposal_id: proposal_id.clone(),
        task_id: task_id_str.clone(),
        command: cmd_trimmed.to_string(),
        work_dir: real_work_dir.to_string_lossy().to_string(),
        staging_dir: staging_dir.to_string_lossy().to_string(),
        staged_work_dir: staged_work_dir.to_string_lossy().to_string(),
        artifacts_dir: artifacts_dir.to_string_lossy().to_string(),
        sandbox_driver: format!("{:?}", driver).to_ascii_lowercase(),
        exit_code,
        stdout,
        stderr,
        diffs,
        requires_approval,
        status,
        changeset_id: None,
        created_at: Utc::now(),
    };

    let _ = core.state_db.record_audit(
        Some(&task_id_str),
        "sandbox.run",
        "e2_staging",
        "exec.sandboxed",
        if requires_approval {
            "staged_for_approval"
        } else {
            "allow"
        },
        "staged",
        &json!({
            "proposal_id": proposal.proposal_id,
            "command": proposal.command,
            "work_dir": proposal.work_dir,
            "total_changes": proposal.diffs.total_changes,
        }),
        Some("E2 沙箱暂存执行完成"),
    );

    registry()
        .lock()
        .unwrap()
        .entry(core.paths.data_dir.clone())
        .or_default()
        .insert(proposal_id, proposal.clone());

    Ok(proposal)
}

fn should_skip_dir_entry(rel_path: &Path) -> bool {
    for comp in rel_path.components() {
        let s = comp.as_os_str().to_string_lossy();
        if matches!(
            s.as_ref(),
            ".git" | "target" | "node_modules" | ".venv" | "__pycache__"
        ) || s.starts_with(".intentos_tmp_")
        {
            return true;
        }
    }
    false
}

fn stage_directory_tree(
    real_work_dir: &Path,
    staged_work_dir: &Path,
) -> anyhow::Result<BTreeMap<String, FileSnapshot>> {
    let mut snapshots = BTreeMap::new();
    for entry in WalkDir::new(real_work_dir)
        .max_depth(5)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        let path = entry.path();
        let Ok(rel) = path.strip_prefix(real_work_dir) else {
            continue;
        };
        if rel.as_os_str().is_empty() || should_skip_dir_entry(rel) {
            continue;
        }
        let target_in_stage = staged_work_dir.join(rel);
        let ftype = entry.file_type();
        if ftype.is_symlink() {
            continue;
        }
        if ftype.is_dir() {
            std::fs::create_dir_all(&target_in_stage)?;
        } else if ftype.is_file() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.len() > MAX_STAGED_FILE_BYTES {
                continue;
            }
            if let Some(parent) = target_in_stage.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let bytes = std::fs::read(path)?;
            std::fs::write(&target_in_stage, &bytes)?;
            let snap = build_file_snapshot(&rel.to_string_lossy(), &bytes);
            snapshots.insert(snap.rel_path.clone(), snap);
        }
    }
    Ok(snapshots)
}

fn build_file_snapshot(rel_path: &str, bytes: &[u8]) -> FileSnapshot {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let sha256 = format!("sha256:{}", hex::encode(hasher.finalize()));
    let is_binary = bytes.iter().take(4096).any(|&b| b == 0);
    let text_content = if !is_binary {
        std::str::from_utf8(bytes).ok().map(String::from)
    } else {
        None
    };
    FileSnapshot {
        rel_path: rel_path.replace('\\', "/"),
        size_bytes: bytes.len() as u64,
        sha256,
        is_binary,
        text_content,
    }
}

/// Compute file tree diffs (`added_files`, `modified_files`, `deleted_files`, `artifacts`) after E2 execution.
pub fn compute_staging_diff(
    real_work_dir: &Path,
    staged_work_dir: &Path,
    artifacts_dir: &Path,
    pre_snapshot: &BTreeMap<String, FileSnapshot>,
) -> anyhow::Result<StagingDiffSummary> {
    let mut post_snapshot = BTreeMap::new();
    for entry in WalkDir::new(staged_work_dir)
        .max_depth(5)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        let path = entry.path();
        let Ok(rel) = path.strip_prefix(staged_work_dir) else {
            continue;
        };
        if rel.as_os_str().is_empty() || should_skip_dir_entry(rel) {
            continue;
        }
        if entry.file_type().is_file() {
            let bytes = std::fs::read(path)?;
            let snap = build_file_snapshot(&rel.to_string_lossy(), &bytes);
            post_snapshot.insert(snap.rel_path.clone(), snap);
        }
    }

    let mut added_files = Vec::new();
    let mut modified_files = Vec::new();
    let mut deleted_files = Vec::new();
    let mut unified_chunks = Vec::new();

    for (rel_path, post) in &post_snapshot {
        let target_path = real_work_dir.join(rel_path).to_string_lossy().to_string();
        match pre_snapshot.get(rel_path) {
            None => {
                let preview = if let Some(ref txt) = post.text_content {
                    let snippet: String = txt.chars().take(MAX_PREVIEW_CHARS).collect();
                    let diff_text = format_unified_added(rel_path, &snippet);
                    unified_chunks.push(diff_text);
                    snippet
                } else {
                    let bin_summary =
                        format!("[二进制文件 {} 字节, {}]", post.size_bytes, post.sha256);
                    unified_chunks.push(format!(
                        "--- /dev/null\n+++ b/{}\n{}",
                        rel_path, bin_summary
                    ));
                    bin_summary
                };
                added_files.push(AddedFileDiff {
                    path: target_path.clone(),
                    rel_path: rel_path.clone(),
                    target_path,
                    size_bytes: post.size_bytes,
                    sha256: post.sha256.clone(),
                    is_binary: post.is_binary,
                    text_preview: preview,
                });
            }
            Some(pre) if pre.sha256 != post.sha256 => {
                let is_binary = pre.is_binary || post.is_binary;
                let unified_diff = if !is_binary {
                    let old_txt = pre.text_content.as_deref().unwrap_or("");
                    let new_txt = post.text_content.as_deref().unwrap_or("");
                    build_unified_text_diff(rel_path, old_txt, new_txt)
                } else {
                    format!(
                        "--- a/{}\n+++ b/{}\n@@ binary file modified @@\n- size: {} ({})\n+ size: {} ({})",
                        rel_path,
                        rel_path,
                        pre.size_bytes,
                        pre.sha256,
                        post.size_bytes,
                        post.sha256
                    )
                };
                unified_chunks.push(unified_diff.clone());
                modified_files.push(ModifiedFileDiff {
                    path: target_path.clone(),
                    rel_path: rel_path.clone(),
                    target_path,
                    old_size_bytes: pre.size_bytes,
                    new_size_bytes: post.size_bytes,
                    old_sha256: pre.sha256.clone(),
                    new_sha256: post.sha256.clone(),
                    is_binary,
                    unified_diff,
                });
            }
            Some(_) => {}
        }
    }

    for (rel_path, pre) in pre_snapshot {
        if !post_snapshot.contains_key(rel_path) {
            let target_path = real_work_dir.join(rel_path).to_string_lossy().to_string();
            unified_chunks.push(format!(
                "--- a/{}\n+++ /dev/null\n@@ deleted ({} bytes, {}) @@",
                rel_path, pre.size_bytes, pre.sha256
            ));
            deleted_files.push(DeletedFileDiff {
                path: target_path.clone(),
                rel_path: rel_path.clone(),
                target_path,
                old_size_bytes: pre.size_bytes,
                old_sha256: pre.sha256.clone(),
            });
        }
    }

    let mut artifacts = Vec::new();
    if artifacts_dir.exists() {
        for entry in WalkDir::new(artifacts_dir)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            if entry.file_type().is_file() {
                let bytes = std::fs::read(entry.path())?;
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let sha256 = format!("sha256:{}", hex::encode(hasher.finalize()));
                let name = entry
                    .path()
                    .strip_prefix(artifacts_dir)
                    .unwrap_or(entry.path())
                    .to_string_lossy()
                    .to_string();
                artifacts.push(StagedArtifact {
                    name,
                    path: entry.path().to_string_lossy().to_string(),
                    size_bytes: bytes.len() as u64,
                    sha256,
                });
            }
        }
    }

    let total_changes = added_files.len() + modified_files.len() + deleted_files.len();
    let only_artifacts = total_changes == 0 && !artifacts.is_empty();

    Ok(StagingDiffSummary {
        added_files,
        modified_files,
        deleted_files,
        artifacts,
        total_changes,
        only_artifacts,
        unified_diff_preview: unified_chunks.join("\n\n"),
    })
}

fn format_unified_added(rel_path: &str, text: &str) -> String {
    let mut lines = Vec::new();
    lines.push("--- /dev/null".to_string());
    lines.push(format!("+++ b/{}", rel_path));
    let raw_lines: Vec<&str> = text.lines().take(30).collect();
    lines.push(format!("@@ -0,0 +1,{} @@", raw_lines.len()));
    for l in raw_lines {
        lines.push(format!("+{}", l));
    }
    lines.join("\n")
}

fn build_unified_text_diff(rel_path: &str, old_text: &str, new_text: &str) -> String {
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();

    let mut out = Vec::new();
    out.push(format!("--- a/{}", rel_path));
    out.push(format!("+++ b/{}", rel_path));
    out.push(format!(
        "@@ -1,{} +1,{} @@",
        old_lines.len(),
        new_lines.len()
    ));

    let max_len = old_lines.len().max(new_lines.len()).min(60);
    for i in 0..max_len {
        match (old_lines.get(i), new_lines.get(i)) {
            (Some(o), Some(n)) if o == n => {
                out.push(format!(" {}", o));
            }
            (Some(o), Some(n)) => {
                out.push(format!("-{}", o));
                out.push(format!("+{}", n));
            }
            (Some(o), None) => {
                out.push(format!("-{}", o));
            }
            (None, Some(n)) => {
                out.push(format!("+{}", n));
            }
            (None, None) => break,
        }
    }
    out.join("\n")
}

/// Atomically apply an approved `StagedProposal` to real authorized directories via `SafeFsEngine`
/// and save a single reversible `ChangeSet` to `core.state_db` (§8.4, §9.1).
pub fn commit_e2_proposal(core: &IntentOsCore, proposal_id: &str) -> anyhow::Result<Value> {
    let mut proposal = {
        let map = registry().lock().unwrap();
        map.get(&core.paths.data_dir)
            .and_then(|m| m.get(proposal_id))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("未找到 E2 暂存提案: {}", proposal_id))?
    };

    if proposal.status == "committed" {
        anyhow::bail!("E2 暂存提案 {} 已提交，请勿重复提交", proposal_id);
    }
    if proposal.status == "discarded" {
        anyhow::bail!("E2 暂存提案 {} 已被丢弃，无法提交", proposal_id);
    }

    let staged_work = PathBuf::from(&proposal.staged_work_dir);
    let mut combined_ops: Vec<ChangeOp> = Vec::new();
    let mut total_backup_bytes = 0u64;

    // 1. Apply added files via SafeFsEngine::write_file_reversible
    for added in &proposal.diffs.added_files {
        let staged_file = staged_work.join(&added.rel_path);
        let bytes = std::fs::read(&staged_file)?;
        let sub_cs = core.fs_engine.write_file_reversible(
            &proposal.task_id,
            Path::new(&added.target_path),
            &bytes,
        )?;
        total_backup_bytes += sub_cs.backup_bytes;
        combined_ops.extend(sub_cs.operations);
    }

    // 2. Apply modified files via SafeFsEngine::write_file_reversible
    for modified in &proposal.diffs.modified_files {
        let staged_file = staged_work.join(&modified.rel_path);
        let bytes = std::fs::read(&staged_file)?;
        let sub_cs = core.fs_engine.write_file_reversible(
            &proposal.task_id,
            Path::new(&modified.target_path),
            &bytes,
        )?;
        total_backup_bytes += sub_cs.backup_bytes;
        combined_ops.extend(sub_cs.operations);
    }

    // 3. Apply deleted files via SafeFsEngine::trash_file
    for deleted in &proposal.diffs.deleted_files {
        let target = Path::new(&deleted.target_path);
        if target.exists() {
            let sub_cs = core.fs_engine.trash_file(&proposal.task_id, target)?;
            total_backup_bytes += sub_cs.backup_bytes;
            combined_ops.extend(sub_cs.operations);
        }
    }

    let now = Utc::now();
    let cs_id = format!("cs_e2_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let summary = format!(
        "E2 沙箱提交 `{}`（新增 {}，修改 {}，删除 {}）",
        proposal.command,
        proposal.diffs.added_files.len(),
        proposal.diffs.modified_files.len(),
        proposal.diffs.deleted_files.len()
    );

    let changeset = ChangeSet {
        id: cs_id.clone(),
        task_id: proposal.task_id.clone(),
        created_at: now,
        capability_id: "sandbox.run".to_string(),
        layer: "E2".to_string(),
        operations: combined_ops,
        backup_bytes: total_backup_bytes,
        status: ChangeSetStatus::Applied,
        undo_expires_at: now + Duration::days(core.app_config.undo.retention_days),
        summary: summary.clone(),
    };

    core.state_db.save_changeset(&changeset)?;
    let _ = core.resources.index_authorized_files();
    let _ = core.state_db.record_audit(
        Some(&proposal.task_id),
        "sandbox.commit",
        "user_approved",
        "write.reversible",
        "allow_with_undo",
        "committed",
        &json!({
            "proposal_id": proposal.proposal_id,
            "changeset_id": cs_id,
            "operations": changeset.operations.len(),
        }),
        Some(&summary),
    );

    // Clean up staging workspace
    let _ = std::fs::remove_dir_all(&proposal.staging_dir);
    proposal.status = "committed".to_string();
    proposal.changeset_id = Some(cs_id.clone());

    registry()
        .lock()
        .unwrap()
        .entry(core.paths.data_dir.clone())
        .or_default()
        .insert(proposal.proposal_id.clone(), proposal.clone());

    Ok(json!({
        "committed": true,
        "proposal_id": proposal.proposal_id,
        "changeset_id": cs_id,
        "changeset": changeset,
        "message": format!("✓ {} [变更集 {}，可一键撤销]", summary, cs_id),
    }))
}

/// Discard an E2 staged proposal and remove its temporary staging directory.
pub fn discard_e2_proposal(core: &IntentOsCore, proposal_id: &str) -> anyhow::Result<Value> {
    let mut proposal = {
        let map = registry().lock().unwrap();
        map.get(&core.paths.data_dir)
            .and_then(|m| m.get(proposal_id))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("未找到 E2 暂存提案: {}", proposal_id))?
    };

    let _ = std::fs::remove_dir_all(&proposal.staging_dir);
    proposal.status = "discarded".to_string();

    registry()
        .lock()
        .unwrap()
        .entry(core.paths.data_dir.clone())
        .or_default()
        .insert(proposal.proposal_id.clone(), proposal.clone());

    let _ = core.state_db.record_audit(
        Some(&proposal.task_id),
        "sandbox.discard",
        "user_explicit",
        "observe",
        "allow",
        "discarded",
        &json!({ "proposal_id": proposal_id }),
        Some("用户丢弃了 E2 暂存变更"),
    );

    Ok(json!({
        "discarded": true,
        "proposal_id": proposal_id,
        "status": "discarded",
        "message": format!("已丢弃并清理 E2 暂存区 {}", proposal_id),
    }))
}

pub fn list_e2_proposals(core: &IntentOsCore) -> Vec<StagedProposal> {
    let map = registry().lock().unwrap();
    map.get(&core.paths.data_dir)
        .map(|m| m.values().rev().cloned().collect())
        .unwrap_or_default()
}
