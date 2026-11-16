#![forbid(unsafe_code)]

//! Project Auto-Discovery (`R-05`), Project-Scoped Memories (`M-04`),
//! Memory Candidate Queue (`M-05`), and Recall Provenance (`M-06`)
//! (`docs/IntentOS_设计方案_v0.3.md` §11.2–§11.5, §12.3).

use crate::core::IntentOsCore;
use chrono::{DateTime, Utc};
use intentos_protocol::{DataClass, Taint, Task, TaskStatus};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectRecord {
    pub project_id: String,
    pub uri: String,
    pub name: String,
    pub root_path: String,
    pub tech_stack: Vec<String>,
    pub git_branch: Option<String>,
    pub last_active: String,
    pub manifest_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCandidate {
    pub candidate_id: String,
    pub mem_type: String,
    pub scope: String,
    pub subject: String,
    pub value: String,
    pub reason: String,
    pub source_task_id: Option<String>,
    pub taint: Vec<Taint>,
    pub confidence: f64,
    pub data_class: DataClass,
    pub status: String, // "pending" | "confirmed" | "rejected"
    pub confirmed_memory_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProvenanceItem {
    pub memory_id: String,
    pub subject: String,
    pub value: String,
    pub scope: String,
    pub source_task_id: Option<String>,
    pub taint: String,
    pub confidence: f64,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ProjectMemoryStore {
    projects: BTreeMap<String, ProjectRecord>,
    candidates: BTreeMap<String, MemoryCandidate>,
    project_memories: BTreeMap<String, MemoryProvenanceItem>,
    processed_task_ids: BTreeSet<String>,
    rejected_fingerprints: BTreeSet<String>,
}

static PROJECT_MEM_STORE: OnceLock<Mutex<HashMap<PathBuf, ProjectMemoryStore>>> = OnceLock::new();

fn store_map() -> &'static Mutex<HashMap<PathBuf, ProjectMemoryStore>> {
    PROJECT_MEM_STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn store_file_path(core: &IntentOsCore) -> PathBuf {
    core.paths.data_dir.join("execution_hub_projects_mem.json")
}

fn with_store<F, R>(core: &IntentOsCore, f: F) -> R
where
    F: FnOnce(&mut ProjectMemoryStore) -> R,
{
    let mut map = store_map().lock().unwrap();
    let entry = map.entry(core.paths.data_dir.clone()).or_insert_with(|| {
        let p = store_file_path(core);
        if p.exists()
            && let Ok(raw) = std::fs::read_to_string(&p)
            && let Ok(parsed) = serde_json::from_str::<ProjectMemoryStore>(&raw)
        {
            return parsed;
        }
        ProjectMemoryStore::default()
    });
    let out = f(entry);
    let p = store_file_path(core);
    if let Ok(serialized) = serde_json::to_string_pretty(entry) {
        let _ = std::fs::write(p, serialized);
    }
    out
}

pub fn compute_memory_fingerprint(subject: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(subject.trim().as_bytes());
    hasher.update(b"=");
    hasher.update(value.trim().as_bytes());
    hex::encode(hasher.finalize())
}

pub fn contains_forbidden_secret(subject: &str, value: &str) -> bool {
    let lower_val = value.to_ascii_lowercase();
    let lower_subj = subject.to_ascii_lowercase();
    lower_val.contains("-----begin ")
        || lower_val.contains("sk-")
        || lower_val.contains("api_key")
        || lower_val.contains("apikey")
        || lower_val.contains("password")
        || value.contains("密码")
        || value.contains("口令")
        || lower_subj.contains("password")
        || lower_subj.contains("secret")
        || lower_subj.contains("token")
        || lower_subj.contains("api_key")
}

/// Scan authorized directories (depth 1..=3) for Git / Rust / Node / Python projects (`R-05`, §12.3).
pub fn discover_and_list_projects(
    core: &IntentOsCore,
    force_rescan: bool,
) -> anyhow::Result<Vec<ProjectRecord>> {
    let cached = with_store(core, |store| {
        if !force_rescan && !store.projects.is_empty() {
            Some(store.projects.values().cloned().collect::<Vec<_>>())
        } else {
            None
        }
    });
    if let Some(list) = cached {
        return Ok(list);
    }

    let mut scan_roots: Vec<PathBuf> = core.fs_engine.authorized_roots().to_vec();
    if core.paths.repo_root.exists()
        && !core.fs_engine.is_forbidden(&core.paths.repo_root)
        && !scan_roots.contains(&core.paths.repo_root)
    {
        scan_roots.push(core.paths.repo_root.clone());
    }

    let mut discovered = BTreeMap::new();
    for root in &scan_roots {
        if !root.exists() || core.fs_engine.is_forbidden(root) {
            continue;
        }
        for entry in WalkDir::new(root)
            .min_depth(0)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                if !e.file_type().is_dir() {
                    return false;
                }
                let name = e.file_name().to_string_lossy();
                !(e.depth() > 0
                    && (name.starts_with('.')
                        || matches!(
                            name.as_ref(),
                            "target" | "node_modules" | ".venv" | "dist" | "build" | "__pycache__"
                        )))
            })
            .flatten()
        {
            let dir_path = entry.path();
            if core.fs_engine.is_forbidden(dir_path) {
                continue;
            }
            if let Some(proj) = inspect_directory_as_project(dir_path) {
                discovered.insert(proj.project_id.clone(), proj);
            }
        }
    }

    let list: Vec<ProjectRecord> = discovered.values().cloned().collect();
    with_store(core, |store| {
        store.projects = discovered;
    });

    Ok(list)
}

fn inspect_directory_as_project(dir: &Path) -> Option<ProjectRecord> {
    let has_git = dir.join(".git").exists();
    let has_cargo = dir.join("Cargo.toml").is_file();
    let has_package_json = dir.join("package.json").is_file();
    let has_pyproject = dir.join("pyproject.toml").is_file();
    let has_gomod = dir.join("go.mod").is_file();

    if !(has_git || has_cargo || has_package_json || has_pyproject || has_gomod) {
        return None;
    }

    let mut tech_stack = Vec::new();
    let mut manifest_files = Vec::new();
    let mut detected_name: Option<String> = None;

    if has_cargo {
        tech_stack.push("Rust".to_string());
        manifest_files.push("Cargo.toml".to_string());
        if let Ok(raw) = std::fs::read_to_string(dir.join("Cargo.toml"))
            && let Ok(val) = toml::from_str::<toml::Value>(&raw)
            && let Some(pkg_name) = val
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
        {
            detected_name = Some(pkg_name.to_string());
        }
    }
    if has_package_json {
        tech_stack.push("Node.js".to_string());
        manifest_files.push("package.json".to_string());
        if dir.join("tsconfig.json").is_file() {
            tech_stack.push("TypeScript".to_string());
        }
        if detected_name.is_none()
            && let Ok(raw) = std::fs::read_to_string(dir.join("package.json"))
            && let Ok(val) = serde_json::from_str::<Value>(&raw)
            && let Some(pkg_name) = val.get("name").and_then(|v| v.as_str())
        {
            detected_name = Some(pkg_name.to_string());
        }
    }
    if has_pyproject {
        tech_stack.push("Python".to_string());
        manifest_files.push("pyproject.toml".to_string());
        if detected_name.is_none()
            && let Ok(raw) = std::fs::read_to_string(dir.join("pyproject.toml"))
            && let Ok(val) = toml::from_str::<toml::Value>(&raw)
            && let Some(pkg_name) = val
                .get("project")
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
        {
            detected_name = Some(pkg_name.to_string());
        }
    }
    if has_gomod {
        tech_stack.push("Go".to_string());
        manifest_files.push("go.mod".to_string());
    }
    if has_git {
        tech_stack.push("Git".to_string());
        manifest_files.push(".git".to_string());
    }

    let folder_name = dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("project")
        .to_string();
    let name = detected_name.unwrap_or_else(|| folder_name.clone());
    let project_id = slugify_id(&folder_name);
    let git_branch = read_git_branch(dir);

    let last_active = std::fs::metadata(dir.join(".git/index"))
        .or_else(|_| std::fs::metadata(dir))
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|st| DateTime::<Utc>::from(st).to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    Some(ProjectRecord {
        project_id: project_id.clone(),
        uri: format!("project://{}", project_id),
        name,
        root_path: dir.to_string_lossy().to_string(),
        tech_stack,
        git_branch,
        last_active,
        manifest_files,
    })
}

fn read_git_branch(dir: &Path) -> Option<String> {
    let head_path = dir.join(".git/HEAD");
    let raw = std::fs::read_to_string(head_path).ok()?;
    let trimmed = raw.trim();
    if let Some(r) = trimmed.strip_prefix("ref: refs/heads/") {
        Some(r.trim().to_string())
    } else if trimmed.len() >= 7 {
        Some(trimmed[..7].to_string())
    } else {
        None
    }
}

fn slugify_id(raw: &str) -> String {
    let mut s = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            s.push(ch.to_ascii_lowercase());
        } else if ch == '.' || ch == ' ' {
            s.push('-');
        }
    }
    let clean = s.trim_matches('-').to_string();
    if clean.is_empty() {
        "project".to_string()
    } else {
        clean
    }
}

/// Extract memory candidates from a completed task without auto-persisting (`M-05`, §11.3).
pub fn propose_memory_candidates_from_task(
    core: &IntentOsCore,
    task: &Task,
) -> Vec<MemoryCandidate> {
    if task.status != TaskStatus::Completed {
        return Vec::new();
    }
    if !core.task_privacy_policy(&task.id).allows_habit_learning()
        || !crate::security_guard::PrivacySessionPolicy::from_session(
            false,
            task.session_id.as_deref(),
        )
        .allows_habit_learning()
    {
        return Vec::new();
    }

    let mut extracted = Vec::new();

    for step in &task.steps {
        let args: Value =
            serde_json::from_str(&step.arguments_summary).unwrap_or_else(|_| json!({}));
        match step.capability_id.as_str() {
            "scene.apply" => {
                if let Some(scene) = args.get("scene").and_then(|v| v.as_str()) {
                    extracted.push((
                        "preference".to_string(),
                        "personal".to_string(),
                        "scene.preferred".to_string(),
                        scene.to_string(),
                        format!("从已完成任务 `{}` 提取的常用场景偏好", task.goal),
                        0.85,
                    ));
                }
            }
            "power.profile.set" => {
                if let Some(prof) = args.get("profile").and_then(|v| v.as_str()) {
                    extracted.push((
                        "preference".to_string(),
                        "personal".to_string(),
                        "power.preferred_profile".to_string(),
                        prof.to_string(),
                        format!("从已完成任务 `{}` 推断的电源档位偏好", task.goal),
                        0.80,
                    ));
                }
            }
            "git.status" | "git.log" | "git.diff" => {
                if let Some(repo_dir) = args.get("repo_dir").and_then(|v| v.as_str()) {
                    let proj_slug = Path::new(repo_dir)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(slugify_id)
                        .unwrap_or_else(|| "default".to_string());
                    extracted.push((
                        "convention".to_string(),
                        format!("project:{}", proj_slug),
                        format!("project.{}.repo_dir", proj_slug),
                        repo_dir.to_string(),
                        format!("从 Git 任务 `{}` 识别的活跃项目仓库路径", task.goal),
                        0.90,
                    ));
                }
            }
            "file.move" | "file.copy" => {
                if let Some(target) = args.get("target").and_then(|v| v.as_str())
                    && let Some(parent) = Path::new(target).parent()
                {
                    extracted.push((
                        "convention".to_string(),
                        "personal".to_string(),
                        "archive.recent_target_dir".to_string(),
                        parent.to_string_lossy().to_string(),
                        format!("从文件整理任务 `{}` 提取的归档目录习惯", task.goal),
                        0.82,
                    ));
                }
            }
            _ => {}
        }
    }

    if extracted.is_empty() && !task.goal.trim().is_empty() {
        let scope = task
            .project_id
            .as_ref()
            .map(|pid| format!("project:{}", pid))
            .unwrap_or_else(|| "personal".to_string());
        extracted.push((
            "fact".to_string(),
            scope,
            format!("task.recent_goal.{}", &task.id[..task.id.len().min(9)]),
            task.goal.clone(),
            "从已验证完成任务生成的跨会话连续性候选".to_string(),
            0.78,
        ));
    }

    with_store(core, |store| {
        if store.processed_task_ids.contains(&task.id) {
            return store
                .candidates
                .values()
                .filter(|c| c.source_task_id.as_deref() == Some(task.id.as_str()))
                .cloned()
                .collect();
        }
        store.processed_task_ids.insert(task.id.clone());

        let mut added = Vec::new();
        for (mem_type, scope, subject, value, reason, confidence) in extracted {
            if contains_forbidden_secret(&subject, &value) {
                continue;
            }
            let fp = compute_memory_fingerprint(&subject, &value);
            if store.rejected_fingerprints.contains(&fp) {
                continue;
            }
            if store
                .candidates
                .values()
                .any(|c| c.subject == subject && c.value == value && c.status != "rejected")
            {
                continue;
            }

            let candidate_id =
                format!("mcand_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
            let cand = MemoryCandidate {
                candidate_id: candidate_id.clone(),
                mem_type,
                scope,
                subject,
                value,
                reason,
                source_task_id: Some(task.id.clone()),
                taint: task.taint.clone(),
                confidence,
                data_class: DataClass::Personal,
                status: "pending".to_string(),
                confirmed_memory_id: None,
                created_at: Utc::now(),
            };
            store.candidates.insert(candidate_id, cand.clone());
            added.push(cand);
        }
        added
    })
}

/// Propose an explicit memory candidate (e.g. from `memory_propose` tool or session-end summary, `M-05`).
pub fn propose_custom_memory_candidate(
    core: &IntentOsCore,
    subject: &str,
    value: &str,
    scope: Option<&str>,
    mem_type: Option<&str>,
    source_task_id: Option<&str>,
) -> anyhow::Result<MemoryCandidate> {
    if contains_forbidden_secret(subject, value) {
        anyhow::bail!("出于安全策略，禁止提出包含密钥、口令或凭据的记忆候选");
    }
    let fp = compute_memory_fingerprint(subject, value);
    with_store(core, |store| {
        if store.rejected_fingerprints.contains(&fp) {
            anyhow::bail!("该记忆候选已被用户拒绝或删除（已命中墓碑指纹），不再重复提议");
        }
        let candidate_id = format!("mcand_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        let cand = MemoryCandidate {
            candidate_id: candidate_id.clone(),
            mem_type: mem_type.unwrap_or("preference").to_string(),
            scope: scope.unwrap_or("personal").to_string(),
            subject: subject.trim().to_string(),
            value: value.trim().to_string(),
            reason: "任务或会话提议的记忆候选（需用户确认后入库）".to_string(),
            source_task_id: source_task_id.map(String::from),
            taint: vec![Taint::User],
            confidence: 0.90,
            data_class: DataClass::Personal,
            status: "pending".to_string(),
            confirmed_memory_id: None,
            created_at: Utc::now(),
        };
        store.candidates.insert(candidate_id, cand.clone());
        Ok(cand)
    })
}

/// List pending/recent memory candidates (`M-05`), project-scoped memories (`M-04`), and recall provenance (`M-06`).
pub fn list_memory_candidates(core: &IntentOsCore) -> anyhow::Result<Value> {
    // Scan recent completed tasks so candidates are up to date
    if let Ok(tasks) = core.state_db.list_tasks(25) {
        for t in tasks {
            if t.status == TaskStatus::Completed {
                let _ = propose_memory_candidates_from_task(core, &t);
            }
        }
    }

    let db_memories = core.state_db.list_memory_entries().unwrap_or_default();

    Ok(with_store(core, |store| {
        let candidates: Vec<&MemoryCandidate> = store.candidates.values().rev().collect();
        let pending_count = store
            .candidates
            .values()
            .filter(|c| c.status == "pending")
            .count();

        let mut provenance: Vec<MemoryProvenanceItem> =
            store.project_memories.values().cloned().collect();
        for m in &db_memories {
            if !provenance.iter().any(|p| p.memory_id == m.id) {
                provenance.push(MemoryProvenanceItem {
                    memory_id: m.id.clone(),
                    subject: m.subject.clone(),
                    value: m.value.clone(),
                    scope: m.scope.clone(),
                    source_task_id: None,
                    taint: "memory".to_string(),
                    confidence: m.confidence,
                    updated_at: m.updated_at.clone(),
                });
            }
        }

        json!({
            "candidates": candidates,
            "pending_count": pending_count,
            "memories": db_memories,
            "provenance": provenance,
            "rejected_fingerprints_count": store.rejected_fingerprints.len(),
        })
    }))
}

/// Confirm or reject a `MemoryCandidate` (`M-05`).
/// When confirmed, writes to `core.state_db` and records provenance (`M-06`).
/// When rejected, records SHA-256 tombstone fingerprint so it is never re-proposed (`M-03`).
pub fn confirm_memory_candidate(
    core: &IntentOsCore,
    candidate_id: &str,
    reject: bool,
) -> anyhow::Result<Value> {
    let cand = with_store(core, |store| {
        store
            .candidates
            .get(candidate_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("未找到记忆候选: {}", candidate_id))
    })?;

    if reject {
        let fp = compute_memory_fingerprint(&cand.subject, &cand.value);
        with_store(core, |store| {
            if let Some(c) = store.candidates.get_mut(candidate_id) {
                c.status = "rejected".to_string();
            }
            store.rejected_fingerprints.insert(fp.clone());
        });
        return Ok(json!({
            "confirmed": false,
            "rejected": true,
            "candidate_id": candidate_id,
            "fingerprint": fp,
            "message": format!("已忽略记忆候选 `{}` 并记录指纹防止重复提议", cand.subject),
        }));
    }

    let mem_id = core.state_db.save_explicit_memory(
        &cand.subject,
        &cand.value,
        cand.source_task_id.as_deref(),
    )?;

    let prov = MemoryProvenanceItem {
        memory_id: mem_id.clone(),
        subject: cand.subject.clone(),
        value: cand.value.clone(),
        scope: cand.scope.clone(),
        source_task_id: cand.source_task_id.clone(),
        taint: "memory".to_string(),
        confidence: cand.confidence,
        updated_at: Utc::now().to_rfc3339(),
    };

    let updated_cand = with_store(core, |store| {
        store.project_memories.insert(mem_id.clone(), prov.clone());
        if let Some(c) = store.candidates.get_mut(candidate_id) {
            c.status = "confirmed".to_string();
            c.confirmed_memory_id = Some(mem_id.clone());
            return c.clone();
        }
        cand
    });

    let _ = core.state_db.record_audit(
        updated_cand.source_task_id.as_deref(),
        "memory.confirm_candidate",
        "user_explicit",
        "write.reversible",
        "allow",
        "confirmed",
        &json!({
            "candidate_id": candidate_id,
            "memory_id": mem_id,
            "subject": updated_cand.subject,
            "scope": updated_cand.scope,
        }),
        Some("用户确认写入记忆候选"),
    );

    Ok(json!({
        "confirmed": true,
        "candidate_id": candidate_id,
        "memory_id": mem_id,
        "candidate": updated_cand,
        "provenance": prov,
        "message": format!("✓ 已确认写入记忆 [{}]：{} = {}", mem_id, updated_cand.subject, updated_cand.value),
    }))
}
