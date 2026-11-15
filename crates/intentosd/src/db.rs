#![forbid(unsafe_code)]

//! SQLite WAL persistence: `state.db` (authoritative state) and `index.db` (rebuildable local index + FTS5) (§16.2).

use crate::security_guard::{PrivacySessionPolicy, SensitiveDataGuard};
use chrono::{DateTime, Utc};
use intentos_protocol::{ChangeSet, ChangeSetStatus, DataClass, MemoryEntry, Task, TaskStatus};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;

const MIGRATION_0001: &str = include_str!("../migrations/0001_init.sql");
const MIGRATION_0002: &str = include_str!("../migrations/0002_v0_1_shell.sql");
const MIGRATION_0003: &str = include_str!("../migrations/0003_v0_2_step_ledger.sql");

/// Persistent execution state for a side-effecting or audited step in `step_execution_log` (`H03`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepExecState {
    Prepared,
    Executing,
    Applied,
    Unknown,
    Verified,
    Denied,
    FailedClean,
    RecoveryRequired,
}

impl StepExecState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Executing => "executing",
            Self::Applied => "applied",
            Self::Unknown => "unknown",
            Self::Verified => "verified",
            Self::Denied => "denied",
            Self::FailedClean => "failed_clean",
            Self::RecoveryRequired => "recovery_required",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "prepared" => Some(Self::Prepared),
            "executing" => Some(Self::Executing),
            "applied" => Some(Self::Applied),
            "unknown" => Some(Self::Unknown),
            "verified" => Some(Self::Verified),
            "denied" => Some(Self::Denied),
            "failed_clean" => Some(Self::FailedClean),
            "recovery_required" => Some(Self::RecoveryRequired),
            _ => None,
        }
    }

    /// True when the step began execution (`Executing`) and its real OS effect is unconfirmed or failed mid-flight.
    pub fn is_uncertain_or_recovery(self) -> bool {
        matches!(
            self,
            Self::Executing | Self::Unknown | Self::RecoveryRequired
        )
    }

    /// True when a side effect either committed (`Verified` / `Applied`) or may have occurred (`Executing` / `Unknown` / `RecoveryRequired`).
    pub fn has_potential_or_committed_side_effect(self) -> bool {
        matches!(
            self,
            Self::Executing
                | Self::Applied
                | Self::Unknown
                | Self::Verified
                | Self::RecoveryRequired
        )
    }
}

/// Authoritative row in `step_execution_log` (`PRIMARY KEY (task_id, step_id)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepExecutionLogRow {
    pub task_id: String,
    pub turn_id: String,
    pub session_id: String,
    pub step_id: String,
    pub attempt_id: String,
    pub idempotency_key: String,
    pub capability_id: String,
    pub effect: String,
    pub exec_state: StepExecState,
    pub expected_summary: String,
    pub changeset_id: Option<String>,
    pub verification_status: String,
    pub recovery_hint: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Authoritative row in `suspended_turn_checkpoints` (`approval_id PRIMARY KEY`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuspendedCheckpointRow {
    pub approval_id: String,
    pub turn_id: String,
    pub task_id: String,
    pub session_id: String,
    pub approval_digest: String,
    pub capability_id: String,
    pub target_scope: String,
    pub checkpoint_json: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

pub struct StateDb {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for StateDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateDb").finish_non_exhaustive()
    }
}

impl StateDb {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        // Backup existing state.db before schema migration if needed (§16.2)
        let existed = path.exists();
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let current_ver: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM sqlite_master m
                 LEFT JOIN schema_version sv ON 1=1
                 WHERE m.type='table' AND m.name='schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if current_ver < 1 {
            if existed {
                let bak = path.with_extension("db.bak-pre-v1");
                let _ = std::fs::copy(path, bak);
            }
            conn.execute_batch(MIGRATION_0001)?;
            conn.execute(
                "INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (1, ?1)",
                params![Utc::now().to_rfc3339()],
            )?;
        }
        if current_ver < 2 {
            if existed && current_ver >= 1 {
                let bak = path.with_extension("db.bak-pre-v2");
                let _ = std::fs::copy(path, bak);
            }
            conn.execute_batch(MIGRATION_0002)?;
            conn.execute(
                "INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (2, ?1)",
                params![Utc::now().to_rfc3339()],
            )?;
        }
        if current_ver < 3 {
            if existed && current_ver >= 1 {
                let bak = path.with_extension("db.bak-pre-v3");
                let _ = std::fs::copy(path, bak);
            }
            conn.execute_batch(MIGRATION_0003)?;
            conn.execute(
                "INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (3, ?1)",
                params![Utc::now().to_rfc3339()],
            )?;
        }

        let db = Self {
            conn: Mutex::new(conn),
        };
        // Any task or mutating step left in 'running'/'planning'/'executing' across a daemon restart
        // enters recovery_required (§13.2, A26, H03).
        db.mark_interrupted_tasks_recovery_required()?;
        Ok(db)
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(MIGRATION_0001)?;
        conn.execute_batch(MIGRATION_0002)?;
        conn.execute_batch(MIGRATION_0003)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn mark_interrupted_tasks_recovery_required(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock().unwrap();
        let now_rfc3339 = Utc::now().to_rfc3339();
        let crash_hint = "守护进程在副作用步骤执行途中异常重启，实际系统状态未知；已阻止自动重放，请先检查真实状态或变更集后再执行恢复。";

        // 1. Transition any steps left in `executing` across a crash to `recovery_required`.
        let interrupted_steps = conn.execute(
            "UPDATE step_execution_log
             SET exec_state = 'recovery_required',
                 verification_status = CASE
                     WHEN verification_status IN ('', 'Executing', 'Prepared') THEN 'UnknownAfterCrash'
                     ELSE verification_status
                 END,
                 recovery_hint = COALESCE(recovery_hint, ?2),
                 updated_at = ?1
             WHERE exec_state = 'executing'",
            params![now_rfc3339, crash_hint],
        )?;

        // 2. Ensure any crashed mutating step whose parent Quick-Chat/Agent task had not yet been
        //    written to `tasks` creates a conservative `recovery_required` task record.
        {
            let mut orphan_stmt = conn.prepare(
                "SELECT s.task_id, s.capability_id, s.expected_summary, s.changeset_id, s.created_at
                 FROM step_execution_log s
                 LEFT JOIN tasks t ON t.id = s.task_id
                 WHERE s.exec_state IN ('unknown', 'recovery_required') AND t.id IS NULL
                 GROUP BY s.task_id",
            )?;
            let orphans: Vec<(String, String, String, Option<String>, String)> = orphan_stmt
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for (tid, cap_id, exp_sum, cs_opt, created_s) in orphans {
                let goal = if exp_sum.trim().is_empty() {
                    format!("中断的步骤恢复检查 ({})", cap_id)
                } else {
                    exp_sum
                };
                let cs_json = match cs_opt {
                    Some(cs) => serde_json::to_string(&vec![cs]).unwrap_or_else(|_| "[]".into()),
                    None => "[]".into(),
                };
                let budget_json = serde_json::to_string(&intentos_protocol::TaskBudget::default())
                    .unwrap_or_else(|_| "{}".into());
                let _ = conn.execute(
                    "INSERT OR IGNORE INTO tasks (
                        id, goal, project_id, trigger_kind, route, status, steps_json,
                        changeset_ids_json, pending_approval_json, assistant_message,
                        result_summary, taint_json, data_class, budget_json, created_at, updated_at
                     ) VALUES (?1, ?2, NULL, 'user', 'L2', 'recovery_required', '[]', ?3, NULL, ?4, ?4, '[\"user\"]', 'personal', ?5, ?6, ?7)",
                    params![
                        tid,
                        SensitiveDataGuard::redact_text(&goal).0,
                        cs_json,
                        crash_hint,
                        budget_json,
                        created_s,
                        now_rfc3339,
                    ],
                );
            }
        }

        // 3. Transition active tasks and tasks owning `unknown` / `recovery_required` steps to `recovery_required`.
        let changed_tasks = conn.execute(
            "UPDATE tasks SET status = 'recovery_required', updated_at = ?1
             WHERE status IN ('running', 'planning', 'verifying')
                OR (status NOT IN ('completed', 'cancelled', 'failed', 'recovery_required')
                    AND id IN (
                        SELECT DISTINCT task_id FROM step_execution_log
                        WHERE exec_state IN ('unknown', 'recovery_required')
                    ))",
            params![now_rfc3339],
        )?;

        // 4. Evict expired persisted approval checkpoints on startup.
        let _ = conn.execute(
            "DELETE FROM suspended_turn_checkpoints WHERE expires_at <= ?1",
            params![now_rfc3339],
        );

        Ok(changed_tasks + interrupted_steps)
    }

    pub fn upsert_task(&self, task: &Task) -> anyhow::Result<()> {
        let clean_task = crate::security_guard::SensitiveDataGuard::sanitize_task_for_storage(task);
        let conn = self.conn.lock().unwrap();
        let steps_json = serde_json::to_string(&clean_task.steps)?;
        let cs_json = serde_json::to_string(&clean_task.changeset_ids)?;
        let pa_json = clean_task
            .pending_approval
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let taint_json = serde_json::to_string(&clean_task.taint)?;
        let budget_json = serde_json::to_string(&clean_task.budget)?;
        let trigger_str = serde_json::to_value(clean_task.trigger)?
            .as_str()
            .unwrap_or("user")
            .to_string();
        let route_str = serde_json::to_value(clean_task.route)?
            .as_str()
            .unwrap_or("L0")
            .to_string();
        let status_str = serde_json::to_value(clean_task.status)?
            .as_str()
            .unwrap_or("created")
            .to_string();
        let dc_str = serde_json::to_value(clean_task.data_class)?
            .as_str()
            .unwrap_or("public")
            .to_string();

        conn.execute(
            "INSERT INTO tasks (
                id, goal, project_id, trigger_kind, route, status, steps_json,
                changeset_ids_json, pending_approval_json, assistant_message,
                result_summary, taint_json, data_class, budget_json, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
             ON CONFLICT(id) DO UPDATE SET
                goal = excluded.goal,
                status = excluded.status,
                steps_json = excluded.steps_json,
                changeset_ids_json = excluded.changeset_ids_json,
                pending_approval_json = excluded.pending_approval_json,
                assistant_message = excluded.assistant_message,
                result_summary = excluded.result_summary,
                taint_json = excluded.taint_json,
                data_class = excluded.data_class,
                updated_at = excluded.updated_at",
            params![
                clean_task.id,
                clean_task.goal,
                clean_task.project_id,
                trigger_str,
                route_str,
                status_str,
                steps_json,
                cs_json,
                pa_json,
                clean_task.assistant_message,
                clean_task.result_summary,
                taint_json,
                dc_str,
                budget_json,
                clean_task.created_at.to_rfc3339(),
                clean_task.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_task(&self, task_id: &str) -> anyhow::Result<Option<Task>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, goal, project_id, trigger_kind, route, status, steps_json,
                    changeset_ids_json, pending_approval_json, assistant_message,
                    result_summary, taint_json, data_class, budget_json, created_at, updated_at
             FROM tasks WHERE id = ?1",
        )?;
        let row = stmt
            .query_row(params![task_id], Self::row_to_task)
            .optional()?;
        Ok(row)
    }

    pub fn list_tasks(&self, limit: usize) -> anyhow::Result<Vec<Task>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, goal, project_id, trigger_kind, route, status, steps_json,
                    changeset_ids_json, pending_approval_json, assistant_message,
                    result_summary, taint_json, data_class, budget_json, created_at, updated_at
             FROM tasks ORDER BY updated_at DESC LIMIT ?1",
        )?;
        let iter = stmt.query_map(params![limit as i64], Self::row_to_task)?;
        let mut out = Vec::new();
        for item in iter {
            out.push(item?);
        }
        Ok(out)
    }

    fn row_to_task(row: &rusqlite::Row<'_>) -> rusqlite::Result<Task> {
        let trigger_s: String = row.get(3)?;
        let route_s: String = row.get(4)?;
        let status_s: String = row.get(5)?;
        let steps_s: String = row.get(6)?;
        let cs_s: String = row.get(7)?;
        let pa_s: Option<String> = row.get(8)?;
        let taint_s: String = row.get(11)?;
        let dc_s: String = row.get(12)?;
        let budget_s: String = row.get(13)?;
        let created_s: String = row.get(14)?;
        let updated_s: String = row.get(15)?;

        let steps: Vec<intentos_protocol::TaskStep> =
            serde_json::from_str(&steps_s).unwrap_or_default();
        let handoff_command = steps.iter().find_map(|st| {
            st.data
                .get("handoff_command")
                .and_then(|v| v.as_str())
                .map(String::from)
        });

        Ok(Task {
            id: row.get(0)?,
            goal: row.get(1)?,
            session_id: None,
            project_id: row.get(2)?,
            trigger: serde_json::from_value(serde_json::Value::String(trigger_s))
                .unwrap_or(intentos_protocol::TaskTrigger::User),
            route: serde_json::from_value(serde_json::Value::String(route_s))
                .unwrap_or(intentos_protocol::RouteLayer::L0),
            status: serde_json::from_value(serde_json::Value::String(status_s))
                .unwrap_or(TaskStatus::Failed),
            steps,
            changeset_ids: serde_json::from_str(&cs_s).unwrap_or_default(),
            pending_approval: pa_s.and_then(|s| serde_json::from_str(&s).ok()),
            candidates_for_disambiguation: Vec::new(),
            assistant_message: row.get(9)?,
            result_summary: row.get(10)?,
            handoff_command,
            taint: serde_json::from_str(&taint_s).unwrap_or_default(),
            data_class: serde_json::from_value(serde_json::Value::String(dc_s)).unwrap_or_default(),
            budget: serde_json::from_str(&budget_s).unwrap_or_default(),
            created_at: DateTime::parse_from_rfc3339(&created_s)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&updated_s)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
    }

    pub fn save_changeset(&self, cs: &ChangeSet) -> anyhow::Result<()> {
        let clean_cs =
            crate::security_guard::SensitiveDataGuard::sanitize_changeset_for_storage(cs);
        let conn = self.conn.lock().unwrap();
        let ops_json = serde_json::to_string(&clean_cs.operations)?;
        let status_str = serde_json::to_value(clean_cs.status)?
            .as_str()
            .unwrap_or("applied")
            .to_string();
        conn.execute(
            "INSERT INTO changesets (
                id, task_id, created_at, capability_id, layer, operations_json,
                backup_bytes, status, undo_expires_at, summary
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET
                operations_json = excluded.operations_json,
                status = excluded.status,
                summary = excluded.summary",
            params![
                clean_cs.id,
                clean_cs.task_id,
                clean_cs
                    .created_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                clean_cs.capability_id,
                clean_cs.layer,
                ops_json,
                clean_cs.backup_bytes as i64,
                status_str,
                clean_cs
                    .undo_expires_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                clean_cs.summary,
            ],
        )?;
        Ok(())
    }

    pub fn insert_changeset(&self, cs: &ChangeSet) -> anyhow::Result<()> {
        self.save_changeset(cs)
    }

    pub fn get_changeset(&self, cs_id: &str) -> anyhow::Result<Option<ChangeSet>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, task_id, created_at, capability_id, layer, operations_json,
                    backup_bytes, status, undo_expires_at, summary
             FROM changesets WHERE id = ?1",
        )?;
        let cs = stmt
            .query_row(params![cs_id], Self::row_to_changeset)
            .optional()?;
        Ok(cs)
    }

    pub fn latest_applied_changeset(&self) -> anyhow::Result<Option<ChangeSet>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, task_id, created_at, capability_id, layer, operations_json,
                    backup_bytes, status, undo_expires_at, summary
             FROM changesets WHERE status = 'applied'
             ORDER BY rowid DESC LIMIT 1",
        )?;
        let cs = stmt.query_row([], Self::row_to_changeset).optional()?;
        Ok(cs)
    }

    pub fn list_changesets(&self, limit: usize) -> anyhow::Result<Vec<ChangeSet>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, task_id, created_at, capability_id, layer, operations_json,
                    backup_bytes, status, undo_expires_at, summary
             FROM changesets ORDER BY rowid DESC LIMIT ?1",
        )?;
        let iter = stmt.query_map(params![limit as i64], Self::row_to_changeset)?;
        let mut out = Vec::new();
        for item in iter {
            out.push(item?);
        }
        Ok(out)
    }

    pub fn count_applied_changesets(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM changesets WHERE status = 'applied'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0) as usize
    }

    fn row_to_changeset(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChangeSet> {
        let created_s: String = row.get(2)?;
        let ops_s: String = row.get(5)?;
        let backup_bytes: i64 = row.get(6)?;
        let status_s: String = row.get(7)?;
        let expires_s: String = row.get(8)?;
        Ok(ChangeSet {
            id: row.get(0)?,
            task_id: row.get(1)?,
            created_at: DateTime::parse_from_rfc3339(&created_s)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            capability_id: row.get(3)?,
            layer: row.get(4)?,
            operations: serde_json::from_str(&ops_s).unwrap_or_default(),
            backup_bytes: backup_bytes.max(0) as u64,
            status: serde_json::from_value(serde_json::Value::String(status_s))
                .unwrap_or(ChangeSetStatus::Applied),
            undo_expires_at: DateTime::parse_from_rfc3339(&expires_s)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            summary: row.get(9)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_audit(
        &self,
        task_id: Option<&str>,
        capability_id: &str,
        origin: &str,
        effect: &str,
        decision: &str,
        status: &str,
        args: &serde_json::Value,
        details: Option<&str>,
    ) -> anyhow::Result<()> {
        let redacted = redact_json_value(args);
        let clean_details =
            details.map(|d| crate::security_guard::SensitiveDataGuard::redact_text(d).0);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_log (timestamp, task_id, capability_id, origin, effect, decision, status, redacted_args, details)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                Utc::now().to_rfc3339(),
                task_id,
                capability_id,
                origin,
                effect,
                decision,
                status,
                serde_json::to_string(&redacted).unwrap_or_default(),
                clean_details,
            ],
        )?;
        Ok(())
    }

    pub fn save_explicit_memory(
        &self,
        subject: &str,
        value: &str,
        task_id: Option<&str>,
    ) -> anyhow::Result<String> {
        // Never persist raw private keys, API tokens, or passwords in memory (§11.3, M-02)
        let lower_val = value.to_ascii_lowercase();
        let lower_subj = subject.to_ascii_lowercase();
        if crate::security_guard::SensitiveDataGuard::contains_sensitive_secret(subject).is_some()
            || crate::security_guard::SensitiveDataGuard::contains_sensitive_secret(value).is_some()
            || lower_val.contains("-----begin ")
            || lower_val.contains("sk-")
            || lower_val.contains("api_key")
            || lower_val.contains("apikey")
            || lower_val.contains("password")
            || value.contains("密码")
            || value.contains("口令")
            || value.contains("密钥")
            || value.contains("私钥")
            || lower_subj.contains("password")
            || lower_subj.contains("secret")
            || lower_subj.contains("token")
            || lower_subj.contains("api_key")
            || subject.contains("密码")
            || subject.contains("口令")
            || subject.contains("密钥")
            || subject.contains("私钥")
        {
            anyhow::bail!("出于安全策略，禁止在记忆中心保存密钥、口令或认证凭据");
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let now = Utc::now().to_rfc3339();
        let existing_id: Option<String> = tx
            .query_row(
                "SELECT id FROM memories WHERE subject = ?1 AND status = 'active' LIMIT 1",
                params![subject],
                |r| r.get(0),
            )
            .optional()?;
        let id = existing_id
            .unwrap_or_else(|| format!("mem_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]));
        let source = serde_json::json!({
            "type": "user_explicit",
            "task_id": task_id,
            "taint": ["user"]
        });
        tx.execute(
            "INSERT OR REPLACE INTO memories
             (id, mem_type, scope_kind, scope_id, subject, value, source_json, confidence, data_class, status, created_at, updated_at)
             VALUES (?1, 'preference', 'user', 'local-user', ?2, ?3, ?4, 1.0, 'personal', 'active', ?5, ?5)",
            params![id, subject, value, source.to_string(), now],
        )?;
        tx.execute("DELETE FROM memories_fts WHERE mem_id = ?1", params![id])?;
        tx.execute(
            "INSERT INTO memories_fts (mem_id, subject, value) VALUES (?1, ?2, ?3)",
            params![id, subject, value],
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn list_active_memories(&self) -> anyhow::Result<Vec<(String, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, subject, value FROM memories WHERE status = 'active' ORDER BY updated_at DESC LIMIT 50",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn list_memory_entries(&self) -> anyhow::Result<Vec<MemoryEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, mem_type, scope_kind, scope_id, subject, value, confidence, created_at, updated_at
             FROM memories WHERE status = 'active' ORDER BY updated_at DESC LIMIT 100",
        )?;
        let rows = stmt.query_map([], |r| {
            let sk: String = r.get(2)?;
            let sid: String = r.get(3)?;
            Ok(MemoryEntry {
                id: r.get(0)?,
                mem_type: r.get(1)?,
                scope: format!("{}:{}", sk, sid),
                subject: r.get(4)?,
                value: r.get(5)?,
                confidence: r.get(6)?,
                data_class: DataClass::Personal,
                created_at: r.get(7)?,
                updated_at: r.get(8)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_memory_value(&self, subject: &str) -> Option<String> {
        let conn = self.conn.lock().ok()?;
        conn.query_row(
            "SELECT value FROM memories WHERE subject = ?1 AND status = 'active' ORDER BY updated_at DESC LIMIT 1",
            params![subject],
            |r| r.get(0),
        )
        .ok()
    }

    /// Transactional memory deletion + fingerprint tombstone (§11.3, M-03).
    pub fn delete_memory(&self, id_or_subject: &str) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let found: Option<(String, String, String)> = tx
            .query_row(
                "SELECT id, subject, value FROM memories WHERE (id = ?1 OR subject = ?1) AND status = 'active' LIMIT 1",
                params![id_or_subject],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((id, subj, val)) = found else {
            return Ok(false);
        };
        tx.execute("DELETE FROM memories WHERE id = ?1", params![id])?;
        tx.execute("DELETE FROM memories_fts WHERE mem_id = ?1", params![id])?;
        let mut h = Sha256::new();
        h.update(subj.as_bytes());
        h.update(b"=");
        h.update(val.as_bytes());
        let fp = hex::encode(h.finalize());
        tx.execute(
            "INSERT OR REPLACE INTO rejected_memory_fingerprints (fingerprint, rejected_at) VALUES (?1, ?2)",
            params![fp, Utc::now().to_rfc3339()],
        )?;
        tx.commit()?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_decision_calibration(
        &self,
        query: &str,
        top_option: &str,
        top_probability: f64,
        margin: f64,
        needs_multistep_prob: f64,
        injection_risk_score: f64,
        action_taken: &str,
    ) {
        let (clean_query, _) = crate::security_guard::SensitiveDataGuard::redact_text(query);
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT INTO decision_calibrations
                 (timestamp, query, top_option, top_probability, margin, needs_multistep_prob, injection_risk_score, action_taken)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    Utc::now().to_rfc3339(),
                    clean_query,
                    top_option,
                    top_probability,
                    margin,
                    needs_multistep_prob,
                    injection_risk_score,
                    action_taken
                ],
            );
        }
    }

    pub fn save_custom_scene(
        &self,
        name: &str,
        description: &str,
        steps: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO custom_scenes (name, description, steps_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)",
            params![name, description, serde_json::to_string(steps)?, now],
        )?;
        Ok(())
    }

    pub fn get_custom_scene(&self, name: &str) -> Option<(String, serde_json::Value)> {
        let conn = self.conn.lock().ok()?;
        let (desc, raw): (String, String) = conn
            .query_row(
                "SELECT description, steps_json FROM custom_scenes WHERE name = ?1",
                params![name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok()?;
        let parsed = serde_json::from_str(&raw).ok()?;
        Some((desc, parsed))
    }

    pub fn list_custom_scenes(&self) -> Vec<(String, String)> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) =
            conn.prepare("SELECT name, description FROM custom_scenes ORDER BY updated_at DESC")
        else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        else {
            return Vec::new();
        };
        rows.flatten().collect()
    }

    pub fn list_recent_audit(&self, limit: usize) -> Vec<serde_json::Value> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT timestamp, task_id, capability_id, origin, effect, decision, status, details
             FROM audit_log ORDER BY id DESC LIMIT ?1",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map(params![limit as i64], |r| {
            Ok(serde_json::json!({
                "timestamp": r.get::<_, String>(0)?,
                "task_id": r.get::<_, Option<String>>(1)?,
                "capability_id": r.get::<_, String>(2)?,
                "origin": r.get::<_, String>(3)?,
                "effect": r.get::<_, String>(4)?,
                "decision": r.get::<_, String>(5)?,
                "status": r.get::<_, String>(6)?,
                "details": r.get::<_, Option<String>>(7)?,
            }))
        }) else {
            return Vec::new();
        };
        rows.flatten().collect()
    }

    fn row_to_step_execution_log(row: &rusqlite::Row<'_>) -> rusqlite::Result<StepExecutionLogRow> {
        let state_s: String = row.get(8)?;
        let created_s: String = row.get(13)?;
        let updated_s: String = row.get(14)?;
        Ok(StepExecutionLogRow {
            task_id: row.get(0)?,
            turn_id: row.get(1)?,
            session_id: row.get(2)?,
            step_id: row.get(3)?,
            attempt_id: row.get(4)?,
            idempotency_key: row.get(5)?,
            capability_id: row.get(6)?,
            effect: row.get(7)?,
            exec_state: StepExecState::parse(&state_s).unwrap_or(StepExecState::Unknown),
            expected_summary: row.get(9)?,
            changeset_id: row.get(10)?,
            verification_status: row.get(11)?,
            recovery_hint: row.get(12)?,
            created_at: DateTime::parse_from_rfc3339(&created_s)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&updated_s)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
    }

    /// Persist or update a `StepExecutionLogRow` in `state.db` (`H03`).
    ///
    /// - Strictly returns `Ok(false)` (0 SQLite writes!) when `!privacy.allows_task_persistence()`
    ///   (`EphemeralReadOnly` and `StrictIsolated` remain 100% in-memory).
    /// - Sanitizes all text fields via `SensitiveDataGuard` BEFORE SQLite write.
    pub fn upsert_step_execution_log(
        &self,
        row: &StepExecutionLogRow,
        privacy: PrivacySessionPolicy,
    ) -> anyhow::Result<bool> {
        if !privacy.allows_task_persistence() {
            return Ok(false);
        }

        let clean_task_id = SensitiveDataGuard::redact_text(&row.task_id).0;
        let clean_turn_id = SensitiveDataGuard::redact_text(&row.turn_id).0;
        let clean_session_id = SensitiveDataGuard::redact_text(&row.session_id).0;
        let clean_expected = SensitiveDataGuard::redact_text(&row.expected_summary).0;
        let clean_verif = SensitiveDataGuard::redact_text(&row.verification_status).0;
        let clean_hint = row
            .recovery_hint
            .as_deref()
            .map(|h| SensitiveDataGuard::redact_text(h).0);

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO step_execution_log (
                task_id, turn_id, session_id, step_id, attempt_id, idempotency_key,
                capability_id, effect, exec_state, expected_summary, changeset_id,
                verification_status, recovery_hint, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(task_id, step_id) DO UPDATE SET
                turn_id = excluded.turn_id,
                session_id = excluded.session_id,
                attempt_id = excluded.attempt_id,
                idempotency_key = excluded.idempotency_key,
                capability_id = excluded.capability_id,
                effect = excluded.effect,
                exec_state = excluded.exec_state,
                expected_summary = CASE
                    WHEN excluded.expected_summary != '' THEN excluded.expected_summary
                    ELSE step_execution_log.expected_summary
                END,
                changeset_id = COALESCE(excluded.changeset_id, step_execution_log.changeset_id),
                verification_status = excluded.verification_status,
                recovery_hint = excluded.recovery_hint,
                updated_at = excluded.updated_at",
            params![
                clean_task_id,
                clean_turn_id,
                clean_session_id,
                row.step_id,
                row.attempt_id,
                row.idempotency_key,
                row.capability_id,
                row.effect,
                row.exec_state.as_str(),
                clean_expected,
                row.changeset_id,
                clean_verif,
                clean_hint,
                row.created_at.to_rfc3339(),
                row.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(true)
    }

    pub fn get_step_execution_log(
        &self,
        task_id: &str,
        step_id: &str,
    ) -> anyhow::Result<Option<StepExecutionLogRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT task_id, turn_id, session_id, step_id, attempt_id, idempotency_key,
                    capability_id, effect, exec_state, expected_summary, changeset_id,
                    verification_status, recovery_hint, created_at, updated_at
             FROM step_execution_log
             WHERE task_id = ?1 AND step_id = ?2",
        )?;
        let row = stmt
            .query_row(params![task_id, step_id], Self::row_to_step_execution_log)
            .optional()?;
        Ok(row)
    }

    pub fn list_step_execution_logs_for_task(
        &self,
        task_id: &str,
    ) -> anyhow::Result<Vec<StepExecutionLogRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT task_id, turn_id, session_id, step_id, attempt_id, idempotency_key,
                    capability_id, effect, exec_state, expected_summary, changeset_id,
                    verification_status, recovery_hint, created_at, updated_at
             FROM step_execution_log
             WHERE task_id = ?1
             ORDER BY rowid ASC",
        )?;
        let iter = stmt.query_map(params![task_id], Self::row_to_step_execution_log)?;
        let mut out = Vec::new();
        for item in iter {
            out.push(item?);
        }
        Ok(out)
    }

    pub fn list_step_execution_logs_for_turn(
        &self,
        turn_id: &str,
    ) -> anyhow::Result<Vec<StepExecutionLogRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT task_id, turn_id, session_id, step_id, attempt_id, idempotency_key,
                    capability_id, effect, exec_state, expected_summary, changeset_id,
                    verification_status, recovery_hint, created_at, updated_at
             FROM step_execution_log
             WHERE turn_id = ?1
             ORDER BY rowid ASC",
        )?;
        let iter = stmt.query_map(params![turn_id], Self::row_to_step_execution_log)?;
        let mut out = Vec::new();
        for item in iter {
            out.push(item?);
        }
        Ok(out)
    }

    /// Returns `true` if `task_id` is in `recovery_required` status OR has any step in
    /// `executing`, `unknown`, or `recovery_required`.
    pub fn task_has_uncertain_or_recovery_steps(&self, task_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let step_uncertain: i64 = conn.query_row(
            "SELECT COUNT(1) FROM step_execution_log
             WHERE task_id = ?1 AND exec_state IN ('executing', 'unknown', 'recovery_required')",
            params![task_id],
            |r| r.get(0),
        )?;
        if step_uncertain > 0 {
            return Ok(true);
        }
        let task_recovery: i64 = conn.query_row(
            "SELECT COUNT(1) FROM tasks WHERE id = ?1 AND status = 'recovery_required'",
            params![task_id],
            |r| r.get(0),
        )?;
        Ok(task_recovery > 0)
    }

    /// Returns `true` if `turn_id` has any step in `executing`, `unknown`, or `recovery_required`.
    pub fn turn_has_uncertain_or_recovery_steps(&self, turn_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(1) FROM step_execution_log
             WHERE turn_id = ?1 AND exec_state IN ('executing', 'unknown', 'recovery_required')",
            params![turn_id],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn count_step_execution_logs(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: i64 =
            conn.query_row("SELECT COUNT(1) FROM step_execution_log", [], |r| r.get(0))?;
        Ok(count as usize)
    }

    /// Persist a `SuspendedCheckpointRow` in `state.db` (`H03`).
    ///
    /// - Strictly returns `Ok(false)` (0 SQLite writes!) when `!privacy.allows_task_persistence()`
    ///   (`EphemeralReadOnly` and `StrictIsolated` remain strictly in-memory).
    /// - Sanitizes `checkpoint_json` and `target_scope` through `SensitiveDataGuard` BEFORE SQLite write.
    pub fn save_suspended_checkpoint_row(
        &self,
        row: &SuspendedCheckpointRow,
        privacy: PrivacySessionPolicy,
    ) -> anyhow::Result<bool> {
        if !privacy.allows_task_persistence() {
            return Ok(false);
        }

        let clean_checkpoint_json = if let Ok(mut parsed) =
            serde_json::from_str::<serde_json::Value>(&row.checkpoint_json)
        {
            SensitiveDataGuard::redact_json(&mut parsed);
            serde_json::to_string(&parsed)?
        } else {
            SensitiveDataGuard::redact_text(&row.checkpoint_json).0
        };
        let clean_scope = SensitiveDataGuard::redact_text(&row.target_scope).0;
        let clean_session = SensitiveDataGuard::redact_text(&row.session_id).0;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO suspended_turn_checkpoints (
                approval_id, turn_id, task_id, session_id, approval_digest,
                capability_id, target_scope, checkpoint_json, expires_at, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                row.approval_id,
                row.turn_id,
                row.task_id,
                clean_session,
                row.approval_digest,
                row.capability_id,
                clean_scope,
                clean_checkpoint_json,
                row.expires_at.to_rfc3339(),
                row.created_at.to_rfc3339(),
            ],
        )?;
        Ok(true)
    }

    pub fn get_suspended_checkpoint_row(
        &self,
        approval_id: &str,
    ) -> anyhow::Result<Option<SuspendedCheckpointRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT approval_id, turn_id, task_id, session_id, approval_digest,
                    capability_id, target_scope, checkpoint_json, expires_at, created_at
             FROM suspended_turn_checkpoints
             WHERE approval_id = ?1",
        )?;
        let row = stmt
            .query_row(params![approval_id], |r| {
                let exp_s: String = r.get(8)?;
                let cre_s: String = r.get(9)?;
                Ok(SuspendedCheckpointRow {
                    approval_id: r.get(0)?,
                    turn_id: r.get(1)?,
                    task_id: r.get(2)?,
                    session_id: r.get(3)?,
                    approval_digest: r.get(4)?,
                    capability_id: r.get(5)?,
                    target_scope: r.get(6)?,
                    checkpoint_json: r.get(7)?,
                    expires_at: DateTime::parse_from_rfc3339(&exp_s)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    created_at: DateTime::parse_from_rfc3339(&cre_s)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            })
            .optional()?;
        Ok(row)
    }

    pub fn delete_suspended_checkpoint_row(&self, approval_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "DELETE FROM suspended_turn_checkpoints WHERE approval_id = ?1",
            params![approval_id],
        )?;
        Ok(n > 0)
    }

    pub fn count_suspended_checkpoints(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: i64 =
            conn.query_row("SELECT COUNT(1) FROM suspended_turn_checkpoints", [], |r| {
                r.get(0)
            })?;
        Ok(count as usize)
    }
}

/// Redact potential credential keys and secret values before writing to audit log (§5.6, §24.5).
pub fn redact_json_value(val: &serde_json::Value) -> serde_json::Value {
    match val {
        serde_json::Value::Object(map) => {
            let mut clean = serde_json::Map::new();
            for (k, v) in map {
                let lower = k.to_ascii_lowercase();
                if lower.contains("key")
                    || lower.contains("token")
                    || lower.contains("secret")
                    || lower.contains("password")
                    || lower.contains("authorization")
                {
                    clean.insert(
                        k.clone(),
                        serde_json::Value::String(
                            crate::security_guard::REDACTED_SECRET_MARKER.into(),
                        ),
                    );
                } else {
                    clean.insert(k.clone(), redact_json_value(v));
                }
            }
            serde_json::Value::Object(clean)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(redact_json_value).collect())
        }
        serde_json::Value::String(s) => {
            serde_json::Value::String(crate::security_guard::SensitiveDataGuard::redact_text(s).0)
        }
        other => other.clone(),
    }
}

/// Rebuildable `index.db` storing apps, files (+FTS5), sites, frecency, and command history (§16.2).
pub struct IndexDb {
    pub conn: Mutex<Connection>,
}

impl IndexDb {
    pub fn open_or_rebuild(path: &Path) -> anyhow::Result<Self> {
        let conn = match Connection::open(path) {
            Ok(c) => c,
            Err(_) => {
                let _ = std::fs::remove_file(path);
                Connection::open(path)?
            }
        };
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS apps (
                app_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                generic_name TEXT NOT NULL DEFAULT '',
                exec_cmd TEXT NOT NULL,
                keywords TEXT NOT NULL DEFAULT '',
                pinyin_full TEXT NOT NULL DEFAULT '',
                pinyin_init TEXT NOT NULL DEFAULT '',
                aliases TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'system'
            );
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                stem TEXT NOT NULL,
                ext TEXT NOT NULL,
                category TEXT NOT NULL,
                parent_dir TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                mtime_secs INTEGER NOT NULL,
                pinyin_full TEXT NOT NULL,
                pinyin_init TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_files_mtime ON files(mtime_secs DESC);
            CREATE INDEX IF NOT EXISTS idx_files_ext ON files(ext);
            CREATE INDEX IF NOT EXISTS idx_files_size ON files(size_bytes DESC);
            CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
                path UNINDEXED,
                name,
                pinyin_full,
                pinyin_init,
                tokenize = 'unicode61'
            );
            CREATE TABLE IF NOT EXISTS frecency (
                item_key TEXT PRIMARY KEY,
                hits INTEGER NOT NULL DEFAULT 1,
                last_used_secs INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                cwd TEXT NOT NULL,
                created_at_secs INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dependency_probes (
                name TEXT PRIMARY KEY,
                available INTEGER NOT NULL,
                details TEXT NOT NULL,
                probed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS fonts (
                family TEXT PRIMARY KEY,
                lower_family TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bookmarks (
                url TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                lower_title TEXT NOT NULL,
                browser TEXT NOT NULL
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn record_frecency(&self, item_key: &str) {
        let now = Utc::now().timestamp();
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT INTO frecency (item_key, hits, last_used_secs) VALUES (?1, 1, ?2)
                 ON CONFLICT(item_key) DO UPDATE SET hits = hits + 1, last_used_secs = excluded.last_used_secs",
                params![item_key, now],
            );
        }
    }

    pub fn get_frecency_boost(&self, item_key: &str) -> f64 {
        let Ok(conn) = self.conn.lock() else {
            return 0.0;
        };
        conn.query_row(
            "SELECT hits, last_used_secs FROM frecency WHERE item_key = ?1",
            params![item_key],
            |r| {
                let hits: i64 = r.get(0)?;
                let last: i64 = r.get(1)?;
                let age_hours = ((Utc::now().timestamp() - last).max(0) as f64) / 3600.0;
                let recency = 1.0 / (1.0 + age_hours / 24.0);
                Ok((hits as f64).ln_1p() * 12.0 + recency * 15.0)
            },
        )
        .unwrap_or(0.0)
    }

    pub fn record_passthrough_command(&self, command: &str, cwd: &str) {
        let now = Utc::now().timestamp();
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT INTO command_history (command, cwd, created_at_secs) VALUES (?1, ?2, ?3)",
                params![command, cwd, now],
            );
        }
    }

    pub fn list_passthrough_history(&self, limit: usize) -> Vec<serde_json::Value> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT command, cwd, created_at_secs FROM command_history ORDER BY id DESC LIMIT ?1",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map(params![limit as i64], |r| {
            Ok(serde_json::json!({
                "command": r.get::<_, String>(0)?,
                "cwd": r.get::<_, String>(1)?,
                "created_at_secs": r.get::<_, i64>(2)?,
            }))
        }) else {
            return Vec::new();
        };
        rows.flatten().collect()
    }

    pub fn clear_passthrough_history(&self) -> usize {
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        conn.execute("DELETE FROM command_history", []).unwrap_or(0)
    }

    pub fn replace_fonts(&self, families: &[String]) {
        let Ok(mut conn) = self.conn.lock() else {
            return;
        };
        let Ok(tx) = conn.transaction() else {
            return;
        };
        let _ = tx.execute("DELETE FROM fonts", []);
        for f in families {
            let clean = f.trim();
            if !clean.is_empty() {
                let _ = tx.execute(
                    "INSERT OR REPLACE INTO fonts (family, lower_family) VALUES (?1, ?2)",
                    params![clean, clean.to_ascii_lowercase()],
                );
            }
        }
        let _ = tx.commit();
    }

    pub fn list_fonts(&self) -> Vec<String> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare("SELECT family FROM fonts ORDER BY family ASC") else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) else {
            return Vec::new();
        };
        rows.flatten().collect()
    }

    pub fn replace_bookmarks(&self, items: &[(String, String, String)]) {
        let Ok(mut conn) = self.conn.lock() else {
            return;
        };
        let Ok(tx) = conn.transaction() else {
            return;
        };
        let _ = tx.execute("DELETE FROM bookmarks", []);
        for (url, title, browser) in items {
            let _ = tx.execute(
                "INSERT OR REPLACE INTO bookmarks (url, title, lower_title, browser) VALUES (?1, ?2, ?3, ?4)",
                params![url, title, title.to_ascii_lowercase(), browser],
            );
        }
        let _ = tx.commit();
    }

    pub fn search_bookmarks(&self, query: &str, limit: usize) -> Vec<(String, String, String)> {
        let q = query.trim().to_ascii_lowercase();
        if q.is_empty() {
            return Vec::new();
        }
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let pat = format!("%{}%", q);
        let Ok(mut stmt) = conn.prepare(
            "SELECT url, title, browser FROM bookmarks
             WHERE lower_title LIKE ?1 OR LOWER(url) LIKE ?1
             LIMIT ?2",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map(params![pat, limit as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        }) else {
            return Vec::new();
        };
        rows.flatten().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use intentos_protocol::{RouteLayer, Taint, TaskBudget, TaskTrigger};
    use tempfile::TempDir;

    #[test]
    fn h03_step_execution_log_crash_recovery_secret_redaction_and_privacy_isolation() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("state.db");
        let now = Utc::now();

        {
            let db = StateDb::open(&db_path).expect("open state db v3");

            // 1. EphemeralReadOnly & StrictIsolated write ZERO rows to step_execution_log / suspended_turn_checkpoints
            let eph_row = StepExecutionLogRow {
                task_id: "task_eph".into(),
                turn_id: "turn_eph".into(),
                session_id: "ephemeral_ro_01".into(),
                step_id: "step_1".into(),
                attempt_id: "attempt_1".into(),
                idempotency_key: "idem_eph".into(),
                capability_id: "file.write".into(),
                effect: "write_reversible".into(),
                exec_state: StepExecState::Executing,
                expected_summary: "ephemeral write".into(),
                changeset_id: None,
                verification_status: "Executing".into(),
                recovery_hint: None,
                created_at: now,
                updated_at: now,
            };
            assert!(
                !db.upsert_step_execution_log(&eph_row, PrivacySessionPolicy::EphemeralReadOnly)
                    .unwrap()
            );
            assert!(
                !db.upsert_step_execution_log(&eph_row, PrivacySessionPolicy::StrictIsolated)
                    .unwrap()
            );
            assert_eq!(db.count_step_execution_logs().unwrap(), 0);

            let eph_cp = SuspendedCheckpointRow {
                approval_id: "apr_eph".into(),
                turn_id: "turn_eph".into(),
                task_id: "task_eph".into(),
                session_id: "ephemeral_ro_01".into(),
                approval_digest: "digest_eph".into(),
                capability_id: "file.write".into(),
                target_scope: "directory:/tmp".into(),
                checkpoint_json: r#"{"secret":"sk-ephemeralSecretToken1234567890"}"#.into(),
                expires_at: now + ChronoDuration::minutes(10),
                created_at: now,
            };
            assert!(
                !db.save_suspended_checkpoint_row(&eph_cp, PrivacySessionPolicy::EphemeralReadOnly)
                    .unwrap()
            );
            assert!(
                !db.save_suspended_checkpoint_row(&eph_cp, PrivacySessionPolicy::StrictIsolated)
                    .unwrap()
            );
            assert_eq!(db.count_suspended_checkpoints().unwrap(), 0);

            // 2. Standard privacy persists with SensitiveDataGuard redaction AND tracks mid-flight Executing state
            let running_task = Task {
                id: "task_crash_tracked".into(),
                goal: "write config".into(),
                session_id: Some("ses_std_1".into()),
                project_id: None,
                trigger: TaskTrigger::User,
                route: RouteLayer::L2,
                status: TaskStatus::Running,
                steps: Vec::new(),
                changeset_ids: Vec::new(),
                pending_approval: None,
                candidates_for_disambiguation: Vec::new(),
                assistant_message: None,
                result_summary: None,
                handoff_command: None,
                taint: vec![Taint::User],
                data_class: DataClass::Personal,
                budget: TaskBudget::default(),
                created_at: now,
                updated_at: now,
            };
            db.upsert_task(&running_task).unwrap();

            let raw_secret = "sk-liveCrashSecretToken1234567890abcd";
            let crash_step = StepExecutionLogRow {
                task_id: "task_crash_tracked".into(),
                turn_id: "turn_crash_1".into(),
                session_id: "ses_std_1".into(),
                step_id: "step_1".into(),
                attempt_id: "attempt_1".into(),
                idempotency_key: "idem_crash_1".into(),
                capability_id: "file.write".into(),
                effect: "write_reversible".into(),
                exec_state: StepExecState::Executing,
                expected_summary: format!("write token {}", raw_secret),
                changeset_id: None,
                verification_status: "Executing".into(),
                recovery_hint: None,
                created_at: now,
                updated_at: now,
            };
            assert!(
                db.upsert_step_execution_log(&crash_step, PrivacySessionPolicy::Standard)
                    .unwrap()
            );
            let stored_pre_crash = db
                .get_step_execution_log("task_crash_tracked", "step_1")
                .unwrap()
                .unwrap();
            assert_eq!(stored_pre_crash.exec_state, StepExecState::Executing);
            assert!(!stored_pre_crash.expected_summary.contains(raw_secret));
            assert!(
                stored_pre_crash
                    .expected_summary
                    .contains("[REDACTED_SECRET]")
            );

            // Also insert an interrupted Quick-Chat Executing step whose parent `tasks` row wasn't written yet
            let orphan_crash_step = StepExecutionLogRow {
                task_id: "task_crash_quickchat_orphan".into(),
                turn_id: "turn_crash_2".into(),
                session_id: "ses_std_2".into(),
                step_id: "step_1".into(),
                attempt_id: "attempt_1".into(),
                idempotency_key: "idem_crash_2".into(),
                capability_id: "file.move".into(),
                effect: "write_reversible".into(),
                exec_state: StepExecState::Executing,
                expected_summary: "move report.md".into(),
                changeset_id: None,
                verification_status: "Executing".into(),
                recovery_hint: None,
                created_at: now,
                updated_at: now,
            };
            db.upsert_step_execution_log(&orphan_crash_step, PrivacySessionPolicy::Standard)
                .unwrap();

            // Persist one valid checkpoint (with secret to scrub) + one already-expired checkpoint
            db.save_suspended_checkpoint_row(
                &SuspendedCheckpointRow {
                    approval_id: "apr_valid".into(),
                    turn_id: "turn_cp_1".into(),
                    task_id: "task_cp_1".into(),
                    session_id: "ses_std_1".into(),
                    approval_digest: "dig_1".into(),
                    capability_id: "file.write".into(),
                    target_scope: "directory:/tmp/ws".into(),
                    checkpoint_json: format!(
                        r#"{{"note":"Bearer {}","api_key":"{}"}}"#,
                        raw_secret, raw_secret
                    ),
                    expires_at: now + ChronoDuration::minutes(30),
                    created_at: now,
                },
                PrivacySessionPolicy::Standard,
            )
            .unwrap();
            db.save_suspended_checkpoint_row(
                &SuspendedCheckpointRow {
                    approval_id: "apr_expired".into(),
                    turn_id: "turn_cp_exp".into(),
                    task_id: "task_cp_exp".into(),
                    session_id: "ses_std_1".into(),
                    approval_digest: "dig_exp".into(),
                    capability_id: "file.write".into(),
                    target_scope: "directory:/tmp/ws".into(),
                    checkpoint_json: "{}".into(),
                    expires_at: now - ChronoDuration::minutes(5),
                    created_at: now - ChronoDuration::minutes(15),
                },
                PrivacySessionPolicy::Standard,
            )
            .unwrap();
        }

        // 3. Reopen StateDb (simulating daemon restart after crash mid-Executing)
        let db2 = StateDb::open(&db_path).expect("reopen state db after crash");

        let rec_step_1 = db2
            .get_step_execution_log("task_crash_tracked", "step_1")
            .unwrap()
            .unwrap();
        assert_eq!(rec_step_1.exec_state, StepExecState::RecoveryRequired);
        assert_eq!(rec_step_1.verification_status, "UnknownAfterCrash");
        assert!(rec_step_1.recovery_hint.is_some());

        let rec_step_2 = db2
            .get_step_execution_log("task_crash_quickchat_orphan", "step_1")
            .unwrap()
            .unwrap();
        assert_eq!(rec_step_2.exec_state, StepExecState::RecoveryRequired);

        let task_1 = db2.get_task("task_crash_tracked").unwrap().unwrap();
        assert_eq!(task_1.status, TaskStatus::RecoveryRequired);
        let task_2 = db2
            .get_task("task_crash_quickchat_orphan")
            .unwrap()
            .expect("orphan crashed step must synthesize recovery_required task row");
        assert_eq!(task_2.status, TaskStatus::RecoveryRequired);

        assert!(
            db2.task_has_uncertain_or_recovery_steps("task_crash_tracked")
                .unwrap()
        );
        assert!(
            db2.task_has_uncertain_or_recovery_steps("task_crash_quickchat_orphan")
                .unwrap()
        );
        assert!(
            db2.turn_has_uncertain_or_recovery_steps("turn_crash_1")
                .unwrap()
        );
        assert!(
            db2.turn_has_uncertain_or_recovery_steps("turn_crash_2")
                .unwrap()
        );

        // Expired checkpoint evicted on startup; valid checkpoint preserved with secrets scrubbed
        assert!(
            db2.get_suspended_checkpoint_row("apr_expired")
                .unwrap()
                .is_none()
        );
        let valid_cp = db2
            .get_suspended_checkpoint_row("apr_valid")
            .unwrap()
            .expect("valid checkpoint must survive restart");
        assert!(
            !valid_cp
                .checkpoint_json
                .contains("sk-liveCrashSecretToken1234567890abcd")
        );
        assert!(valid_cp.checkpoint_json.contains("[REDACTED_SECRET]"));
    }
}
