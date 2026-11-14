#![forbid(unsafe_code)]

//! SQLite WAL persistence: `state.db` (authoritative state) and `index.db` (rebuildable local index + FTS5) (§16.2).

use chrono::{DateTime, Utc};
use intentos_protocol::{ChangeSet, ChangeSetStatus, DataClass, MemoryEntry, Task, TaskStatus};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;

const MIGRATION_0001: &str = include_str!("../migrations/0001_init.sql");
const MIGRATION_0002: &str = include_str!("../migrations/0002_v0_1_shell.sql");

pub struct StateDb {
    conn: Mutex<Connection>,
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

        let db = Self {
            conn: Mutex::new(conn),
        };
        // Any task left in 'running' or 'planning' across a daemon restart enters recovery_required (§13.2, A26).
        db.mark_interrupted_tasks_recovery_required()?;
        Ok(db)
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(MIGRATION_0001)?;
        conn.execute_batch(MIGRATION_0002)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn mark_interrupted_tasks_recovery_required(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE tasks SET status = 'recovery_required', updated_at = ?1
             WHERE status IN ('running', 'planning', 'verifying')",
            params![Utc::now().to_rfc3339()],
        )?;
        Ok(changed)
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
        let clean_cs = crate::security_guard::SensitiveDataGuard::sanitize_changeset_for_storage(cs);
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
                clean_cs.created_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                clean_cs.capability_id,
                clean_cs.layer,
                ops_json,
                clean_cs.backup_bytes as i64,
                status_str,
                clean_cs.undo_expires_at
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
        serde_json::Value::String(s) => serde_json::Value::String(
            crate::security_guard::SensitiveDataGuard::redact_text(s).0,
        ),
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
