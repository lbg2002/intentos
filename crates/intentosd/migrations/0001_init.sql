-- IntentOS state.db Schema v1 (Frozen Baseline §16.2, §24.4)
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    goal TEXT NOT NULL,
    project_id TEXT,
    trigger_kind TEXT NOT NULL,
    route TEXT NOT NULL,
    status TEXT NOT NULL,
    steps_json TEXT NOT NULL,
    changeset_ids_json TEXT NOT NULL,
    pending_approval_json TEXT,
    assistant_message TEXT,
    result_summary TEXT,
    taint_json TEXT NOT NULL,
    data_class TEXT NOT NULL,
    budget_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tasks_updated_at ON tasks(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);

CREATE TABLE IF NOT EXISTS changesets (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    layer TEXT NOT NULL,
    operations_json TEXT NOT NULL,
    backup_bytes INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    undo_expires_at TEXT NOT NULL,
    summary TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_changesets_created_at ON changesets(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_changesets_task_id ON changesets(task_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    task_id TEXT,
    capability_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    effect TEXT NOT NULL,
    decision TEXT NOT NULL,
    status TEXT NOT NULL,
    redacted_args TEXT NOT NULL,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);

CREATE TABLE IF NOT EXISTS memories (
    id TEXT PRIMARY KEY,
    mem_type TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    value TEXT NOT NULL,
    source_json TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    data_class TEXT NOT NULL DEFAULT 'personal',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT
);

CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
    mem_id UNINDEXED,
    subject,
    value
);

CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    capability_pattern TEXT NOT NULL,
    resource_scope TEXT NOT NULL,
    max_effect TEXT NOT NULL,
    max_operations INTEGER NOT NULL DEFAULT 50,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);
