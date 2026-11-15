-- IntentOS state.db Schema v3 (v0.2-M1.1 H03 Persistent Step Execution Ledger & Checkpoints)

CREATE TABLE IF NOT EXISTS step_execution_log (
    task_id TEXT NOT NULL,
    turn_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    effect TEXT NOT NULL,
    exec_state TEXT NOT NULL CHECK (
        exec_state IN (
            'prepared',
            'executing',
            'applied',
            'unknown',
            'verified',
            'denied',
            'failed_clean',
            'recovery_required'
        )
    ),
    expected_summary TEXT NOT NULL DEFAULT '',
    changeset_id TEXT,
    verification_status TEXT NOT NULL DEFAULT '',
    recovery_hint TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (task_id, step_id)
);

CREATE INDEX IF NOT EXISTS idx_step_exec_log_turn_step
    ON step_execution_log(turn_id, step_id);

CREATE INDEX IF NOT EXISTS idx_step_exec_log_session_updated
    ON step_execution_log(session_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_step_exec_log_state
    ON step_execution_log(exec_state);

CREATE TABLE IF NOT EXISTS suspended_turn_checkpoints (
    approval_id TEXT PRIMARY KEY,
    turn_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    approval_digest TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    target_scope TEXT NOT NULL,
    checkpoint_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_suspended_checkpoints_turn
    ON suspended_turn_checkpoints(turn_id);

CREATE INDEX IF NOT EXISTS idx_suspended_checkpoints_task
    ON suspended_turn_checkpoints(task_id);

CREATE INDEX IF NOT EXISTS idx_suspended_checkpoints_expires
    ON suspended_turn_checkpoints(expires_at);
