-- IntentOS state.db Schema v2 (v0.1 Intent Shell Additive Tables: §4.2, §7.8.2 J, §11.3)

CREATE TABLE IF NOT EXISTS decision_calibrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    query TEXT NOT NULL,
    top_option TEXT NOT NULL,
    top_probability REAL NOT NULL,
    margin REAL NOT NULL,
    needs_multistep_prob REAL NOT NULL,
    injection_risk_score REAL NOT NULL,
    action_taken TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_decision_calibrations_ts ON decision_calibrations(timestamp DESC);

CREATE TABLE IF NOT EXISTS custom_scenes (
    name TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    steps_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rejected_memory_fingerprints (
    fingerprint TEXT PRIMARY KEY,
    rejected_at TEXT NOT NULL
);
