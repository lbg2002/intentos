#![forbid(unsafe_code)]

//! Dedicated SQLite WAL database (`${data_dir}/memory_hub.db`) and core domain models
//! for IntentOS Memory & Personal Data Management Layer (`memory_hub`).

use crate::core::IntentOsCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entity_mentions (
    id TEXT PRIMARY KEY,
    entity_kind TEXT NOT NULL,
    canonical_value TEXT NOT NULL,
    display_name TEXT NOT NULL,
    action_verb TEXT NOT NULL DEFAULT 'mention',
    context_snippet TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL DEFAULT '',
    mention_count INTEGER NOT NULL DEFAULT 1,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_seen_epoch INTEGER NOT NULL,
    UNIQUE(entity_kind, canonical_value)
);
CREATE INDEX IF NOT EXISTS idx_entity_mentions_last_seen
    ON entity_mentions(last_seen_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_entity_mentions_kind
    ON entity_mentions(entity_kind, last_seen_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_entity_mentions_session
    ON entity_mentions(session_id, last_seen_epoch DESC);

CREATE TABLE IF NOT EXISTS long_term_files (
    path TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    open_count INTEGER NOT NULL DEFAULT 1,
    xbel_count INTEGER NOT NULL DEFAULT 0,
    intentos_count INTEGER NOT NULL DEFAULT 0,
    last_used_at TEXT NOT NULL,
    last_used_epoch INTEGER NOT NULL,
    preferred_apps_json TEXT NOT NULL DEFAULT '[]',
    category TEXT NOT NULL DEFAULT 'other',
    mime_type TEXT NOT NULL DEFAULT '',
    exists_on_disk INTEGER NOT NULL DEFAULT 1,
    frecency_score REAL NOT NULL DEFAULT 0.0
);
CREATE INDEX IF NOT EXISTS idx_long_term_files_frecency
    ON long_term_files(frecency_score DESC);
CREATE INDEX IF NOT EXISTS idx_long_term_files_category
    ON long_term_files(category, frecency_score DESC);

CREATE TABLE IF NOT EXISTS software_inventory (
    app_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    name_zh TEXT,
    name_en TEXT NOT NULL,
    generic_name TEXT NOT NULL DEFAULT '',
    comment TEXT NOT NULL DEFAULT '',
    exec TEXT NOT NULL DEFAULT '',
    executable TEXT NOT NULL DEFAULT '',
    icon TEXT NOT NULL DEFAULT '',
    categories_json TEXT NOT NULL DEFAULT '[]',
    mime_types_json TEXT NOT NULL DEFAULT '[]',
    dbus_activatable INTEGER NOT NULL DEFAULT 0,
    uri_schemes_json TEXT NOT NULL DEFAULT '[]',
    packaging TEXT NOT NULL DEFAULT 'deb_system',
    desktop_file_path TEXT NOT NULL DEFAULT '',
    xbel_launch_count INTEGER NOT NULL DEFAULT 0,
    intentos_launch_count INTEGER NOT NULL DEFAULT 0,
    launch_count INTEGER NOT NULL DEFAULT 0,
    last_used_at TEXT,
    last_used_epoch INTEGER NOT NULL DEFAULT 0,
    frecency_score REAL NOT NULL DEFAULT 0.0,
    pinyin_full TEXT NOT NULL DEFAULT '',
    pinyin_init TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_software_frecency
    ON software_inventory(frecency_score DESC, launch_count DESC);

CREATE TABLE IF NOT EXISTS chat_sessions (
    session_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    message_count INTEGER NOT NULL DEFAULT 0,
    last_message_preview TEXT NOT NULL DEFAULT '',
    pinned INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_epoch INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_updated
    ON chat_sessions(pinned DESC, updated_epoch DESC);

CREATE TABLE IF NOT EXISTS chat_messages (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    thinking TEXT,
    trace_dots_json TEXT NOT NULL DEFAULT '[]',
    tool_steps_json TEXT NOT NULL DEFAULT '[]',
    mentioned_entities_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    created_epoch INTEGER NOT NULL,
    FOREIGN KEY(session_id) REFERENCES chat_sessions(session_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_chat_messages_session
    ON chat_messages(session_id, created_epoch ASC);
CREATE INDEX IF NOT EXISTS idx_chat_messages_created
    ON chat_messages(created_epoch DESC);

CREATE VIRTUAL TABLE IF NOT EXISTS chat_messages_fts USING fts5(
    msg_id UNINDEXED,
    session_id UNINDEXED,
    role UNINDEXED,
    content,
    tokenize = 'unicode61'
);

CREATE TABLE IF NOT EXISTS document_outlines (
    path TEXT PRIMARY KEY,
    mtime_epoch INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL,
    doc_title TEXT NOT NULL,
    doc_summary TEXT NOT NULL,
    headings_json TEXT NOT NULL,
    sections_json TEXT NOT NULL,
    keywords TEXT NOT NULL,
    indexed_epoch INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_document_outlines_mtime
    ON document_outlines(mtime_epoch DESC);
"#;

/// Entity mentioned in a user prompt, assistant reply, or tool execution step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityMention {
    pub id: String,
    pub entity_kind: String,
    pub canonical_value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub display_name: String,
    pub action_verb: String,
    pub context_snippet: String,
    pub session_id: String,
    pub mention_count: u64,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub last_seen_epoch: i64,
}

/// Long-term / frequently used file habit ranked by Frecency (`frequency * recency_decay`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LongTermFileHabit {
    pub path: String,
    pub title: String,
    pub open_count: u64,
    pub xbel_count: u64,
    pub intentos_count: u64,
    pub last_used_at: String,
    pub last_used_epoch: i64,
    pub preferred_apps: Vec<String>,
    pub category: String,
    pub mime_type: String,
    pub exists_on_disk: bool,
    pub frecency_score: f64,
}

/// Installed desktop application & usage profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareProfile {
    pub app_id: String,
    pub name: String,
    pub name_zh: Option<String>,
    pub name_en: String,
    pub generic_name: String,
    pub comment: String,
    pub exec: String,
    pub executable: String,
    pub icon: String,
    pub categories: Vec<String>,
    pub mime_types: Vec<String>,
    pub dbus_activatable: bool,
    pub uri_schemes: Vec<String>,
    pub packaging: String,
    pub desktop_file_path: String,
    pub xbel_launch_count: u64,
    pub intentos_launch_count: u64,
    pub launch_count: u64,
    pub last_used_at: Option<String>,
    pub last_used_epoch: i64,
    pub frecency_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryCount {
    pub category: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledAppsSummary {
    pub total_installed: usize,
    pub frequent_apps_count: usize,
    pub dbus_activatable_count: usize,
    pub uri_scheme_apps_count: usize,
    pub by_packaging: BTreeMap<String, usize>,
    pub top_categories: Vec<CategoryCount>,
}

/// Persistent multi-turn chat session metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSessionRecord {
    pub session_id: String,
    pub title: String,
    pub summary: String,
    pub message_count: u64,
    pub last_message_preview: String,
    pub pinned: bool,
    pub created_at: String,
    pub updated_at: String,
    pub updated_epoch: i64,
}

/// Persistent chat message inside a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessageRecord {
    pub id: String,
    pub session_id: String,
    pub role: String,
    pub content: String,
    pub thinking: Option<String>,
    pub trace_dots: Vec<serde_json::Value>,
    pub tool_steps: Vec<serde_json::Value>,
    pub mentioned_entities: Vec<String>,
    pub created_at: String,
    pub created_epoch: i64,
}

/// Search hit from historical conversations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PastChatHit {
    pub message_id: String,
    pub session_id: String,
    pub session_title: String,
    pub role: String,
    pub snippet: String,
    pub created_at: String,
    pub score: f64,
}

/// Extracted chapter / section entry inside an indexed document (`document_outlines`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DocSection {
    pub heading: String,
    pub level: u8,
    pub paragraph_index: usize,
    pub excerpt: String,
}

/// Layer-1 persistent document outline record stored in `document_outlines`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentOutlineRecord {
    pub path: String,
    pub mtime_epoch: i64,
    pub size_bytes: u64,
    pub doc_title: String,
    pub doc_summary: String,
    pub headings: Vec<String>,
    pub sections: Vec<DocSection>,
    pub keywords: String,
    pub indexed_epoch: i64,
}

/// Ranked hit from `search_document_outlines`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentOutlineHit {
    pub record: DocumentOutlineRecord,
    pub score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_section: Option<DocSection>,
    pub toc_preview: String,
}

/// Compact preview item surfaced in `get_memory_dashboard.document_outlines_preview`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentOutlinePreview {
    pub path: String,
    pub file_name: String,
    pub doc_title: String,
    pub doc_summary: String,
    pub heading_count: usize,
    pub sample_headings: Vec<String>,
    pub mtime_epoch: i64,
}

/// Dedicated SQLite WAL handle for `${data_dir}/memory_hub.db`.
pub struct MemoryHubDb {
    pub(crate) conn: Mutex<Connection>,
    db_path: PathBuf,
}

static DB_POOL: OnceLock<Mutex<HashMap<PathBuf, Arc<MemoryHubDb>>>> = OnceLock::new();

impl MemoryHubDb {
    /// Open or initialize a `memory_hub.db` SQLite WAL database at `path`.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_millis(5000))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA_SQL)?;
        conn.execute(
            "INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '1')",
            [],
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            db_path: path.to_path_buf(),
        })
    }

    /// Open (or reuse pooled connection for) `${core.paths.data_dir}/memory_hub.db`.
    pub fn open_for_core(core: &IntentOsCore) -> anyhow::Result<Arc<Self>> {
        let db_path = Self::path_for_core(core);
        let pool = DB_POOL.get_or_init(|| Mutex::new(HashMap::new()));
        let mut guard = pool.lock().unwrap();
        if let Some(existing) = guard.get(&db_path)
            && db_path.exists()
        {
            return Ok(existing.clone());
        }
        let opened = Arc::new(Self::open(&db_path)?);
        guard.insert(db_path, opened.clone());
        Ok(opened)
    }

    /// Canonical database path for an `IntentOsCore` instance.
    pub fn path_for_core(core: &IntentOsCore) -> PathBuf {
        core.paths.data_dir.join("memory_hub.db")
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn get_meta(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().ok()?;
        conn.query_row(
            "SELECT value FROM schema_meta WHERE key = ?1",
            params![key],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn set_meta(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO schema_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

/// Compute deterministic entity mention ID from `(entity_kind, canonical_value)`.
pub fn compute_entity_id(entity_kind: &str, canonical_value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entity_kind.as_bytes());
    hasher.update(b"::");
    hasher.update(canonical_value.as_bytes());
    let hex_str = hex::encode(hasher.finalize());
    format!("ent_{}", &hex_str[..16])
}

/// Scrub secret tokens / private keys before persisting snippets or messages to disk.
pub fn scrub_sensitive_text(raw: &str) -> String {
    crate::security_guard::SensitiveDataGuard::redact_text(raw).0
}

/// Check whether a filesystem path points to sensitive credential storage that must not be indexed.
pub fn is_sensitive_credential_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("/.ssh/")
        || lower.ends_with("/.ssh")
        || lower.contains("/.gnupg/")
        || lower.ends_with("/.gnupg")
        || lower.ends_with("/id_rsa")
        || lower.ends_with("/id_ed25519")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.contains("/.aws/credentials")
}

/// Detect whether `core` was initialized with an isolated `Some(custom_base)` directory (unit/E2E tests)
/// rather than the real user XDG layout (`~/.local/share/intentos`).
pub fn is_hermetic_test_core(core: &IntentOsCore) -> bool {
    core.paths.data_dir.file_name().and_then(|s| s.to_str()) != Some("intentos")
}

/// Check whether a file path is an OS package installer or raw system image artifact
/// (`.deb`, `.rpm`, `.pkg.tar.zst`, `.iso`, `.AppImage`, etc.) that should not pollute general document recall.
pub fn is_installer_or_package_artifact(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".deb")
        || lower.ends_with(".rpm")
        || lower.ends_with(".pkg.tar.zst")
        || lower.ends_with(".tar.zst")
        || lower.ends_with(".iso")
        || lower.ends_with(".appimage")
        || lower.ends_with(".snap")
        || lower.ends_with(".flatpak")
        || lower.ends_with(".msi")
        || lower.ends_with(".dmg")
}
