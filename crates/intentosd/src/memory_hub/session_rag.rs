#![forbid(unsafe_code)]

//! Persistent Multi-Turn Chat Sessions, Automatic LLM RAG Context Builder,
//! and LLM Memory Tools (`session_rag.rs`).

use crate::core::IntentOsCore;
use crate::memory_hub::conversational_entities::{
    extract_entities_from_turn, is_conversational_entity_reference, list_recent_mentions,
    recall_mentioned_entities, upsert_entity_mentions,
};
use crate::memory_hub::document_outline::{
    ensure_document_outlines_synced, extract_chapter_number_hint, format_toc_preview,
    get_document_outline_by_path, index_document_file, search_document_outlines,
};
use crate::memory_hub::long_term_habits::{
    ensure_lazy_synced, get_installed_apps_summary, query_frequent_files, query_software_catalog,
    query_software_catalog_scored, record_app_launch, record_file_usage,
};
use crate::memory_hub::schema_and_db::{
    ChatMessageRecord, ChatSessionRecord, DocumentOutlineHit, EntityMention, LongTermFileHabit,
    MemoryHubDb, PastChatHit, is_installer_or_package_artifact, scrub_sensitive_text,
};
use chrono::Utc;
use intentos_protocol::ToolSpec;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;

/// Strict character budget (~280 tokens max) for automatic `[Personal OS Memory]` system prompt injection.
pub const MAX_AUTO_MEMORY_CHARS: usize = 950;

/// Strict character budget (`<= 2200 chars`) for `memory_inspect_document` JSON output.
pub const MAX_INSPECT_DOC_CHARS: usize = 2200;

/// Minimum relevance score (`>= 48.0`) required for Specific Document / Topic / Chapter recall.
const MIN_DOC_TOPIC_RECALL_SCORE: f64 = 48.0;

/// Minimum software match score (`>= 65.0`) required for personalized app disambiguation.
const MIN_APP_CONTROL_SCORE: f64 = 65.0;

/// Input payload for recording a completed conversation turn.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecordTurnInput {
    #[serde(default)]
    pub session_id: Option<String>,
    pub user_text: String,
    #[serde(default)]
    pub assistant_text: String,
    #[serde(default)]
    pub thinking: Option<String>,
    #[serde(default)]
    pub tool_steps: Vec<Value>,
    #[serde(default)]
    pub trace_dots: Vec<Value>,
    #[serde(default)]
    pub incognito: bool,
}

/// Output returned after processing a conversation turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordTurnOutcome {
    pub recorded: bool,
    pub incognito: bool,
    pub session_id: String,
    pub extracted_entities: Vec<EntityMention>,
    pub updated_files: usize,
    pub updated_apps: usize,
}

/// Full session view returned by `get_session`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDetail {
    pub session: ChatSessionRecord,
    pub messages: Vec<ChatMessageRecord>,
    pub mentioned_entities: Vec<EntityMention>,
}

/// Create a new persistent chat session in `memory_hub.db`.
pub fn create_session(
    db: &MemoryHubDb,
    session_id: Option<&str>,
    title: Option<&str>,
) -> anyhow::Result<ChatSessionRecord> {
    let now = Utc::now();
    let now_rfc = now.to_rfc3339();
    let now_epoch = now.timestamp();
    let sid = session_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| format!("ses_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]));
    let clean_title = title
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("新对话")
        .to_string();

    let conn = db.conn.lock().unwrap();
    conn.execute(
        "INSERT INTO chat_sessions (
            session_id, title, summary, message_count, last_message_preview,
            pinned, created_at, updated_at, updated_epoch
         ) VALUES (?1, ?2, '', 0, '', 0, ?3, ?3, ?4)
         ON CONFLICT(session_id) DO UPDATE SET
            title = CASE WHEN chat_sessions.title = '新对话' THEN excluded.title ELSE chat_sessions.title END,
            updated_at = excluded.updated_at,
            updated_epoch = excluded.updated_epoch",
        params![sid, clean_title, now_rfc, now_epoch],
    )?;
    drop(conn);

    get_session_record(db, &sid)?.ok_or_else(|| anyhow::anyhow!("创建会话后读取失败: {}", sid))
}

pub fn get_session_record(
    db: &MemoryHubDb,
    session_id: &str,
) -> anyhow::Result<Option<ChatSessionRecord>> {
    let conn = db.conn.lock().unwrap();
    let rec = conn
        .query_row(
            "SELECT session_id, title, summary, message_count, last_message_preview,
                    pinned, created_at, updated_at, updated_epoch
             FROM chat_sessions WHERE session_id = ?1",
            params![session_id],
            row_to_session,
        )
        .optional()?;
    Ok(rec)
}

fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChatSessionRecord> {
    Ok(ChatSessionRecord {
        session_id: row.get(0)?,
        title: row.get(1)?,
        summary: row.get(2)?,
        message_count: row.get::<_, i64>(3)?.max(0) as u64,
        last_message_preview: row.get(4)?,
        pinned: row.get::<_, i32>(5)? != 0,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        updated_epoch: row.get(8)?,
    })
}

/// List persistent chat sessions ordered by pinned status and recency.
pub fn list_sessions(
    db: &MemoryHubDb,
    limit: usize,
    query: Option<&str>,
) -> anyhow::Result<Vec<ChatSessionRecord>> {
    let cap = limit.clamp(1, 200) as i64;
    let conn = db.conn.lock().unwrap();
    let mut out = Vec::new();
    if let Some(q) = query.map(str::trim).filter(|s| !s.is_empty()) {
        let like = format!("%{}%", q.to_ascii_lowercase());
        let mut stmt = conn.prepare(
            "SELECT session_id, title, summary, message_count, last_message_preview,
                    pinned, created_at, updated_at, updated_epoch
             FROM chat_sessions
             WHERE LOWER(title) LIKE ?1 OR LOWER(last_message_preview) LIKE ?1
             ORDER BY pinned DESC, updated_epoch DESC LIMIT ?2",
        )?;
        for row in stmt.query_map(params![like, cap], row_to_session)? {
            out.push(row?);
        }
    } else {
        let mut stmt = conn.prepare(
            "SELECT session_id, title, summary, message_count, last_message_preview,
                    pinned, created_at, updated_at, updated_epoch
             FROM chat_sessions
             ORDER BY pinned DESC, updated_epoch DESC LIMIT ?1",
        )?;
        for row in stmt.query_map(params![cap], row_to_session)? {
            out.push(row?);
        }
    }
    Ok(out)
}

/// Get a persistent chat session along with its messages and mentioned entities.
pub fn get_session_detail(
    db: &MemoryHubDb,
    session_id: &str,
    message_limit: usize,
) -> anyhow::Result<Option<SessionDetail>> {
    let Some(session) = get_session_record(db, session_id)? else {
        return Ok(None);
    };
    let cap = message_limit.clamp(1, 500) as i64;
    let mut messages = Vec::new();
    {
        let conn = db.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, role, content, thinking, trace_dots_json,
                    tool_steps_json, mentioned_entities_json, created_at, created_epoch
             FROM chat_messages
             WHERE session_id = ?1
             ORDER BY created_epoch ASC, rowid ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![session_id, cap], |r| {
            let td_s: String = r.get(5)?;
            let ts_s: String = r.get(6)?;
            let me_s: String = r.get(7)?;
            Ok(ChatMessageRecord {
                id: r.get(0)?,
                session_id: r.get(1)?,
                role: r.get(2)?,
                content: r.get(3)?,
                thinking: r.get(4)?,
                trace_dots: serde_json::from_str(&td_s).unwrap_or_default(),
                tool_steps: serde_json::from_str(&ts_s).unwrap_or_default(),
                mentioned_entities: serde_json::from_str(&me_s).unwrap_or_default(),
                created_at: r.get(8)?,
                created_epoch: r.get(9)?,
            })
        })?;
        for m in rows {
            messages.push(m?);
        }
    }
    let mentioned_entities = list_recent_mentions(db, false, Some(session_id), 50)?;
    Ok(Some(SessionDetail {
        session,
        messages,
        mentioned_entities,
    }))
}

/// Delete a persistent chat session and its messages (`chat_messages` + `chat_messages_fts`).
pub fn delete_session(db: &MemoryHubDb, session_id: &str) -> anyhow::Result<bool> {
    let mut conn = db.conn.lock().unwrap();
    let tx = conn.transaction()?;
    tx.execute(
        "DELETE FROM chat_messages_fts WHERE session_id = ?1",
        params![session_id],
    )?;
    tx.execute(
        "DELETE FROM chat_messages WHERE session_id = ?1",
        params![session_id],
    )?;
    let deleted = tx.execute(
        "DELETE FROM chat_sessions WHERE session_id = ?1",
        params![session_id],
    )?;
    tx.commit()?;
    Ok(deleted > 0)
}

/// Record a user + assistant conversation turn, extract mentioned files/apps, and update usage habits.
///
/// Strictly performs ZERO writes when `input.incognito == true`.
pub fn record_conversation_turn(
    core: &IntentOsCore,
    input: &RecordTurnInput,
) -> anyhow::Result<RecordTurnOutcome> {
    let fallback_sid = input
        .session_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(String::from)
        .unwrap_or_else(|| format!("incog_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));

    if input.incognito
        || fallback_sid.starts_with("incog_")
        || fallback_sid.starts_with("ephemeral_ro_")
    {
        return Ok(RecordTurnOutcome {
            recorded: false,
            incognito: true,
            session_id: fallback_sid,
            extracted_entities: Vec::new(),
            updated_files: 0,
            updated_apps: 0,
        });
    }

    let db = MemoryHubDb::open_for_core(core)?;
    ensure_lazy_synced(core, &db);

    let session_id = input
        .session_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| format!("ses_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]));

    let known_files = build_known_file_lookup(core, &db);
    let known_apps = build_known_app_lookup(&db);

    let extracted_candidates = extract_entities_from_turn(
        &input.user_text,
        &input.assistant_text,
        &input.tool_steps,
        &known_files,
        &known_apps,
        None,
    );
    let persisted_entities = upsert_entity_mentions(&db, &extracted_candidates, &session_id)?;

    // Update long-term file & software usage counters for concrete actions
    let mut updated_files = 0usize;
    let mut updated_apps = 0usize;
    for ent in &persisted_entities {
        if ent.entity_kind == "file"
            && ent.canonical_value.starts_with('/')
            && !core.fs_engine.is_forbidden(Path::new(&ent.canonical_value))
            && ent.action_verb != "mention"
        {
            record_file_usage(&db, &ent.canonical_value, Some("IntentOS"), 1)?;
            updated_files += 1;
        } else if ent.entity_kind == "app"
            && ent.action_verb == "launch"
            && record_app_launch(&db, &ent.canonical_value, 1)?
        {
            updated_apps += 1;
        }
    }

    // Persist session & messages (scrubbing secrets)
    let now = Utc::now();
    let now_rfc = now.to_rfc3339();
    let now_epoch = now.timestamp();
    let derived_title = derive_session_title(&input.user_text);
    let clean_user = scrub_sensitive_text(&input.user_text);
    let clean_asst = scrub_sensitive_text(&input.assistant_text);
    let clean_thinking = input.thinking.as_deref().map(scrub_sensitive_text);
    let preview = truncate_chars(
        if !clean_asst.trim().is_empty() {
            &clean_asst
        } else {
            &clean_user
        },
        80,
    );
    let entity_labels: Vec<String> = persisted_entities
        .iter()
        .map(|e| e.canonical_value.clone())
        .collect();

    let user_msg_id = format!("msg_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let asst_msg_id = format!("msg_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);

    {
        let mut conn = db.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let msg_delta = if clean_asst.trim().is_empty() {
            1i64
        } else {
            2i64
        };
        tx.execute(
            "INSERT INTO chat_sessions (
                session_id, title, summary, message_count, last_message_preview,
                pinned, created_at, updated_at, updated_epoch
             ) VALUES (?1, ?2, '', ?3, ?4, 0, ?5, ?5, ?6)
             ON CONFLICT(session_id) DO UPDATE SET
                title = CASE
                    WHEN chat_sessions.title = '新对话' OR chat_sessions.title = '' THEN excluded.title
                    ELSE chat_sessions.title
                END,
                message_count = chat_sessions.message_count + ?3,
                last_message_preview = excluded.last_message_preview,
                updated_at = excluded.updated_at,
                updated_epoch = excluded.updated_epoch",
            params![
                session_id,
                derived_title,
                msg_delta,
                preview,
                now_rfc,
                now_epoch
            ],
        )?;

        tx.execute(
            "INSERT INTO chat_messages (
                id, session_id, role, content, thinking, trace_dots_json,
                tool_steps_json, mentioned_entities_json, created_at, created_epoch
             ) VALUES (?1, ?2, 'user', ?3, NULL, '[]', '[]', ?4, ?5, ?6)",
            params![
                user_msg_id,
                session_id,
                clean_user,
                serde_json::to_string(&entity_labels)?,
                now_rfc,
                now_epoch,
            ],
        )?;
        tx.execute(
            "INSERT INTO chat_messages_fts (msg_id, session_id, role, content)
             VALUES (?1, ?2, 'user', ?3)",
            params![user_msg_id, session_id, clean_user],
        )?;

        if !clean_asst.trim().is_empty() {
            tx.execute(
                "INSERT INTO chat_messages (
                    id, session_id, role, content, thinking, trace_dots_json,
                    tool_steps_json, mentioned_entities_json, created_at, created_epoch
                 ) VALUES (?1, ?2, 'assistant', ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    asst_msg_id,
                    session_id,
                    clean_asst,
                    clean_thinking,
                    serde_json::to_string(&input.trace_dots)?,
                    serde_json::to_string(&input.tool_steps)?,
                    serde_json::to_string(&entity_labels)?,
                    now_rfc,
                    now_epoch,
                ],
            )?;
            tx.execute(
                "INSERT INTO chat_messages_fts (msg_id, session_id, role, content)
                 VALUES (?1, ?2, 'assistant', ?3)",
                params![asst_msg_id, session_id, clean_asst],
            )?;
        }

        tx.commit()?;
    }

    Ok(RecordTurnOutcome {
        recorded: true,
        incognito: false,
        session_id,
        extracted_entities: persisted_entities,
        updated_files,
        updated_apps,
    })
}

/// Remove any synthetic `"确认执行：..."` user + raw-step assistant echo written by `core.approve_pending`
/// right before `resume_approved_turn` records the full conversational `(user_text, final_reply)` turn.
pub fn remove_synthetic_approval_echo(core: &IntentOsCore, session_id: &str) -> usize {
    let sid = session_id.trim();
    if sid.is_empty() || sid.starts_with("incog_") {
        return 0;
    }
    let Ok(db) = MemoryHubDb::open_for_core(core) else {
        return 0;
    };
    let mut conn = match db.conn.lock() {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let Ok(tx) = conn.transaction() else {
        return 0;
    };

    let recent_rows: Vec<(String, String, String)> = {
        let Ok(mut stmt) = tx.prepare(
            "SELECT id, role, content
             FROM chat_messages
             WHERE session_id = ?1
             ORDER BY rowid DESC
             LIMIT 4",
        ) else {
            return 0;
        };
        let Ok(mapped) = stmt.query_map(params![sid], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        }) else {
            return 0;
        };
        mapped.filter_map(Result::ok).collect()
    };

    let mut to_delete: Vec<String> = Vec::new();
    if recent_rows.len() >= 2
        && recent_rows[0].1 == "assistant"
        && recent_rows[1].1 == "user"
        && recent_rows[1].2.starts_with("确认执行：")
    {
        to_delete.push(recent_rows[0].0.clone());
        to_delete.push(recent_rows[1].0.clone());
    } else if !recent_rows.is_empty()
        && recent_rows[0].1 == "user"
        && recent_rows[0].2.starts_with("确认执行：")
    {
        to_delete.push(recent_rows[0].0.clone());
    }

    if to_delete.is_empty() {
        return 0;
    }

    let mut deleted = 0usize;
    for msg_id in &to_delete {
        let _ = tx.execute(
            "DELETE FROM chat_messages_fts WHERE msg_id = ?1",
            params![msg_id],
        );
        if let Ok(n) = tx.execute("DELETE FROM chat_messages WHERE id = ?1", params![msg_id]) {
            deleted += n;
        }
    }
    if deleted > 0 {
        let _ = tx.execute(
            "UPDATE chat_sessions
             SET message_count = MAX(0, message_count - ?2)
             WHERE session_id = ?1",
            params![sid, deleted as i64],
        );
    }
    let _ = tx.commit();
    deleted
}

/// Search past conversations across `chat_messages` (combining FTS5 + CJK substring matching).
pub fn search_past_chats(
    db: &MemoryHubDb,
    query: &str,
    session_id: Option<&str>,
    limit: usize,
) -> anyhow::Result<Vec<PastChatHit>> {
    let q = query.trim();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let cap = limit.clamp(1, 50);
    let tokens: Vec<String> = q
        .split(|c: char| c.is_whitespace() || matches!(c, '，' | ',' | '。' | '？' | '?' | '！'))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect();

    let conn = db.conn.lock().unwrap();
    let mut candidates: HashMap<String, PastChatHit> = HashMap::new();

    // 1. FTS5 fast token lookup for safe alphanumeric/unicode61 tokens
    let fts_tokens: Vec<String> = tokens
        .iter()
        .map(|t| {
            t.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .filter(|t| t.chars().count() >= 2)
        .collect();

    if !fts_tokens.is_empty() {
        let fts_expr = fts_tokens
            .iter()
            .map(|t| format!("\"{}\"", t))
            .collect::<Vec<_>>()
            .join(" OR ");
        if let Ok(mut stmt) = conn.prepare(
            "SELECT m.id, m.session_id, COALESCE(s.title, '对话'), m.role, m.content, m.created_at
             FROM chat_messages_fts f
             JOIN chat_messages m ON m.id = f.msg_id
             LEFT JOIN chat_sessions s ON s.session_id = m.session_id
             WHERE chat_messages_fts MATCH ?1
             LIMIT 60",
        ) && let Ok(rows) = stmt.query_map(params![fts_expr], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        }) {
            for (mid, sid, stitle, role, content, cat) in rows.flatten() {
                if let Some(req_sid) = session_id.filter(|s| !s.is_empty())
                    && sid != req_sid
                {
                    continue;
                }
                candidates.insert(
                    mid.clone(),
                    PastChatHit {
                        message_id: mid,
                        session_id: sid,
                        session_title: stitle,
                        role,
                        snippet: truncate_chars(&content, 160),
                        created_at: cat,
                        score: 80.0,
                    },
                );
            }
        }
    }

    // 2. Substring scan over recent messages (crucial for Chinese phrase substrings!)
    let primary_like = format!(
        "%{}%",
        tokens
            .first()
            .cloned()
            .unwrap_or_else(|| q.to_ascii_lowercase())
    );
    let mut stmt = conn.prepare(
        "SELECT m.id, m.session_id, COALESCE(s.title, '对话'), m.role, m.content, m.created_at, m.created_epoch
         FROM chat_messages m
         LEFT JOIN chat_sessions s ON s.session_id = m.session_id
         WHERE LOWER(m.content) LIKE ?1
         ORDER BY m.created_epoch DESC
         LIMIT 80",
    )?;
    let now_ep = Utc::now().timestamp();
    let rows = stmt.query_map(params![primary_like], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, i64>(6)?,
        ))
    })?;
    for item in rows {
        let (mid, sid, stitle, role, content, cat, ep) = item?;
        if let Some(req_sid) = session_id.filter(|s| !s.is_empty())
            && sid != req_sid
        {
            continue;
        }
        let content_lc = content.to_ascii_lowercase();
        let matched_count = tokens
            .iter()
            .filter(|t| content_lc.contains(t.as_str()))
            .count();
        let age_h = ((now_ep - ep).max(0) as f64) / 3600.0;
        let score = 60.0 + (matched_count as f64) * 20.0 + 15.0 / (1.0 + age_h / 24.0);
        candidates
            .entry(mid.clone())
            .and_modify(|e| {
                if score > e.score {
                    e.score = score;
                }
            })
            .or_insert_with(|| PastChatHit {
                message_id: mid,
                session_id: sid,
                session_title: stitle,
                role,
                snippet: truncate_chars(&content, 160),
                created_at: cat,
                score,
            });
    }

    let mut out: Vec<PastChatHit> = candidates.into_values().collect();
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out.truncate(cap);
    Ok(out)
}

/// Query intent classification executed BEFORE recalling personal memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRecallIntent {
    /// Pure App / Media / System Control (e.g. `"打开QQ"`, `"关闭SODAM音乐"`, `"把音量调到50%"`, `"暂停音乐"`).
    PureAppMediaSystemControl,
    /// Explicit Memory Overview Queries (`"我之前说的文件有哪些"`, `"我长期使用的文件有哪些"`, `"电脑上装了什么软件"`).
    ExplicitMemoryOverview(MemoryOverviewCategory),
    /// Pronoun / Conversational Back-Reference (`"刚才那个文件"`, `"我之前说的文档"`, `"上次改的配置"`).
    ConversationalBackRef,
    /// Specific Document / Topic / Chapter Lookup (`"打开我的硕士论文第四章"`, `"周报"`, `"毕业设计"`).
    DocumentTopicLookup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryOverviewCategory {
    MentionedFiles,
    FrequentFiles,
    Software,
}

const PERSONAL_MEMORY_HEADER: &str =
    "[Personal OS Memory: 历史提及文件 / 长期高频文件 / 本机常用与已装软件]\n";

/// Classify user query intent prior to touching recall tables so app/media/system commands
/// never pollute LLM context with unrelated `.deb`, `.pkg.tar.zst`, or `.docx` files.
pub fn classify_memory_query_intent(query: &str) -> MemoryRecallIntent {
    let q = query.trim();
    if let Some(cat) = classify_explicit_overview_category(q) {
        return MemoryRecallIntent::ExplicitMemoryOverview(cat);
    }
    if is_conversational_entity_reference(q) {
        return MemoryRecallIntent::ConversationalBackRef;
    }
    if is_pure_app_media_or_system_control(q) {
        return MemoryRecallIntent::PureAppMediaSystemControl;
    }
    MemoryRecallIntent::DocumentTopicLookup
}

fn classify_explicit_overview_category(q: &str) -> Option<MemoryOverviewCategory> {
    if q.is_empty() {
        return None;
    }
    let is_imperative = q.starts_with("打开")
        || q.starts_with("移动")
        || q.starts_with("复制")
        || q.starts_with("删除")
        || q.starts_with("重命名")
        || q.starts_with("关闭")
        || q.starts_with("启动");
    if is_imperative {
        return None;
    }

    let asks_overview = q.contains("有哪些")
        || q.contains("有什么")
        || q.contains("装了什么")
        || q.contains("安装了什么")
        || q.contains("常用哪些")
        || q.contains("经常用哪些")
        || q.contains("文件列表")
        || q.contains("软件列表")
        || q.contains("软件清单")
        || q.contains("应用列表");
    if !asks_overview {
        return None;
    }

    if (q.contains("长期")
        || q.contains("常用")
        || q.contains("高频")
        || q.contains("经常打开")
        || q.contains("最近和长期"))
        && (q.contains("文件") || q.contains("文档"))
    {
        return Some(MemoryOverviewCategory::FrequentFiles);
    }

    if is_conversational_entity_reference(q)
        && (q.contains("文件") || q.contains("文档"))
        && !q.contains("软件")
        && !q.contains("应用")
        && !q.contains("转译")
    {
        return Some(MemoryOverviewCategory::MentionedFiles);
    }

    if (q.contains("软件") || q.contains("应用") || q.contains("程序"))
        && (q.contains("电脑上")
            || q.contains("本机")
            || q.contains("装了")
            || q.contains("安装")
            || q.contains("常用")
            || q.contains("有哪些")
            || q.contains("有什么"))
        && !is_conversational_entity_reference(q)
    {
        return Some(MemoryOverviewCategory::Software);
    }

    None
}

fn has_file_or_doc_signal(q: &str) -> bool {
    if q.contains('/') || q.contains("《") || q.contains("》") {
        return true;
    }
    if extract_chapter_number_hint(q).is_some() {
        return true;
    }
    let q_lc = q.to_ascii_lowercase();
    for ext in [
        ".docx",
        ".doc",
        ".pdf",
        ".md",
        ".markdown",
        ".txt",
        ".xlsx",
        ".xls",
        ".csv",
        ".pptx",
        ".ppt",
        ".tex",
        ".typ",
        ".toml",
        ".yaml",
        ".yml",
        ".json",
        ".rs",
        ".py",
        ".js",
        ".ts",
        ".sh",
        ".zip",
        ".tar",
        ".gz",
        ".zst",
        ".deb",
        ".rpm",
        ".appimage",
        ".iso",
    ] {
        if q_lc.contains(ext) {
            return true;
        }
    }
    for noun in [
        "文件",
        "文档",
        "目录",
        "文件夹",
        "路径",
        "论文",
        "报告",
        "周报",
        "月报",
        "年报",
        "季报",
        "汇报",
        "总结",
        "方案",
        "毕业设计",
        "毕设",
        "简历",
        "合同",
        "协议",
        "表格",
        "预算",
        "账单",
        "发票",
        "幻灯片",
        "课件",
        "讲义",
        "笔记",
        "大纲",
        "草稿",
        "手稿",
        "说明书",
        "手册",
        "白皮书",
        "指南",
        "配置",
        "脚本",
        "代码",
        "源码",
        "仓库",
        "日志",
        "备份",
        "安装包",
        "压缩包",
        "附件",
        "资料",
        "材料",
        "教材",
        "章节",
        "小节",
        "摘要",
        "引言",
        "绪论",
        "结论",
        "参考文献",
        "附录",
    ] {
        if q.contains(noun) {
            return true;
        }
    }
    false
}

fn is_pure_app_media_or_system_control(q: &str) -> bool {
    if q.is_empty() || has_file_or_doc_signal(q) {
        return false;
    }
    let q_lc = q.to_ascii_lowercase();

    for sys_kw in [
        "音量",
        "亮度",
        "护眼模式",
        "夜间模式",
        "深色模式",
        "浅色模式",
        "暗色模式",
        "蓝牙",
        "wifi",
        "wi-fi",
        "无线网",
        "截图",
        "截屏",
        "录屏",
        "锁屏",
        "关机",
        "休眠",
        "待机",
        "睡眠",
        "壁纸",
        "勿扰模式",
        "飞行模式",
        "静音",
        "取消静音",
        "下一首",
        "上一首",
        "切歌",
        "暂停",
        "继续播放",
        "单曲循环",
        "随机播放",
    ] {
        if q_lc.contains(sys_kw) {
            return true;
        }
    }

    let stripped = q
        .trim_start_matches("请")
        .trim_start_matches("帮我")
        .trim_start_matches("麻烦")
        .trim_start_matches("给我")
        .trim();

    for verb in [
        "打开",
        "启动",
        "运行",
        "关闭",
        "退出",
        "关掉",
        "杀掉",
        "结束",
        "重启",
        "切换到",
        "聚焦",
        "最小化",
        "最大化",
        "全屏",
        "播放",
        "开启",
        "调高",
        "调低",
        "把",
    ] {
        if stripped.starts_with(verb) {
            return true;
        }
    }
    false
}

fn query_asks_for_package(q: &str) -> bool {
    let lc = q.to_ascii_lowercase();
    for kw in [
        "安装包",
        "软件包",
        "包文件",
        ".deb",
        "deb包",
        ".rpm",
        "rpm包",
        "pkg.tar",
        ".zst",
        "appimage",
        ".iso",
        "镜像",
        "package",
        "installer",
    ] {
        if lc.contains(kw) {
            return true;
        }
    }
    false
}

/// Build the Intent-Gated Selective Personal OS Memory RAG block (`<= 950 chars`) + `memory_hits`.
pub fn build_personal_memory_prompt(
    core: &IntentOsCore,
    query: &str,
    session_id: Option<&str>,
) -> (String, Vec<Value>) {
    build_personal_memory_prompt_with_sync(core, query, session_id, true)
}

/// Build Personal OS Memory RAG block with explicit `allow_sync` control (`false` for `EphemeralReadOnly`
/// so read-only queries NEVER create `memory_hub.db` or write lazy-sync/outline rows).
pub fn build_personal_memory_prompt_with_sync(
    core: &IntentOsCore,
    query: &str,
    session_id: Option<&str>,
    allow_sync: bool,
) -> (String, Vec<Value>) {
    let q_trim = query.trim();
    if q_trim.is_empty() {
        return (String::new(), Vec::new());
    }
    if !allow_sync && !MemoryHubDb::path_for_core(core).exists() {
        return (String::new(), Vec::new());
    }

    let Ok(db) = MemoryHubDb::open_for_core(core) else {
        return (String::new(), Vec::new());
    };
    if allow_sync {
        ensure_lazy_synced(core, &db);
    }

    let intent = classify_memory_query_intent(q_trim);
    let (raw_md, hits) = match intent {
        MemoryRecallIntent::PureAppMediaSystemControl => build_pure_app_control_memory(&db, q_trim),
        MemoryRecallIntent::ExplicitMemoryOverview(cat) => {
            build_explicit_overview_memory(core, &db, q_trim, session_id, cat, allow_sync)
        }
        MemoryRecallIntent::ConversationalBackRef => {
            build_conversational_backref_memory(core, &db, q_trim, session_id, allow_sync)
        }
        MemoryRecallIntent::DocumentTopicLookup => {
            build_document_topic_lookup_memory(core, &db, q_trim, session_id, allow_sync)
        }
    };

    if raw_md.trim().is_empty() || hits.is_empty() {
        return (String::new(), Vec::new());
    }

    (enforce_char_budget(&raw_md, MAX_AUTO_MEMORY_CHARS), hits)
}

/// Branch 1: Pure App / Media / System Control — NEVER injects files!
/// Returns `(String::new(), Vec::new())` for system/media controls and well-known trivial apps
/// (`"打开QQ"`, `"把音量调到50%"`, `"暂停音乐"`), and injects at most 1 compact software line
/// ONLY when a non-obvious personalized desktop app matches with high lexical score (`>= 65.0`).
fn build_pure_app_control_memory(db: &MemoryHubDb, q_trim: &str) -> (String, Vec<Value>) {
    let Some((raw_app, core_app)) = extract_app_candidate_from_control_query(q_trim) else {
        return (String::new(), Vec::new());
    };

    if is_trivial_well_known_app(&raw_app) || is_trivial_well_known_app(&core_app) {
        return (String::new(), Vec::new());
    }

    let mut candidates_to_try = vec![core_app.clone()];
    if raw_app != core_app && !raw_app.is_empty() {
        candidates_to_try.push(raw_app);
    }

    for cand in candidates_to_try {
        if cand.chars().count() < 2 {
            continue;
        }
        let scored = query_software_catalog_scored(db, &cand, 3).unwrap_or_default();
        if let Some((app, score)) = scored
            .into_iter()
            .find(|(a, sc)| *sc >= MIN_APP_CONTROL_SCORE && has_direct_app_identity_match(a, &cand))
        {
            let md = format!(
                "{}- 本机已装匹配应用: **{}** (`{}` | Exec: `{}`)\n",
                PERSONAL_MEMORY_HEADER,
                app.name,
                app.app_id,
                truncate_chars(&app.executable, 40),
            );
            let hit = json!({
                "kind": "software",
                "relevance": "direct",
                "title": app.name,
                "value": app.app_id,
                "detail": format!("匹配已装应用 · Exec={}", app.executable),
                "score": score,
            });
            return (md, vec![hit]);
        }
    }

    (String::new(), Vec::new())
}

fn extract_app_candidate_from_control_query(q: &str) -> Option<(String, String)> {
    let q_lc = q.to_ascii_lowercase();
    for pure_sys in [
        "音量",
        "亮度",
        "护眼",
        "夜间模式",
        "深色模式",
        "浅色模式",
        "暗色模式",
        "蓝牙",
        "wifi",
        "wi-fi",
        "无线网",
        "截图",
        "截屏",
        "录屏",
        "锁屏",
        "关机",
        "休眠",
        "睡眠",
        "壁纸",
        "勿扰",
        "飞行模式",
        "静音",
        "下一首",
        "上一首",
        "切歌",
        "单曲循环",
        "随机播放",
    ] {
        if q_lc.contains(pure_sys) {
            return None;
        }
    }

    let mut rest = q
        .trim()
        .trim_start_matches("请")
        .trim_start_matches("帮我")
        .trim_start_matches("麻烦")
        .trim_start_matches("给我")
        .trim();

    let mut matched_verb = false;
    for verb in [
        "打开",
        "启动",
        "运行",
        "关闭",
        "退出",
        "关掉",
        "杀掉",
        "结束",
        "重启",
        "切换到",
        "聚焦",
        "最小化",
        "最大化",
        "播放",
        "暂停",
    ] {
        if let Some(after) = rest.strip_prefix(verb) {
            rest = after.trim();
            matched_verb = true;
            break;
        }
    }
    if !matched_verb {
        return None;
    }

    let raw_clean = rest
        .trim_matches(|c: char| {
            c.is_whitespace() || matches!(c, '。' | '！' | '!' | '？' | '?' | '吧')
        })
        .trim_end_matches("一下")
        .trim()
        .to_string();
    if raw_clean.is_empty()
        || matches!(
            raw_clean.as_str(),
            "音乐" | "歌曲" | "视频" | "窗口" | "软件" | "应用"
        )
    {
        return None;
    }

    let mut core = raw_clean.as_str();
    for suffix in [
        "音乐播放器",
        "播放器",
        "客户端",
        "浏览器",
        "编辑器",
        "音乐",
        "软件",
        "应用",
        "程序",
    ] {
        if let Some(stripped) = core.strip_suffix(suffix) {
            let st = stripped.trim();
            if st.chars().count() >= 2 {
                core = st;
                break;
            }
        }
    }

    Some((raw_clean.clone(), core.to_string()))
}

fn is_trivial_well_known_app(token: &str) -> bool {
    let lc = token.trim().to_ascii_lowercase();
    matches!(
        lc.as_str(),
        "qq" | "linuxqq"
            | "腾讯qq"
            | "tim"
            | "微信"
            | "wechat"
            | "chrome"
            | "google chrome"
            | "google-chrome"
            | "firefox"
            | "火狐"
            | "edge"
            | "vscode"
            | "vs code"
            | "code"
            | "终端"
            | "terminal"
            | "gnome-terminal"
            | "文件管理器"
            | "nautilus"
            | "files"
            | "设置"
            | "settings"
            | "计算器"
            | "calculator"
            | "vlc"
            | "spotify"
            | "telegram"
            | "discord"
            | "steam"
            | "obs"
            | "wps"
            | "libreoffice"
    )
}

fn has_direct_app_identity_match(
    app: &crate::memory_hub::schema_and_db::SoftwareProfile,
    cand: &str,
) -> bool {
    let c_lc = cand.trim().to_ascii_lowercase();
    if c_lc.len() < 2 {
        return false;
    }
    let aid_stem = app.app_id.trim_end_matches(".desktop").to_ascii_lowercase();
    let name_lc = app.name.to_ascii_lowercase();
    let name_en_lc = app.name_en.to_ascii_lowercase();
    let exec_lc = app.executable.to_ascii_lowercase();

    aid_stem == c_lc
        || aid_stem.contains(&c_lc)
        || name_lc.contains(&c_lc)
        || name_en_lc.contains(&c_lc)
        || exec_lc == c_lc
        || exec_lc.ends_with(&format!("/{}", c_lc))
}

/// Branch 2: Explicit Memory Overview Queries — injects compact top-6 summary (`<= 900 chars`)
/// ONLY for the requested category, never mashing unrelated categories together.
fn build_explicit_overview_memory(
    core: &IntentOsCore,
    db: &MemoryHubDb,
    q_trim: &str,
    session_id: Option<&str>,
    category: MemoryOverviewCategory,
    allow_sync: bool,
) -> (String, Vec<Value>) {
    let asks_pkg = query_asks_for_package(q_trim);
    let mut md = String::from(PERSONAL_MEMORY_HEADER);
    let mut hits = Vec::new();

    match category {
        MemoryOverviewCategory::MentionedFiles => {
            if allow_sync {
                ensure_document_outlines_synced(core, db);
            }
            let mut list = list_recent_mentions(db, true, session_id, 10).unwrap_or_default();
            if list.is_empty() {
                list = list_recent_mentions(db, true, None, 10).unwrap_or_default();
            }
            list.retain(|e| asks_pkg || !is_installer_or_package_artifact(&e.canonical_value));
            if list.is_empty() {
                return (String::new(), Vec::new());
            }
            md.push_str("### 历史对话提及文件 (Top 6)\n");
            for (idx, ent) in list.into_iter().take(6).enumerate() {
                let title_note = get_document_outline_by_path(db, &ent.canonical_value)
                    .ok()
                    .flatten()
                    .map(|o| format!(" | 标题: {}", truncate_chars(&o.doc_title, 32)))
                    .unwrap_or_default();
                md.push_str(&format!(
                    "- [{}] `{}` ({} · {}次{})\n",
                    idx + 1,
                    ent.canonical_value,
                    ent.action_verb,
                    ent.mention_count,
                    title_note
                ));
                hits.push(json!({
                    "kind": "mentioned_file",
                    "relevance": "direct",
                    "title": ent.display_name,
                    "value": ent.canonical_value,
                    "detail": format!("历史提及 {} 次 ({})", ent.mention_count, ent.action_verb),
                    "score": 85.0,
                }));
            }
        }
        MemoryOverviewCategory::FrequentFiles => {
            if allow_sync {
                ensure_document_outlines_synced(core, db);
            }
            let mut files = query_frequent_files(db, None, None, 12).unwrap_or_default();
            files.retain(|f| asks_pkg || !is_installer_or_package_artifact(&f.path));
            if files.is_empty() {
                return (String::new(), Vec::new());
            }
            md.push_str("### 长期高频使用文件 (Top 6)\n");
            for (idx, f) in files.into_iter().take(6).enumerate() {
                md.push_str(&format!(
                    "- [{}] `{}` (打开 {} 次 | Frecency {:.1} | {})\n",
                    idx + 1,
                    f.path,
                    f.open_count,
                    f.frecency_score,
                    f.category
                ));
                hits.push(json!({
                    "kind": "frequent_file",
                    "relevance": "direct",
                    "title": f.title,
                    "value": f.path,
                    "detail": format!("长期打开 {} 次 · Frecency {:.1}", f.open_count, f.frecency_score),
                    "score": f.frecency_score,
                }));
            }
        }
        MemoryOverviewCategory::Software => {
            let apps = query_software_catalog(db, None, false, 6).unwrap_or_default();
            if apps.is_empty() {
                return (String::new(), Vec::new());
            }
            if let Ok(sum) = get_installed_apps_summary(db) {
                md.push_str(&format!(
                    "### 本机软件画像 (共 {} 款，常用 {} 款，Top 6)\n",
                    sum.total_installed, sum.frequent_apps_count
                ));
            } else {
                md.push_str("### 本机常用与已装软件 (Top 6)\n");
            }
            for (idx, app) in apps.into_iter().take(6).enumerate() {
                let cats = app
                    .categories
                    .iter()
                    .take(2)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("/");
                md.push_str(&format!(
                    "- [{}] **{}** (`{}` | 使用 {} 次 | {})\n",
                    idx + 1,
                    app.name,
                    app.app_id,
                    app.launch_count,
                    cats
                ));
                hits.push(json!({
                    "kind": "software",
                    "relevance": "direct",
                    "title": app.name,
                    "value": app.app_id,
                    "detail": format!("使用频次 {} · {}", app.launch_count, app.generic_name),
                    "score": app.frecency_score,
                }));
            }
        }
    }

    (enforce_char_budget(&md, 900), hits)
}

/// Branch 3: Pronoun / Conversational Back-Reference (`"刚才那个文件"`, `"上次改的配置"`).
/// Injects ONLY Top 1–3 `mentioned_ranked` entities (enriched with semantic title & TOC if indexed),
/// plus up to 2 matching software items ONLY if the query also explicitly asks for apps/media.
fn build_conversational_backref_memory(
    core: &IntentOsCore,
    db: &MemoryHubDb,
    q_trim: &str,
    session_id: Option<&str>,
    allow_sync: bool,
) -> (String, Vec<Value>) {
    if allow_sync {
        ensure_document_outlines_synced(core, db);
    }
    let asks_pkg = query_asks_for_package(q_trim);

    let mut ranked = recall_mentioned_entities(db, q_trim, None, session_id, 5).unwrap_or_default();
    if ranked.is_empty()
        && let Ok(recent) = list_recent_mentions(db, true, session_id, 4)
    {
        ranked = recent.into_iter().map(|e| (e, 55.0)).collect();
    }
    if ranked.is_empty()
        && let Ok(recent_any) = list_recent_mentions(db, true, None, 3)
    {
        ranked = recent_any.into_iter().map(|e| (e, 48.0)).collect();
    }
    ranked.retain(|(e, _)| asks_pkg || !is_installer_or_package_artifact(&e.canonical_value));

    let also_asks_software = q_trim.contains("软件")
        || q_trim.contains("应用")
        || q_trim.contains("媒体")
        || q_trim.contains("转译")
        || q_trim.contains("播放器");

    let mut md = String::from(PERSONAL_MEMORY_HEADER);
    let mut hits = Vec::new();

    if !ranked.is_empty() {
        md.push_str("### 历史指代目标 (Top 1-3)\n");
        for (idx, (ent, sc)) in ranked.into_iter().take(3).enumerate() {
            let outline_opt = get_document_outline_by_path(db, &ent.canonical_value)
                .ok()
                .flatten();
            let outline_suffix = if let Some(ref o) = outline_opt {
                let toc = format_toc_preview(o, None, 80);
                if toc.is_empty() {
                    format!(" | 标题: {}", truncate_chars(&o.doc_title, 36))
                } else {
                    format!(" | 标题: {} {}", truncate_chars(&o.doc_title, 28), toc)
                }
            } else {
                String::new()
            };

            let prefix = if idx == 0 { "★ " } else { "" };
            md.push_str(&format!(
                "- {}`{}` (名称: {} | 动作: {} | {}次{})\n",
                prefix,
                ent.canonical_value,
                ent.display_name,
                ent.action_verb,
                ent.mention_count,
                outline_suffix
            ));
            hits.push(json!({
                "kind": "mentioned_file",
                "relevance": if idx == 0 { "direct" } else { "context" },
                "title": if idx == 0 {
                    format!("指代召回: {}", ent.display_name)
                } else {
                    ent.display_name
                },
                "value": ent.canonical_value,
                "detail": format!("动作={} · 提及{}次", ent.action_verb, ent.mention_count),
                "score": sc,
            }));
        }
    }

    if also_asks_software {
        let mut apps = query_software_catalog(db, Some(q_trim), false, 3).unwrap_or_default();
        if apps.is_empty() {
            apps = query_software_catalog(db, None, false, 2).unwrap_or_default();
        }
        if !apps.is_empty() {
            md.push_str("### 关联桌面软件\n");
            for app in apps.into_iter().take(2) {
                let cats = app
                    .categories
                    .iter()
                    .take(2)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("/");
                md.push_str(&format!(
                    "- **{}** (`{}` | 使用 {} 次 | {})\n",
                    app.name, app.app_id, app.launch_count, cats
                ));
                hits.push(json!({
                    "kind": "software",
                    "relevance": "direct",
                    "title": app.name,
                    "value": app.app_id,
                    "detail": format!("使用频次 {} · {}", app.launch_count, app.generic_name),
                    "score": app.frecency_score,
                }));
            }
        }
    }

    if hits.is_empty() {
        return (String::new(), Vec::new());
    }
    (md, hits)
}

#[derive(Debug, Clone)]
struct SemanticRecallCard {
    path: String,
    display_title: String,
    score: f64,
    source_kind: &'static str,
    detail_note: String,
    outline_hit: Option<DocumentOutlineHit>,
}

/// Branch 4: Specific Document / Topic / Chapter Lookup (e.g. `"打开我的硕士论文第四章"`, `"周报"`).
/// Queries `document_outlines` + `entity_mentions` + `long_term_files`, enforces `score >= 48.0`,
/// caps at Top 3 Layer-0 Semantic Index Cards, and NEVER pads with global `.deb`/`.tar.zst` files!
fn build_document_topic_lookup_memory(
    core: &IntentOsCore,
    db: &MemoryHubDb,
    q_trim: &str,
    session_id: Option<&str>,
    allow_sync: bool,
) -> (String, Vec<Value>) {
    if allow_sync {
        ensure_document_outlines_synced(core, db);
    }
    let asks_pkg = query_asks_for_package(q_trim);
    let mut merged: HashMap<String, SemanticRecallCard> = HashMap::new();

    // 1. Semantic Document Outlines (`doc_title` + chapter headings + keywords + Chinese numeral normalization)
    if let Ok(outline_hits) = search_document_outlines(db, q_trim, None, 6) {
        for hit in outline_hits {
            let mut sc = hit.score;
            if !asks_pkg && is_installer_or_package_artifact(&hit.record.path) {
                sc -= 75.0;
            }
            if sc <= 0.0 {
                continue;
            }
            let path = hit.record.path.clone();
            let title = hit.record.doc_title.clone();
            let matched_note = hit
                .matched_section
                .as_ref()
                .map(|s| format!("命中章节: {}", s.heading))
                .unwrap_or_else(|| format!("共 {} 个章节标题", hit.record.headings.len()));
            merged.insert(
                path.clone(),
                SemanticRecallCard {
                    path,
                    display_title: title,
                    score: sc,
                    source_kind: "document_outline",
                    detail_note: matched_note,
                    outline_hit: Some(hit),
                },
            );
        }
    }

    // 2. Previously mentioned files & document references
    if let Ok(mentioned) = recall_mentioned_entities(db, q_trim, None, session_id, 6) {
        for (ent, ent_score) in mentioned {
            if ent.entity_kind == "app" {
                continue;
            }
            let mut sc = ent_score;
            if !asks_pkg && is_installer_or_package_artifact(&ent.canonical_value) {
                sc -= 70.0;
            }
            if sc <= 0.0 {
                continue;
            }
            merged
                .entry(ent.canonical_value.clone())
                .and_modify(|existing| {
                    existing.score = existing.score.max(sc) + 8.0;
                })
                .or_insert_with(|| SemanticRecallCard {
                    path: ent.canonical_value,
                    display_title: ent.display_name,
                    score: sc,
                    source_kind: "mentioned_file",
                    detail_note: format!("历史提及 {} 次 ({})", ent.mention_count, ent.action_verb),
                    outline_hit: None,
                });
        }
    }

    // 3. Long-term frequent files (strictly lexical relevance scored — NEVER global frecency padding!)
    if let Ok(freq_candidates) = query_frequent_files(db, None, None, 50) {
        for f in freq_candidates {
            let sc = score_frequent_file_lexical(&f, q_trim, asks_pkg);
            if sc <= 0.0 {
                continue;
            }
            merged
                .entry(f.path.clone())
                .and_modify(|existing| {
                    existing.score = existing.score.max(sc) + 6.0;
                })
                .or_insert_with(|| SemanticRecallCard {
                    path: f.path,
                    display_title: f.title,
                    score: sc,
                    source_kind: "frequent_file",
                    detail_note: format!("高频打开 {} 次", f.open_count),
                    outline_hit: None,
                });
        }
    }

    // Enforce strict relevance floor (`score >= 48.0`) and cap at Top 3 Semantic Index Cards!
    let mut qualified: Vec<SemanticRecallCard> = merged
        .into_values()
        .filter(|c| c.score >= MIN_DOC_TOPIC_RECALL_SCORE)
        .collect();

    if qualified.is_empty() {
        return (String::new(), Vec::new());
    }

    qualified.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    qualified.truncate(3);

    // Enrich any non-outline card with cached/lazy `DocumentOutlineRecord` if available
    for card in &mut qualified {
        if card.outline_hit.is_none() && card.path.starts_with('/') {
            let p = Path::new(&card.path);
            let rec_opt = get_document_outline_by_path(db, &card.path)
                .ok()
                .flatten()
                .or_else(|| {
                    if allow_sync && p.is_file() && !core.fs_engine.is_forbidden(p) {
                        index_document_file(core, db, p).ok().flatten()
                    } else {
                        None
                    }
                });
            if let Some(rec) = rec_opt {
                let toc_preview = format_toc_preview(&rec, None, 100);
                card.display_title = rec.doc_title.clone();
                card.outline_hit = Some(DocumentOutlineHit {
                    record: rec,
                    score: card.score,
                    matched_section: None,
                    toc_preview,
                });
            }
        }
    }

    let mut md = String::from(PERSONAL_MEMORY_HEADER);
    md.push_str(
        "（语义文档索引卡 Top 1-3；如需读取具体章节内容，请调用 `memory_inspect_document`）\n",
    );
    let mut hits = Vec::new();

    for card in qualified {
        if let Some(ref oh) = card.outline_hit {
            let summary_short = truncate_chars(&oh.record.doc_summary, 52);
            let toc_part = if oh.toc_preview.is_empty() {
                String::new()
            } else {
                format!(" | {}", oh.toc_preview)
            };
            let chap_part = oh
                .matched_section
                .as_ref()
                .map(|s| format!(" | ★目标章节: `{}`", truncate_chars(&s.heading, 34)))
                .unwrap_or_default();
            md.push_str(&format!(
                "- 📄 `{}` | 标题: **{}** | 摘要: {}{}{}\n",
                card.path,
                truncate_chars(&oh.record.doc_title, 42),
                summary_short,
                toc_part,
                chap_part
            ));
        } else {
            md.push_str(&format!(
                "- 📄 `{}` (名称: **{}** | {})\n",
                card.path,
                truncate_chars(&card.display_title, 42),
                card.detail_note
            ));
        }

        hits.push(json!({
            "kind": card.source_kind,
            "relevance": "direct",
            "title": card.display_title,
            "value": card.path,
            "detail": card.detail_note,
            "score": (card.score * 100.0).round() / 100.0,
        }));
    }

    (md, hits)
}

fn score_frequent_file_lexical(f: &LongTermFileHabit, query: &str, asks_pkg: bool) -> f64 {
    if !asks_pkg && is_installer_or_package_artifact(&f.path) {
        return 0.0;
    }

    let q_lc = query.trim().to_ascii_lowercase();
    let title_lc = f.title.to_ascii_lowercase();
    let stem_lc = Path::new(&f.title)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&f.title)
        .to_ascii_lowercase();
    let path_lc = f.path.to_ascii_lowercase();

    let mut lexical_score = 0.0f64;
    if !stem_lc.is_empty() && stem_lc.chars().count() >= 2 && q_lc.contains(&stem_lc) {
        lexical_score += 78.0;
    } else if !title_lc.is_empty() && q_lc.contains(&title_lc) {
        lexical_score += 82.0;
    }

    let mut cleaned = query.to_string();
    for stop in [
        "帮我看看",
        "帮我看一下",
        "帮我查看",
        "帮我打开",
        "打开我的",
        "查看我的",
        "看看我的",
        "请打开",
        "请查看",
        "帮我看",
        "打开",
        "查看",
        "看看",
        "查找",
        "搜索",
        "我的",
        "那份",
        "那个",
        "这份",
        "这个",
        "文件",
        "文档",
        "里的",
        "中的",
    ] {
        cleaned = cleaned.replace(stop, " ");
    }
    let tokens: Vec<&str> = cleaned
        .split(|c: char| {
            c.is_whitespace() || matches!(c, '，' | ',' | '。' | '？' | '?' | '！' | '《' | '》')
        })
        .map(str::trim)
        .filter(|t| t.chars().count() >= 2)
        .collect();

    for tok in tokens {
        let t_lc = tok.to_ascii_lowercase();
        if title_lc.contains(&t_lc) {
            lexical_score += 56.0;
        } else if path_lc.contains(&t_lc) {
            lexical_score += 48.0;
        }
    }

    if lexical_score <= 0.0 {
        return 0.0;
    }

    lexical_score + (f.frecency_score * 0.15).min(18.0)
}

fn enforce_char_budget(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out = String::new();
    for line in text.lines() {
        let candidate_len = out.chars().count() + line.chars().count() + 1;
        if candidate_len <= max_chars {
            out.push_str(line);
            out.push('\n');
        } else {
            let remaining = max_chars.saturating_sub(out.chars().count() + 2);
            if remaining >= 16 {
                let clipped: String = line.chars().take(remaining).collect();
                out.push_str(&clipped);
                out.push_str("…\n");
            }
            break;
        }
    }
    if out.is_empty() {
        let mut clipped: String = text.chars().take(max_chars.saturating_sub(1)).collect();
        clipped.push('…');
        clipped
    } else {
        out
    }
}

/// Format a purple `memory` Trace Dot (`●`) from structured `memory_hits`.
pub fn build_memory_trace_dot(memory_hits: &[Value]) -> Option<Value> {
    if memory_hits.is_empty() {
        return None;
    }
    let preview = memory_hits
        .iter()
        .take(5)
        .filter_map(|h| {
            let t = h.get("title").and_then(|v| v.as_str())?;
            let val = h.get("value").and_then(|v| v.as_str()).unwrap_or("");
            let det = h.get("detail").and_then(|v| v.as_str()).unwrap_or("");
            Some(format!("• {} ({}) — {}", t, val, det))
        })
        .collect::<Vec<_>>()
        .join("\n");

    Some(json!({
        "kind": "memory",
        "color": "purple",
        "title": format!("记忆召回: {} 项文件/软件", memory_hits.len()),
        "detail": preview,
        "hits": memory_hits,
    }))
}

/// Expose LLM Tool definitions for querying personal OS memory (`memory_*`).
pub fn memory_tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "memory_recall_mentioned_files".to_string(),
            description: "检索用户在当前或历史对话中之前提到过、打开过或修改过的文件、目录、文档（如《周报》）、网址或软件，支持自然语言指代如『我之前说的那个文件』『上次提到的文档』『刚才改的配置』。".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "自然语言指代或关键词，例如 '刚才改的配置'、'上次提到的文档'、'周报'"
                    },
                    "entity_kind": {
                        "type": "string",
                        "enum": ["all", "file", "directory", "document_ref", "app", "url"],
                        "description": "可选实体类别过滤"
                    },
                    "session_id": {
                        "type": "string",
                        "description": "可选会话 ID"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "返回最大条数（默认 10）"
                    }
                }
            }),
        },
        ToolSpec {
            name: "memory_get_frequent_files".to_string(),
            description: "获取用户长期高频使用的文件列表（融合 Ubuntu 系统 ~/.local/share/recently-used.xbel 历史打开记录、时间衰减 Frecency 与 IntentOS 操作频次）。".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "可选文件名、路径或拼音过滤词"
                    },
                    "category": {
                        "type": "string",
                        "description": "可选文件类型过滤（pdf / word / spreadsheet / presentation / markdown / code / image / video / archive）"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "返回最大条数（默认 15）"
                    }
                }
            }),
        },
        ToolSpec {
            name: "memory_get_software_catalog".to_string(),
            description: "查询本机安装的 Ubuntu 桌面软件全量清单与长期常用软件画像（含中文名、英文名、分类、MIME 类型、x-scheme-handler URI 协议、DBusActivatable 及历史使用次数）。".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "可选软件名、功能类别或协议关键词（如 '音乐'、'浏览器'、'vscode'、'pdf'）"
                    },
                    "only_frequent": {
                        "type": "boolean",
                        "description": "是否只返回有历史使用记录的常用软件（默认 false）"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "返回最大条数（默认 25）"
                    }
                }
            }),
        },
        ToolSpec {
            name: "memory_search_past_chats".to_string(),
            description: "在持久化的多轮历史会话记录中搜索之前聊过的内容、方案或指令（隐私会话不会被记录）。".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "搜索关键词或短语"
                    },
                    "session_id": {
                        "type": "string",
                        "description": "可选会话 ID 过滤"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "返回最大条数（默认 10）"
                    }
                },
                "required": ["query"]
            }),
        },
        ToolSpec {
            name: "memory_inspect_document".to_string(),
            description: "按文件名、语义主题（如『硕士论文』『毕业设计』『周报』）或路径检索本地文档（.docx/.md/.txt/.tex/.typ/.pdf）的结构化章节大纲，并按需读取指定章节（如『第四章』『实验分析』）的标题与精简正文摘要，无需将整篇大文档塞入上下文。".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "文件名、主题或路径（如 硕士论文 或 paper_main.docx）"
                    },
                    "section": {
                        "type": "string",
                        "description": "可选章节名或关键词（如 第四章 / 实验分析）"
                    }
                },
                "required": ["query"]
            }),
        },
    ]
}

/// Check whether a tool name belongs to `memory_hub` (handles both `_` and `.` separators).
pub fn is_memory_tool(tool_name: &str) -> bool {
    matches!(
        normalize_tool_name(tool_name).as_str(),
        "memory_recall_mentioned_files"
            | "memory_get_frequent_files"
            | "memory_get_software_catalog"
            | "memory_search_past_chats"
            | "memory_inspect_document"
    )
}

fn normalize_tool_name(name: &str) -> String {
    name.trim().replace('.', "_").to_ascii_lowercase()
}

/// Execute one of the `memory_*` LLM tools against `memory_hub.db`.
pub fn execute_memory_tool(
    core: &IntentOsCore,
    tool_name: &str,
    args: &Value,
) -> anyhow::Result<Value> {
    execute_memory_tool_with_sync(core, tool_name, args, true)
}

pub fn execute_memory_tool_with_sync(
    core: &IntentOsCore,
    tool_name: &str,
    args: &Value,
    allow_sync: bool,
) -> anyhow::Result<Value> {
    if !allow_sync && !MemoryHubDb::path_for_core(core).exists() {
        return Ok(json!({
            "ok": true,
            "tool": normalize_tool_name(tool_name),
            "found": false,
            "count": 0,
            "items": [],
            "hits": [],
            "files": [],
            "apps": [],
        }));
    }
    let db = MemoryHubDb::open_for_core(core)?;
    if allow_sync {
        ensure_lazy_synced(core, &db);
    }

    match normalize_tool_name(tool_name).as_str() {
        "memory_recall_mentioned_files" => {
            let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let kind = args.get("entity_kind").and_then(|v| v.as_str());
            let sid = args.get("session_id").and_then(|v| v.as_str());
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
            let ranked = recall_mentioned_entities(&db, query, kind, sid, limit)?;
            let items: Vec<Value> = ranked
                .into_iter()
                .map(|(ent, score)| {
                    json!({
                        "entity": ent,
                        "score": score,
                    })
                })
                .collect();
            Ok(json!({
                "ok": true,
                "tool": "memory_recall_mentioned_files",
                "count": items.len(),
                "items": items,
            }))
        }
        "memory_get_frequent_files" => {
            let query = args.get("query").and_then(|v| v.as_str());
            let category = args.get("category").and_then(|v| v.as_str());
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(15) as usize;
            let files = query_frequent_files(&db, query, category, limit)?;
            Ok(json!({
                "ok": true,
                "tool": "memory_get_frequent_files",
                "count": files.len(),
                "files": files,
            }))
        }
        "memory_get_software_catalog" => {
            let query = args.get("query").and_then(|v| v.as_str());
            let only_frequent = args
                .get("only_frequent")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(25) as usize;
            let apps = query_software_catalog(&db, query, only_frequent, limit)?;
            let summary = get_installed_apps_summary(&db)?;
            Ok(json!({
                "ok": true,
                "tool": "memory_get_software_catalog",
                "summary": summary,
                "count": apps.len(),
                "apps": apps,
            }))
        }
        "memory_search_past_chats" => {
            let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let sid = args.get("session_id").and_then(|v| v.as_str());
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
            let hits = search_past_chats(&db, query, sid, limit)?;
            Ok(json!({
                "ok": true,
                "tool": "memory_search_past_chats",
                "count": hits.len(),
                "hits": hits,
            }))
        }
        "memory_inspect_document" => {
            let query = args
                .get("query")
                .or_else(|| args.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let section = args
                .get("section")
                .or_else(|| args.get("chapter"))
                .or_else(|| args.get("section_hint"))
                .and_then(|v| v.as_str());
            inspect_document_with_sync(core, query, section, allow_sync)
        }
        other => anyhow::bail!("未知的 memory_hub 工具: {}", other),
    }
}

/// Layer-2 On-Demand Document Outline & Chapter Inspector (`memory_inspect_document`).
///
/// Strictly bounds serialized JSON output to `<= 2200 chars` (`MAX_INSPECT_DOC_CHARS`)
/// so LLM context stays lean even on 100-page `.docx` / `.pdf` theses!
pub fn inspect_document(
    core: &IntentOsCore,
    query: &str,
    section: Option<&str>,
) -> anyhow::Result<Value> {
    inspect_document_with_sync(core, query, section, true)
}

pub fn inspect_document_with_sync(
    core: &IntentOsCore,
    query: &str,
    section: Option<&str>,
    allow_sync: bool,
) -> anyhow::Result<Value> {
    if !allow_sync && !MemoryHubDb::path_for_core(core).exists() {
        return Ok(json!({
            "ok": true,
            "tool": "memory_inspect_document",
            "count": 0,
            "found": false,
            "path": Value::Null,
            "doc_title": Value::Null,
            "doc_summary": Value::Null,
            "outline": [],
            "matched_section": Value::Null,
        }));
    }
    let db = MemoryHubDb::open_for_core(core)?;
    if allow_sync {
        ensure_lazy_synced(core, &db);
        ensure_document_outlines_synced(core, &db);
    }

    let q_trim = query.trim();
    let sec_trim = section.map(str::trim).filter(|s| !s.is_empty());

    // If caller passed an explicit existing path on disk that hasn't been indexed yet, index it now
    if allow_sync && q_trim.starts_with('/') {
        let direct_path = Path::new(q_trim);
        if direct_path.is_file() && !core.fs_engine.is_forbidden(direct_path) {
            let _ = index_document_file(core, &db, direct_path);
        }
    }

    let hits = search_document_outlines(&db, q_trim, sec_trim, 3)?;
    let Some(best) = hits.into_iter().next() else {
        return Ok(json!({
            "ok": true,
            "tool": "memory_inspect_document",
            "count": 0,
            "found": false,
            "path": Value::Null,
            "doc_title": Value::Null,
            "doc_summary": Value::Null,
            "outline": [],
            "matched_section": Value::Null,
        }));
    };

    let doc_title = truncate_chars(&best.record.doc_title, 96);
    let doc_summary = truncate_chars(&best.record.doc_summary, 160);
    let matched_heading_opt = best.matched_section.as_ref().map(|s| s.heading.clone());

    // Build compact outline array (preferring top-level headings if large, always preserving matched heading)
    let raw_outline: Vec<String> = if best.record.headings.len() <= 16 {
        best.record
            .headings
            .iter()
            .map(|h| truncate_chars(h, 48))
            .collect()
    } else {
        let mut selected: Vec<String> = best
            .record
            .sections
            .iter()
            .filter(|s| s.level <= 2)
            .take(15)
            .map(|s| truncate_chars(&s.heading, 48))
            .collect();
        if selected.is_empty() {
            selected = best
                .record
                .headings
                .iter()
                .take(15)
                .map(|h| truncate_chars(h, 48))
                .collect();
        }
        if let Some(ref mh) = matched_heading_opt {
            let mh_short = truncate_chars(mh, 48);
            if !selected.iter().any(|x| x == &mh_short) {
                selected.push(mh_short);
            }
        }
        selected
    };

    // Progressively tighten `excerpt` and `outline` until serialized JSON <= 2200 chars!
    let mut excerpt_cap = 820usize;
    let mut outline_cap = raw_outline.len();
    loop {
        let mut outline_slice: Vec<String> =
            raw_outline.iter().take(outline_cap).cloned().collect();
        if let Some(ref mh) = matched_heading_opt {
            let mh_short = truncate_chars(mh, 48);
            if !outline_slice.iter().any(|x| x == &mh_short) {
                if !outline_slice.is_empty() {
                    outline_slice.pop();
                }
                outline_slice.push(mh_short);
            }
        }

        let matched_val = best.matched_section.as_ref().map(|sec| {
            json!({
                "heading": truncate_chars(&sec.heading, 72),
                "level": sec.level,
                "paragraph_index": sec.paragraph_index,
                "excerpt": truncate_chars(&sec.excerpt, excerpt_cap),
            })
        });

        let payload = json!({
            "ok": true,
            "tool": "memory_inspect_document",
            "count": 1,
            "found": true,
            "path": best.record.path,
            "doc_title": doc_title,
            "doc_summary": doc_summary,
            "outline": outline_slice,
            "matched_section": matched_val,
        });

        let serialized_chars = serde_json::to_string(&payload)
            .map(|s| s.chars().count())
            .unwrap_or(0);
        if serialized_chars <= MAX_INSPECT_DOC_CHARS || (excerpt_cap <= 120 && outline_cap <= 4) {
            return Ok(payload);
        }

        if excerpt_cap > 260 {
            excerpt_cap = excerpt_cap.saturating_sub(140);
        } else if outline_cap > 6 {
            outline_cap = outline_cap.saturating_sub(3);
        } else {
            excerpt_cap = 120;
            outline_cap = outline_cap.min(4);
        }
    }
}

/// Deterministic fallback responder for direct user questions about remembered files,
/// long-term frequent files, or installed/frequent desktop software (works 100% offline!).
pub fn try_answer_memory_query_deterministically(
    core: &IntentOsCore,
    query: &str,
    session_id: Option<&str>,
) -> Option<(String, Vec<Value>)> {
    try_answer_memory_query_deterministically_with_sync(core, query, session_id, true)
}

pub fn try_answer_memory_query_deterministically_with_sync(
    core: &IntentOsCore,
    query: &str,
    session_id: Option<&str>,
    allow_sync: bool,
) -> Option<(String, Vec<Value>)> {
    let q = query.trim();
    if q.is_empty() {
        return None;
    }

    // Do not intercept imperative file/app mutation commands ("打开...", "移动...", "删除...", "把...复制到...")
    let is_imperative_mutation = q.starts_with("打开")
        || q.starts_with("移动")
        || q.starts_with("复制")
        || q.starts_with("删除")
        || q.starts_with("重命名")
        || (q.starts_with("把")
            && (q.contains("移") || q.contains("复制") || q.contains("删") || q.contains("改")));
    if is_imperative_mutation {
        return None;
    }

    let asks_what_or_list = q.contains("哪些")
        || q.contains("什么")
        || q.contains("哪个")
        || q.contains("哪份")
        || q.contains("列表")
        || q.contains("清单")
        || q.contains("看看")
        || q.contains("查看")
        || q.contains("列出");

    let asks_mentioned = is_conversational_entity_reference(q) && asks_what_or_list;
    let asks_frequent_files = (q.contains("长期")
        || q.contains("常用")
        || q.contains("高频")
        || q.contains("经常打开")
        || q.contains("最近和长期"))
        && q.contains("文件")
        && asks_what_or_list;
    let asks_software = (q.contains("软件") || q.contains("应用") || q.contains("程序"))
        && (q.contains("电脑上")
            || q.contains("本机")
            || q.contains("装了")
            || q.contains("安装")
            || q.contains("常用")
            || q.contains("有哪些"));

    if !asks_mentioned && !asks_frequent_files && !asks_software {
        return None;
    }

    if !allow_sync && !MemoryHubDb::path_for_core(core).exists() {
        return None;
    }
    let db = MemoryHubDb::open_for_core(core).ok()?;
    if allow_sync {
        ensure_lazy_synced(core, &db);
    }
    let mut hits = Vec::new();
    let mut sections = Vec::new();

    if asks_mentioned {
        let mut ranked = recall_mentioned_entities(&db, q, Some("mentioned_files"), session_id, 10)
            .unwrap_or_default();
        if ranked.is_empty()
            && let Ok(recent) = list_recent_mentions(&db, true, None, 10)
        {
            ranked = recent.into_iter().map(|e| (e, 50.0)).collect();
        }
        if ranked.is_empty() {
            sections.push(
                "### 🕘 之前对话提及的文件\n当前还没有在非隐私对话中记录到已提及的文件。您可以在对话中直接提及文件路径或文档名（如 `/home/.../report.pdf` 或 `《周报》`），我会自动记住。".to_string(),
            );
        } else {
            let mut body = String::from("### 🕘 您之前在对话中提到的文件与文档\n");
            for (i, (ent, sc)) in ranked.iter().enumerate() {
                body.push_str(&format!(
                    "{}. **{}** (`{}`)\n   - 最近动作：`{}` · 提及次数：{} 次 · 上下文：{}\n",
                    i + 1,
                    ent.display_name,
                    ent.canonical_value,
                    ent.action_verb,
                    ent.mention_count,
                    ent.context_snippet
                ));
                hits.push(json!({
                    "kind": "mentioned_file",
                    "title": ent.display_name,
                    "value": ent.canonical_value,
                    "detail": format!("动作={} · 提及{}次", ent.action_verb, ent.mention_count),
                    "score": sc,
                }));
            }
            sections.push(body);
        }
    }

    if asks_frequent_files {
        let files = query_frequent_files(&db, None, None, 10).unwrap_or_default();
        if files.is_empty() {
            sections.push("### 📂 长期高频使用的文件\n暂未检索到系统最近使用（XBEL）或授权目录中的高频文件记录。".to_string());
        } else {
            let mut body =
                String::from("### 📂 您长期与高频使用的文件（融合系统 XBEL 与 IntentOS 热度）\n");
            for (i, f) in files.iter().enumerate() {
                let apps_str = if f.preferred_apps.is_empty() {
                    "默认关联".to_string()
                } else {
                    f.preferred_apps.join(", ")
                };
                body.push_str(&format!(
                    "{}. **{}** (`{}`)\n   - 累计打开：**{} 次** · Frecency：**{:.1}** · 类别：`{}` · 常用打开软件：{}\n",
                    i + 1,
                    f.title,
                    f.path,
                    f.open_count,
                    f.frecency_score,
                    f.category,
                    apps_str
                ));
                hits.push(json!({
                    "kind": "frequent_file",
                    "title": f.title,
                    "value": f.path,
                    "detail": format!("打开 {} 次 · Frecency {:.1}", f.open_count, f.frecency_score),
                    "score": f.frecency_score,
                }));
            }
            sections.push(body);
        }
    }

    if asks_software {
        let summary = get_installed_apps_summary(&db).ok();
        let apps = query_software_catalog(&db, None, false, 16).unwrap_or_default();
        let mut body = String::from("### 🧩 本机已安装与常用桌面软件画像\n");
        if let Some(sum) = summary {
            let pkg = sum
                .by_packaging
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join(" · ");
            body.push_str(&format!(
                "共扫描到 **{} 款**桌面软件（其中有历史高频使用记录 **{} 款**，支持 D-Bus 激活 **{} 款**，支持自定义 URI 协议 **{} 款**；来源分布：{}）。\n\n",
                sum.total_installed,
                sum.frequent_apps_count,
                sum.dbus_activatable_count,
                sum.uri_scheme_apps_count,
                pkg
            ));
        }
        for (i, app) in apps.iter().enumerate() {
            let freq_badge = if app.launch_count > 0 {
                format!("常用 · {}次", app.launch_count)
            } else {
                "已安装".to_string()
            };
            let cats = app
                .categories
                .iter()
                .take(2)
                .cloned()
                .collect::<Vec<_>>()
                .join("/");
            body.push_str(&format!(
                "{}. **{}** (`{}`) — `[{}]` {}\n",
                i + 1,
                app.name,
                app.app_id,
                freq_badge,
                if cats.is_empty() {
                    app.generic_name.clone()
                } else {
                    format!("分类: {}", cats)
                }
            ));
            if hits.len() < 12 {
                hits.push(json!({
                    "kind": "software",
                    "title": app.name,
                    "value": app.app_id,
                    "detail": format!("{} · {}", freq_badge, app.generic_name),
                    "score": app.frecency_score,
                }));
            }
        }
        sections.push(body);
    }

    Some((sections.join("\n"), hits))
}

fn build_known_file_lookup(core: &IntentOsCore, db: &MemoryHubDb) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(idx_conn) = core.index_db.conn.lock()
        && let Ok(mut stmt) = idx_conn
            .prepare("SELECT path, name, stem FROM files ORDER BY mtime_secs DESC LIMIT 1000")
        && let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
    {
        for (path, name, stem) in rows.flatten() {
            map.entry(name.to_ascii_lowercase())
                .or_insert_with(|| path.clone());
            map.entry(stem.to_ascii_lowercase()).or_insert(path);
        }
    }

    if let Ok(conn) = db.conn.lock()
        && let Ok(mut stmt) = conn.prepare(
            "SELECT path, title FROM long_term_files ORDER BY frecency_score DESC LIMIT 500",
        )
        && let Ok(rows) =
            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
    {
        for (path, title) in rows.flatten() {
            if let Some(stem) = Path::new(&title).file_stem().and_then(|s| s.to_str()) {
                map.entry(stem.to_ascii_lowercase())
                    .or_insert_with(|| path.clone());
            }
            map.entry(title.to_ascii_lowercase()).or_insert(path);
        }
    }

    if let Ok(conn) = db.conn.lock()
        && let Ok(mut stmt) = conn.prepare(
            "SELECT path, doc_title FROM document_outlines ORDER BY mtime_epoch DESC LIMIT 300",
        )
        && let Ok(rows) =
            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
    {
        for (path, doc_title) in rows.flatten() {
            let clean = doc_title.trim().to_ascii_lowercase();
            if clean.chars().count() >= 2 {
                map.entry(clean).or_insert(path);
            }
        }
    }
    map
}

fn build_known_app_lookup(db: &MemoryHubDb) -> HashMap<String, (String, String)> {
    let mut map = HashMap::new();
    let Ok(conn) = db.conn.lock() else {
        return map;
    };
    if let Ok(mut stmt) = conn.prepare(
        "SELECT app_id, name, name_en, executable FROM software_inventory ORDER BY launch_count DESC",
    ) && let Ok(rows) = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    }) {
        for (aid, name, name_en, exec) in rows.flatten() {
            for alias in [&name, &name_en, &exec] {
                let lc = alias.trim().to_ascii_lowercase();
                if lc.chars().count() >= 3 && !matches!(lc.as_str(), "env" | "sh" | "bash" | "gio") {
                    map.entry(lc)
                        .or_insert_with(|| (aid.clone(), name.clone()));
                }
            }
        }
    }
    map
}

fn derive_session_title(user_text: &str) -> String {
    let clean = scrub_sensitive_text(user_text);
    let first_line = clean
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("新对话");
    truncate_chars(first_line, 26)
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    let single = s
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if single.chars().count() <= max_chars {
        single
    } else {
        let mut out: String = single.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}
