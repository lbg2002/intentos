#![forbid(unsafe_code)]

//! Memory & Personal Data Management Hub (`crates/intentosd/src/memory_hub/`).
//!
//! Solves core AIOS personal memory capabilities in dedicated `${data_dir}/memory_hub.db` (WAL):
//! 1. `conversational_entities`: Remembers previously mentioned files, directories, quoted documents
//!    (`《周报》`), URLs, and apps across multi-turn prompts, replies, and tool executions, resolving
//!    natural references like "我之前说的那个文件", "上次提到的文档", "刚才改的配置".
//! 2. `long_term_habits`: Parses Ubuntu's `~/.local/share/recently-used.xbel` (decoding percent-encoded
//!    Chinese paths), merges `core.resources` indexed files and IntentOS tool usage to compute Frecency
//!    for Long-Term / Frequently Used Files, and scans system/Snap/Flatpak/user `.desktop` entries to
//!    build the Full Ubuntu Software Inventory & Usage Profile.
//! 3. `session_rag`: Manages persistent multi-turn chat sessions (strictly zero-write in incognito),
//!    builds automatic `[Personal OS Memory]` RAG prompts + purple `trace_dots` hits, and exposes
//!    `memory_*` LLM tools.

pub mod context_compressor;
pub mod conversational_entities;
pub mod document_outline;
pub mod long_term_habits;
pub mod schema_and_db;
pub mod session_rag;

pub use context_compressor::{
    CompressedSessionHistory, CompressedTurnTierPreview, ContextCompressionStats,
    ContextDecayConfig, HydratedQaTurn, build_compressed_session_history, compress_markdown_answer,
    compress_qa_turns, compress_qa_turns_detailed, compute_retention_weight,
    estimate_text_tokens, hydrate_session_qa_turns, load_context_decay_config,
    preview_session_compression, save_context_decay_config, update_context_decay_config_from_json,
};
pub use conversational_entities::{
    ExtractedEntity, extract_entities_from_turn, infer_action_verb_from_text,
    is_conversational_entity_reference, list_recent_mentions, recall_mentioned_entities,
    upsert_entity_mentions,
};
pub use document_outline::{
    arabic_to_chinese_number, build_stored_zip_archive, ensure_document_outlines_synced,
    extract_chapter_number_hint, extract_stored_zip_entry, format_toc_preview,
    get_document_outline_by_path, index_document_file, list_document_outlines_preview,
    parse_chinese_or_arabic_number, search_document_outlines, sync_document_outlines,
};
pub use long_term_habits::{
    SyncSummary, XbelAppUsage, XbelBookmark, compute_frecency_score, ensure_lazy_synced,
    get_installed_apps_summary, parse_desktop_file_full, parse_xbel_content, parse_xbel_file,
    query_frequent_files, query_software_catalog, query_software_catalog_scored, record_app_launch,
    record_file_usage, scan_desktop_directories, sync_system_usage_with_options,
};
pub use schema_and_db::{
    CategoryCount, ChatMessageRecord, ChatSessionRecord, DocSection, DocumentOutlineHit,
    DocumentOutlinePreview, DocumentOutlineRecord, EntityMention, InstalledAppsSummary,
    LongTermFileHabit, MemoryHubDb, PastChatHit, SoftwareProfile,
};
pub use session_rag::{
    MAX_AUTO_MEMORY_CHARS, MAX_INSPECT_DOC_CHARS, MemoryOverviewCategory, MemoryRecallIntent,
    RecordTurnInput, RecordTurnOutcome, SessionDetail, build_memory_trace_dot,
    classify_memory_query_intent, create_session, delete_session, get_session_detail,
    get_session_record, inspect_document, is_memory_tool, list_sessions, memory_tool_specs,
    remove_synthetic_approval_echo, search_past_chats,
};

use crate::core::IntentOsCore;
use crate::security_guard::{PrivacySessionPolicy, SensitiveDataGuard};
use serde_json::{Value, json};
use std::path::PathBuf;

/// Privacy- and redaction-guarded conversation turn recorder (`memory_hub`).
///
/// Enforces:
/// 1. `StrictIsolated` (`incognito == true` or `incog_*`) and `EphemeralReadOnly` perform ZERO SQLite writes.
/// 2. `Standard` sessions scrub `user_text`, `assistant_text`, `thinking`, `tool_steps`, and `trace_dots`
///    via [`SensitiveDataGuard`] BEFORE entity extraction or SQLite persistence.
pub fn record_conversation_turn(
    core: &IntentOsCore,
    input: &RecordTurnInput,
) -> anyhow::Result<RecordTurnOutcome> {
    let policy = PrivacySessionPolicy::from_session(input.incognito, input.session_id.as_deref());
    if !policy.allows_memory_write() {
        return Ok(RecordTurnOutcome {
            recorded: false,
            incognito: true,
            session_id: input.session_id.clone().unwrap_or_default(),
            extracted_entities: Vec::new(),
            updated_files: 0,
            updated_apps: 0,
        });
    }

    let mut clean_steps = input.tool_steps.clone();
    for step in &mut clean_steps {
        SensitiveDataGuard::redact_json(step);
    }
    let mut clean_dots = input.trace_dots.clone();
    for dot in &mut clean_dots {
        SensitiveDataGuard::redact_json(dot);
    }

    let sanitized = RecordTurnInput {
        session_id: input.session_id.clone(),
        user_text: SensitiveDataGuard::redact_text(&input.user_text).0,
        assistant_text: SensitiveDataGuard::redact_text(&input.assistant_text).0,
        thinking: input
            .thinking
            .as_deref()
            .map(|t| SensitiveDataGuard::redact_text(t).0),
        tool_steps: clean_steps,
        trace_dots: clean_dots,
        incognito: false,
    };
    session_rag::record_conversation_turn(core, &sanitized)
}

/// Privacy-guarded `[Personal OS Memory]` RAG prompt builder.
/// Returns empty context and zero hits when `session_id` belongs to a `StrictIsolated` (`incog_*`) session.
pub fn build_personal_memory_prompt(
    core: &IntentOsCore,
    user_text: &str,
    session_id: Option<&str>,
) -> (String, Vec<Value>) {
    let policy = PrivacySessionPolicy::from_session(false, session_id);
    if !policy.allows_memory_read() {
        return (String::new(), Vec::new());
    }
    session_rag::build_personal_memory_prompt(core, user_text, session_id)
}

/// Privacy-guarded deterministic personal-memory responder for offline mode.
/// Returns `None` without opening `memory_hub.db` when `!policy.allows_memory_read()`.
pub fn try_answer_memory_query_deterministically(
    core: &IntentOsCore,
    user_text: &str,
    session_id: Option<&str>,
) -> Option<(String, Vec<Value>)> {
    let policy = PrivacySessionPolicy::from_session(false, session_id);
    if !policy.allows_memory_read() {
        return None;
    }
    session_rag::try_answer_memory_query_deterministically(core, user_text, session_id)
}

/// Privacy-guarded `memory_*` LLM tool executor.
pub fn execute_memory_tool(
    core: &IntentOsCore,
    tool_name: &str,
    args: &Value,
) -> anyhow::Result<Value> {
    let incog = args
        .get("incognito")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let sid = args.get("session_id").and_then(|v| v.as_str());
    let policy = PrivacySessionPolicy::from_session(incog, sid);
    if !policy.allows_memory_read() {
        return Ok(json!({
            "ok": true,
            "incognito_isolated": true,
            "found": false,
            "count": 0,
            "items": [],
            "hits": [],
        }));
    }
    session_rag::execute_memory_tool(core, tool_name, args)
}

/// Unified `UiRpcRequest::ModuleRpc { domain: "memory_hub", action, payload }` dispatcher.
pub async fn handle_module_rpc(
    core: &IntentOsCore,
    action: &str,
    payload: Value,
) -> anyhow::Result<Value> {
    match action {
        "ping" => {
            let db_path = MemoryHubDb::path_for_core(core);
            Ok(json!({
                "module": "memory_hub",
                "status": "ok",
                "db_path": db_path.to_string_lossy(),
                "tools": memory_tool_specs().into_iter().map(|t| t.name).collect::<Vec<_>>(),
            }))
        }

        "sync_system_usage" => {
            let db = MemoryHubDb::open_for_core(core)?;
            let custom_xbel = payload
                .get("xbel_path")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from);
            let custom_dirs: Option<Vec<PathBuf>> = payload
                .get("desktop_dirs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(PathBuf::from))
                        .collect()
                });
            let summary = sync_system_usage_with_options(
                core,
                &db,
                custom_xbel.as_deref(),
                custom_dirs.as_deref(),
            )?;
            Ok(serde_json::to_value(summary)?)
        }

        "get_memory_dashboard" => {
            let db = MemoryHubDb::open_for_core(core)?;
            let auto_sync = payload
                .get("auto_sync")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if auto_sync {
                ensure_lazy_synced(core, &db);
                ensure_document_outlines_synced(core, &db);
            }

            let limit = payload
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(20) as usize;
            let session_id = payload.get("session_id").and_then(|v| v.as_str());

            let mentioned_files = list_recent_mentions(&db, true, session_id, limit)?;
            let mentioned_entities = list_recent_mentions(&db, false, session_id, limit)?;
            let frequent_files = query_frequent_files(&db, None, None, limit)?;
            let frequent_apps = query_software_catalog(&db, None, false, limit)?;
            let installed_apps_summary = get_installed_apps_summary(&db)?;
            let document_outlines_preview = list_document_outlines_preview(&db, 12)?;
            let sessions = list_sessions(&db, limit, None)?;
            let last_sync_at = db.get_meta("last_sync_at");
            let context_compression_config = load_context_decay_config(&db);

            Ok(json!({
                "mentioned_files": mentioned_files,
                "mentioned_entities": mentioned_entities,
                "frequent_files": frequent_files,
                "frequent_apps": frequent_apps,
                "installed_apps_summary": installed_apps_summary,
                "document_outlines_preview": document_outlines_preview,
                "sessions": sessions,
                "context_compression_config": context_compression_config,
                "stats": {
                    "mentioned_files_count": mentioned_files.len(),
                    "mentioned_entities_count": mentioned_entities.len(),
                    "frequent_files_count": frequent_files.len(),
                    "installed_apps_count": installed_apps_summary.total_installed,
                    "frequent_apps_count": installed_apps_summary.frequent_apps_count,
                    "document_outlines_count": document_outlines_preview.len(),
                    "sessions_count": sessions.len(),
                    "last_sync_at": last_sync_at,
                }
            }))
        }

        "get_context_compression_config" => {
            let db = MemoryHubDb::open_for_core(core)?;
            let cfg = load_context_decay_config(&db);
            Ok(serde_json::to_value(cfg)?)
        }

        "set_context_compression_config" => {
            let db = MemoryHubDb::open_for_core(core)?;
            let cfg = update_context_decay_config_from_json(&db, &payload)?;
            Ok(serde_json::to_value(cfg)?)
        }

        "preview_session_compression" => {
            let db = MemoryHubDb::open_for_core(core)?;
            preview_session_compression(core, &db, &payload)
        }

        "inspect_document" => {
            let query = payload
                .get("query")
                .or_else(|| payload.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let section = payload
                .get("section")
                .or_else(|| payload.get("chapter"))
                .or_else(|| payload.get("section_hint"))
                .and_then(|v| v.as_str());
            inspect_document(core, query, section)
        }

        "record_conversation_turn" => {
            let session_id = payload
                .get("session_id")
                .and_then(|v| v.as_str())
                .map(String::from);
            let user_text = payload
                .get("user_text")
                .or_else(|| payload.get("text"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let assistant_text = payload
                .get("assistant_text")
                .or_else(|| payload.get("reply_markdown"))
                .or_else(|| payload.get("reply"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let thinking = payload
                .get("thinking")
                .and_then(|v| v.as_str())
                .map(String::from);
            let tool_steps = payload
                .get("tool_steps")
                .or_else(|| payload.get("steps"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let trace_dots = payload
                .get("trace_dots")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let incognito = payload
                .get("incognito")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let out = record_conversation_turn(
                core,
                &RecordTurnInput {
                    session_id,
                    user_text,
                    assistant_text,
                    thinking,
                    tool_steps,
                    trace_dots,
                    incognito,
                },
            )?;
            Ok(serde_json::to_value(out)?)
        }

        "query_personal_memory" => {
            let query = payload
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let kind = payload
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("all");
            let session_id = payload.get("session_id").and_then(|v| v.as_str());
            let incognito = payload
                .get("incognito")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !PrivacySessionPolicy::from_session(incognito, session_id).allows_memory_read() {
                return Ok(json!({
                    "query": query,
                    "kind": kind,
                    "hits": [],
                    "mentioned_files": [],
                    "frequent_files": [],
                    "document_outlines": [],
                    "software": [],
                    "past_chats": [],
                    "context_markdown": "",
                    "answer_markdown": Value::Null,
                    "trace_dot": Value::Null,
                }));
            }

            let db = MemoryHubDb::open_for_core(core)?;
            ensure_lazy_synced(core, &db);
            let limit = payload
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(12) as usize;

            let mut hits: Vec<Value> = Vec::new();
            let mut mentioned_files = Vec::new();
            let mut frequent_files = Vec::new();
            let mut document_outlines = Vec::new();
            let mut software = Vec::new();
            let mut past_chats = Vec::new();

            if matches!(kind, "all" | "document_outlines") && !query.trim().is_empty() {
                ensure_document_outlines_synced(core, &db);
                let section_hint = payload.get("section").and_then(|v| v.as_str());
                let outlines = search_document_outlines(&db, query, section_hint, limit)?;
                for o in outlines {
                    if kind == "all" && o.score < 48.0 {
                        continue;
                    }
                    hits.push(json!({
                        "kind": "document_outline",
                        "title": o.record.doc_title,
                        "value": o.record.path,
                        "toc_preview": o.toc_preview,
                        "matched_section": o.matched_section,
                        "score": o.score,
                    }));
                    document_outlines.push(o);
                }
            }

            if matches!(kind, "all" | "mentioned_files") {
                let ranked = recall_mentioned_entities(
                    &db,
                    query,
                    if kind == "mentioned_files" {
                        Some("mentioned_files")
                    } else {
                        None
                    },
                    session_id,
                    limit,
                )?;
                for (ent, score) in ranked {
                    hits.push(json!({
                        "kind": "mentioned_file",
                        "title": ent.display_name,
                        "value": ent.canonical_value,
                        "action_verb": ent.action_verb,
                        "mention_count": ent.mention_count,
                        "score": score,
                    }));
                    mentioned_files.push(ent);
                }
            }

            if matches!(kind, "all" | "frequent_files") {
                let files = query_frequent_files(&db, Some(query), None, limit)?;
                for f in files {
                    hits.push(json!({
                        "kind": "frequent_file",
                        "title": f.title,
                        "value": f.path,
                        "open_count": f.open_count,
                        "preferred_apps": f.preferred_apps,
                        "score": f.frecency_score,
                    }));
                    frequent_files.push(f);
                }
            }

            if matches!(kind, "all" | "software") {
                let apps = query_software_catalog(&db, Some(query), false, limit)?;
                for app in apps {
                    hits.push(json!({
                        "kind": "software",
                        "title": app.name,
                        "value": app.app_id,
                        "launch_count": app.launch_count,
                        "categories": app.categories,
                        "uri_schemes": app.uri_schemes,
                        "dbus_activatable": app.dbus_activatable,
                        "score": app.frecency_score,
                    }));
                    software.push(app);
                }
            }

            if matches!(kind, "all" | "past_chats") && !query.trim().is_empty() {
                let chats = search_past_chats(&db, query, session_id, limit)?;
                for ch in chats {
                    hits.push(json!({
                        "kind": "past_chat",
                        "title": ch.session_title,
                        "value": ch.session_id,
                        "snippet": ch.snippet,
                        "score": ch.score,
                    }));
                    past_chats.push(ch);
                }
            }

            let (context_markdown, rag_hits) =
                build_personal_memory_prompt(core, query, session_id);
            let answer_markdown =
                try_answer_memory_query_deterministically(core, query, session_id)
                    .map(|(ans, _)| ans);
            let final_hits = if hits.is_empty() { rag_hits } else { hits };
            let trace_dot = build_memory_trace_dot(&final_hits);

            Ok(json!({
                "query": query,
                "kind": kind,
                "hits": final_hits,
                "mentioned_files": mentioned_files,
                "frequent_files": frequent_files,
                "document_outlines": document_outlines,
                "software": software,
                "past_chats": past_chats,
                "context_markdown": context_markdown,
                "answer_markdown": answer_markdown,
                "trace_dot": trace_dot,
            }))
        }

        "list_sessions" => {
            let db = MemoryHubDb::open_for_core(core)?;
            let limit = payload
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(30) as usize;
            let query = payload.get("query").and_then(|v| v.as_str());
            let sessions = list_sessions(&db, limit, query)?;
            Ok(json!({ "sessions": sessions }))
        }

        "get_session" => {
            let db = MemoryHubDb::open_for_core(core)?;
            let session_id = payload
                .get("session_id")
                .or_else(|| payload.get("id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("get_session 缺少 session_id 参数"))?;
            let limit = payload
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(200) as usize;
            match get_session_detail(&db, session_id, limit)? {
                Some(detail) => Ok(serde_json::to_value(detail)?),
                None => anyhow::bail!("未找到会话: {}", session_id),
            }
        }

        "create_session" => {
            let db = MemoryHubDb::open_for_core(core)?;
            let session_id = payload.get("session_id").and_then(|v| v.as_str());
            let title = payload.get("title").and_then(|v| v.as_str());
            let session = create_session(&db, session_id, title)?;
            Ok(json!({ "session": session }))
        }

        "delete_session" => {
            let db = MemoryHubDb::open_for_core(core)?;
            let session_id = payload
                .get("session_id")
                .or_else(|| payload.get("id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("delete_session 缺少 session_id 参数"))?;
            let deleted = delete_session(&db, session_id)?;
            Ok(json!({
                "session_id": session_id,
                "deleted": deleted,
            }))
        }

        "list_tools" => Ok(json!({ "tools": memory_tool_specs() })),

        "execute_tool" => {
            let name = payload
                .get("tool_name")
                .or_else(|| payload.get("name"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("execute_tool 缺少 tool_name"))?;
            let args = payload.get("arguments").cloned().unwrap_or_else(|| json!({}));
            execute_memory_tool(core, name, &args)
        }

        other => anyhow::bail!("未知的 memory_hub RPC 动作: {}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_test_core() -> (TempDir, std::sync::Arc<IntentOsCore>) {
        let tmp = TempDir::new().expect("temp dir");
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .to_path_buf();
        let core = IntentOsCore::initialize(Some(tmp.path()), repo_root).expect("init core");
        (tmp, core)
    }

    #[test]
    fn test_xbel_parsing_chinese_percent_encoded_paths_and_portal_filtering() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0"
      xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks"
      xmlns:mime="http://www.freedesktop.org/standards/shared-mime-info">
  <bookmark href="file:///home/alice/%E6%96%87%E6%A1%A3/%E5%AD%A3%E5%BA%A6%E5%91%A8%E6%8A%A5_2026Q2.pdf"
            added="2026-11-10T08:00:00Z"
            modified="2026-11-13T09:30:00Z"
            visited="2026-11-13T10:15:00Z">
    <info>
      <metadata owner="http://freedesktop.org">
        <mime:mime-type type="application/pdf"/>
        <bookmark:applications>
          <bookmark:application name="xdg-desktop-portal-gtk" exec="&apos;xdg-desktop-portal-gtk %u&apos;" modified="2026-11-10T08:00:00Z" count="2"/>
          <bookmark:application name="org.gnome.Evince" exec="&apos;evince %u&apos;" modified="2026-11-13T10:15:00Z" count="14"/>
          <bookmark:application name="com.google.Chrome" exec="&apos;google-chrome %u&apos;" modified="2026-11-12T12:00:00Z" count="3"/>
        </bookmark:applications>
      </metadata>
    </info>
  </bookmark>
  <bookmark href="file:///home/alice/%E4%B8%8B%E8%BD%BD/temp_installer.deb"
            added="2026-09-01T07:00:00Z"
            modified="2026-09-01T07:00:01Z"
            visited="2026-09-01T07:00:01Z">
    <info>
      <metadata owner="http://freedesktop.org">
        <mime:mime-type type="application/vnd.debian.binary-package"/>
        <bookmark:applications>
          <bookmark:application name="xdg-desktop-portal-gtk" exec="&apos;xdg-desktop-portal-gtk %u&apos;" count="1"/>
          <bookmark:application name="com.google.Chrome" exec="&apos;gio open %u&apos;" count="1"/>
        </bookmark:applications>
      </metadata>
    </info>
  </bookmark>
</xbel>"#;

        let parsed = parse_xbel_content(xml);
        assert_eq!(parsed.len(), 2);

        let top = &parsed[0];
        assert_eq!(top.path, "/home/alice/文档/季度周报_2026Q2.pdf");
        assert_eq!(top.total_open_count, 17); // 14 (Evince) + 3 (Chrome), portal excluded!
        assert_eq!(top.preferred_apps[0], "org.gnome.Evince");
        assert_eq!(top.preferred_apps[1], "com.google.Chrome");
        assert!(!top.preferred_apps.iter().any(|a| a.contains("portal")));

        let second = &parsed[1];
        assert_eq!(second.path, "/home/alice/下载/temp_installer.deb");
        assert_eq!(second.total_open_count, 1);

        let now_ep = chrono::DateTime::parse_from_rfc3339("2026-11-14T00:00:00Z")
            .unwrap()
            .timestamp();
        let sc_top = compute_frecency_score(top.total_open_count, top.last_used_epoch, now_ep, true);
        let sc_sec = compute_frecency_score(
            second.total_open_count,
            second.last_used_epoch,
            now_ep,
            true,
        );
        assert!(sc_top > sc_sec * 5.0);
    }

    #[test]
    fn test_mentioned_files_extraction_and_natural_reference_recall() {
        let (tmp, core) = make_test_core();
        let db = MemoryHubDb::open_for_core(&core).unwrap();
        let work_dir = tmp.path().join("docs");
        fs::create_dir_all(&work_dir).unwrap();
        let report_path = work_dir.join("2026研发周报.docx");
        let cfg_path = work_dir.join("gateway_config.toml");
        fs::write(&report_path, "weekly report").unwrap();
        fs::write(&cfg_path, "port = 8080").unwrap();

        // Turn 1: User mentions report document and 《产品蓝图》
        record_conversation_turn(
            &core,
            &RecordTurnInput {
                session_id: Some("ses_alpha".into()),
                user_text: format!(
                    "帮我查看一下 `{}` 和《产品蓝图》，顺便参考 https://rust-lang.org",
                    report_path.display()
                ),
                assistant_text: "好的，已为您定位到 2026研发周报.docx 与《产品蓝图》。".into(),
                tool_steps: vec![],
                trace_dots: vec![],
                thinking: None,
                incognito: false,
            },
        )
        .unwrap();

        // Turn 2: User edits gateway_config.toml via tool step
        record_conversation_turn(
            &core,
            &RecordTurnInput {
                session_id: Some("ses_alpha".into()),
                user_text: format!("把 `{}` 里的端口改一下，然后打开 VSCode", cfg_path.display()),
                assistant_text: "已修改 gateway_config.toml 配置。".into(),
                tool_steps: vec![json!({
                    "capability_id": "file.write",
                    "arguments": { "path": cfg_path.to_string_lossy() },
                    "message": "updated gateway_config.toml"
                })],
                trace_dots: vec![],
                thinking: None,
                incognito: false,
            },
        )
        .unwrap();

        // Natural Query 1: "刚才改的配置" -> MUST rank gateway_config.toml #1!
        let cfg_hits =
            recall_mentioned_entities(&db, "刚才改的配置", None, Some("ses_alpha"), 5).unwrap();
        assert!(!cfg_hits.is_empty());
        assert_eq!(cfg_hits[0].0.canonical_value, cfg_path.to_string_lossy());
        assert_eq!(cfg_hits[0].0.action_verb, "edit");

        // Natural Query 2: "上次提到的文档" -> MUST surface 2026研发周报.docx / 《产品蓝图》!
        let doc_hits =
            recall_mentioned_entities(&db, "上次提到的文档", None, Some("ses_alpha"), 5).unwrap();
        assert!(!doc_hits.is_empty());
        let top_doc_names: Vec<&str> = doc_hits
            .iter()
            .take(2)
            .map(|(e, _)| e.display_name.as_str())
            .collect();
        assert!(
            top_doc_names.contains(&"2026研发周报.docx")
                || top_doc_names.contains(&"《产品蓝图》")
        );

        // Natural Query 3: "我之前说的那个文件" -> surfaces mentioned file entities cleanly
        let generic_hits =
            recall_mentioned_entities(&db, "我之前说的那个文件", None, Some("ses_alpha"), 5)
                .unwrap();
        assert!(generic_hits.len() >= 2);
        assert!(matches!(
            generic_hits[0].0.entity_kind.as_str(),
            "file" | "document_ref"
        ));
    }

    #[test]
    fn test_software_inventory_desktop_scan_and_idempotent_xbel_merge() {
        let (tmp, core) = make_test_core();
        let db = MemoryHubDb::open_for_core(&core).unwrap();

        let apps_dir = tmp.path().join("mock_applications");
        fs::create_dir_all(&apps_dir).unwrap();

        fs::write(
            apps_dir.join("code.desktop"),
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Visual Studio Code\n\
             Name[zh_CN]=VS Code 代码编辑器\n\
             GenericName=Code Editor\n\
             Comment=Code Editing. Redefined.\n\
             Exec=/usr/share/code/code %F\n\
             Categories=Development;IDE;\n\
             MimeType=text/plain;x-scheme-handler/vscode;\n\
             DBusActivatable=false\n",
        )
        .unwrap();

        fs::write(
            apps_dir.join("obsidian.desktop"),
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Obsidian\n\
             GenericName=Knowledge Base\n\
             Exec=obsidian %u\n\
             Categories=Office;\n\
             MimeType=x-scheme-handler/obsidian;\n\
             DBusActivatable=true\n",
        )
        .unwrap();

        fs::write(
            apps_dir.join("hidden-helper.desktop"),
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Hidden Helper\n\
             Exec=helper\n\
             NoDisplay=true\n",
        )
        .unwrap();

        let freq_pdf = tmp.path().join("workspace_doc.pdf");
        fs::write(&freq_pdf, "pdf content").unwrap();
        let xbel_file = tmp.path().join("recently-used.xbel");
        let encoded_uri = format!("file://{}", freq_pdf.to_string_lossy());
        fs::write(
            &xbel_file,
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0" xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks" xmlns:mime="http://www.freedesktop.org/standards/shared-mime-info">
  <bookmark href="{}" visited="2026-11-14T02:00:00Z" modified="2026-11-14T02:00:00Z">
    <info><metadata owner="http://freedesktop.org">
      <mime:mime-type type="application/pdf"/>
      <bookmark:applications>
        <bookmark:application name="code" exec="&apos;code %u&apos;" count="12"/>
      </bookmark:applications>
    </metadata></info>
  </bookmark>
</xbel>"#,
                encoded_uri
            ),
        )
        .unwrap();

        // Sync #1
        let dirs = vec![apps_dir.clone()];
        let sum1 =
            sync_system_usage_with_options(&core, &db, Some(&xbel_file), Some(&dirs)).unwrap();
        assert_eq!(sum1.total_installed_apps, 2); // hidden-helper skipped!
        assert_eq!(sum1.synced_xbel_bookmarks, 1);

        // Sync #2 (idempotency check: counts MUST NOT double!)
        let _sum2 =
            sync_system_usage_with_options(&core, &db, Some(&xbel_file), Some(&dirs)).unwrap();

        let apps = query_software_catalog(&db, None, false, 10).unwrap();
        assert_eq!(apps.len(), 2);
        // VS Code has XBEL count=12 so it MUST rank #1 above Obsidian (count=0)
        assert_eq!(apps[0].app_id, "code.desktop");
        assert_eq!(apps[0].name, "VS Code 代码编辑器");
        assert_eq!(apps[0].launch_count, 12);
        assert_eq!(apps[0].uri_schemes, vec!["vscode".to_string()]);

        assert_eq!(apps[1].app_id, "obsidian.desktop");
        assert!(apps[1].dbus_activatable);
        assert_eq!(apps[1].uri_schemes, vec!["obsidian".to_string()]);

        // Record an IntentOS launch of obsidian and verify ranking updates
        assert!(record_app_launch(&db, "obsidian", 20).unwrap());
        let apps_after = query_software_catalog(&db, None, true, 10).unwrap();
        assert_eq!(apps_after[0].app_id, "obsidian.desktop");
        assert_eq!(apps_after[0].launch_count, 20);
    }

    #[test]
    fn test_incognito_zero_write_and_secret_scrubbing() {
        let (_tmp, core) = make_test_core();

        // 1. Incognito turn MUST NOT persist anything
        let incog_out = record_conversation_turn(
            &core,
            &RecordTurnInput {
                session_id: Some("ses_secret_private".into()),
                user_text: "请打开 /home/alice/private_tax_2026.pdf".into(),
                assistant_text: "已在隐私模式打开 /home/alice/private_tax_2026.pdf".into(),
                thinking: None,
                tool_steps: vec![],
                trace_dots: vec![],
                incognito: true,
            },
        )
        .unwrap();
        assert!(!incog_out.recorded);
        assert!(incog_out.incognito);

        let db = MemoryHubDb::open_for_core(&core).unwrap();
        assert!(list_sessions(&db, 10, None).unwrap().is_empty());
        assert!(list_recent_mentions(&db, false, None, 10).unwrap().is_empty());

        // 2. Non-incognito turn with API key scrubs secret before writing to SQLite
        record_conversation_turn(
            &core,
            &RecordTurnInput {
                session_id: Some("ses_normal".into()),
                user_text: "配置 /home/alice/app.toml，不要泄露 sk-abcdef1234567890SECRETKEY".into(),
                assistant_text: "已更新配置。".into(),
                thinking: None,
                tool_steps: vec![],
                trace_dots: vec![],
                incognito: false,
            },
        )
        .unwrap();

        let detail = get_session_detail(&db, "ses_normal", 20).unwrap().unwrap();
        assert_eq!(detail.messages.len(), 2);
        assert!(!detail.messages[0].content.contains("sk-abcdef1234567890SECRETKEY"));
        assert!(detail.messages[0].content.contains("[REDACTED_SECRET]"));

        // 3. Incognito session (`incog_*`) MUST also perform ZERO reads from MemoryHub
        let (incog_prompt, incog_hits) =
            build_personal_memory_prompt(&core, "刚才改的 app.toml 在哪里", Some("incog_isolated"));
        assert!(incog_prompt.is_empty());
        assert!(incog_hits.is_empty());
        assert!(
            try_answer_memory_query_deterministically(
                &core,
                "我之前说的文件有哪些",
                Some("incog_isolated")
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn test_rag_prompt_llm_tools_and_module_rpc_actions() {
        let (tmp, core) = make_test_core();
        let sample_file = tmp.path().join("architecture_v2.md");
        fs::write(&sample_file, "# Architecture").unwrap();

        // Record a turn via handle_module_rpc
        let rec = handle_module_rpc(
            &core,
            "record_conversation_turn",
            json!({
                "session_id": "ses_rag_1",
                "user_text": format!("帮我修改 `{}` 的架构章节", sample_file.display()),
                "assistant_text": "已为您更新 architecture_v2.md。",
                "incognito": false
            }),
        )
        .await
        .unwrap();
        assert_eq!(rec["recorded"], true);

        // Test build_personal_memory_prompt
        let (prompt, hits) =
            build_personal_memory_prompt(&core, "刚才改的文档是哪个？", Some("ses_rag_1"));
        assert!(prompt.contains("[Personal OS Memory: 历史提及文件 / 长期高频文件 / 本机常用与已装软件]"));
        assert!(prompt.contains("architecture_v2.md"));
        assert!(!hits.is_empty());

        let dot = build_memory_trace_dot(&hits).expect("purple trace dot");
        assert_eq!(dot["kind"], "memory");
        assert_eq!(dot["color"], "purple");

        // Test deterministic offline responder
        let (det_ans, det_hits) = try_answer_memory_query_deterministically(
            &core,
            "我之前说的文件有哪些？",
            Some("ses_rag_1"),
        )
        .expect("deterministic answer");
        assert!(det_ans.contains("architecture_v2.md"));
        assert!(!det_hits.is_empty());

        // Test LLM memory tools (both underscore and dot-separated names)
        let specs = memory_tool_specs();
        assert_eq!(specs.len(), 5);
        assert!(is_memory_tool("memory_recall_mentioned_files"));
        assert!(is_memory_tool("memory.get.software.catalog"));
        assert!(is_memory_tool("memory_inspect_document"));
        assert!(is_memory_tool("memory.inspect_document"));

        let recall_res = execute_memory_tool(
            &core,
            "memory_recall_mentioned_files",
            &json!({ "query": "刚才改的文档" }),
        )
        .unwrap();
        assert_eq!(recall_res["ok"], true);
        assert!(recall_res["count"].as_u64().unwrap() >= 1);

        let chat_res = execute_memory_tool(
            &core,
            "memory_search_past_chats",
            &json!({ "query": "架构章节" }),
        )
        .unwrap();
        assert_eq!(chat_res["ok"], true);
        assert!(chat_res["count"].as_u64().unwrap() >= 1);

        // Test remaining RPC actions: ping, get_memory_dashboard, query_personal_memory, session CRUD
        let ping = handle_module_rpc(&core, "ping", json!({})).await.unwrap();
        assert_eq!(ping["status"], "ok");

        let dash = handle_module_rpc(&core, "get_memory_dashboard", json!({}))
            .await
            .unwrap();
        assert!(!dash["mentioned_files"].as_array().unwrap().is_empty());
        assert!(dash["installed_apps_summary"]["total_installed"].as_u64().is_some());

        let qpm = handle_module_rpc(
            &core,
            "query_personal_memory",
            json!({ "query": "architecture_v2", "kind": "all" }),
        )
        .await
        .unwrap();
        assert!(qpm["context_markdown"].as_str().unwrap().contains("architecture_v2.md"));

        let created = handle_module_rpc(
            &core,
            "create_session",
            json!({ "title": "测试新建会话" }),
        )
        .await
        .unwrap();
        let new_sid = created["session"]["session_id"].as_str().unwrap().to_string();

        let listed = handle_module_rpc(&core, "list_sessions", json!({}))
            .await
            .unwrap();
        assert!(listed["sessions"].as_array().unwrap().len() >= 2);

        let fetched = handle_module_rpc(
            &core,
            "get_session",
            json!({ "session_id": "ses_rag_1" }),
        )
        .await
        .unwrap();
        assert_eq!(fetched["session"]["session_id"], "ses_rag_1");

        let deleted = handle_module_rpc(
            &core,
            "delete_session",
            json!({ "session_id": new_sid }),
        )
        .await
        .unwrap();
        assert_eq!(deleted["deleted"], true);
    }

    #[test]
    fn test_intent_gated_recall_zero_pollution_on_qq_and_sodam_and_system_controls() {
        let (tmp, core) = make_test_core();
        let db = MemoryHubDb::open_for_core(&core).unwrap();

        // Populate noisy installer artifacts (.deb, .pkg.tar.zst, .AppImage) AND .docx files
        let dl_dir = tmp.path().join("下载");
        let desk_dir = tmp.path().join("桌面");
        fs::create_dir_all(&dl_dir).unwrap();
        fs::create_dir_all(&desk_dir).unwrap();

        let deb_path = dl_dir.join("linuxqq_3.2.12_amd64.deb");
        let zst_path = dl_dir.join("wechat-uos-2.1.5-x86_64.pkg.tar.zst");
        let appimg_path = dl_dir.join("Cursor-0.45.AppImage");
        let docx_path = desk_dir.join("2026研发周报.docx");
        fs::write(&deb_path, "deb installer").unwrap();
        fs::write(&zst_path, "zst package").unwrap();
        fs::write(&appimg_path, "appimage binary").unwrap();
        fs::write(&docx_path, "weekly report content").unwrap();

        // Seed high-frecency long_term_files + entity_mentions so global tables are full of tempting noise
        record_file_usage(&db, &deb_path.to_string_lossy(), Some("gio"), 25).unwrap();
        record_file_usage(&db, &zst_path.to_string_lossy(), Some("ark"), 20).unwrap();
        record_file_usage(&db, &appimg_path.to_string_lossy(), Some("bash"), 15).unwrap();
        record_file_usage(&db, &docx_path.to_string_lossy(), Some("libreoffice"), 18).unwrap();

        record_conversation_turn(
            &core,
            &RecordTurnInput {
                session_id: Some("ses_noise".into()),
                user_text: format!(
                    "刚刚下载了 `{}` 和 `{}`，并修改了 `{}`",
                    deb_path.display(),
                    zst_path.display(),
                    docx_path.display()
                ),
                assistant_text: "已记录相关文件。".into(),
                thinking: None,
                tool_steps: vec![],
                trace_dots: vec![],
                incognito: false,
            },
        )
        .unwrap();

        // Seed desktop applications including QQ and personalized SodaM (`汽水音乐`)
        let apps_dir = tmp.path().join("mock_apps");
        fs::create_dir_all(&apps_dir).unwrap();
        fs::write(
            apps_dir.join("qq.desktop"),
            "[Desktop Entry]\nType=Application\nName=QQ\nExec=/opt/QQ/qq %U\nCategories=Network;InstantMessaging;\n",
        )
        .unwrap();
        fs::write(
            apps_dir.join("sodam.desktop"),
            "[Desktop Entry]\nType=Application\nName=汽水音乐\nGenericName=Music Player\nExec=/opt/SodaM/sodam %U\nCategories=AudioVideo;Music;Player;\nKeywords=music;qishui;soda;sodam;\n",
        )
        .unwrap();
        sync_system_usage_with_options(&core, &db, None, Some(&[apps_dir])).unwrap();

        // 1. "打开QQ" -> trivial app command: MUST return 0 hits and empty prompt (no purple trace dot!)
        let (qq_prompt, qq_hits) = build_personal_memory_prompt(&core, "打开QQ", Some("ses_noise"));
        assert!(
            qq_hits.is_empty(),
            "打开QQ must produce 0 memory hits, got: {:?}",
            qq_hits
        );
        assert!(qq_prompt.is_empty());
        assert!(build_memory_trace_dot(&qq_hits).is_none());

        // 2. "关闭SODAM音乐" -> MUST return 0 file hits (no .deb, .pkg.tar.zst, or .docx!);
        //    at most 1 compact software disambiguation line for `sodam.desktop` (`汽水音乐`)
        let (sodam_prompt, sodam_hits) =
            build_personal_memory_prompt(&core, "关闭SODAM音乐", Some("ses_noise"));
        assert!(
            sodam_hits.iter().all(|h| h["kind"] == "software"),
            "关闭SODAM音乐 must NEVER inject file hits, got: {:?}",
            sodam_hits
        );
        assert!(sodam_hits.len() <= 1);
        assert!(!sodam_prompt.contains(".deb"));
        assert!(!sodam_prompt.contains(".pkg.tar.zst"));
        assert!(!sodam_prompt.contains(".docx"));
        if !sodam_hits.is_empty() {
            assert_eq!(sodam_hits[0]["value"], "sodam.desktop");
            assert!(sodam_prompt.contains("汽水音乐"));
            assert!(sodam_prompt.chars().count() <= MAX_AUTO_MEMORY_CHARS);
        }

        // 3. Pure system & media controls -> MUST return 0 hits and empty prompt!
        for cmd in ["把音量调到50%", "开启护眼模式", "暂停音乐", "下一首"] {
            let (p, h) = build_personal_memory_prompt(&core, cmd, Some("ses_noise"));
            assert!(h.is_empty(), "'{}' should inject 0 hits, got {:?}", cmd, h);
            assert!(p.is_empty(), "'{}' should produce empty memory prompt", cmd);
        }

        // 4. Specific document lookup ("帮我看看研发周报") -> recalls ONLY 2026研发周报.docx, zero .deb/.zst!
        let (rep_prompt, rep_hits) =
            build_personal_memory_prompt(&core, "帮我看看研发周报", Some("ses_noise"));
        assert!(!rep_hits.is_empty());
        assert!(rep_prompt.contains("2026研发周报.docx"));
        assert!(!rep_prompt.contains(".deb"));
        assert!(!rep_prompt.contains(".pkg.tar.zst"));
        assert!(!rep_prompt.contains(".AppImage"));
        assert!(rep_prompt.chars().count() <= MAX_AUTO_MEMORY_CHARS);
    }

    #[tokio::test]
    async fn test_docx_thesis_outline_indexer_chinese_chapter_search_and_inspect_document_tool() {
        let (tmp, core) = make_test_core();
        let db = MemoryHubDb::open_for_core(&core).unwrap();

        let desktop_dir = tmp.path().join("桌面");
        fs::create_dir_all(&desktop_dir).unwrap();
        let thesis_path = desktop_dir.join("paper_main.docx");

        // Build synthetic `.docx` ZIP with `word/styles.xml` + `word/document.xml`
        // Notice the English filename `paper_main.docx` while internal title & chapters are Chinese!
        let styles_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/></w:style>
  <w:style w:type="paragraph" w:styleId="704"><w:name w:val="heading 1"/><w:pPr><w:outlineLvl w:val="0"/></w:pPr></w:style>
  <w:style w:type="paragraph" w:styleId="705"><w:name w:val="heading 2"/><w:pPr><w:outlineLvl w:val="1"/></w:pPr></w:style>
</w:styles>"#;

        let document_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>哈尔滨工业大学</w:t></w:r></w:p>
    <w:p><w:r><w:t>硕士学位论文</w:t></w:r></w:p>
    <w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr><w:r><w:t>基于轨道置信度区间的多脉冲交会优化研究</w:t></w:r></w:p>
    <w:p><w:r><w:t>作者：王明</w:t></w:r></w:p>
    <w:p><w:pPr><w:pStyle w:val="704"/></w:pPr><w:r><w:t>摘要</w:t></w:r></w:p>
    <w:p><w:r><w:t>本文围绕近地空间非合作目标交会任务中的不确定性传播与多脉冲燃料最优控制问题展开深入研究。</w:t></w:r></w:p>
    <w:p><w:pPr><w:pStyle w:val="704"/></w:pPr><w:r><w:t>第一章 绪论</w:t></w:r></w:p>
    <w:p><w:r><w:t>随着空间在轨服务技术的发展，高精度自主交会轨迹规划成为核心关键技术。</w:t></w:r></w:p>
    <w:p><w:pPr><w:pStyle w:val="704"/></w:pPr><w:r><w:t>第二章 相对运动动力学建模</w:t></w:r></w:p>
    <w:p><w:r><w:t>建立考虑J2摄动项的非线性相对运动方程与状态转移矩阵。</w:t></w:r></w:p>
    <w:p><w:pPr><w:pStyle w:val="704"/></w:pPr><w:r><w:t>第三章 候选机动区间提取</w:t></w:r></w:p>
    <w:p><w:r><w:t>利用协方差椭球投影筛选满足测角约束的脉冲窗口。</w:t></w:r></w:p>
    <w:p><w:pPr><w:pStyle w:val="704"/></w:pPr><w:r><w:t>第四章 实验设计与结果分析</w:t></w:r></w:p>
    <w:p><w:r><w:t>本章构建了三组典型地球同步轨道交会仿真算例，对比验证所提多脉冲序列规划算法的收敛速度与速度增量节省率。</w:t></w:r></w:p>
    <w:p><w:pPr><w:pStyle w:val="705"/></w:pPr><w:r><w:t>4.1 仿真参数配置与基准算例</w:t></w:r></w:p>
    <w:p><w:r><w:t>蒙特卡洛打靶法共运行 1000 次，燃料消耗平均降低 14.8%，计算耗时小于 38 毫秒。</w:t></w:r></w:p>
    <w:p><w:pPr><w:pStyle w:val="704"/></w:pPr><w:r><w:t>第五章 总结与展望</w:t></w:r></w:p>
    <w:p><w:r><w:t>总结全文研究成果并展望未来在轨实时自主规划应用前景。</w:t></w:r></w:p>
  </w:body>
</w:document>"#;

        let docx_bytes = build_stored_zip_archive(&[
            ("word/styles.xml", styles_xml.as_bytes()),
            ("word/document.xml", document_xml.as_bytes()),
        ]);
        fs::write(&thesis_path, &docx_bytes).unwrap();

        // Verify pure-Rust Stored-ZIP fallback scanner works without external tools
        let fallback_xml =
            extract_stored_zip_entry(&docx_bytes, "word/document.xml", 512 * 1024).unwrap();
        assert!(String::from_utf8_lossy(&fallback_xml).contains("第四章 实验设计与结果分析"));

        // Index via `index_document_file` and verify cover title + chapters + sections
        let rec = index_document_file(&core, &db, &thesis_path)
            .unwrap()
            .expect("indexed paper_main.docx");
        assert!(
            rec.doc_title.contains("硕士学位论文")
                && rec.doc_title.contains("基于轨道置信度区间的多脉冲交会优化研究"),
            "unexpected doc_title: {}",
            rec.doc_title
        );
        assert!(
            rec.headings
                .iter()
                .any(|h| h == "第四章 实验设计与结果分析"),
            "headings missing 第四章: {:?}",
            rec.headings
        );

        // Verify Chinese <-> Arabic numeral normalization (`第四章` and `第4章` both score > 90!)
        for q in ["打开我的硕士论文第四章", "打开我的硕士论文第4章"] {
            let hits = search_document_outlines(&db, q, None, 5).unwrap();
            assert!(!hits.is_empty(), "expected outline hit for {}", q);
            assert_eq!(hits[0].record.path, thesis_path.to_string_lossy());
            assert!(
                hits[0].score > 90.0,
                "expected score > 90.0 on '{}', got {}",
                q,
                hits[0].score
            );
            let matched = hits[0]
                .matched_section
                .as_ref()
                .expect("matched Chapter 4 section");
            assert_eq!(matched.heading, "第四章 实验设计与结果分析");
            assert!(matched.excerpt.contains("三组典型地球同步轨道交会仿真算例"));
        }

        // Verify `build_personal_memory_prompt` injects Layer-0 Semantic Index Card within <= 950 chars!
        let (rag_prompt, rag_hits) =
            build_personal_memory_prompt(&core, "打开我的硕士论文第四章", Some("ses_thesis"));
        assert!(!rag_hits.is_empty());
        assert!(rag_prompt.contains("paper_main.docx"));
        assert!(rag_prompt.contains("硕士学位论文"));
        assert!(rag_prompt.contains("第四章 实验设计与结果分析"));
        assert!(
            rag_prompt.chars().count() <= MAX_AUTO_MEMORY_CHARS,
            "prompt exceeded MAX_AUTO_MEMORY_CHARS ({}): {} chars",
            MAX_AUTO_MEMORY_CHARS,
            rag_prompt.chars().count()
        );

        // Verify 5th LLM tool `memory_inspect_document` (underscore, dot, and ModuleRpc `"inspect_document"`)
        let tool_out = execute_memory_tool(
            &core,
            "memory_inspect_document",
            &json!({
                "query": "硕士论文",
                "section": "第四章"
            }),
        )
        .unwrap();
        let serialized_len = serde_json::to_string(&tool_out).unwrap().chars().count();
        assert!(
            serialized_len <= MAX_INSPECT_DOC_CHARS,
            "memory_inspect_document exceeded 2200 chars: {}",
            serialized_len
        );
        assert_eq!(tool_out["found"], true);
        assert_eq!(tool_out["count"], 1);
        assert_eq!(tool_out["path"], thesis_path.to_string_lossy().as_ref());
        assert_eq!(
            tool_out["matched_section"]["heading"],
            "第四章 实验设计与结果分析"
        );
        assert!(
            tool_out["matched_section"]["excerpt"]
                .as_str()
                .unwrap()
                .contains("三组典型地球同步轨道交会仿真算例")
        );

        let dot_tool_out = execute_memory_tool(
            &core,
            "memory.inspect_document",
            &json!({ "query": "paper_main.docx", "section": "第4章" }),
        )
        .unwrap();
        assert_eq!(dot_tool_out["found"], true);
        assert_eq!(
            dot_tool_out["matched_section"]["heading"],
            "第四章 实验设计与结果分析"
        );

        let rpc_out = handle_module_rpc(
            &core,
            "inspect_document",
            json!({ "query": "打开我的硕士论文第四章" }),
        )
        .await
        .unwrap();
        assert_eq!(rpc_out["found"], true);
        assert_eq!(
            rpc_out["matched_section"]["heading"],
            "第四章 实验设计与结果分析"
        );

        // Verify `get_memory_dashboard` exposes `document_outlines_preview`
        let dash = handle_module_rpc(&core, "get_memory_dashboard", json!({ "auto_sync": false }))
            .await
            .unwrap();
        let previews = dash["document_outlines_preview"].as_array().unwrap();
        assert!(
            previews
                .iter()
                .any(|p| p["path"] == thesis_path.to_string_lossy().as_ref()
                    && p["heading_count"].as_u64().unwrap_or(0) >= 5)
        );
    }

    #[test]
    fn test_explicit_overview_isolation_and_markup_and_real_docx_outline() {
        let (tmp, core) = make_test_core();
        let db = MemoryHubDb::open_for_core(&core).unwrap();

        let doc_dir = tmp.path().join("文档");
        fs::create_dir_all(&doc_dir).unwrap();
        let md_path = doc_dir.join("毕业设计开题报告.md");
        fs::write(
            &md_path,
            "# 面向桌面智能体的渐进式记忆系统设计\n\n本项目研究本地低延迟语义记忆架构。\n\n## 第一章 研究背景\n介绍桌面操作系统中的上下文污染问题。\n\n## 第四章 原型系统实现\n基于 Rust 与 SQLite WAL 构建三层渐进式文档大纲索引。\n",
        )
        .unwrap();

        record_file_usage(&db, &md_path.to_string_lossy(), Some("code"), 9).unwrap();
        record_conversation_turn(
            &core,
            &RecordTurnInput {
                session_id: Some("ses_ov".into()),
                user_text: format!("查看 `{}`", md_path.display()),
                assistant_text: "已查看毕业设计开题报告.md".into(),
                thinking: None,
                tool_steps: vec![],
                trace_dots: vec![],
                incognito: false,
            },
        )
        .unwrap();

        let apps_dir = tmp.path().join("apps_ov");
        fs::create_dir_all(&apps_dir).unwrap();
        fs::write(
            apps_dir.join("firefox.desktop"),
            "[Desktop Entry]\nType=Application\nName=Firefox 浏览器\nExec=firefox %u\nCategories=Network;WebBrowser;\n",
        )
        .unwrap();
        sync_system_usage_with_options(&core, &db, None, Some(&[apps_dir])).unwrap();

        // Category isolation: asking for software MUST NOT dump mentioned/frequent files
        let (sw_md, sw_hits) =
            build_personal_memory_prompt(&core, "电脑上装了什么软件", Some("ses_ov"));
        assert!(sw_md.contains("Firefox 浏览器"));
        assert!(!sw_md.contains("毕业设计开题报告.md"));
        assert!(sw_hits.iter().all(|h| h["kind"] == "software"));
        assert!(sw_md.chars().count() <= 900);

        // Category isolation: asking for long-term frequent files MUST NOT dump software catalog
        let (ff_md, ff_hits) =
            build_personal_memory_prompt(&core, "我长期使用的文件有哪些", Some("ses_ov"));
        assert!(ff_md.contains("毕业设计开题报告.md"));
        assert!(!ff_md.contains("Firefox 浏览器"));
        assert!(ff_hits.iter().all(|h| h["kind"] == "frequent_file"));
        assert!(ff_md.chars().count() <= 900);

        // Verify synthetic `.docx` thesis indexing & Chapter 4 lookup!
        let synth_docx_path = tmp.path().join("thesis_main.docx");
        let doc_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr><w:r><w:t>硕士学位论文：智能操作系统架构研究</w:t></w:r></w:p>
    <w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>第一章 绪论</w:t></w:r></w:p>
    <w:p><w:r><w:t>研究背景与意义。</w:t></w:r></w:p>
    <w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>第四章 系统实现与实验分析</w:t></w:r></w:p>
    <w:p><w:r><w:t>本章详细阐述硕士论文第四章核心架构实验。</w:t></w:r></w:p>
  </w:body>
</w:document>"#
            .as_bytes();
        let zip_bytes = build_stored_zip_archive(&[("word/document.xml", doc_xml)]);
        std::fs::write(&synth_docx_path, zip_bytes).unwrap();
        let real_rec = index_document_file(&core, &db, &synth_docx_path)
            .unwrap()
            .expect("index synthetic thesis_main.docx");
        assert!(!real_rec.headings.is_empty());
        let hits = search_document_outlines(&db, "打开我的硕士论文第四章", None, 3).unwrap();
        assert!(!hits.is_empty());
        assert!(hits[0].matched_section.is_some());
    }

    #[tokio::test]
    async fn test_context_compression_rpcs_30_turns_preview_and_echo_cleanup() {
        let (_tmp, core) = make_test_core();

        // 1. Default config via RPC and dashboard
        let def_cfg = handle_module_rpc(&core, "get_context_compression_config", json!({}))
            .await
            .unwrap();
        assert_eq!(def_cfg["enabled"], true);
        assert_eq!(def_cfg["drop_tool_records"], true);
        assert_eq!(def_cfg["max_context_tokens"], 6000);
        assert_eq!(def_cfg["verbatim_recent_turns"], 3);

        let dash = handle_module_rpc(&core, "get_memory_dashboard", json!({"auto_sync": false}))
            .await
            .unwrap();
        assert_eq!(dash["context_compression_config"]["enabled"], true);

        // 2. Update config with clamping validation
        let updated = handle_module_rpc(
            &core,
            "set_context_compression_config",
            json!({
                "enabled": true,
                "drop_tool_records": true,
                "max_context_tokens": 1800,
                "verbatim_recent_turns": 2,
                "decay_lambda": 0.28,
                "decay_gamma": 1.4,
            }),
        )
        .await
        .unwrap();
        assert_eq!(updated["max_context_tokens"], 1800);
        assert_eq!(updated["verbatim_recent_turns"], 2);

        // 3. Record 30 turns with `<think>` blocks and tool steps
        let sid = "ses_decay_30";
        for i in 0..30 {
            record_conversation_turn(
                &core,
                &RecordTurnInput {
                    session_id: Some(sid.into()),
                    user_text: format!(
                        "第 {} 轮提问：请分析 `/home/alice/project/mod_{}.rs` 的异步调度瓶颈与配置参数？",
                        i + 1,
                        i + 1
                    ),
                    assistant_text: format!(
                        "<think>内部推理第 {} 轮，不应进入后续上下文</think># 模块 {} 分析结论\n- 关键文件：`/home/alice/project/mod_{}.rs`\n```rust\npub fn heavy_loop_{}() {{ for _ in 0..1000 {{ println!(\"tick\"); }} }}\n```\n最终建议：将队列容量调整为 {} 并启用批处理。",
                        i + 1,
                        i + 1,
                        i + 1,
                        i + 1,
                        (i + 1) * 64
                    ),
                    thinking: Some("hidden chain of thought".into()),
                    tool_steps: vec![json!({
                        "tool": "file.read",
                        "arguments": {"path": format!("/home/alice/project/mod_{}.rs", i + 1)},
                        "result": {"lines": 420}
                    })],
                    trace_dots: vec![json!({"kind": "tool_ok", "color": "green"})],
                    incognito: false,
                },
            )
            .unwrap();
        }

        // 4. Preview compression via ModuleRpc
        let preview = handle_module_rpc(
            &core,
            "preview_session_compression",
            json!({ "session_id": sid }),
        )
        .await
        .unwrap();
        let stats = &preview["stats"];
        assert_eq!(stats["raw_qa_turns"], 30);
        assert_eq!(stats["verbatim_turns"], 2);
        assert!(stats["dropped_tool_records"].as_u64().unwrap() >= 30);
        assert!(stats["rolled_up_ancient_turns"].as_u64().unwrap() > 0);
        assert!(stats["compressed_estimated_tokens"].as_u64().unwrap() <= 1800);
        assert!(stats["saved_pct"].as_f64().unwrap() > 25.0);
        let anchor = preview["ancient_summary_anchor"].as_str().unwrap_or("");
        assert!(anchor.contains("早期会话非线性时间衰减摘要"));

        // 5. Verify `remove_synthetic_approval_echo` cleans only trailing `"确认执行：..."` pair
        record_conversation_turn(
            &core,
            &RecordTurnInput {
                session_id: Some(sid.into()),
                user_text: "确认执行：检索 /home 目录".into(),
                assistant_text: "在授权目录中检索到 1 个文件".into(),
                thinking: None,
                tool_steps: vec![],
                trace_dots: vec![],
                incognito: false,
            },
        )
        .unwrap();
        let removed = remove_synthetic_approval_echo(&core, sid);
        assert_eq!(removed, 2);
        let db = MemoryHubDb::open_for_core(&core).unwrap();
        let detail = get_session_detail(&db, sid, 200).unwrap().unwrap();
        assert_eq!(detail.messages.len(), 60);
        assert!(!detail.messages.iter().any(|m| m.content.starts_with("确认执行：")));
    }
}
