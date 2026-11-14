#![forbid(unsafe_code)]

//! 3-Layer Progressive Document Outline & Chapter Indexer (`document_outline.rs`).
//!
//! - **Layer 0 (Semantic Index Card)**: Compact card (~60 tokens/doc) with `path`, `doc_title`,
//!   1-line `doc_summary`, and condensed TOC preview (`[章节: 第一章 ... | 第四章 ...]`) for RAG.
//! - **Layer 1 (`document_outlines` SQLite table)**: Cached by `(mtime_epoch, size_bytes)` so
//!   already-indexed files cost 0ms on subsequent queries.
//! - **Layer 2 (`memory_inspect_document`)**: On-demand chapter/section excerpt reader strictly
//!   bounded within LLM context budget (`<= 2200 chars`).

use crate::core::IntentOsCore;
use crate::memory_hub::long_term_habits::unescape_xml_entities;
use crate::memory_hub::schema_and_db::{
    DocSection, DocumentOutlineHit, DocumentOutlinePreview, DocumentOutlineRecord, MemoryHubDb,
    is_hermetic_test_core, is_sensitive_credential_path, scrub_sensitive_text,
};
use crate::resource::to_pinyin_pair;
use chrono::Utc;
use regex::Regex;
use rusqlite::{OptionalExtension, params};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::UNIX_EPOCH;
use walkdir::WalkDir;

pub const MAX_DOC_FILE_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB
const MAX_UNZIP_XML_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB
const MAX_TEXT_READ_BYTES: u64 = 256 * 1024; // 256 KiB
const MAX_LAZY_DOCS_PER_PASS: usize = 120;
const MAX_SECTION_EXCERPT_CHARS: usize = 900;

const SUPPORTED_DOC_EXTENSIONS: &[&str] = &[
    "docx", "md", "markdown", "txt", "tex", "typ", "pdf",
];

const SKIP_DIR_NAMES: &[&str] = &[
    "node_modules",
    "target",
    "__pycache__",
    "venv",
    ".venv",
    "miniconda3",
    "anaconda3",
    "build",
    "dist",
    "vendor",
    "cache",
    "undo",
    "trash",
];

/// Ensure user documents across XDG Desktop/Documents/Downloads, `authorized_roots`,
/// `long_term_files`, and `entity_mentions` are lazily indexed into `document_outlines`.
pub fn ensure_document_outlines_synced(core: &IntentOsCore, db: &MemoryHubDb) {
    let _ = sync_document_outlines_with_extra_paths(core, db, &[]);
}

/// Synchronize `document_outlines` and return the number of newly parsed/updated documents.
pub fn sync_document_outlines(core: &IntentOsCore, db: &MemoryHubDb) -> anyhow::Result<usize> {
    sync_document_outlines_with_extra_paths(core, db, &[])
}

/// Synchronize `document_outlines` including explicit extra file paths (e.g. newly synced XBEL bookmarks).
pub fn sync_document_outlines_with_extra_paths(
    core: &IntentOsCore,
    db: &MemoryHubDb,
    extra_paths: &[PathBuf],
) -> anyhow::Result<usize> {
    let existing_meta = load_indexed_mtime_size_map(db);
    let candidates = collect_candidate_documents(core, db, extra_paths);

    let mut to_parse: Vec<(PathBuf, i64, u64)> = Vec::new();
    for (path, mtime_epoch, size_bytes) in candidates {
        let key = path.to_string_lossy().to_string();
        if let Some(&(prev_mtime, prev_size)) = existing_meta.get(&key)
            && prev_mtime == mtime_epoch
            && prev_size == size_bytes
        {
            continue;
        }
        to_parse.push((path, mtime_epoch, size_bytes));
    }

    if to_parse.is_empty() {
        return Ok(0);
    }

    // Prioritize most recently modified documents so newly created/edited files index first
    to_parse.sort_by_key(|b| std::cmp::Reverse(b.1));
    to_parse.truncate(MAX_LAZY_DOCS_PER_PASS);

    let now_epoch = Utc::now().timestamp();
    let mut parsed_records: Vec<DocumentOutlineRecord> = Vec::with_capacity(to_parse.len());
    for (path, mtime_epoch, size_bytes) in to_parse {
        if let Some(rec) = extract_document_outline(&path, mtime_epoch, size_bytes, now_epoch) {
            parsed_records.push(rec);
        }
    }

    if parsed_records.is_empty() {
        return Ok(0);
    }

    upsert_document_outlines(db, &parsed_records)?;
    Ok(parsed_records.len())
}

/// Index a single document file immediately if supported and changed (or return cached record).
pub fn index_document_file(
    core: &IntentOsCore,
    db: &MemoryHubDb,
    path: &Path,
) -> anyhow::Result<Option<DocumentOutlineRecord>> {
    let path_str = path.to_string_lossy().to_string();
    if core.fs_engine.is_forbidden(path) || is_sensitive_credential_path(&path_str) {
        return Ok(None);
    }
    if !is_supported_document_path(path) {
        return Ok(None);
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return get_document_outline_by_path(db, &path_str);
    };
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_DOC_FILE_BYTES {
        return Ok(None);
    }
    let mtime_epoch = file_mtime_epoch(&meta);
    let size_bytes = meta.len();

    if let Some(existing) = get_document_outline_by_path(db, &path_str)?
        && existing.mtime_epoch == mtime_epoch
        && existing.size_bytes == size_bytes
    {
        return Ok(Some(existing));
    }

    let now_epoch = Utc::now().timestamp();
    if let Some(rec) = extract_document_outline(path, mtime_epoch, size_bytes, now_epoch) {
        upsert_document_outlines(db, std::slice::from_ref(&rec))?;
        return Ok(Some(rec));
    }
    Ok(None)
}

/// Fetch a single `DocumentOutlineRecord` by exact path from `document_outlines`.
pub fn get_document_outline_by_path(
    db: &MemoryHubDb,
    path: &str,
) -> anyhow::Result<Option<DocumentOutlineRecord>> {
    let conn = db.conn.lock().unwrap();
    let rec = conn
        .query_row(
            "SELECT path, mtime_epoch, size_bytes, doc_title, doc_summary,
                    headings_json, sections_json, keywords, indexed_epoch
             FROM document_outlines WHERE path = ?1",
            params![path],
            row_to_outline_record,
        )
        .optional()?;
    Ok(rec)
}

/// Return top `limit` indexed document previews for `get_memory_dashboard`.
pub fn list_document_outlines_preview(
    db: &MemoryHubDb,
    limit: usize,
) -> anyhow::Result<Vec<DocumentOutlinePreview>> {
    let cap = limit.clamp(1, 50) as i64;
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT path, mtime_epoch, doc_title, doc_summary, headings_json
         FROM document_outlines
         ORDER BY mtime_epoch DESC, indexed_epoch DESC
         LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![cap], |r| {
        let path: String = r.get(0)?;
        let mtime_epoch: i64 = r.get(1)?;
        let doc_title: String = r.get(2)?;
        let doc_summary: String = r.get(3)?;
        let h_json: String = r.get(4)?;
        let headings: Vec<String> = serde_json::from_str(&h_json).unwrap_or_default();
        let file_name = Path::new(&path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&path)
            .to_string();
        let heading_count = headings.len();
        let sample_headings = headings.into_iter().take(6).collect();
        Ok(DocumentOutlinePreview {
            path,
            file_name,
            doc_title,
            doc_summary,
            heading_count,
            sample_headings,
            mtime_epoch,
        })
    })?;

    let mut out = Vec::new();
    for item in rows {
        out.push(item?);
    }
    Ok(out)
}

fn row_to_outline_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<DocumentOutlineRecord> {
    let h_json: String = row.get(5)?;
    let s_json: String = row.get(6)?;
    Ok(DocumentOutlineRecord {
        path: row.get(0)?,
        mtime_epoch: row.get(1)?,
        size_bytes: row.get::<_, i64>(2)?.max(0) as u64,
        doc_title: row.get(3)?,
        doc_summary: row.get(4)?,
        headings: serde_json::from_str(&h_json).unwrap_or_default(),
        sections: serde_json::from_str(&s_json).unwrap_or_default(),
        keywords: row.get(7)?,
        indexed_epoch: row.get(8)?,
    })
}

fn load_indexed_mtime_size_map(db: &MemoryHubDb) -> HashMap<String, (i64, u64)> {
    let mut map = HashMap::new();
    let Ok(conn) = db.conn.lock() else {
        return map;
    };
    if let Ok(mut stmt) =
        conn.prepare("SELECT path, mtime_epoch, size_bytes FROM document_outlines")
        && let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?.max(0) as u64,
            ))
        })
    {
        for (p, mt, sz) in rows.flatten() {
            map.insert(p, (mt, sz));
        }
    }
    map
}

fn upsert_document_outlines(
    db: &MemoryHubDb,
    records: &[DocumentOutlineRecord],
) -> anyhow::Result<()> {
    let mut conn = db.conn.lock().unwrap();
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO document_outlines (
                path, mtime_epoch, size_bytes, doc_title, doc_summary,
                headings_json, sections_json, keywords, indexed_epoch
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(path) DO UPDATE SET
                mtime_epoch = excluded.mtime_epoch,
                size_bytes = excluded.size_bytes,
                doc_title = excluded.doc_title,
                doc_summary = excluded.doc_summary,
                headings_json = excluded.headings_json,
                sections_json = excluded.sections_json,
                keywords = excluded.keywords,
                indexed_epoch = excluded.indexed_epoch",
        )?;
        for rec in records {
            stmt.execute(params![
                rec.path,
                rec.mtime_epoch,
                rec.size_bytes as i64,
                rec.doc_title,
                rec.doc_summary,
                serde_json::to_string(&rec.headings)?,
                serde_json::to_string(&rec.sections)?,
                rec.keywords,
                rec.indexed_epoch,
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Discover candidate document files across XDG dirs, `authorized_roots`, and DB references.
fn collect_candidate_documents(
    core: &IntentOsCore,
    db: &MemoryHubDb,
    extra_paths: &[PathBuf],
) -> Vec<(PathBuf, i64, u64)> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut seen_roots: HashSet<PathBuf> = HashSet::new();

    let mut push_root = |p: PathBuf| {
        if p.exists() && p.is_dir() && !core.fs_engine.is_forbidden(&p) && seen_roots.insert(p.clone()) {
            roots.push(p);
        }
    };

    for auth in core.fs_engine.authorized_roots() {
        push_root(auth.clone());
    }

    if is_hermetic_test_core(core) {
        if let Some(base) = core.paths.data_dir.parent() {
            for sub in [
                "桌面",
                "文档",
                "下载",
                "Desktop",
                "Documents",
                "Downloads",
                "docs",
            ] {
                push_root(base.join(sub));
            }
        }
    } else if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(&home);
        for xdg_dir in discover_xdg_document_dirs(&home_path) {
            push_root(xdg_dir);
        }
        for sub in ["桌面", "文档", "下载", "Desktop", "Documents", "Downloads"] {
            push_root(home_path.join(sub));
        }
    }

    let mut seen_files: HashSet<PathBuf> = HashSet::new();
    let mut out: Vec<(PathBuf, i64, u64)> = Vec::new();

    let mut consider_file = |p: PathBuf| {
        if !is_supported_document_path(&p) {
            return;
        }
        let p_str = p.to_string_lossy();
        if core.fs_engine.is_forbidden(&p) || is_sensitive_credential_path(&p_str) {
            return;
        }
        if !seen_files.insert(p.clone()) {
            return;
        }
        if let Ok(meta) = std::fs::metadata(&p)
            && meta.is_file()
            && meta.len() > 0
            && meta.len() <= MAX_DOC_FILE_BYTES
        {
            out.push((p, file_mtime_epoch(&meta), meta.len()));
        }
    };

    // 1. Explicit extra paths + paths recorded in `long_term_files` & `entity_mentions`
    for ep in extra_paths {
        consider_file(ep.clone());
    }
    if let Ok(conn) = db.conn.lock() {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT path FROM long_term_files ORDER BY frecency_score DESC LIMIT 200",
        ) && let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0))
        {
            for p in rows.flatten() {
                consider_file(PathBuf::from(p));
            }
        }
        if let Ok(mut stmt) = conn.prepare(
            "SELECT canonical_value FROM entity_mentions
             WHERE entity_kind = 'file' ORDER BY last_seen_epoch DESC LIMIT 200",
        ) && let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0))
        {
            for p in rows.flatten() {
                if p.starts_with('/') {
                    consider_file(PathBuf::from(p));
                }
            }
        }
    }

    // 2. Shallow walk (depth <= 3) of candidate user document directories
    for root in roots {
        let walker = WalkDir::new(&root)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                if entry.depth() == 0 {
                    return true;
                }
                let name = entry.file_name().to_string_lossy();
                if name.starts_with('.') || name.starts_with("~$") {
                    return false;
                }
                if entry.file_type().is_dir() {
                    let nl = name.to_ascii_lowercase();
                    if SKIP_DIR_NAMES.contains(&nl.as_str()) {
                        return false;
                    }
                }
                true
            });

        for entry in walker.flatten() {
            if entry.file_type().is_file() {
                consider_file(entry.into_path());
            }
        }
    }

    out
}

/// Parse `~/.config/user-dirs.dirs` to locate localized XDG Desktop/Documents/Downloads directories.
pub fn discover_xdg_document_dirs(home: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let cfg_path = home.join(".config/user-dirs.dirs");
    let Ok(raw) = std::fs::read_to_string(cfg_path) else {
        return dirs;
    };
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, val_raw)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !matches!(
            key,
            "XDG_DESKTOP_DIR" | "XDG_DOCUMENTS_DIR" | "XDG_DOWNLOAD_DIR"
        ) {
            continue;
        }
        let val = val_raw.trim().trim_matches('"').trim_matches('\'');
        let resolved = if let Some(rest) = val.strip_prefix("$HOME/") {
            home.join(rest)
        } else if val == "$HOME" {
            home.to_path_buf()
        } else if val.starts_with('/') {
            PathBuf::from(val)
        } else {
            continue;
        };
        if !dirs.contains(&resolved) {
            dirs.push(resolved);
        }
    }
    dirs
}

pub fn is_supported_document_path(path: &Path) -> bool {
    let Some(fname) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if fname.starts_with('.') || fname.starts_with("~$") || fname.ends_with('~') {
        return false;
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    SUPPORTED_DOC_EXTENSIONS.contains(&ext.as_str())
}

fn file_mtime_epoch(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Dispatch document outline extraction by file extension.
pub fn extract_document_outline(
    path: &Path,
    mtime_epoch: i64,
    size_bytes: u64,
    indexed_epoch: i64,
) -> Option<DocumentOutlineRecord> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        "docx" => extract_docx_outline(path, mtime_epoch, size_bytes, indexed_epoch),
        "md" | "markdown" | "txt" | "tex" | "typ" => {
            extract_text_or_markup_outline(path, &ext, mtime_epoch, size_bytes, indexed_epoch)
        }
        "pdf" => extract_pdf_outline(path, mtime_epoch, size_bytes, indexed_epoch),
        _ => None,
    }
}

// =============================================================================
// `.docx` Extractor (`unzip -p` primary + pure-Rust Stored-ZIP fallback)
// =============================================================================

#[derive(Debug, Clone)]
struct RawParagraph {
    index: usize,
    style_id: String,
    style_name: String,
    outline_lvl: Option<u8>,
    text: String,
}

fn extract_docx_outline(
    path: &Path,
    mtime_epoch: i64,
    size_bytes: u64,
    indexed_epoch: i64,
) -> Option<DocumentOutlineRecord> {
    let doc_xml_bytes = read_docx_entry_bytes(path, "word/document.xml", MAX_UNZIP_XML_BYTES)?;
    let doc_xml = String::from_utf8_lossy(&doc_xml_bytes);
    let styles_xml = read_docx_entry_bytes(path, "word/styles.xml", 1024 * 1024)
        .map(|b| String::from_utf8_lossy(&b).into_owned());

    extract_docx_outline_from_xml(
        path,
        &doc_xml,
        styles_xml.as_deref(),
        mtime_epoch,
        size_bytes,
        indexed_epoch,
    )
}

/// Parse `.docx` `word/document.xml` (and optional `word/styles.xml`) into a `DocumentOutlineRecord`.
pub fn extract_docx_outline_from_xml(
    path: &Path,
    doc_xml: &str,
    styles_xml: Option<&str>,
    mtime_epoch: i64,
    size_bytes: u64,
    indexed_epoch: i64,
) -> Option<DocumentOutlineRecord> {
    let style_map = styles_xml.map(parse_docx_styles_xml).unwrap_or_default();
    let paragraphs = parse_docx_paragraphs(doc_xml, &style_map);
    if paragraphs.is_empty() {
        return None;
    }

    let fallback_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("文档")
        .to_string();

    let doc_title = scrub_sensitive_text(&infer_docx_title(&paragraphs, &fallback_stem));

    // Pass 1: collect non-TOC headings; Pass 2: allow TOC headings only if zero body headings exist
    let mut sections = build_sections_from_paragraphs(&paragraphs, &doc_title, false);
    if sections.is_empty() {
        sections = build_sections_from_paragraphs(&paragraphs, &doc_title, true);
    }

    let doc_summary = scrub_sensitive_text(&infer_doc_summary(&paragraphs, &doc_title));
    let headings: Vec<String> = sections.iter().map(|s| s.heading.clone()).collect();
    let keywords = build_document_keywords(path, &doc_title, &doc_summary, &headings, &paragraphs);

    Some(DocumentOutlineRecord {
        path: path.to_string_lossy().to_string(),
        mtime_epoch,
        size_bytes,
        doc_title,
        doc_summary,
        headings,
        sections,
        keywords,
        indexed_epoch,
    })
}

fn read_docx_entry_bytes(path: &Path, entry_name: &str, max_bytes: u64) -> Option<Vec<u8>> {
    // 1. Primary: `/usr/bin/unzip -p <path> <entry_name>` (non-shell, capped stdout)
    if Path::new("/usr/bin/unzip").is_file()
        && let Ok(mut child) = Command::new("/usr/bin/unzip")
            .arg("-p")
            .arg(path.as_os_str())
            .arg(entry_name)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
    {
        let mut buf = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            let _ = stdout.take(max_bytes).read_to_end(&mut buf);
        }
        let status = child.wait().ok();
        if status.is_some_and(|s| s.success()) && !buf.is_empty() {
            return Some(buf);
        }
    }

    // 2. Fallback: pure-Rust Stored-ZIP entry scanner (works without `unzip` installed)
    let file = File::open(path).ok()?;
    let mut zip_bytes = Vec::new();
    file.take(MAX_DOC_FILE_BYTES).read_to_end(&mut zip_bytes).ok()?;
    extract_stored_zip_entry(&zip_bytes, entry_name, max_bytes as usize)
}

/// Pure-Rust Stored-ZIP (`compression_method == 0`) entry extractor supporting both Central
/// Directory (`PK\x05\x06` / `PK\x01\x02`) and direct Local File Header (`PK\x03\x04`) scanning.
pub fn extract_stored_zip_entry(
    zip_bytes: &[u8],
    target_entry: &str,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    // Pass A: Locate End of Central Directory (`PK\x05\x06`) from tail of archive
    let search_start = zip_bytes.len().saturating_sub(65_558);
    if zip_bytes.len() >= 22 {
        for pos in (search_start..=zip_bytes.len() - 22).rev() {
            if &zip_bytes[pos..pos + 4] == b"PK\x05\x06" {
                let cd_size = read_u32_le(zip_bytes, pos + 12)? as usize;
                let cd_offset = read_u32_le(zip_bytes, pos + 16)? as usize;
                if let Some(end_cd) = cd_offset.checked_add(cd_size)
                    && end_cd <= zip_bytes.len()
                {
                    let mut cur = cd_offset;
                    while cur + 46 <= end_cd && &zip_bytes[cur..cur + 4] == b"PK\x01\x02" {
                        let method = read_u16_le(zip_bytes, cur + 10)?;
                        let comp_size = read_u32_le(zip_bytes, cur + 20)? as usize;
                        let name_len = read_u16_le(zip_bytes, cur + 28)? as usize;
                        let extra_len = read_u16_le(zip_bytes, cur + 30)? as usize;
                        let comment_len = read_u16_le(zip_bytes, cur + 32)? as usize;
                        let lfh_offset = read_u32_le(zip_bytes, cur + 42)? as usize;

                        let name_end = cur + 46 + name_len;
                        if name_end > end_cd {
                            break;
                        }
                        if let Ok(name) = std::str::from_utf8(&zip_bytes[cur + 46..name_end])
                            && name == target_entry
                            && method == 0
                            && lfh_offset + 30 <= zip_bytes.len()
                            && &zip_bytes[lfh_offset..lfh_offset + 4] == b"PK\x03\x04"
                        {
                            let lfh_name_len = read_u16_le(zip_bytes, lfh_offset + 26)? as usize;
                            let lfh_extra_len = read_u16_le(zip_bytes, lfh_offset + 28)? as usize;
                            let data_start = lfh_offset + 30 + lfh_name_len + lfh_extra_len;
                            let take_len = comp_size.min(max_bytes);
                            if data_start + take_len <= zip_bytes.len() {
                                return Some(zip_bytes[data_start..data_start + take_len].to_vec());
                            }
                        }
                        cur = name_end + extra_len + comment_len;
                    }
                }
                break;
            }
        }
    }

    // Pass B: Sequential Local File Header (`PK\x03\x04`) scan
    let mut offset = 0usize;
    while offset + 30 <= zip_bytes.len() {
        if &zip_bytes[offset..offset + 4] != b"PK\x03\x04" {
            offset += 1;
            continue;
        }
        let method = read_u16_le(zip_bytes, offset + 8)?;
        let comp_size = read_u32_le(zip_bytes, offset + 18)? as usize;
        let name_len = read_u16_le(zip_bytes, offset + 26)? as usize;
        let extra_len = read_u16_le(zip_bytes, offset + 28)? as usize;
        let header_end = offset + 30 + name_len + extra_len;
        if header_end > zip_bytes.len() {
            break;
        }
        if let Ok(name) = std::str::from_utf8(&zip_bytes[offset + 30..offset + 30 + name_len])
            && name == target_entry
            && method == 0
        {
            let take_len = comp_size.min(max_bytes);
            if header_end + take_len <= zip_bytes.len() {
                return Some(zip_bytes[header_end..header_end + take_len].to_vec());
            }
        }
        offset = header_end.saturating_add(comp_size.max(1));
    }
    None
}

/// Build a valid PKZIP Stored (`method = 0`) archive with CRC32 & Central Directory
/// (accepted by `/usr/bin/unzip`, Python `zipfile`, LibreOffice, and `extract_stored_zip_entry`).
pub fn build_stored_zip_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd_records: Vec<Vec<u8>> = Vec::with_capacity(entries.len());

    for &(name, data) in entries {
        let name_bytes = name.as_bytes();
        let lfh_offset = out.len() as u32;
        let crc = crc32_ieee(data);
        let size = data.len() as u32;

        // Local File Header (`PK\x03\x04`)
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 flag
        out.extend_from_slice(&0u16.to_le_bytes()); // compression method = 0 (Stored)
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);

        // Central Directory Header (`PK\x01\x02`)
        let mut cd = Vec::with_capacity(46 + name_bytes.len());
        cd.extend_from_slice(b"PK\x01\x02");
        cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
        cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
        cd.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 flag
        cd.extend_from_slice(&0u16.to_le_bytes()); // method = 0
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod time
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod date
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&size.to_le_bytes());
        cd.extend_from_slice(&size.to_le_bytes());
        cd.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // extra len
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk number
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        cd.extend_from_slice(&lfh_offset.to_le_bytes());
        cd.extend_from_slice(name_bytes);
        cd_records.push(cd);
    }

    let cd_offset = out.len() as u32;
    for cd in &cd_records {
        out.extend_from_slice(cd);
    }
    let cd_size = (out.len() as u32) - cd_offset;
    let count = entries.len() as u16;

    // End of Central Directory (`PK\x05\x06`)
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes()); // disk num
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn read_u16_le(buf: &[u8], offset: usize) -> Option<u16> {
    let slice = buf.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    let slice = buf.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Parse `word/styles.xml` mapping `styleId -> (style_name, outline_lvl)`.
fn parse_docx_styles_xml(styles_xml: &str) -> HashMap<String, (String, Option<u8>)> {
    static STYLE_BLOCK_RE: OnceLock<Regex> = OnceLock::new();
    static STYLE_ID_RE: OnceLock<Regex> = OnceLock::new();
    static STYLE_NAME_RE: OnceLock<Regex> = OnceLock::new();
    static OUTLINE_LVL_RE: OnceLock<Regex> = OnceLock::new();

    let block_re = STYLE_BLOCK_RE.get_or_init(|| {
        Regex::new(r"(?s)<w:style(?:\s[^>]*)?>(.*?)</w:style>").expect("valid w:style regex")
    });
    let id_re = STYLE_ID_RE.get_or_init(|| {
        Regex::new(r#"<w:style\b[^>]*\bw:styleId\s*=\s*["']([^"']+)["']"#)
            .expect("valid styleId regex")
    });
    let name_re = STYLE_NAME_RE.get_or_init(|| {
        Regex::new(r#"<w:name\b[^>]*\bw:val\s*=\s*["']([^"']+)["']"#).expect("valid w:name regex")
    });
    let olvl_re = OUTLINE_LVL_RE.get_or_init(|| {
        Regex::new(r#"<w:outlineLvl\b[^>]*\bw:val\s*=\s*["']([0-9]+)["']"#)
            .expect("valid outlineLvl regex")
    });

    let mut map = HashMap::new();
    for m in block_re.find_iter(styles_xml) {
        let full = m.as_str();
        let Some(sid) = id_re.captures(full).and_then(|c| c.get(1)).map(|x| x.as_str()) else {
            continue;
        };
        let sname = name_re
            .captures(full)
            .and_then(|c| c.get(1))
            .map(|x| unescape_xml_entities(x.as_str()))
            .unwrap_or_default();
        let olvl = olvl_re
            .captures(full)
            .and_then(|c| c.get(1))
            .and_then(|x| x.as_str().parse::<u8>().ok())
            .filter(|&v| v < 9);
        if !sname.is_empty() || olvl.is_some() {
            map.insert(sid.to_string(), (sname, olvl));
        }
    }
    map
}

fn parse_docx_paragraphs(
    doc_xml: &str,
    style_map: &HashMap<String, (String, Option<u8>)>,
) -> Vec<RawParagraph> {
    static PARA_RE: OnceLock<Regex> = OnceLock::new();
    static PSTYLE_RE: OnceLock<Regex> = OnceLock::new();
    static OLVL_RE: OnceLock<Regex> = OnceLock::new();
    static WT_RE: OnceLock<Regex> = OnceLock::new();
    static TAB_BR_RE: OnceLock<Regex> = OnceLock::new();

    // Crucial: require `>` or whitespace after `<w:p` / `<w:t` so `<w:pPr>` and `<w:tbl>` never match!
    let para_re = PARA_RE
        .get_or_init(|| Regex::new(r"(?s)<w:p(?:\s[^>]*)?>(.*?)</w:p>").expect("valid w:p regex"));
    let pstyle_re = PSTYLE_RE.get_or_init(|| {
        Regex::new(r#"<w:pStyle\b[^>]*\bw:val\s*=\s*["']([^"']+)["']"#)
            .expect("valid w:pStyle regex")
    });
    let olvl_re = OLVL_RE.get_or_init(|| {
        Regex::new(r#"<w:outlineLvl\b[^>]*\bw:val\s*=\s*["']([0-9]+)["']"#)
            .expect("valid w:outlineLvl regex")
    });
    let wt_re = WT_RE
        .get_or_init(|| Regex::new(r"(?s)<w:t(?:\s[^>]*)?>(.*?)</w:t>").expect("valid w:t regex"));
    let tab_br_re = TAB_BR_RE
        .get_or_init(|| Regex::new(r"<w:(?:tab|br|cr)\b[^>]*/?>").expect("valid tab/br regex"));

    let mut out = Vec::new();
    for (idx, caps) in para_re.captures_iter(doc_xml).enumerate() {
        let inner = &caps[1];
        let style_id = pstyle_re
            .captures(inner)
            .and_then(|c| c.get(1))
            .map(|m| unescape_xml_entities(m.as_str()))
            .unwrap_or_default();
        let direct_olvl = olvl_re
            .captures(inner)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse::<u8>().ok())
            .filter(|&v| v < 9);

        let (mapped_name, mapped_olvl) = style_map
            .get(&style_id)
            .cloned()
            .unwrap_or_else(|| (String::new(), None));

        // Preserve tab separators between heading numbers and titles if `<w:tab/>` was used
        let normalized_inner = if inner.contains("<w:tab") || inner.contains("<w:br") {
            tab_br_re
                .replace_all(inner, "<w:t> </w:t>")
                .into_owned()
        } else {
            inner.to_string()
        };

        let mut raw_text = String::new();
        for t_cap in wt_re.captures_iter(&normalized_inner) {
            raw_text.push_str(&unescape_xml_entities(&t_cap[1]));
        }
        let text = collapse_whitespace(&raw_text);
        if text.is_empty() {
            continue;
        }

        out.push(RawParagraph {
            index: idx,
            style_id,
            style_name: mapped_name,
            outline_lvl: direct_olvl.or(mapped_olvl),
            text,
        });
    }
    out
}

fn infer_docx_title(paragraphs: &[RawParagraph], fallback_stem: &str) -> String {
    let inspect_slice = &paragraphs[..paragraphs.len().min(28)];

    // 1. Explicit Title style or level-0 heading at very start of document
    let mut degree_banner: Option<String> = None;
    let mut candidate_subject: Option<String> = None;

    for (pos, p) in inspect_slice.iter().enumerate() {
        let t = p.text.trim();
        let char_len = t.chars().count();
        if char_len == 0 || char_len > 90 || is_cover_metadata_line(t) {
            continue;
        }
        // Stop scanning cover once we hit Abstract / TOC / Chapter 1
        if pos > 0 && is_abstract_or_chapter_start(t) {
            break;
        }

        let sl = format!("{} {}", p.style_id, p.style_name).to_ascii_lowercase();
        let is_degree_only = matches!(
            t,
            "硕士学位论文"
                | "博士学位论文"
                | "本科毕业论文"
                | "学士学位论文"
                | "毕业设计（论文）"
                | "毕业设计(论文)"
                | "硕士论文"
                | "博士论文"
        ) || (char_len <= 18
            && (t.ends_with("硕士学位论文")
                || t.ends_with("博士学位论文")
                || t.ends_with("本科毕业论文")));

        if is_degree_only {
            degree_banner = Some(t.to_string());
            continue;
        }

        if (t.contains("学位论文") || t.contains("硕士论文") || t.contains("毕业设计"))
            && char_len > 8
        {
            return t.to_string();
        }

        if candidate_subject.is_none() {
            let is_university_only =
                char_len <= 16 && (t.ends_with("大学") || t.ends_with("学院") || t.ends_with("研究院"));
            if !is_university_only
                && (sl.contains("title")
                    || sl.contains("标题")
                    || p.outline_lvl == Some(0)
                    || t.contains("论文")
                    || t.contains("报告")
                    || t.contains("方案")
                    || t.contains("白皮书")
                    || t.contains("指南")
                    || (pos <= 5 && (4..=80).contains(&char_len)))
            {
                candidate_subject = Some(t.to_string());
            }
        }
    }

    match (degree_banner, candidate_subject) {
        (Some(deg), Some(subj)) => {
            if subj.contains(&deg) {
                subj
            } else {
                format!("{} — {}", deg, subj)
            }
        }
        (Some(deg), None) => format!("{} — {}", deg, fallback_stem),
        (None, Some(subj)) => subj,
        (None, None) => paragraphs
            .first()
            .map(|p| truncate_clean(&p.text, 80))
            .unwrap_or_else(|| fallback_stem.to_string()),
    }
}

fn is_cover_metadata_line(t: &str) -> bool {
    let prefixes = [
        "作者",
        "姓名",
        "学号",
        "指导教师",
        "导师",
        "副导师",
        "学院",
        "院系",
        "专业",
        "学科",
        "研究方向",
        "分类号",
        "密级",
        "学校代码",
        "UDC",
        "日期",
        "提交日期",
        "答辩日期",
    ];
    prefixes
        .iter()
        .any(|p| t.starts_with(p) && (t.contains('：') || t.contains(':') || t.chars().count() <= 24))
}

fn is_abstract_or_chapter_start(t: &str) -> bool {
    let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    if matches!(
        compact.as_str(),
        "摘要" | "目录" | "绪论" | "引言" | "Abstract" | "ABSTRACT"
    ) {
        return true;
    }
    classify_heading_text_pattern(t).is_some()
}

fn is_toc_entry_line(p: &RawParagraph) -> bool {
    let sl = format!("{} {}", p.style_id, p.style_name).to_ascii_lowercase();
    if sl.contains("toc") || sl.contains("目录") {
        return true;
    }
    static TOC_DOTS_RE: OnceLock<Regex> = OnceLock::new();
    let re = TOC_DOTS_RE.get_or_init(|| {
        Regex::new(r"(?:\.{3,}|…{2,}|\s{3,})\s*\d{1,4}$").expect("valid toc leader regex")
    });
    re.is_match(&p.text)
}

/// Classify whether a paragraph is a Chapter / Section heading and return its level (`1..=4`).
fn detect_paragraph_heading_level(
    p: &RawParagraph,
    doc_title: &str,
    allow_toc: bool,
) -> Option<u8> {
    let t = p.text.trim();
    let char_len = t.chars().count();
    if char_len == 0 || char_len > 90 {
        return None;
    }
    // Skip the document cover title itself so we don't duplicate it as a chapter heading
    if p.index == 0 && (t == doc_title || doc_title.ends_with(t)) {
        return None;
    }
    if !allow_toc && is_toc_entry_line(p) {
        return None;
    }
    // Avoid classifying long full-stop body sentences as headings unless explicitly styled
    let ends_like_sentence = t.ends_with('。') || t.ends_with('；') || t.ends_with('，');

    // 1. Explicit Word style (`Heading*` / `标题*` / `outlineLvl` / optional `TOC*`)
    let sl = format!("{} {}", p.style_id, p.style_name).to_ascii_lowercase();
    if let Some(olvl) = p.outline_lvl
        && !ends_like_sentence
    {
        return Some((olvl + 1).clamp(1, 4));
    }
    if !ends_like_sentence {
        if sl.contains("heading 1")
            || sl.contains("heading1")
            || sl.contains("标题 1")
            || sl.contains("标题1")
        {
            return Some(1);
        }
        if sl.contains("heading 2")
            || sl.contains("heading2")
            || sl.contains("标题 2")
            || sl.contains("标题2")
        {
            return Some(2);
        }
        if sl.contains("heading 3")
            || sl.contains("heading3")
            || sl.contains("标题 3")
            || sl.contains("标题3")
        {
            return Some(3);
        }
        if sl.contains("heading") || sl.contains("标题") || (allow_toc && sl.contains("toc")) {
            return Some(2);
        }
    }

    // 2. Structural text pattern (`第四章 ...`, `Chapter 4 ...`, `一、...`, `4.1 ...`, `4 ...`)
    if !ends_like_sentence {
        return classify_heading_text_pattern(t);
    }
    None
}

/// Detect heading level (`1..=3`) purely from heading text structure.
pub fn classify_heading_text_pattern(text: &str) -> Option<u8> {
    static CH_CHAPTER_RE: OnceLock<Regex> = OnceLock::new();
    static CH_SECTION_RE: OnceLock<Regex> = OnceLock::new();
    static EN_CHAP_RE: OnceLock<Regex> = OnceLock::new();
    static CN_ENUM_RE: OnceLock<Regex> = OnceLock::new();
    static DEC_SUB3_RE: OnceLock<Regex> = OnceLock::new();
    static DEC_SUB2_RE: OnceLock<Regex> = OnceLock::new();
    static DEC_TOP_RE: OnceLock<Regex> = OnceLock::new();

    let t = text.trim();
    let char_len = t.chars().count();
    if char_len == 0 || char_len > 90 || t.ends_with('。') || t.ends_with('；') {
        return None;
    }

    let ch_chap = CH_CHAPTER_RE.get_or_init(|| {
        Regex::new(r"^第\s*[一二三四五六七八九十百零〇两0-9]+\s*[章节篇部分回]")
            .expect("valid cn chapter regex")
    });
    let ch_sec = CH_SECTION_RE.get_or_init(|| {
        Regex::new(r"^第\s*[一二三四五六七八九十百零〇两0-9]+\s*节").expect("valid cn sec regex")
    });
    let en_chap = EN_CHAP_RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:chapter|section|part)\s+\d+\b").expect("valid en chapter regex")
    });
    let cn_enum = CN_ENUM_RE.get_or_init(|| {
        Regex::new(r"^[一二三四五六七八九十]+、\s*\S+").expect("valid cn enum regex")
    });
    let dec_sub3 = DEC_SUB3_RE.get_or_init(|| {
        Regex::new(r"^\d{1,2}\.\d{1,2}\.\d{1,2}\s+\S+").expect("valid d.d.d regex")
    });
    let dec_sub2 = DEC_SUB2_RE
        .get_or_init(|| Regex::new(r"^\d{1,2}\.\d{1,2}\s+\S+").expect("valid d.d regex"));
    let dec_top = DEC_TOP_RE.get_or_init(|| {
        Regex::new(r"^(?:[1-9]|1[0-5])\s+[\u{4e00}-\u{9fa5}A-Za-z]\S*")
            .expect("valid top numbered heading regex")
    });

    if ch_sec.is_match(t) {
        return Some(2);
    }
    if ch_chap.is_match(t) || en_chap.is_match(t) || cn_enum.is_match(t) {
        return Some(1);
    }
    if dec_sub3.is_match(t) {
        return Some(3);
    }
    if dec_sub2.is_match(t) {
        return Some(2);
    }
    if char_len <= 52 && dec_top.is_match(t) && !t.contains('，') {
        return Some(1);
    }

    let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    if matches!(
        compact.as_str(),
        "摘要" | "Abstract" | "引言" | "绪论" | "结论" | "总结与展望" | "致谢" | "参考文献" | "References"
    ) {
        return Some(1);
    }
    None
}

fn build_sections_from_paragraphs(
    paragraphs: &[RawParagraph],
    doc_title: &str,
    allow_toc: bool,
) -> Vec<DocSection> {
    let mut sections: Vec<DocSection> = Vec::new();
    let mut current_body = String::new();

    for p in paragraphs {
        if let Some(level) = detect_paragraph_heading_level(p, doc_title, allow_toc) {
            if let Some(last) = sections.last_mut() {
                last.excerpt = scrub_sensitive_text(&truncate_clean(
                    &current_body,
                    MAX_SECTION_EXCERPT_CHARS,
                ));
            }
            current_body.clear();
            let clean_heading = scrub_sensitive_text(&clean_toc_dots(&p.text));
            sections.push(DocSection {
                heading: clean_heading,
                level,
                paragraph_index: p.index,
                excerpt: String::new(),
            });
        } else if !sections.is_empty() && current_body.chars().count() < MAX_SECTION_EXCERPT_CHARS + 120 {
            if !current_body.is_empty() {
                current_body.push(' ');
            }
            current_body.push_str(&p.text);
        }
    }
    if let Some(last) = sections.last_mut() {
        last.excerpt =
            scrub_sensitive_text(&truncate_clean(&current_body, MAX_SECTION_EXCERPT_CHARS));
    }

    // Roll up immediate child subsections (`4.1 ...`) when a top-level chapter heading (`第四章` or `4 ...`)
    // immediately precedes its first subsection without an introductory paragraph.
    let len = sections.len();
    for i in 0..len {
        if sections[i].excerpt.chars().count() < 80 {
            let parent_lvl = sections[i].level;
            let mut rolled = sections[i].excerpt.clone();
            for child in sections.iter().skip(i + 1) {
                if child.level <= parent_lvl {
                    break;
                }
                if !child.excerpt.is_empty() {
                    if !rolled.is_empty() {
                        rolled.push_str(" | ");
                    }
                    rolled.push_str(&format!("[{}] {}", child.heading, child.excerpt));
                } else {
                    if !rolled.is_empty() {
                        rolled.push_str(" | ");
                    }
                    rolled.push_str(&format!("[{}]", child.heading));
                }
                if rolled.chars().count() >= MAX_SECTION_EXCERPT_CHARS {
                    break;
                }
            }
            if !rolled.is_empty() {
                sections[i].excerpt =
                    scrub_sensitive_text(&truncate_clean(&rolled, MAX_SECTION_EXCERPT_CHARS));
            }
        }
    }

    // Normalize top heading levels if every heading in the doc had level >= 2 (e.g. Title=H1, Chapters=H2)
    if let Some(min_lvl) = sections.iter().map(|s| s.level).min()
        && min_lvl > 1
    {
        let shift = min_lvl - 1;
        for s in &mut sections {
            s.level = s.level.saturating_sub(shift).max(1);
        }
    }

    sections
}

fn clean_toc_dots(raw: &str) -> String {
    static LEADER_RE: OnceLock<Regex> = OnceLock::new();
    let re = LEADER_RE.get_or_init(|| {
        Regex::new(r"\s*(?:\.{3,}|…{2,})\s*\d{1,4}$").expect("valid leader strip regex")
    });
    re.replace(raw.trim(), "").trim().to_string()
}

fn infer_doc_summary(paragraphs: &[RawParagraph], doc_title: &str) -> String {
    // Prefer the paragraph right after `摘要` / `Abstract` or the first substantive body paragraph
    for (idx, p) in paragraphs.iter().enumerate() {
        let compact: String = p.text.chars().filter(|c| !c.is_whitespace()).collect();
        if matches!(compact.as_str(), "摘要" | "Abstract")
            && let Some(next_p) = paragraphs.get(idx + 1)
            && next_p.text.chars().count() >= 16
        {
            return truncate_clean(&next_p.text, 150);
        }
        if let Some(rest) = p
            .text
            .strip_prefix("摘要：")
            .or_else(|| p.text.strip_prefix("摘要:"))
            && rest.trim().chars().count() >= 12
        {
            return truncate_clean(rest.trim(), 150);
        }
    }

    for p in paragraphs.iter().take(30) {
        let t = p.text.trim();
        if t == doc_title || doc_title.contains(t) || is_cover_metadata_line(t) {
            continue;
        }
        if t.chars().count() >= 24 && classify_heading_text_pattern(t).is_none() {
            return truncate_clean(t, 150);
        }
    }

    paragraphs
        .iter()
        .find(|p| p.text.trim() != doc_title)
        .map(|p| truncate_clean(&p.text, 140))
        .unwrap_or_else(|| truncate_clean(doc_title, 120))
}

fn build_document_keywords(
    path: &Path,
    doc_title: &str,
    doc_summary: &str,
    headings: &[String],
    paragraphs: &[RawParagraph],
) -> String {
    let mut kw_parts: Vec<String> = Vec::new();
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let stem_lc = stem.to_ascii_lowercase();
    if !stem.is_empty() {
        kw_parts.push(stem.clone());
    }

    // Extract explicit `关键词：` / `Keywords:` lines if present
    for p in paragraphs.iter().take(40) {
        let t = p.text.trim();
        if let Some(rest) = t
            .strip_prefix("关键词：")
            .or_else(|| t.strip_prefix("关键词:"))
            .or_else(|| t.strip_prefix("Keywords:"))
            .or_else(|| t.strip_prefix("KEYWORDS:"))
        {
            kw_parts.push(truncate_clean(rest, 140));
        }
    }

    // Semantic academic / thesis / report tags so English filenames like `paper_main.docx`
    // match natural Chinese queries like `"我的硕士论文"` / `"毕业论文"`!
    let has_abstract = headings.iter().any(|h| h.contains("摘要") || h.eq_ignore_ascii_case("abstract"))
        || paragraphs.iter().take(20).any(|p| p.text.starts_with("摘要") || p.text.starts_with("关键词"));
    let has_refs = headings.iter().any(|h| h.contains("参考文献") || h.eq_ignore_ascii_case("references"));
    let is_academic_paper = stem_lc.contains("paper")
        || stem_lc.contains("thesis")
        || stem_lc.contains("dissertation")
        || doc_title.contains("论文")
        || (has_abstract && has_refs);

    if is_academic_paper {
        kw_parts.push("论文 学术论文 学位论文 毕业论文 paper thesis".to_string());
        if stem_lc == "paper_main"
            || stem_lc.contains("master")
            || stem_lc.contains("thesis")
            || doc_title.contains("硕士")
        {
            kw_parts.push("硕士论文 硕士学位论文".to_string());
        }
    }
    if stem_lc.contains("report") || doc_title.contains("周报") || doc_title.contains("报告") {
        kw_parts.push("报告 周报 总结汇报 report".to_string());
    }
    if stem_lc.contains("manual") || doc_title.contains("说明") || doc_title.contains("指南") {
        kw_parts.push("说明 指南 手册 文档 manual".to_string());
    }

    let (py_full, py_init) = to_pinyin_pair(&format!("{} {}", stem, doc_title));
    if !py_full.is_empty() {
        kw_parts.push(truncate_clean(&py_full, 120));
    }
    if !py_init.is_empty() {
        kw_parts.push(truncate_clean(&py_init, 60));
    }
    let _ = doc_summary;

    scrub_sensitive_text(&kw_parts.join(" "))
}

// =============================================================================
// `.md` / `.txt` / `.tex` / `.typ` and `.pdf` Extractors
// =============================================================================

fn extract_text_or_markup_outline(
    path: &Path,
    ext: &str,
    mtime_epoch: i64,
    size_bytes: u64,
    indexed_epoch: i64,
) -> Option<DocumentOutlineRecord> {
    let file = File::open(path).ok()?;
    let mut buf = Vec::new();
    file.take(MAX_TEXT_READ_BYTES).read_to_end(&mut buf).ok()?;
    if buf.is_empty() || buf[..buf.len().min(1024)].contains(&0) {
        return None;
    }
    let raw_text = String::from_utf8_lossy(&buf);
    parse_plain_or_markup_text(path, ext, &raw_text, mtime_epoch, size_bytes, indexed_epoch)
}

fn extract_pdf_outline(
    path: &Path,
    mtime_epoch: i64,
    size_bytes: u64,
    indexed_epoch: i64,
) -> Option<DocumentOutlineRecord> {
    if !Path::new("/usr/bin/pdftotext").is_file() {
        return None;
    }
    let mut child = Command::new("/usr/bin/pdftotext")
        .args(["-l", "12", "-nopgbrk"])
        .arg(path.as_os_str())
        .arg("-")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut buf = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let _ = stdout.take(MAX_TEXT_READ_BYTES).read_to_end(&mut buf);
    }
    let _ = child.wait();
    if buf.is_empty() {
        return None;
    }
    let raw_text = String::from_utf8_lossy(&buf);
    if raw_text.trim().is_empty() {
        return None;
    }
    parse_plain_or_markup_text(path, "pdf", &raw_text, mtime_epoch, size_bytes, indexed_epoch)
}

fn parse_plain_or_markup_text(
    path: &Path,
    ext: &str,
    raw_text: &str,
    mtime_epoch: i64,
    size_bytes: u64,
    indexed_epoch: i64,
) -> Option<DocumentOutlineRecord> {
    static MD_HEADING_RE: OnceLock<Regex> = OnceLock::new();
    static TYP_HEADING_RE: OnceLock<Regex> = OnceLock::new();
    static TEX_SEC_RE: OnceLock<Regex> = OnceLock::new();
    static TEX_TITLE_RE: OnceLock<Regex> = OnceLock::new();

    let md_re =
        MD_HEADING_RE.get_or_init(|| Regex::new(r"^(#{1,4})\s+(.+)$").expect("valid md heading"));
    let typ_re =
        TYP_HEADING_RE.get_or_init(|| Regex::new(r"^(=+)\s+(.+)$").expect("valid typst heading"));
    let tex_sec_re = TEX_SEC_RE.get_or_init(|| {
        Regex::new(r"^\\(chapter|section|subsection|subsubsection)\*?\{([^}]+)\}")
            .expect("valid tex sec")
    });
    let tex_title_re =
        TEX_TITLE_RE.get_or_init(|| Regex::new(r"\\title\{([^}]+)\}").expect("valid tex title"));

    let fallback_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("文档")
        .to_string();

    let mut explicit_title: Option<String> = None;
    if ext == "tex"
        && let Some(c) = tex_title_re.captures(raw_text)
    {
        explicit_title = Some(collapse_whitespace(&c[1]));
    }

    let mut sections: Vec<DocSection> = Vec::new();
    let mut current_body = String::new();
    let mut intro_body = String::new();
    let mut in_code_fence = false;
    let mut in_frontmatter = false;
    let mut raw_paras = Vec::new();

    for (line_idx, raw_line) in raw_text.lines().enumerate() {
        let trimmed = raw_line.trim();
        if line_idx == 0 && trimmed == "---" && matches!(ext, "md" | "markdown") {
            in_frontmatter = true;
            continue;
        }
        if in_frontmatter {
            if trimmed == "---" || trimmed == "..." {
                in_frontmatter = false;
            } else if let Some(tval) = trimmed.strip_prefix("title:") {
                let clean_t = tval.trim().trim_matches('"').trim_matches('\'');
                if !clean_t.is_empty() {
                    explicit_title = Some(clean_t.to_string());
                }
            }
            continue;
        }
        if trimmed.starts_with("```") {
            in_code_fence = !in_code_fence;
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }

        let mut detected_heading: Option<(u8, String)> = None;
        if !in_code_fence {
            if matches!(ext, "md" | "markdown")
                && let Some(caps) = md_re.captures(trimmed)
            {
                let lvl = (caps[1].len() as u8).clamp(1, 4);
                let htxt = collapse_whitespace(&caps[2]);
                if explicit_title.is_none() && lvl == 1 && sections.is_empty() {
                    explicit_title = Some(htxt.clone());
                }
                detected_heading = Some((lvl, htxt));
            } else if ext == "typ"
                && let Some(caps) = typ_re.captures(trimmed)
            {
                let lvl = (caps[1].len() as u8).clamp(1, 4);
                detected_heading = Some((lvl, collapse_whitespace(&caps[2])));
            } else if ext == "tex"
                && let Some(caps) = tex_sec_re.captures(trimmed)
            {
                let lvl = match &caps[1] {
                    "chapter" | "section" => 1,
                    "subsection" => 2,
                    _ => 3,
                };
                detected_heading = Some((lvl, collapse_whitespace(&caps[2])));
            } else if let Some(lvl) = classify_heading_text_pattern(trimmed) {
                detected_heading = Some((lvl, collapse_whitespace(trimmed)));
            }
        }

        raw_paras.push(RawParagraph {
            index: line_idx,
            style_id: String::new(),
            style_name: String::new(),
            outline_lvl: None,
            text: collapse_whitespace(trimmed),
        });

        if let Some((lvl, h_title)) = detected_heading {
            if let Some(last) = sections.last_mut() {
                last.excerpt = scrub_sensitive_text(&truncate_clean(
                    &current_body,
                    MAX_SECTION_EXCERPT_CHARS,
                ));
            }
            current_body.clear();
            sections.push(DocSection {
                heading: scrub_sensitive_text(&h_title),
                level: lvl,
                paragraph_index: line_idx,
                excerpt: String::new(),
            });
        } else if sections.is_empty() {
            if intro_body.chars().count() < 400 {
                if !intro_body.is_empty() {
                    intro_body.push(' ');
                }
                intro_body.push_str(trimmed);
            }
        } else if current_body.chars().count() < MAX_SECTION_EXCERPT_CHARS + 120 {
            if !current_body.is_empty() {
                current_body.push(' ');
            }
            current_body.push_str(trimmed);
        }
    }

    if let Some(last) = sections.last_mut() {
        last.excerpt =
            scrub_sensitive_text(&truncate_clean(&current_body, MAX_SECTION_EXCERPT_CHARS));
    }

    let doc_title = scrub_sensitive_text(
        &explicit_title
            .unwrap_or_else(|| infer_docx_title(&raw_paras, &fallback_stem)),
    );
    let doc_summary = scrub_sensitive_text(&if !intro_body.is_empty() {
        truncate_clean(&intro_body, 150)
    } else {
        infer_doc_summary(&raw_paras, &doc_title)
    });
    let headings: Vec<String> = sections.iter().map(|s| s.heading.clone()).collect();
    let keywords = build_document_keywords(path, &doc_title, &doc_summary, &headings, &raw_paras);

    Some(DocumentOutlineRecord {
        path: path.to_string_lossy().to_string(),
        mtime_epoch,
        size_bytes,
        doc_title,
        doc_summary,
        headings,
        sections,
        keywords,
        indexed_epoch,
    })
}

// =============================================================================
// Chinese Number Normalization & Semantic Outline Search
// =============================================================================

/// Parse an Arabic or Chinese numeral (`"4"`, `"四"`, `"十二"`, `"二十三"`) into `u32`.
pub fn parse_chinese_or_arabic_number(raw: &str) -> Option<u32> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(n) = t.parse::<u32>() {
        return Some(n);
    }

    let mut total = 0u32;
    let mut current = 0u32;
    let mut saw_digit = false;

    for ch in t.chars() {
        match ch {
            '零' | '〇' => {
                saw_digit = true;
            }
            '一' => {
                current = 1;
                saw_digit = true;
            }
            '二' | '两' => {
                current = 2;
                saw_digit = true;
            }
            '三' => {
                current = 3;
                saw_digit = true;
            }
            '四' => {
                current = 4;
                saw_digit = true;
            }
            '五' => {
                current = 5;
                saw_digit = true;
            }
            '六' => {
                current = 6;
                saw_digit = true;
            }
            '七' => {
                current = 7;
                saw_digit = true;
            }
            '八' => {
                current = 8;
                saw_digit = true;
            }
            '九' => {
                current = 9;
                saw_digit = true;
            }
            '十' => {
                saw_digit = true;
                total += if current == 0 { 10 } else { current * 10 };
                current = 0;
            }
            '百' => {
                saw_digit = true;
                total += if current == 0 { 100 } else { current * 100 };
                current = 0;
            }
            _ => return None,
        }
    }
    if saw_digit {
        Some(total + current)
    } else {
        None
    }
}

/// Format an integer (`1..=99`) into standard Chinese numeral (`4` -> `"四"`, `12` -> `"十二"`).
pub fn arabic_to_chinese_number(n: u32) -> Option<String> {
    const DIGITS: [&str; 10] = ["零", "一", "二", "三", "四", "五", "六", "七", "八", "九"];
    match n {
        0 => Some("零".to_string()),
        1..=9 => Some(DIGITS[n as usize].to_string()),
        10 => Some("十".to_string()),
        11..=19 => Some(format!("十{}", DIGITS[(n % 10) as usize])),
        20..=99 => {
            let tens = DIGITS[(n / 10) as usize];
            let ones = n % 10;
            if ones == 0 {
                Some(format!("{}十", tens))
            } else {
                Some(format!("{}十{}", tens, DIGITS[ones as usize]))
            }
        }
        _ => None,
    }
}

/// Extract target chapter/section number from natural text (`"第四章"` -> `Some(4)`, `"第4章"` -> `Some(4)`).
pub fn extract_chapter_number_hint(text: &str) -> Option<u32> {
    static CN_CHAP_RE: OnceLock<Regex> = OnceLock::new();
    static EN_CHAP_RE: OnceLock<Regex> = OnceLock::new();

    let cn_re = CN_CHAP_RE.get_or_init(|| {
        Regex::new(r"第\s*([一二三四五六七八九十百零〇两0-9]+)\s*[章节篇部分回]")
            .expect("valid chapter num regex")
    });
    let en_re = EN_CHAP_RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:chapter|chap|section|sec|part)\s*(\d{1,3})\b")
            .expect("valid en chap num regex")
    });

    if let Some(caps) = cn_re.captures(text) {
        return parse_chinese_or_arabic_number(&caps[1]);
    }
    if let Some(caps) = en_re.captures(text) {
        return caps[1].parse::<u32>().ok();
    }
    None
}

fn heading_top_chapter_number(heading: &str) -> Option<(u32, bool)> {
    static HEAD_CN_ENUM_RE: OnceLock<Regex> = OnceLock::new();
    static HEAD_DEC_RE: OnceLock<Regex> = OnceLock::new();

    let t = heading.trim();
    if let Some(n) = extract_chapter_number_hint(t) {
        let is_top = !t.contains("节");
        return Some((n, is_top));
    }

    let cn_enum = HEAD_CN_ENUM_RE.get_or_init(|| {
        Regex::new(r"^([一二三四五六七八九十]+)、").expect("valid heading cn enum")
    });
    if let Some(caps) = cn_enum.captures(t)
        && let Some(n) = parse_chinese_or_arabic_number(&caps[1])
    {
        return Some((n, true));
    }

    let dec_re = HEAD_DEC_RE
        .get_or_init(|| Regex::new(r"^(\d{1,2})(?:\.(\d{1,2}))?\s+\S+").expect("valid dec head"));
    if let Some(caps) = dec_re.captures(t)
        && let Ok(n) = caps[1].parse::<u32>()
    {
        let is_top = caps.get(2).is_none();
        return Some((n, is_top));
    }
    None
}

/// Search `document_outlines` by document topic/title/filename and optional chapter/section hint.
pub fn search_document_outlines(
    db: &MemoryHubDb,
    query: &str,
    section_hint: Option<&str>,
    limit: usize,
) -> anyhow::Result<Vec<DocumentOutlineHit>> {
    let cap = limit.clamp(1, 25);
    let records = {
        let conn = db.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT path, mtime_epoch, size_bytes, doc_title, doc_summary,
                    headings_json, sections_json, keywords, indexed_epoch
             FROM document_outlines
             ORDER BY mtime_epoch DESC LIMIT 300",
        )?;
        let mut list = Vec::new();
        for row in stmt.query_map([], row_to_outline_record)? {
            list.push(row?);
        }
        list
    };

    if records.is_empty() {
        return Ok(Vec::new());
    }

    let q_trim = query.trim();
    let sec_trim = section_hint.map(str::trim).filter(|s| !s.is_empty());
    let combined_sec_text = match sec_trim {
        Some(s) => format!("{} {}", q_trim, s),
        None => q_trim.to_string(),
    };
    let target_chap_num = sec_trim
        .and_then(extract_chapter_number_hint)
        .or_else(|| extract_chapter_number_hint(&combined_sec_text));

    let topic_tokens = extract_doc_topic_tokens(q_trim);
    let sec_topic_tokens = sec_trim.map(extract_section_topic_tokens).unwrap_or_default();
    let q_lc = q_trim.to_ascii_lowercase();

    let mut hits: Vec<DocumentOutlineHit> = Vec::new();

    for rec in records {
        let path_lc = rec.path.to_ascii_lowercase();
        let fname = Path::new(&rec.path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&rec.path);
        let fname_lc = fname.to_ascii_lowercase();
        let stem_lc = Path::new(fname)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(fname)
            .to_ascii_lowercase();
        let title_lc = rec.doc_title.to_ascii_lowercase();
        let summary_lc = rec.doc_summary.to_ascii_lowercase();
        let kw_lc = rec.keywords.to_ascii_lowercase();

        let mut topic_score = 0.0f64;

        // 1. Direct path or filename match
        if !q_lc.is_empty() && (rec.path == q_trim || path_lc == q_lc || fname_lc == q_lc || stem_lc == q_lc) {
            topic_score += 115.0;
        } else if stem_lc.len() >= 3 && q_lc.contains(&stem_lc) {
            topic_score += 95.0;
        }

        // 2. Topic token & sub-token matching across `doc_title`, `keywords`, `fname`, `doc_summary`, and headings
        for tok in &topic_tokens {
            let tok_lc = tok.to_ascii_lowercase();
            let sub_terms = split_compound_cjk_terms(&tok_lc);
            let title_all_subs = sub_terms.len() >= 2
                && sub_terms
                    .iter()
                    .all(|sub| title_lc.contains(sub.as_str()) || fname_lc.contains(sub.as_str()));

            if title_lc.contains(&tok_lc) || fname_lc.contains(&tok_lc) {
                topic_score += 72.0;
            } else if title_all_subs {
                topic_score += 70.0;
            } else if kw_lc.contains(&tok_lc) {
                topic_score += 56.0;
            } else if summary_lc.contains(&tok_lc) {
                topic_score += 38.0;
            } else if rec
                .headings
                .iter()
                .any(|h| h.to_ascii_lowercase().contains(&tok_lc))
            {
                topic_score += 36.0;
            } else if sub_terms.len() >= 2 {
                // Partial/keyword match on decomposed Chinese phrase (`"硕士论文"` -> `["硕士", "论文"]`)
                let mut matched_subs = 0usize;
                for sub in &sub_terms {
                    if title_lc.contains(sub.as_str())
                        || kw_lc.contains(sub.as_str())
                        || fname_lc.contains(sub.as_str())
                    {
                        matched_subs += 1;
                    }
                }
                if matched_subs == sub_terms.len() {
                    topic_score += 58.0;
                } else if matched_subs > 0 {
                    topic_score += (matched_subs as f64) * 26.0;
                }
            }
        }

        // 3. Chapter / Section matching (`第四章` <-> `第4章` <-> `4 ...` + explicit `section_hint` keywords)
        let (matched_section, section_score) = find_best_matching_section(
            &rec,
            target_chap_num,
            sec_trim,
            &sec_topic_tokens,
            &topic_tokens,
        );

        // Guard: if the user asked for a specific topic (e.g. `"硕士论文"`) AND a chapter (`"第四章"`),
        // a completely unrelated document that merely happens to have 4 sections MUST NOT score >= 48!
        let total_score = if !topic_tokens.is_empty() && topic_score < 15.0 {
            (section_score * 0.4).min(24.0)
        } else {
            topic_score + section_score
        };

        if total_score < 20.0 {
            continue;
        }

        let toc_preview = format_toc_preview(&rec, matched_section.as_ref(), 115);
        hits.push(DocumentOutlineHit {
            record: rec,
            score: (total_score * 100.0).round() / 100.0,
            matched_section,
            toc_preview,
        });
    }

    hits.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.record.mtime_epoch.cmp(&a.record.mtime_epoch))
    });
    hits.truncate(cap);
    Ok(hits)
}

fn find_best_matching_section(
    rec: &DocumentOutlineRecord,
    target_chap_num: Option<u32>,
    sec_trim: Option<&str>,
    sec_topic_tokens: &[String],
    doc_topic_tokens: &[String],
) -> (Option<DocSection>, f64) {
    if rec.sections.is_empty() {
        return (None, 0.0);
    }

    let cn_num_str = target_chap_num.and_then(arabic_to_chinese_number);
    let mut best_idx: Option<usize> = None;
    let mut best_score = 0.0f64;

    for (idx, sec) in rec.sections.iter().enumerate() {
        let mut sc = 0.0f64;
        let h_lc = sec.heading.to_ascii_lowercase();
        let ex_lc = sec.excerpt.to_ascii_lowercase();

        if let Some(target_n) = target_chap_num {
            if let Some((sec_n, is_top)) = heading_top_chapter_number(&sec.heading)
                && sec_n == target_n
            {
                sc += if is_top { 48.0 } else { 30.0 };
            } else if let Some(ref cn_s) = cn_num_str
                && (sec.heading.contains(&format!("第{}章", cn_s))
                    || sec.heading.contains(&format!("第{}章", target_n)))
            {
                sc += 48.0;
            }
        }

        if let Some(raw_sec) = sec_trim {
            let rs_lc = raw_sec.to_ascii_lowercase();
            if h_lc.contains(&rs_lc) {
                sc += 45.0;
            } else if ex_lc.contains(&rs_lc) {
                sc += 25.0;
            }
        }

        for stok in sec_topic_tokens {
            let slc = stok.to_ascii_lowercase();
            if h_lc.contains(&slc) {
                sc += 38.0;
            } else if ex_lc.contains(&slc) {
                sc += 20.0;
            }
        }

        if target_chap_num.is_none() && sec_trim.is_none() {
            for dtok in doc_topic_tokens {
                let dlc = dtok.to_ascii_lowercase();
                if dlc.chars().count() >= 2 && h_lc.contains(&dlc) {
                    sc += 22.0;
                }
            }
        }

        if sc > best_score {
            best_score = sc;
            best_idx = Some(idx);
        }
    }

    if let Some(i) = best_idx {
        (Some(rec.sections[i].clone()), best_score)
    } else if sec_trim.is_none() && target_chap_num.is_none() {
        // Default preview section when inspecting whole document without chapter hint
        let default_sec = rec
            .sections
            .iter()
            .find(|s| !s.excerpt.is_empty())
            .or_else(|| rec.sections.first())
            .cloned();
        (default_sec, 0.0)
    } else {
        (None, 0.0)
    }
}

/// Format Layer-0 condensed TOC preview (`[章节: 第一章 ... | ... | 第四章 ...]`).
pub fn format_toc_preview(
    rec: &DocumentOutlineRecord,
    matched_section: Option<&DocSection>,
    max_chars: usize,
) -> String {
    if rec.headings.is_empty() {
        return String::new();
    }

    let top_headings: Vec<&str> = {
        let lvl1: Vec<&str> = rec
            .sections
            .iter()
            .filter(|s| s.level == 1)
            .map(|s| s.heading.as_str())
            .collect();
        if lvl1.len() >= 2 {
            lvl1
        } else {
            rec.headings.iter().map(String::as_str).collect()
        }
    };

    let matched_h = matched_section.map(|m| m.heading.as_str());
    let mut picked: Vec<String> = Vec::new();
    for &h in top_headings.iter().take(3) {
        picked.push(truncate_clean(h, 24));
    }
    if let Some(mh) = matched_h {
        let mh_short = truncate_clean(mh, 28);
        if !picked.iter().any(|p| p == &mh_short || mh.starts_with(p.trim_end_matches('…'))) {
            if top_headings.len() > 3 {
                picked.push("...".to_string());
            }
            picked.push(mh_short);
        }
    } else if top_headings.len() > 3 {
        picked.push(format!("...共{}节", rec.headings.len()));
    }

    let joined = format!("[章节: {}]", picked.join(" | "));
    truncate_clean(&joined, max_chars)
}

fn extract_doc_topic_tokens(query: &str) -> Vec<String> {
    static CHAP_STRIP_RE: OnceLock<Regex> = OnceLock::new();
    let chap_re = CHAP_STRIP_RE.get_or_init(|| {
        Regex::new(r"(?i)第\s*[一二三四五六七八九十百零〇两0-9]+\s*[章节篇部分回]|\b(?:chapter|section|part)\s*\d+\b")
            .expect("valid chap strip")
    });

    let mut cleaned = chap_re.replace_all(query, " ").into_owned();
    for phrase in [
        "帮我打开我的",
        "请帮我打开",
        "打开我的",
        "查看我的",
        "看看我的",
        "阅读我的",
        "帮我打开",
        "帮我查看",
        "帮我看看",
        "帮我看一下",
        "帮我找一下",
        "帮我找",
        "帮我看",
        "请打开",
        "请查看",
        "定位到",
        "跳转到",
        "打开",
        "查看",
        "看看",
        "阅读",
        "检索",
        "搜索",
        "查找",
        "我的",
        "那篇",
        "那份",
        "那个",
        "这篇",
        "这份",
        "这个",
        "里的",
        "中的",
        "里面",
        "关于",
        "内容",
        "部分",
        "章节",
        "大纲",
        "文件",
        "文档",
    ] {
        cleaned = cleaned.replace(phrase, " ");
    }

    cleaned
        .split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '，' | ',' | '。' | '？' | '?' | '！' | '!' | '：' | ':' | '；' | ';' | '《'
                        | '》' | '「' | '」' | '"' | '\'' | '(' | ')' | '（' | '）'
                )
        })
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.chars().count() >= 2)
        .map(String::from)
        .collect()
}

fn extract_section_topic_tokens(section: &str) -> Vec<String> {
    static CHAP_STRIP_RE: OnceLock<Regex> = OnceLock::new();
    let chap_re = CHAP_STRIP_RE.get_or_init(|| {
        Regex::new(r"(?i)第\s*[一二三四五六七八九十百零〇两0-9]+\s*[章节篇部分回]|\b(?:chapter|section|part)\s*\d+\b")
            .expect("valid sec chap strip")
    });
    let cleaned = chap_re.replace_all(section, " ");
    cleaned
        .split(|c: char| c.is_whitespace() || matches!(c, '/' | '|' | '，' | ',' | '、' | '：' | ':'))
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.chars().count() >= 2)
        .map(String::from)
        .collect()
}

fn split_compound_cjk_terms(term: &str) -> Vec<String> {
    let chars: Vec<char> = term.chars().collect();
    if chars.len() < 4 || !chars.iter().all(|c| !c.is_ascii()) {
        return Vec::new();
    }
    let mut parts = Vec::new();
    let mut idx = 0;
    while idx + 2 <= chars.len() {
        let two: String = chars[idx..idx + 2].iter().collect();
        parts.push(two);
        idx += 2;
    }
    if idx < chars.len() && chars.len() >= 3 {
        let tail: String = chars[chars.len() - 2..].iter().collect();
        if !parts.contains(&tail) {
            parts.push(tail);
        }
    }
    parts
}

fn collapse_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_clean(s: &str, max_chars: usize) -> String {
    let clean = collapse_whitespace(s);
    if clean.chars().count() <= max_chars {
        clean
    } else {
        let mut out: String = clean.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}
