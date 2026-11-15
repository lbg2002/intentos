#![forbid(unsafe_code)]

//! Resource Engine (WP05, §12):
//! - Desktop application indexing with Chinese Pinyin (full + initials) & aliases
//! - Authorized directory file indexing (+ SQLite FTS5) with forbidden-path exclusion
//! - Deterministic Website & Search URL resolution (default Google, strict http/https validation)

use crate::config::{AppConfig, SiteEntry};
use crate::db::IndexDb;
pub use crate::world_state::{
    AMBIGUITY_CONFIDENCE_MARGIN, ResourceKind, ResourceRef, ResourceResolution, ResourceResolver,
    compute_stable_resource_id,
};
use chrono::{TimeZone, Utc};
use intentos_fsops::SafeFsEngine;
use pinyin::ToPinyin;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRecord {
    pub app_id: String,
    pub name: String,
    pub generic_name: String,
    pub exec_cmd: String,
    pub keywords: String,
    pub pinyin_full: String,
    pub pinyin_init: String,
    pub aliases: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub name: String,
    pub stem: String,
    pub ext: String,
    pub category: String,
    pub parent_dir: String,
    pub size_bytes: u64,
    pub mtime_secs: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileSearchFilter {
    pub query: Option<String>,
    pub extensions: Vec<String>,
    pub category: Option<String>,
    pub directory_prefix: Option<String>,
    pub min_size_bytes: Option<u64>,
    pub max_size_bytes: Option<u64>,
    pub modified_after_secs: Option<i64>,
    pub modified_before_secs: Option<i64>,
    pub sort_by: FileSortOrder,
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileSortOrder {
    #[default]
    RelevanceAndRecent,
    RecentFirst,
    LargestFirst,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedWebTarget {
    pub url: String,
    pub title: String,
    pub source: String,
}

impl AppRecord {
    /// Convert an indexed `AppRecord` into a unified [`ResourceRef`] (`M2-B`).
    pub fn to_resource_ref(&self, confidence: f64, source: &str) -> ResourceRef {
        let uri = format!("app://{}", self.app_id);
        let desktop_path = {
            let p = Path::new(&self.source);
            if p.is_file() {
                Some(p.to_path_buf())
            } else {
                None
            }
        };
        ResourceRef {
            id: compute_stable_resource_id(ResourceKind::Application, &uri),
            kind: ResourceKind::Application,
            uri,
            path: desktop_path,
            display_name: self.name.clone(),
            project_id: None,
            source: source.to_string(),
            confidence: confidence.clamp(0.0, 1.0),
            last_verified_at: Utc::now(),
            metadata: json!({
                "app_id": self.app_id,
                "generic_name": self.generic_name,
                "exec_cmd": self.exec_cmd,
                "desktop_source": self.source,
            }),
        }
    }
}

impl FileRecord {
    /// Construct a `FileRecord` directly from a live on-disk file path.
    pub fn from_path(path: &Path) -> Option<Self> {
        let meta = fs::symlink_metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        let name = path.file_name()?.to_string_lossy().to_string();
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| name.clone());
        let ext = path
            .extension()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let category = classify_extension(&ext).to_string();
        let parent_dir = path
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let mtime_secs = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Some(Self {
            path: path.to_string_lossy().to_string(),
            name,
            stem,
            ext,
            category,
            parent_dir,
            size_bytes: meta.len(),
            mtime_secs,
        })
    }

    /// Infer semantic [`ResourceKind`] (`ExperimentResult`, `Document`, or `File`) from extension and path.
    pub fn infer_resource_kind(&self) -> ResourceKind {
        let ext = self.ext.to_ascii_lowercase();
        let stem_lc = self.stem.to_lowercase();
        let parent_lc = self.parent_dir.to_lowercase();
        let is_exp_ext = matches!(
            ext.as_str(),
            "csv" | "json" | "jsonl" | "tsv" | "md" | "txt" | "yaml" | "yml" | "log"
        );
        let has_exp_signal = [
            "exp",
            "experiment",
            "result",
            "results",
            "metric",
            "metrics",
            "eval",
            "bench",
            "benchmark",
            "ablation",
            "run_",
            "summary",
            "实验",
            "结果",
            "指标",
            "评测",
            "对比",
        ]
        .iter()
        .any(|kw| {
            stem_lc.contains(kw) || parent_lc.ends_with(kw) || parent_lc.contains(&format!("/{kw}"))
        });

        if is_exp_ext && has_exp_signal {
            return ResourceKind::ExperimentResult;
        }
        if matches!(
            ext.as_str(),
            "doc"
                | "docx"
                | "odt"
                | "rtf"
                | "pdf"
                | "md"
                | "markdown"
                | "tex"
                | "ppt"
                | "pptx"
                | "odp"
                | "xls"
                | "xlsx"
                | "ods"
        ) {
            return ResourceKind::Document;
        }
        ResourceKind::File
    }

    /// Convert a `FileRecord` into a unified [`ResourceRef`] (`M2-B`).
    pub fn to_resource_ref(
        &self,
        confidence: f64,
        source: &str,
        project_id: Option<String>,
    ) -> ResourceRef {
        let kind = self.infer_resource_kind();
        let uri = format!("file://{}", self.path);
        let verified_at = Utc
            .timestamp_opt(self.mtime_secs, 0)
            .single()
            .unwrap_or_else(Utc::now);
        ResourceRef {
            id: compute_stable_resource_id(kind, &uri),
            kind,
            uri,
            path: Some(PathBuf::from(&self.path)),
            display_name: self.name.clone(),
            project_id,
            source: source.to_string(),
            confidence: confidence.clamp(0.0, 1.0),
            last_verified_at: verified_at,
            metadata: json!({
                "ext": self.ext,
                "category": self.category,
                "parent_dir": self.parent_dir,
                "size_bytes": self.size_bytes,
                "mtime_secs": self.mtime_secs,
            }),
        }
    }
}

/// Strip Conda (`miniconda`, `anaconda`, `conda`) library directories from `LD_LIBRARY_PATH`
/// so spawned system GTK / Electron / Wayland desktop apps are never poisoned by Conda's libraries.
pub fn sanitize_desktop_ld_library_path(raw: &str) -> Option<String> {
    let kept: Vec<&str> = raw
        .split(':')
        .map(str::trim)
        .filter(|seg| {
            if seg.is_empty() {
                return false;
            }
            let lc = seg.to_ascii_lowercase();
            !(lc.contains("miniconda") || lc.contains("anaconda") || lc.contains("conda"))
        })
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(kept.join(":"))
    }
}

/// Convert mixed Chinese/ASCII text to `(pinyin_full, pinyin_initials)` lowercase strings.
pub fn to_pinyin_pair(input: &str) -> (String, String) {
    let mut full = String::with_capacity(input.len() * 2);
    let mut init = String::with_capacity(input.len());
    for ch in input.chars() {
        if let Some(py) = ch.to_pinyin() {
            let plain = py.plain();
            full.push_str(plain);
            if let Some(first) = plain.chars().next() {
                init.push(first);
            }
        } else if ch.is_ascii_alphanumeric() {
            let lc = ch.to_ascii_lowercase();
            full.push(lc);
            init.push(lc);
        } else if ch == '_' || ch == '-' || ch == '.' {
            full.push(ch);
            init.push(ch);
        }
    }
    (full, init)
}

pub struct ResourceEngine {
    index_db: Arc<IndexDb>,
    fs_engine: Arc<SafeFsEngine>,
    app_config: AppConfig,
}

impl ResourceEngine {
    pub fn new(
        index_db: Arc<IndexDb>,
        fs_engine: Arc<SafeFsEngine>,
        app_config: AppConfig,
    ) -> Self {
        Self {
            index_db,
            fs_engine,
            app_config,
        }
    }

    pub fn app_config(&self) -> &AppConfig {
        &self.app_config
    }

    pub fn index_db(&self) -> &Arc<IndexDb> {
        &self.index_db
    }

    pub fn fs_engine(&self) -> &Arc<SafeFsEngine> {
        &self.fs_engine
    }

    pub fn authorized_roots(&self) -> &[PathBuf] {
        self.fs_engine.authorized_roots()
    }

    /// Return all indexed `.desktop` application records from `index.db` without disk re-scanning.
    pub fn list_indexed_apps(&self) -> Vec<AppRecord> {
        let Ok(conn) = self.index_db.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare(
            "SELECT app_id, name, generic_name, exec_cmd, keywords, pinyin_full, pinyin_init, aliases, source FROM apps",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([], |r| {
            Ok(AppRecord {
                app_id: r.get(0)?,
                name: r.get(1)?,
                generic_name: r.get(2)?,
                exec_cmd: r.get(3)?,
                keywords: r.get(4)?,
                pinyin_full: r.get(5)?,
                pinyin_init: r.get(6)?,
                aliases: r.get(7)?,
                source: r.get(8)?,
            })
        }) else {
            return Vec::new();
        };
        rows.flatten().collect()
    }

    /// Collect verified live `FileRecord`s across `index.db` and authorized directories (plus optional
    /// non-forbidden `extra_dirs`), ensuring newly created workspace/experiment files are immediately visible
    /// without full daemon re-indexing while strictly filtering out forbidden paths and symlinks (`M2-B`).
    pub fn collect_live_or_indexed_files(&self, extra_dirs: &[PathBuf]) -> Vec<FileRecord> {
        const MAX_LIVE_SCAN_FILES: usize = 5_000;
        let mut by_path: HashMap<String, FileRecord> = HashMap::new();

        // 1. Seed from `index.db`, verifying on-disk existence & refreshing metadata
        if let Ok(conn) = self.index_db.conn.lock()
            && let Ok(mut stmt) = conn.prepare(
                "SELECT path, name, stem, ext, category, parent_dir, size_bytes, mtime_secs FROM files LIMIT 5000",
            )
            && let Ok(rows) = stmt.query_map([], |r| {
                Ok(FileRecord {
                    path: r.get(0)?,
                    name: r.get(1)?,
                    stem: r.get(2)?,
                    ext: r.get(3)?,
                    category: r.get(4)?,
                    parent_dir: r.get(5)?,
                    size_bytes: r.get::<_, i64>(6)?.max(0) as u64,
                    mtime_secs: r.get(7)?,
                })
            })
        {
            for rec in rows.flatten() {
                let p = Path::new(&rec.path);
                if self.fs_engine.is_forbidden(p) {
                    continue;
                }
                if let Some(fresh) = FileRecord::from_path(p) {
                    by_path.insert(fresh.path.clone(), fresh);
                }
            }
        }

        // 2. Bounded incremental walk over authorized roots + authorized extra_dirs
        let mut roots: Vec<PathBuf> = self.fs_engine.authorized_roots().to_vec();
        for extra in extra_dirs {
            if !self.fs_engine.is_forbidden(extra)
                && self
                    .fs_engine
                    .authorized_roots()
                    .iter()
                    .any(|r| extra.starts_with(r))
                && !roots.contains(extra)
            {
                roots.push(extra.clone());
            }
        }

        'scan: for root in &roots {
            if !root.exists() || self.fs_engine.is_forbidden(root) {
                continue;
            }
            for entry in WalkDir::new(root)
                .max_depth(5)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    let name = e.file_name().to_string_lossy();
                    if e.depth() > 0
                        && (name == ".git"
                            || name == "target"
                            || name == "node_modules"
                            || name == ".cache")
                    {
                        return false;
                    }
                    !self.fs_engine.is_forbidden(e.path())
                })
            {
                let Ok(entry) = entry else { continue };
                if entry.depth() == 0 || entry.path_is_symlink() {
                    continue;
                }
                let p = entry.path();
                let key = p.to_string_lossy().to_string();
                if let std::collections::hash_map::Entry::Vacant(slot) = by_path.entry(key)
                    && let Some(rec) = FileRecord::from_path(p)
                {
                    slot.insert(rec);
                }
                if by_path.len() >= MAX_LIVE_SCAN_FILES {
                    break 'scan;
                }
            }
        }

        let mut list: Vec<FileRecord> = by_path.into_values().collect();
        list.sort_by(|a, b| {
            b.mtime_secs
                .cmp(&a.mtime_secs)
                .then_with(|| a.path.cmp(&b.path))
        });
        list
    }

    /// Scan desktop entries, authorized directories, installed fonts, and browser bookmarks into `index.db`.
    pub fn refresh_all(&self) -> anyhow::Result<(usize, usize)> {
        let apps = self.index_applications()?;
        let files = self.index_authorized_files()?;
        let _ = self.index_fonts();
        let _ = self.index_bookmarks();
        Ok((apps, files))
    }

    /// Index installed font families via `fc-list : family` plus standard Ubuntu fallback catalog (`A11c`).
    pub fn index_fonts(&self) -> usize {
        let mut set = std::collections::BTreeSet::new();
        if let Some(fc_bin) = intentos_capability_sdk::resolve_trusted_executable("fc-list")
            && let Ok(out) = std::process::Command::new(fc_bin)
                .args([":", "family"])
                .output()
            && out.status.success()
        {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                for fam in line.split(',') {
                    let clean = fam.trim();
                    if !clean.is_empty() && clean.len() <= 80 {
                        set.insert(clean.to_string());
                    }
                }
            }
        }
        if self.app_config.allow_simulated_hardware_fallback || set.is_empty() {
            for std_font in [
                "Ubuntu",
                "Ubuntu Sans",
                "Ubuntu Mono",
                "DejaVu Sans",
                "DejaVu Sans Mono",
                "Liberation Sans",
                "Liberation Mono",
                "Noto Sans CJK SC",
                "Noto Serif CJK SC",
                "Source Han Sans CN",
                "JetBrains Mono",
                "Fira Code",
                "Cantarell",
            ] {
                set.insert(std_font.to_string());
            }
        }
        let list: Vec<String> = set.into_iter().collect();
        self.index_db.replace_fonts(&list);
        list.len()
    }

    pub fn list_fonts(&self, query: Option<&str>) -> Vec<String> {
        let all = self.index_db.list_fonts();
        match query.map(str::trim).filter(|q| !q.is_empty()) {
            None => all,
            Some(q) => {
                let ql = q.to_ascii_lowercase();
                all.into_iter()
                    .filter(|f| f.to_ascii_lowercase().contains(&ql))
                    .collect()
            }
        }
    }

    /// Validate a requested font family against installed `fc-list` fonts; reject metacharacters or unknown names and return close suggestions (`A11c`, §19.2).
    pub fn validate_or_suggest_font(&self, family_hint: &str) -> Result<String, Vec<String>> {
        let trimmed = family_hint.trim();
        let all = self.index_db.list_fonts();
        if trimmed.is_empty()
            || trimmed.chars().any(|c| {
                c.is_control()
                    || matches!(
                        c,
                        ';' | '|' | '&' | '`' | '$' | '\\' | '\'' | '"' | '<' | '>'
                    )
            })
        {
            let defaults: Vec<String> = all.into_iter().take(4).collect();
            return Err(defaults);
        }

        let ql = trimmed.to_ascii_lowercase();
        if let Some(exact) = all.iter().find(|f| f.to_ascii_lowercase() == ql) {
            return Ok(exact.clone());
        }

        let tokens: Vec<&str> = ql.split_whitespace().filter(|t| t.len() >= 2).collect();
        let mut scored: Vec<(String, usize)> = all
            .iter()
            .filter_map(|f| {
                let fl = f.to_ascii_lowercase();
                let mut sc = 0;
                if fl.contains(&ql) || ql.contains(&fl) {
                    sc += 5;
                }
                for tok in &tokens {
                    if fl.contains(tok) {
                        sc += 3;
                    }
                }
                if ql.contains("mono") && fl.contains("mono") {
                    sc += 4;
                }
                if sc > 0 { Some((f.clone(), sc)) } else { None }
            })
            .collect();
        scored.sort_by_key(|a| std::cmp::Reverse(a.1));
        let mut suggestions: Vec<String> = scored.into_iter().take(4).map(|(f, _)| f).collect();
        if suggestions.is_empty() {
            suggestions = all
                .into_iter()
                .filter(|f| {
                    let fl = f.to_ascii_lowercase();
                    fl.contains("ubuntu") || fl.contains("noto") || fl.contains("jetbrains")
                })
                .take(4)
                .collect();
        }
        Err(suggestions)
    }

    /// Read-only Chromium/Chrome Bookmarks JSON indexer (never reads cookies/history/passwords, §12).
    pub fn index_bookmarks(&self) -> usize {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
        let candidates = [
            (
                PathBuf::from(&home).join(".config/google-chrome/Default/Bookmarks"),
                "chrome",
            ),
            (
                PathBuf::from(&home).join(".config/chromium/Default/Bookmarks"),
                "chromium",
            ),
        ];
        let mut collected = Vec::new();
        for (path, browser) in candidates {
            if let Ok(raw) = fs::read_to_string(&path)
                && let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw)
                && let Some(roots) = val.get("roots").and_then(|r| r.as_object())
            {
                for node in roots.values() {
                    collect_chromium_bookmarks(node, browser, &mut collected);
                }
            }
        }
        self.index_db.replace_bookmarks(&collected);
        collected.len()
    }

    pub fn search_bookmarks(&self, query: &str, limit: usize) -> Vec<(String, String, String)> {
        self.index_db.search_bookmarks(query, limit)
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let Ok(conn) = self.index_db.conn.lock() else {
            return (0, 0, self.app_config.web.sites.len());
        };
        let apps: i64 = conn
            .query_row("SELECT COUNT(*) FROM apps", [], |r| r.get(0))
            .unwrap_or(0);
        let files: i64 = conn
            .query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))
            .unwrap_or(0);
        (
            apps as usize,
            files as usize,
            self.app_config.web.sites.len(),
        )
    }

    pub fn index_applications(&self) -> anyhow::Result<usize> {
        self.index_applications_with_extra_dirs(&[])
    }

    pub fn index_applications_with_extra_dirs(
        &self,
        extra_dirs: &[PathBuf],
    ) -> anyhow::Result<usize> {
        let mut discovered: HashMap<String, AppRecord> = HashMap::new();
        let alias_table = builtin_app_aliases();

        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
        let mut app_dirs = vec![
            PathBuf::from("/usr/share/applications"),
            PathBuf::from("/usr/local/share/applications"),
            PathBuf::from("/var/lib/flatpak/exports/share/applications"),
            PathBuf::from("/var/lib/snapd/desktop/applications"),
            PathBuf::from(&home).join(".local/share/applications"),
        ];
        // Support hermetic test `.desktop` fixtures placed alongside a temp workspace/config base
        let temp_root = std::env::temp_dir();
        for root in self.fs_engine.authorized_roots() {
            if root.starts_with(&temp_root)
                && let Some(base) = root.parent()
            {
                for sub in [
                    "applications",
                    "mock_applications",
                    "config/applications",
                    "data/applications",
                ] {
                    let candidate = base.join(sub);
                    if !app_dirs.contains(&candidate) {
                        app_dirs.push(candidate);
                    }
                }
            }
        }
        for extra in extra_dirs {
            if !app_dirs.contains(extra) {
                app_dirs.push(extra.clone());
            }
        }

        for dir in &app_dirs {
            if !dir.exists() {
                continue;
            }
            if let Ok(rd) = fs::read_dir(dir) {
                for entry in rd.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) != Some("desktop") {
                        continue;
                    }
                    let app_id = match path.file_name().map(|s| s.to_string_lossy().to_string()) {
                        Some(id) if !id.is_empty() => id,
                        _ => continue,
                    };
                    match parse_desktop_entry(&path, &alias_table) {
                        Some(mut rec) => {
                            if let Some(prev) = discovered.get(&app_id) {
                                if rec.generic_name.is_empty() && !prev.generic_name.is_empty() {
                                    rec.generic_name = prev.generic_name.clone();
                                }
                                if rec.keywords.is_empty() && !prev.keywords.is_empty() {
                                    rec.keywords = prev.keywords.clone();
                                }
                                let combined_py =
                                    format!("{} {} {}", rec.name, rec.aliases, rec.generic_name);
                                let (pf, pi) = to_pinyin_pair(&combined_py);
                                rec.pinyin_full = pf;
                                rec.pinyin_init = pi;
                            }
                            discovered.insert(rec.app_id.clone(), rec);
                        }
                        None => {
                            // User override in `~/.local/share/applications` with `NoDisplay=true` / `Hidden=true` hides system entry
                            if is_explicitly_hidden_desktop_entry(&path) {
                                discovered.remove(&app_id);
                            }
                        }
                    }
                }
            }
        }

        // Seed standard developer desktop catalog entries if missing (for headless / minimal test hosts)
        if self.app_config.allow_simulated_hardware_fallback {
            for seed in standard_developer_app_catalog() {
                discovered.entry(seed.app_id.clone()).or_insert(seed);
            }
        }

        let mut conn = self.index_db.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM apps", [])?;
        for rec in discovered.values() {
            tx.execute(
                "INSERT INTO apps (app_id, name, generic_name, exec_cmd, keywords, pinyin_full, pinyin_init, aliases, source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    rec.app_id,
                    rec.name,
                    rec.generic_name,
                    rec.exec_cmd,
                    rec.keywords,
                    rec.pinyin_full,
                    rec.pinyin_init,
                    rec.aliases,
                    rec.source,
                ],
            )?;
        }
        tx.commit()?;
        Ok(discovered.len())
    }

    pub fn index_authorized_files(&self) -> anyhow::Result<usize> {
        let mut records = Vec::new();
        const MAX_INDEXED_FILES: usize = 250_000;

        'roots: for root in self.fs_engine.authorized_roots() {
            if !root.exists() {
                continue;
            }
            for entry in WalkDir::new(root)
                .max_depth(8)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    let name = e.file_name().to_string_lossy();
                    if e.depth() > 0
                        && (name == ".git"
                            || name == "target"
                            || name == "node_modules"
                            || name == ".cache")
                    {
                        return false;
                    }
                    !self.fs_engine.is_forbidden(e.path())
                })
            {
                let Ok(entry) = entry else { continue };
                if entry.depth() == 0 || entry.path_is_symlink() {
                    continue;
                }
                let Ok(meta) = entry.metadata() else { continue };
                if !meta.is_file() {
                    continue;
                }
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                let stem = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| name.clone());
                let ext = path
                    .extension()
                    .map(|s| s.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default();
                let category = classify_extension(&ext).to_string();
                let parent_dir = path
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let mtime_secs = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let (py_full, py_init) = to_pinyin_pair(&name);
                records.push((
                    path.to_string_lossy().to_string(),
                    name,
                    stem,
                    ext,
                    category,
                    parent_dir,
                    meta.len() as i64,
                    mtime_secs,
                    py_full,
                    py_init,
                ));
                if records.len() >= MAX_INDEXED_FILES {
                    break 'roots;
                }
            }
        }

        let mut conn = self.index_db.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM files", [])?;
        tx.execute("DELETE FROM files_fts", [])?;
        {
            let mut ins_file = tx.prepare(
                "INSERT OR REPLACE INTO files (path, name, stem, ext, category, parent_dir, size_bytes, mtime_secs, pinyin_full, pinyin_init)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            let mut ins_fts = tx.prepare(
                "INSERT INTO files_fts (path, name, pinyin_full, pinyin_init) VALUES (?1, ?2, ?3, ?4)",
            )?;
            for r in &records {
                ins_file.execute(params![r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7, r.8, r.9])?;
                ins_fts.execute(params![r.0, r.1, r.8, r.9])?;
            }
        }
        tx.commit()?;
        Ok(records.len())
    }

    /// Search indexed applications with exact > alias > stem > bidirectional pinyin/keyword > prefix > substring scoring + frecency.
    pub fn search_apps(&self, query: &str, limit: usize) -> Vec<(AppRecord, f64)> {
        let raw_q = query
            .trim()
            .trim_matches(['"', '\'', '“', '”', '「', '」', '`']);
        let q = raw_q.to_lowercase();
        if q.is_empty() {
            return Vec::new();
        }
        let q_stem = q.strip_suffix(".desktop").unwrap_or(&q);
        let q_nospace: String = q.chars().filter(|c| !c.is_whitespace()).collect();
        let (q_py_full, _q_py_init) = to_pinyin_pair(raw_q);
        let core_opt = strip_app_query_suffix(&q);
        let core_py_opt = core_opt.map(|c| (c, to_pinyin_pair(c).0));

        let mut scored = Vec::new();
        {
            let Ok(conn) = self.index_db.conn.lock() else {
                return Vec::new();
            };
            let Ok(mut stmt) = conn.prepare(
                "SELECT app_id, name, generic_name, exec_cmd, keywords, pinyin_full, pinyin_init, aliases, source FROM apps",
            ) else {
                return Vec::new();
            };
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok(AppRecord {
                    app_id: r.get(0)?,
                    name: r.get(1)?,
                    generic_name: r.get(2)?,
                    exec_cmd: r.get(3)?,
                    keywords: r.get(4)?,
                    pinyin_full: r.get(5)?,
                    pinyin_init: r.get(6)?,
                    aliases: r.get(7)?,
                    source: r.get(8)?,
                })
            }) {
                for rec in rows.flatten() {
                    let base_score = score_app_record(
                        &rec,
                        &q,
                        q_stem,
                        &q_nospace,
                        &q_py_full,
                        core_py_opt.as_ref().map(|(c, cp)| (*c, cp.as_str())),
                    );
                    if base_score > 0.0 {
                        scored.push((rec, base_score));
                    }
                }
            }
        }

        for (rec, sc) in &mut scored {
            *sc += self
                .index_db
                .get_frecency_boost(&format!("app:{}", rec.app_id));
        }
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.app_id.cmp(&b.0.app_id))
        });
        scored.truncate(limit);
        scored
    }

    /// Resolve a user/LLM app hint (`.desktop` ID, case-insensitive stem, Chinese/English name, or pinyin)
    /// to the best indexed `AppRecord`.
    pub fn resolve_best_app(&self, hint: &str) -> Option<AppRecord> {
        let clean = hint
            .trim()
            .trim_matches(['"', '\'', '“', '”', '「', '」', '`'])
            .trim();
        if clean.is_empty() {
            return None;
        }
        let clean_stem = clean
            .strip_suffix(".desktop")
            .or_else(|| clean.strip_suffix(".DESKTOP"))
            .unwrap_or(clean);

        if let Ok(conn) = self.index_db.conn.lock()
            && let Ok(mut stmt) = conn.prepare(
                "SELECT app_id, name, generic_name, exec_cmd, keywords, pinyin_full, pinyin_init, aliases, source FROM apps",
            )
            && let Ok(rows) = stmt.query_map([], |r| {
                Ok(AppRecord {
                    app_id: r.get(0)?,
                    name: r.get(1)?,
                    generic_name: r.get(2)?,
                    exec_cmd: r.get(3)?,
                    keywords: r.get(4)?,
                    pinyin_full: r.get(5)?,
                    pinyin_init: r.get(6)?,
                    aliases: r.get(7)?,
                    source: r.get(8)?,
                })
            })
        {
            let mut exact_matches: Vec<AppRecord> = rows
                .flatten()
                .filter(|rec| {
                    let id_stem = rec.app_id.trim_end_matches(".desktop");
                    rec.app_id.eq_ignore_ascii_case(clean)
                        || id_stem.eq_ignore_ascii_case(clean_stem)
                })
                .collect();
            if !exact_matches.is_empty() {
                exact_matches.sort_by(|a, b| {
                    let a_real = Path::new(&a.source).is_file();
                    let b_real = Path::new(&b.source).is_file();
                    b_real.cmp(&a_real).then_with(|| a.app_id.cmp(&b.app_id))
                });
                return exact_matches.into_iter().next();
            }
        }

        self.search_apps(clean, 1)
            .into_iter()
            .find(|(_, sc)| *sc >= 60.0)
            .map(|(rec, _)| rec)
    }

    /// Resolve an `AppRecord` to a concrete on-disk `.desktop` entry when running on a real desktop
    /// (e.g. upgrading a synthetic `"catalog"` seed like `code.desktop` to `/usr/share/applications/com.microsoft.VSCode.desktop`).
    pub fn resolve_installed_desktop_app(
        &self,
        rec: &AppRecord,
        raw_hint: &str,
    ) -> Option<AppRecord> {
        if Path::new(&rec.source).is_file() {
            return Some(rec.clone());
        }

        let exec_stem = extract_binary_stem(&rec.exec_cmd).to_ascii_lowercase();
        let rec_name_lc = rec.name.to_lowercase();

        if let Ok(conn) = self.index_db.conn.lock()
            && let Ok(mut stmt) = conn.prepare(
                "SELECT app_id, name, generic_name, exec_cmd, keywords, pinyin_full, pinyin_init, aliases, source FROM apps",
            )
            && let Ok(rows) = stmt.query_map([], |r| {
                Ok(AppRecord {
                    app_id: r.get(0)?,
                    name: r.get(1)?,
                    generic_name: r.get(2)?,
                    exec_cmd: r.get(3)?,
                    keywords: r.get(4)?,
                    pinyin_full: r.get(5)?,
                    pinyin_init: r.get(6)?,
                    aliases: r.get(7)?,
                    source: r.get(8)?,
                })
            })
        {
            let on_disk: Vec<AppRecord> = rows
                .flatten()
                .filter(|r| Path::new(&r.source).is_file())
                .collect();

            if let Some(found) = on_disk.iter().find(|r| {
                r.app_id.eq_ignore_ascii_case(&rec.app_id)
                    || r.name.to_lowercase() == rec_name_lc
                    || (!exec_stem.is_empty()
                        && extract_binary_stem(&r.exec_cmd).eq_ignore_ascii_case(&exec_stem))
            }) {
                return Some(found.clone());
            }
        }

        for candidate_q in [raw_hint, rec.name.as_str()] {
            if candidate_q.trim().is_empty() {
                continue;
            }
            for (cand, sc) in self.search_apps(candidate_q, 5) {
                if sc >= 75.0 && Path::new(&cand.source).is_file() {
                    return Some(cand);
                }
            }
        }
        None
    }

    /// Search authorized files with name/pinyin/extension/time/size/location filtering.
    pub fn search_files(&self, filter: &FileSearchFilter) -> Vec<(FileRecord, f64)> {
        let limit = if filter.limit == 0 { 20 } else { filter.limit };
        let q = filter
            .query
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());

        let mut sql = String::from(
            "SELECT path, name, stem, ext, category, parent_dir, size_bytes, mtime_secs, pinyin_full, pinyin_init
             FROM files WHERE 1=1",
        );
        let mut bind_vals: Vec<rusqlite::types::Value> = Vec::new();

        if let Some(ref dir_pref) = filter.directory_prefix {
            sql.push_str(" AND (parent_dir = ? OR parent_dir LIKE ?)");
            bind_vals.push(rusqlite::types::Value::Text(dir_pref.clone()));
            bind_vals.push(rusqlite::types::Value::Text(format!(
                "{}/%",
                dir_pref.trim_end_matches('/')
            )));
        }
        if let Some(ref cat) = filter.category {
            sql.push_str(" AND category = ?");
            bind_vals.push(rusqlite::types::Value::Text(cat.clone()));
        }
        if !filter.extensions.is_empty() {
            let placeholders = std::iter::repeat_n("?", filter.extensions.len())
                .collect::<Vec<_>>()
                .join(",");
            sql.push_str(&format!(" AND ext IN ({})", placeholders));
            for ext in &filter.extensions {
                bind_vals.push(rusqlite::types::Value::Text(
                    ext.trim_start_matches('.').to_ascii_lowercase(),
                ));
            }
        }
        if let Some(min_sz) = filter.min_size_bytes {
            sql.push_str(" AND size_bytes >= ?");
            bind_vals.push(rusqlite::types::Value::Integer(min_sz as i64));
        }
        if let Some(max_sz) = filter.max_size_bytes {
            sql.push_str(" AND size_bytes <= ?");
            bind_vals.push(rusqlite::types::Value::Integer(max_sz as i64));
        }
        if let Some(after) = filter.modified_after_secs {
            sql.push_str(" AND mtime_secs >= ?");
            bind_vals.push(rusqlite::types::Value::Integer(after));
        }
        if let Some(before) = filter.modified_before_secs {
            sql.push_str(" AND mtime_secs <= ?");
            bind_vals.push(rusqlite::types::Value::Integer(before));
        }
        if let Some(ref q_str) = q {
            let like = format!("%{}%", q_str);
            sql.push_str(" AND (LOWER(name) LIKE ? OR pinyin_full LIKE ? OR pinyin_init LIKE ?)");
            bind_vals.push(rusqlite::types::Value::Text(like.clone()));
            bind_vals.push(rusqlite::types::Value::Text(like.clone()));
            bind_vals.push(rusqlite::types::Value::Text(like));
        }

        match filter.sort_by {
            FileSortOrder::LargestFirst => sql.push_str(" ORDER BY size_bytes DESC LIMIT 200"),
            _ => sql.push_str(" ORDER BY mtime_secs DESC LIMIT 200"),
        }

        let mut candidates = Vec::new();
        if let Ok(conn) = self.index_db.conn.lock()
            && let Ok(mut stmt) = conn.prepare(&sql)
        {
            let params_refs: Vec<&dyn rusqlite::ToSql> = bind_vals
                .iter()
                .map(|v| v as &dyn rusqlite::ToSql)
                .collect();
            if let Ok(rows) = stmt.query_map(params_refs.as_slice(), |r| {
                Ok((
                    FileRecord {
                        path: r.get(0)?,
                        name: r.get(1)?,
                        stem: r.get(2)?,
                        ext: r.get(3)?,
                        category: r.get(4)?,
                        parent_dir: r.get(5)?,
                        size_bytes: r.get::<_, i64>(6)?.max(0) as u64,
                        mtime_secs: r.get(7)?,
                    },
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                ))
            }) {
                for item in rows.flatten() {
                    candidates.push(item);
                }
            }
        }

        let now = chrono::Utc::now().timestamp();
        let mut scored: Vec<(FileRecord, f64)> = candidates
            .into_iter()
            .map(|(rec, py_full, py_init)| {
                let mut score = match filter.sort_by {
                    FileSortOrder::LargestFirst => (rec.size_bytes as f64).ln_1p() * 5.0,
                    FileSortOrder::RecentFirst => {
                        let age_h = ((now - rec.mtime_secs).max(0) as f64) / 3600.0;
                        90.0 / (1.0 + age_h / 24.0)
                    }
                    FileSortOrder::RelevanceAndRecent => {
                        let age_h = ((now - rec.mtime_secs).max(0) as f64) / 3600.0;
                        let recency = 15.0 / (1.0 + age_h / 48.0);
                        let name_score = if let Some(ref q_str) = q {
                            let name_lc = rec.name.to_ascii_lowercase();
                            let stem_lc = rec.stem.to_ascii_lowercase();
                            if name_lc == *q_str || stem_lc == *q_str {
                                98.0
                            } else if name_lc.starts_with(q_str) || stem_lc.starts_with(q_str) {
                                88.0
                            } else if py_init == *q_str || py_full == *q_str {
                                84.0
                            } else if py_init.starts_with(q_str) || py_full.starts_with(q_str) {
                                76.0
                            } else {
                                66.0
                            }
                        } else {
                            70.0
                        };
                        name_score + recency
                    }
                };
                score += self
                    .index_db
                    .get_frecency_boost(&format!("file:{}", rec.path));
                (rec, score)
            })
            .collect();

        if filter.sort_by == FileSortOrder::RelevanceAndRecent {
            scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        }
        scored.truncate(limit);
        scored
    }

    /// Resolve a site name, alias, localhost address, or explicit URL safely (§4.7).
    pub fn resolve_web_target(
        &self,
        raw_target: &str,
    ) -> Result<Option<ResolvedWebTarget>, String> {
        let t = raw_target.trim();
        if t.is_empty() {
            return Ok(None);
        }
        let lower = t.to_ascii_lowercase();

        // Strictly reject dangerous schemes (§4.7, §19.2)
        for bad_scheme in [
            "javascript:",
            "data:",
            "file:",
            "vbscript:",
            "about:",
            "chrome:",
        ] {
            if lower.starts_with(bad_scheme) {
                return Err(format!(
                    "安全策略拒绝打开非 HTTP(S) 协议地址: {}",
                    bad_scheme
                ));
            }
        }

        // 1. Explicit http:// or https:// URL
        if lower.starts_with("https://") || lower.starts_with("http://") {
            if t.contains(char::is_whitespace) {
                return Ok(None);
            }
            return Ok(Some(ResolvedWebTarget {
                url: t.to_string(),
                title: t.to_string(),
                source: "explicit_url".into(),
            }));
        }

        // 2. Localhost / loopback / LAN dev address (e.g. localhost:3000, 127.0.0.1:8080, 192.168.1.1)
        if lower == "localhost"
            || lower.starts_with("localhost:")
            || lower.starts_with("localhost/")
            || lower.starts_with("127.0.0.1")
            || lower.starts_with("192.168.")
            || lower.starts_with("10.")
        {
            let url = format!("http://{}", t);
            return Ok(Some(ResolvedWebTarget {
                url,
                title: format!("本地地址 {}", t),
                source: "local_address".into(),
            }));
        }

        // 3. Site alias registry (exact match on id or names)
        for site in &self.app_config.web.sites {
            if site.id.eq_ignore_ascii_case(t)
                || site.names.iter().any(|n| n.eq_ignore_ascii_case(t))
            {
                return Ok(Some(ResolvedWebTarget {
                    url: site.url.clone(),
                    title: site
                        .names
                        .first()
                        .cloned()
                        .unwrap_or_else(|| site.id.clone()),
                    source: "site_registry".into(),
                }));
            }
        }

        // 3b. Indexed browser bookmarks (exact title match)
        for (b_url, b_title, browser) in self.index_db.search_bookmarks(t, 4) {
            if b_title.eq_ignore_ascii_case(t) {
                return Ok(Some(ResolvedWebTarget {
                    url: b_url,
                    title: b_title,
                    source: format!("bookmark:{}", browser),
                }));
            }
        }

        // 4. Bare domain name like github.com or docs.rs/tokio (must have known-looking TLD and no spaces)
        if !t.contains(char::is_whitespace) && looks_like_domain(t) {
            return Ok(Some(ResolvedWebTarget {
                url: format!("https://{}", t),
                title: t.to_string(),
                source: "domain".into(),
            }));
        }

        Ok(None)
    }

    pub fn find_site(&self, name_or_alias: &str) -> Option<&SiteEntry> {
        let q = name_or_alias.trim();
        self.app_config.web.sites.iter().find(|s| {
            s.id.eq_ignore_ascii_case(q) || s.names.iter().any(|n| n.eq_ignore_ascii_case(q))
        })
    }

    /// Build a properly URL-encoded web search URL (default Google, D21, §4.7).
    pub fn build_search_url(&self, query: &str, engine_override: Option<&str>) -> (String, String) {
        let engine_id = engine_override.unwrap_or(&self.app_config.web.default_search);
        let engine = self
            .app_config
            .web
            .search_engines
            .iter()
            .find(|e| e.id.eq_ignore_ascii_case(engine_id))
            .or_else(|| self.app_config.web.search_engines.first());

        let encoded = urlencoding::encode(query.trim());
        match engine {
            Some(e) => (e.url.replace("{query}", &encoded), e.name.clone()),
            None => (
                format!("https://www.google.com/search?q={}", encoded),
                "Google".to_string(),
            ),
        }
    }

    /// Build a properly URL-encoded site-specific search URL.
    pub fn build_site_search_url(&self, site_key: &str, query: &str) -> Option<(String, String)> {
        let site = self.find_site(site_key)?;
        let tpl = site.search.as_ref()?;
        let encoded = urlencoding::encode(query.trim());
        let title = site
            .names
            .first()
            .cloned()
            .unwrap_or_else(|| site.id.clone());
        Some((tpl.replace("{query}", &encoded), title))
    }

    /// Resolve XDG / Chinese folder names (`下载`, `文档`, `桌面`, `代码`) to real authorized directories (A03).
    pub fn resolve_named_directory(&self, hint: &str) -> Option<PathBuf> {
        let h = hint.trim().to_ascii_lowercase();
        let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/home/user".into()));

        let candidates: &[(&[&str], &[&str])] = &[
            (&["下载", "downloads", "download"], &["Downloads", "下载"]),
            (
                &["文档", "documents", "docs", "doc"],
                &["Documents", "文档"],
            ),
            (&["桌面", "desktop"], &["Desktop", "桌面"]),
            (
                &["代码", "code", "项目", "workspace", "intentos"],
                &["intentos", "code", "workspace"],
            ),
        ];

        for (triggers, folder_names) in candidates {
            if triggers.iter().any(|t| h.contains(t)) {
                // First match directly against configured authorized_roots by directory name
                for root in self.fs_engine.authorized_roots() {
                    if let Some(leaf) = root.file_name().and_then(|s| s.to_str())
                        && folder_names
                            .iter()
                            .any(|fnm| leaf.eq_ignore_ascii_case(fnm))
                    {
                        return Some(root.clone());
                    }
                }
                for folder in *folder_names {
                    let p = home.join(folder);
                    if p.exists()
                        && self
                            .fs_engine
                            .authorized_roots()
                            .iter()
                            .any(|r| p.starts_with(r))
                    {
                        return Some(p);
                    }
                }
                for folder in *folder_names {
                    let p = home.join(folder);
                    if self
                        .fs_engine
                        .authorized_roots()
                        .iter()
                        .any(|r| p.starts_with(r))
                    {
                        return Some(p);
                    }
                }
            }
        }
        None
    }
}

fn collect_chromium_bookmarks(
    node: &serde_json::Value,
    browser: &str,
    out: &mut Vec<(String, String, String)>,
) {
    if out.len() >= 2000 {
        return;
    }
    if let Some(url) = node.get("url").and_then(|v| v.as_str()) {
        let lower = url.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            let title = node
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(url)
                .to_string();
            out.push((url.to_string(), title, browser.to_string()));
        }
    }
    if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
        for ch in children {
            collect_chromium_bookmarks(ch, browser, out);
        }
    }
}

fn looks_like_domain(s: &str) -> bool {
    let host = s.split('/').next().unwrap_or(s);
    if !host.contains('.') || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    let tlds = [
        "com", "org", "net", "io", "dev", "rs", "ai", "cn", "edu", "gov", "app", "me", "co", "sh",
    ];
    let last = host.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    // Avoid confusing common document extensions (`report.docx`, `notes.md`, `paper.pdf`) with websites!
    tlds.contains(&last.as_str())
}

fn classify_extension(ext: &str) -> &'static str {
    match ext {
        "pdf" => "pdf",
        "doc" | "docx" | "odt" | "rtf" => "word",
        "xls" | "xlsx" | "csv" | "ods" => "spreadsheet",
        "ppt" | "pptx" | "odp" => "presentation",
        "md" | "markdown" | "txt" | "rst" => "markdown",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" => "image",
        "mp4" | "mkv" | "mov" | "webm" | "avi" => "video",
        "zip" | "tar" | "gz" | "xz" | "7z" | "rar" | "bz2" => "archive",
        "rs" | "py" | "ts" | "tsx" | "js" | "go" | "c" | "cpp" | "h" | "java" | "toml" | "yaml"
        | "yml" | "json" | "sh" => "code",
        _ => "other",
    }
}

pub fn builtin_app_aliases() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("code", "vsc,vscode,vs code,编辑器,代码编辑器"),
        ("firefox", "ff,火狐,浏览器,firefox"),
        ("chromium", "chrome,浏览器,谷歌浏览器,chromium"),
        ("google-chrome", "chrome,谷歌浏览器,浏览器"),
        ("org.gnome.TextEditor", "文本编辑器,记事本,editor,gedit"),
        ("org.gnome.gedit", "文本编辑器,记事本,gedit"),
        ("org.gnome.Nautilus", "文件管理器,文件夹,files,nautilus"),
        ("org.gnome.Terminal", "终端,命令行,terminal,term"),
        ("org.gnome.Console", "终端,命令行,kgx,term"),
        ("org.gnome.Calculator", "计算器,calc,calculator"),
        (
            "wps-office-prometheus",
            "wps,WPS,WPS Office,WPS 文字,文档,word",
        ),
        ("wps-office-wps", "WPS文字,WPS 文字,Word"),
        ("wps", "WPS,WPS文字,Word"),
        ("wps-office-wpp", "WPS演示,WPS 演示,PPT"),
        ("wpp", "WPS演示,PPT"),
        ("wps-office-et", "WPS表格,WPS 表格,Excel"),
        ("et", "WPS表格,Excel"),
        ("wps-office-pdf", "WPS PDF"),
        ("wpspdf", "WPS PDF"),
        ("org.kde.okular", "okular,PDF阅读器,pdf"),
        ("org.gnome.Evince", "evince,文档查看器,pdf"),
        ("htop", "任务管理器,进程监控,htop"),
        ("sodam", "汽水音乐,汽水,qishui,sodam"),
        ("qqmusic", "QQ音乐,qq音乐,腾讯音乐"),
        ("qq", "QQ,腾讯QQ,linuxqq"),
        ("wechat", "微信,weixin,wechat,wx"),
        ("bytedance-feishu", "飞书,feishu,lark"),
        ("wemeetapp", "腾讯会议,wemeet,会议"),
        ("baidunetdisk", "百度网盘,百度云"),
        ("mcloud", "中国移动云盘,移动云盘"),
        ("betternotes", "轻笺,PinPlan,便签,笔记"),
        ("flclash", "FlClash,Clash,代理,科学上网"),
        ("discforge", "光铸,刻录"),
        ("yozo", "永中,永中Office"),
        ("localsend", "LocalSend,快传,局域网传输"),
        ("localsend_app", "LocalSend,快传,局域网传输"),
        ("rustdesk", "RustDesk,远程桌面"),
        ("trae-cn", "Trae,Trae CN"),
        ("zcode", "ZCode"),
        ("omni-mouse-studio", "Omni Mouse,鼠标智控,鼠标设置"),
    ])
}

fn standard_developer_app_catalog() -> Vec<AppRecord> {
    let items = [
        (
            "code.desktop",
            "Visual Studio Code",
            "Code Editor",
            "code",
            "vsc,vscode,vs code,代码编辑器",
        ),
        (
            "firefox.desktop",
            "Firefox 浏览器",
            "Web Browser",
            "firefox",
            "ff,firefox,火狐,浏览器",
        ),
        (
            "org.gnome.TextEditor.desktop",
            "文本编辑器",
            "Text Editor",
            "gnome-text-editor",
            "editor,gedit,记事本",
        ),
        (
            "org.gnome.Terminal.desktop",
            "终端",
            "Terminal Emulator",
            "gnome-terminal",
            "terminal,term,命令行",
        ),
        (
            "org.gnome.Nautilus.desktop",
            "文件管理器",
            "Files",
            "nautilus",
            "files,文件夹",
        ),
        (
            "wps-office-prometheus.desktop",
            "WPS 文字",
            "Office Suite",
            "wps",
            "wps,WPS,WPS文字,office",
        ),
        (
            "libreoffice-writer.desktop",
            "LibreOffice Writer",
            "Office Suite",
            "libreoffice",
            "libreoffice,writer",
        ),
        (
            "org.kde.okular.desktop",
            "Okular",
            "Document Viewer",
            "okular",
            "okular,pdf阅读器,pdf",
        ),
        (
            "org.gnome.Evince.desktop",
            "文档查看器",
            "Document Viewer",
            "evince",
            "evince,文档查看器",
        ),
        (
            "org.gnome.Calculator.desktop",
            "计算器",
            "Calculator",
            "gnome-calculator",
            "calc,calculator,计算器",
        ),
        (
            "org.telegram.desktop.desktop",
            "Telegram",
            "Messenger",
            "telegram-desktop",
            "tg,telegram,电报",
        ),
        (
            "wechat.desktop",
            "微信",
            "Instant Messenger",
            "wechat",
            "wx,wechat,微信,weixin",
        ),
    ];
    items
        .into_iter()
        .map(|(id, name, gname, exec, aliases)| {
            let (py_full, py_init) = to_pinyin_pair(&format!("{} {} {}", name, aliases, gname));
            AppRecord {
                app_id: id.into(),
                name: name.into(),
                generic_name: gname.into(),
                exec_cmd: exec.into(),
                keywords: aliases.into(),
                pinyin_full: py_full,
                pinyin_init: py_init,
                aliases: aliases.into(),
                source: "catalog".into(),
            }
        })
        .collect()
}

fn strip_app_query_suffix(q: &str) -> Option<&str> {
    if q.chars().count() <= 2 {
        return None;
    }
    for suffix in [
        "音乐播放器",
        "播放器",
        "客户端",
        "桌面版",
        "浏览器",
        "音乐",
        "软件",
        "应用",
        "办公",
    ] {
        if let Some(stripped) = q.strip_suffix(suffix) {
            let clean = stripped.trim();
            if clean.chars().count() >= 2 {
                return Some(clean);
            }
        }
    }
    None
}

pub(crate) fn extract_exec_binary(exec_raw: &str) -> String {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for ch in exec_raw.chars() {
        match quote {
            Some(qch) => {
                if ch == qch {
                    quote = None;
                } else {
                    cur.push(ch);
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                } else if ch.is_whitespace() {
                    if !cur.is_empty() {
                        tokens.push(std::mem::take(&mut cur));
                    }
                } else {
                    cur.push(ch);
                }
            }
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }

    let mut idx = 0usize;
    while idx < tokens.len() {
        let t = tokens[idx].as_str();
        if t == "env" || t == "/usr/bin/env" || t == "/bin/env" {
            idx += 1;
            continue;
        }
        if t.contains('=') && !t.starts_with('-') && !t.starts_with('/') {
            idx += 1;
            continue;
        }
        break;
    }
    let Some(first) = tokens.get(idx) else {
        return String::new();
    };
    let first_base = Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(first)
        .to_ascii_lowercase();
    let is_script_runner = matches!(
        first_base.as_str(),
        "python" | "python3" | "sh" | "bash" | "dash"
    ) || first_base.starts_with("python3.");
    if is_script_runner {
        for next_tok in &tokens[idx + 1..] {
            if next_tok.starts_with('-') || next_tok.starts_with('%') {
                continue;
            }
            if next_tok.contains('/') || next_tok.ends_with(".py") || next_tok.ends_with(".sh") {
                return next_tok.clone();
            }
            break;
        }
    }
    first.clone()
}

pub(crate) fn extract_binary_stem(exec_cmd: &str) -> String {
    let base = Path::new(exec_cmd.trim())
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(exec_cmd.trim());
    for ext in [".sh", ".py", ".bin", ".AppImage", ".appimage", ".run"] {
        if let Some(s) = base.strip_suffix(ext)
            && !s.is_empty()
        {
            return s.to_string();
        }
    }
    base.to_string()
}

fn score_app_record(
    rec: &AppRecord,
    q: &str,
    q_stem: &str,
    q_nospace: &str,
    q_py_full: &str,
    core_and_py: Option<(&str, &str)>,
) -> f64 {
    let name_lc = rec.name.to_lowercase();
    let name_nospace: String = name_lc.chars().filter(|c| !c.is_whitespace()).collect();
    let id_lc = rec.app_id.to_lowercase();
    let id_stem = rec.app_id.trim_end_matches(".desktop").to_lowercase();
    let exec_stem = extract_binary_stem(&rec.exec_cmd).to_lowercase();
    let (name_py_full, name_py_init) = to_pinyin_pair(&rec.name);

    let alias_list: Vec<&str> = rec
        .aliases
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let alias_lc_list: Vec<String> = alias_list.iter().map(|a| a.to_lowercase()).collect();

    let kw_lc = rec.keywords.to_lowercase();
    let kw_tokens: Vec<&str> = kw_lc
        .split([';', ',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if name_lc == q
        || id_lc == q
        || id_stem == q
        || id_stem == q_stem
        || (!q_nospace.is_empty() && name_nospace == q_nospace)
    {
        return 100.0;
    }

    if alias_lc_list.iter().any(|a| {
        a == q
            || a == q_stem
            || (!q_nospace.is_empty()
                && q_nospace.chars().count() >= 2
                && a.chars().filter(|c| !c.is_whitespace()).collect::<String>() == q_nospace)
    }) {
        return 97.0;
    }

    if !exec_stem.is_empty() && (exec_stem == q || exec_stem == q_stem) {
        return 95.0;
    }

    let alias_py_exact = alias_list.iter().any(|a| {
        let (af, ai) = to_pinyin_pair(a);
        (!af.is_empty() && af == q) || (!ai.is_empty() && ai == q)
    });
    let q_py_token_exact = q_py_full.len() >= 3
        && (id_stem == q_py_full
            || exec_stem == q_py_full
            || name_lc == q_py_full
            || kw_tokens.contains(&q_py_full)
            || alias_lc_list.iter().any(|a| a == q_py_full));

    if name_py_init == q
        || name_py_full == q
        || rec.pinyin_init == q
        || rec.pinyin_full == q
        || alias_py_exact
        || q_py_token_exact
    {
        return 94.0;
    }

    if let Some((core_str, core_py)) = core_and_py
        && core_py.len() >= 3
        && (kw_tokens.iter().any(|k| *k == core_py || *k == core_str)
            || id_stem == core_py
            || id_stem == core_str
            || (!exec_stem.is_empty() && (exec_stem == core_py || exec_stem == core_str))
            || name_lc == core_str
            || name_lc == core_py
            || (!name_py_full.is_empty() && name_py_full == core_py)
            || alias_lc_list.iter().any(|a| a == core_str || a == core_py))
    {
        return 91.0;
    }

    if kw_tokens.contains(&q) {
        return 88.0;
    }

    if name_lc.starts_with(q)
        || id_stem.starts_with(q)
        || alias_lc_list.iter().any(|a| a.starts_with(q))
    {
        return 85.0;
    }

    let alias_py_prefix = alias_list.iter().any(|a| {
        let (af, ai) = to_pinyin_pair(a);
        (af.len() >= 2 && af.starts_with(q)) || (ai.len() >= 2 && ai.starts_with(q))
    });
    if name_py_init.starts_with(q)
        || name_py_full.starts_with(q)
        || rec.pinyin_init.starts_with(q)
        || rec.pinyin_full.starts_with(q)
        || alias_py_prefix
    {
        return 80.0;
    }

    let aliases_joined_lc = rec.aliases.to_lowercase();
    if q_py_full.len() >= 4
        && (kw_lc.contains(q_py_full)
            || name_py_full.contains(q_py_full)
            || aliases_joined_lc.contains(q_py_full))
    {
        return 72.0;
    }

    if name_lc.contains(q)
        || rec.generic_name.to_lowercase().contains(q)
        || kw_lc.contains(q)
        || aliases_joined_lc.contains(q)
    {
        return 68.0;
    }

    0.0
}

fn is_explicitly_hidden_desktop_entry(path: &Path) -> bool {
    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };
    let mut in_entry = false;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && matches!(k.trim(), "NoDisplay" | "Hidden")
            && v.trim().eq_ignore_ascii_case("true")
        {
            return true;
        }
    }
    false
}

fn push_unique_token(list: &mut Vec<String>, candidate: &str) {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return;
    }
    if !list
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(trimmed))
    {
        list.push(trimmed.to_string());
    }
}

pub fn parse_desktop_entry(path: &Path, alias_table: &HashMap<&str, &str>) -> Option<AppRecord> {
    let content = fs::read_to_string(path).ok()?;
    let app_id = path.file_name()?.to_string_lossy().to_string();
    let stem = app_id.trim_end_matches(".desktop");
    let stem_lc = stem.to_ascii_lowercase();

    let mut in_entry = false;
    let mut no_display = false;
    let mut entry_type: Option<String> = None;
    let mut name_zh_cn: Option<String> = None;
    let mut name_zh: Option<String> = None;
    let mut name_default: Option<String> = None;
    let mut generic_zh_cn: Option<String> = None;
    let mut generic_zh: Option<String> = None;
    let mut generic_default: Option<String> = None;
    let mut comment_zh_cn: Option<String> = None;
    let mut comment_zh: Option<String> = None;
    let mut startup_wm_class = String::new();
    let mut exec_cmd = String::new();
    let mut keywords_parts: Vec<String> = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let val = v.trim();
            if val.is_empty() {
                continue;
            }
            match key {
                "NoDisplay" | "Hidden" if val.eq_ignore_ascii_case("true") => {
                    no_display = true;
                }
                "Type" if entry_type.is_none() => {
                    entry_type = Some(val.to_string());
                }
                "Name[zh_CN]" => name_zh_cn = Some(val.to_string()),
                "Name[zh]" => name_zh = Some(val.to_string()),
                "Name" if name_default.is_none() => name_default = Some(val.to_string()),
                "GenericName[zh_CN]" => generic_zh_cn = Some(val.to_string()),
                "GenericName[zh]" => generic_zh = Some(val.to_string()),
                "GenericName" if generic_default.is_none() => {
                    generic_default = Some(val.to_string());
                }
                "Comment[zh_CN]" => comment_zh_cn = Some(val.to_string()),
                "Comment[zh]" => comment_zh = Some(val.to_string()),
                "StartupWMClass" if startup_wm_class.is_empty() => {
                    startup_wm_class = val.to_string();
                }
                "Exec" if exec_cmd.is_empty() => {
                    exec_cmd = extract_exec_binary(val);
                }
                "Keywords" | "Keywords[zh_CN]" | "Keywords[zh]" => {
                    for kw in val.split([';', ',']) {
                        push_unique_token(&mut keywords_parts, kw);
                    }
                }
                _ => {}
            }
        }
    }

    if no_display {
        return None;
    }
    if let Some(ref t) = entry_type
        && !t.eq_ignore_ascii_case("Application")
    {
        return None;
    }

    let name = name_zh_cn
        .clone()
        .or_else(|| name_zh.clone())
        .or_else(|| name_default.clone())?;
    let generic_name = generic_zh_cn
        .or(generic_zh)
        .or(generic_default)
        .or_else(|| comment_zh_cn.clone().filter(|c| c.chars().count() <= 48))
        .or_else(|| comment_zh.clone().filter(|c| c.chars().count() <= 48))
        .unwrap_or_default();

    let exec_stem = extract_binary_stem(&exec_cmd);
    let exec_stem_lc = exec_stem.to_ascii_lowercase();

    let mut alias_tokens: Vec<String> = Vec::new();
    push_unique_token(&mut alias_tokens, stem);
    if stem.contains('.')
        && let Some(last_seg) = stem.rsplit('.').next()
        && last_seg.len() >= 3
        && !matches!(
            last_seg.to_ascii_lowercase().as_str(),
            "desktop" | "native" | "app" | "application" | "client" | "browser"
        )
    {
        push_unique_token(&mut alias_tokens, last_seg);
    }
    if let Some(ref def_n) = name_default
        && def_n != &name
    {
        push_unique_token(&mut alias_tokens, def_n);
    }
    if let Some(ref zh_cn) = name_zh_cn
        && zh_cn != &name
    {
        push_unique_token(&mut alias_tokens, zh_cn);
    }
    if let Some(ref zh) = name_zh
        && zh != &name
    {
        push_unique_token(&mut alias_tokens, zh);
    }
    if !startup_wm_class.is_empty() {
        push_unique_token(&mut alias_tokens, &startup_wm_class);
        push_unique_token(&mut keywords_parts, &startup_wm_class);
    }
    if !exec_stem.is_empty() {
        push_unique_token(&mut alias_tokens, &exec_stem);
        push_unique_token(&mut keywords_parts, &exec_stem);
    }
    if let Some(ref c_zh) = comment_zh_cn
        && c_zh.chars().count() <= 48
    {
        push_unique_token(&mut keywords_parts, c_zh);
    }

    // Lookup builtin aliases across exact stem, case-insensitive stem, non-generic reverse-DNS segments, and normalized exec stem
    let mut matched_alias_keys: Vec<String> = vec![stem.to_string(), stem_lc.clone()];
    for seg in stem_lc.split('.') {
        if seg.len() >= 4
            && !matches!(
                seg,
                "com"
                    | "org"
                    | "net"
                    | "io"
                    | "github"
                    | "gitlab"
                    | "gnome"
                    | "kde"
                    | "freedesktop"
                    | "microsoft"
                    | "google"
                    | "brave"
                    | "desktop"
                    | "native"
                    | "app"
                    | "application"
                    | "office"
            )
        {
            matched_alias_keys.push(seg.to_string());
        }
    }
    if !exec_stem_lc.is_empty() && !matches!(exec_stem_lc.as_str(), "code" | "wps") {
        matched_alias_keys.push(exec_stem_lc.clone());
        for trimmed_exec in [
            exec_stem_lc.strip_suffix("-native"),
            exec_stem_lc.strip_suffix("_app"),
            exec_stem_lc.strip_suffix("-stable"),
        ]
        .into_iter()
        .flatten()
        {
            if trimmed_exec.len() >= 3 {
                matched_alias_keys.push(trimmed_exec.to_string());
            }
        }
    }
    for (k, v) in alias_table {
        if matched_alias_keys
            .iter()
            .any(|cand| cand.eq_ignore_ascii_case(k))
        {
            for item in v.split(',') {
                push_unique_token(&mut alias_tokens, item);
            }
        }
    }

    let aliases = alias_tokens.join(",");
    let keywords = keywords_parts.join(";");
    let combined_for_py = format!("{} {} {}", name, aliases, generic_name);
    let (py_full, py_init) = to_pinyin_pair(&combined_for_py);

    Some(AppRecord {
        app_id,
        name,
        generic_name,
        exec_cmd,
        keywords,
        pinyin_full: py_full,
        pinyin_init: py_init,
        aliases,
        source: path.to_string_lossy().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinyin_full_and_initials_work_for_chinese_app_names() {
        let (full, init) = to_pinyin_pair("文本编辑器");
        assert_eq!(full, "wenbenbianjiqi");
        assert_eq!(init, "wbbjq");
    }

    #[test]
    fn blocks_dangerous_url_schemes_and_encodes_search_queries() {
        let tmp = tempfile::TempDir::new().unwrap();
        let idx = Arc::new(IndexDb::open_or_rebuild(&tmp.path().join("idx.db")).unwrap());
        let fs_eng = Arc::new(
            SafeFsEngine::new(
                vec![tmp.path().to_path_buf()],
                vec![],
                tmp.path().join("undo"),
                tmp.path().join("trash"),
            )
            .unwrap(),
        );
        let res = ResourceEngine::new(idx, fs_eng, AppConfig::default());
        res.index_fonts();

        assert!(res.resolve_web_target("javascript:alert(1)").is_err());
        assert!(res.resolve_web_target("file:///etc/passwd").is_err());
        assert!(res.resolve_web_target("data:text/html,hi").is_err());

        let gh = res.resolve_web_target("gh").unwrap().unwrap();
        assert_eq!(gh.url, "https://github.com");

        let loc = res.resolve_web_target("localhost:3000").unwrap().unwrap();
        assert_eq!(loc.url, "http://localhost:3000");

        let (search_url, engine_name) = res.build_search_url("tokio select & cancel #1", None);
        assert_eq!(engine_name, "Google");
        assert!(search_url.starts_with("https://www.google.com/search?q="));
        assert!(search_url.contains("%26"));
        assert!(search_url.contains("%23"));

        // A11c & §19.2: Installed font validates; unknown or metacharacter font rejected with suggestions!
        assert_eq!(
            res.validate_or_suggest_font("jetbrains mono").unwrap(),
            "JetBrains Mono"
        );
        let missing = res
            .validate_or_suggest_font("NonExistentMonoFont")
            .unwrap_err();
        assert!(!missing.is_empty());
        assert!(res.validate_or_suggest_font("Fira Code; rm -rf ~").is_err());
    }

    #[test]
    fn sodam_chinese_query_matches_pinyin_keywords_even_without_hardcoded_aliases() {
        let tmp = tempfile::TempDir::new().unwrap();
        let sodam_path = tmp.path().join("sodam.desktop");
        fs::write(
            &sodam_path,
            "[Desktop Entry]\nType=Application\nName=SodaM\nGenericName=Music Player\nComment=SodaM music client\nExec=/usr/bin/sodam\nIcon=sodam\nTerminal=false\nCategories=AudioVideo;Audio;Music;Player;\nKeywords=music;qishui;soda;sodam;\nStartupWMClass=SodaM\n",
        )
        .unwrap();

        let flclash_path = tmp.path().join("FlClash.desktop");
        fs::write(
            &flclash_path,
            "[Desktop Entry]\nType=Application\nName=FlClash\nExec=FlClash %U\nKeywords=FlClash;Clash;Proxy;\nStartupWMClass=com.follow.clash\n",
        )
        .unwrap();

        let qqmusic_path = tmp.path().join("qqmusic.desktop");
        fs::write(
            &qqmusic_path,
            "[Desktop Entry]\nType=Application\nName=qqmusic\nExec=env LIBGL_ALWAYS_SOFTWARE=1 /opt/qqmusic/qqmusic --use-gl=swiftshader %U\nStartupWMClass=qqmusic\n",
        )
        .unwrap();

        // Parse sodam.desktop with an EMPTY alias table to prove pure query->pinyin (`汽水音乐` -> `qishui`) keyword matching!
        let empty_aliases: HashMap<&str, &str> = HashMap::new();
        let sodam_rec = parse_desktop_entry(&sodam_path, &empty_aliases).unwrap();
        assert_eq!(sodam_rec.app_id, "sodam.desktop");
        assert_eq!(sodam_rec.exec_cmd, "/usr/bin/sodam");
        assert_eq!(sodam_rec.source, sodam_path.to_string_lossy().to_string());

        let flclash_rec = parse_desktop_entry(&flclash_path, &builtin_app_aliases()).unwrap();
        assert_eq!(flclash_rec.app_id, "FlClash.desktop");

        let qqmusic_rec = parse_desktop_entry(&qqmusic_path, &builtin_app_aliases()).unwrap();
        assert_eq!(qqmusic_rec.exec_cmd, "/opt/qqmusic/qqmusic");

        let idx = Arc::new(IndexDb::open_or_rebuild(&tmp.path().join("idx.db")).unwrap());
        {
            let conn = idx.conn.lock().unwrap();
            for rec in [&sodam_rec, &flclash_rec, &qqmusic_rec] {
                conn.execute(
                    "INSERT INTO apps (app_id, name, generic_name, exec_cmd, keywords, pinyin_full, pinyin_init, aliases, source)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        rec.app_id,
                        rec.name,
                        rec.generic_name,
                        rec.exec_cmd,
                        rec.keywords,
                        rec.pinyin_full,
                        rec.pinyin_init,
                        rec.aliases,
                        rec.source,
                    ],
                )
                .unwrap();
            }
        }
        let fs_eng = Arc::new(
            SafeFsEngine::new(
                vec![tmp.path().to_path_buf()],
                vec![],
                tmp.path().join("undo"),
                tmp.path().join("trash"),
            )
            .unwrap(),
        );
        let res = ResourceEngine::new(idx, fs_eng, AppConfig::default());

        // (a) `汽水音乐` -> core `汽水` -> `qishui` hits `Keywords=music;qishui;soda;sodam;` with score >= 90.0
        let hits = res.search_apps("汽水音乐", 3);
        assert!(!hits.is_empty(), "expected 汽水音乐 to match sodam.desktop");
        assert_eq!(hits[0].0.app_id, "sodam.desktop");
        assert!(
            hits[0].1 >= 90.0,
            "expected score >= 90.0 for 汽水音乐 -> qishui keyword match, got {}",
            hits[0].1
        );

        // (b) Case-insensitive `SodaM` and `flclash` resolve to exact `.desktop` filenames (`sodam.desktop`, `FlClash.desktop`)
        let resolved_sodam = res.resolve_best_app("SodaM").unwrap();
        assert_eq!(resolved_sodam.app_id, "sodam.desktop");
        assert_eq!(
            resolved_sodam.source,
            sodam_path.to_string_lossy().to_string()
        );

        let resolved_flclash = res.resolve_best_app("flclash").unwrap();
        assert_eq!(resolved_flclash.app_id, "FlClash.desktop");

        let resolved_qqmusic = res.resolve_best_app("QQ音乐").unwrap();
        assert_eq!(resolved_qqmusic.app_id, "qqmusic.desktop");

        assert!(res.resolve_best_app("不存在的宇宙飞船软件XYZ").is_none());
    }

    #[test]
    fn sanitize_desktop_ld_library_path_strips_conda_and_preserves_system_dirs() {
        assert_eq!(
            sanitize_desktop_ld_library_path("/home/alice/miniconda3/lib"),
            None
        );
        assert_eq!(
            sanitize_desktop_ld_library_path(
                "/home/alice/miniconda3/lib:/usr/local/lib:/opt/anaconda3/envs/dev/lib:/usr/lib/x86_64-linux-gnu"
            ),
            Some("/usr/local/lib:/usr/lib/x86_64-linux-gnu".to_string())
        );
        assert_eq!(
            sanitize_desktop_ld_library_path("/usr/local/lib:/opt/vendor/lib"),
            Some("/usr/local/lib:/opt/vendor/lib".to_string())
        );
    }
}
