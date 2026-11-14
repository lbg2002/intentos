#![forbid(unsafe_code)]

//! Offline Speech Recognition Model Catalog, Thread-Safe Progress Tracker,
//! and Async Streaming Downloader (`crates/intentosd/src/speech_hub/model_manager.rs`).

use crate::core::IntentOsCore;
use crate::speech_hub::{load_speech_config_from_dir, save_speech_config_to_dir};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelFileSpec {
    pub rel_path: String,
    pub expected_min_bytes: u64,
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeechModelCatalogEntry {
    pub id: String,
    pub name: String,
    pub badge: String,
    pub languages: Vec<String>,
    pub languages_label: String,
    pub engine_kind: String,
    pub approx_size_mb: u64,
    pub description: String,
    pub files: Vec<ModelFileSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadTaskState {
    pub model_id: String,
    pub status: String,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub progress_pct: f64,
    pub speed_bps: u64,
    pub current_file: String,
    pub error: Option<String>,
    #[serde(skip)]
    pub cancel_flag: Arc<AtomicBool>,
    #[serde(skip)]
    pub cancel_notify: Arc<Notify>,
}

impl Default for DownloadTaskState {
    fn default() -> Self {
        Self {
            model_id: String::new(),
            status: "idle".to_string(),
            downloaded_bytes: 0,
            total_bytes: 0,
            progress_pct: 0.0,
            speed_bps: 0,
            current_file: String::new(),
            error: None,
            cancel_flag: Arc::new(AtomicBool::new(false)),
            cancel_notify: Arc::new(Notify::new()),
        }
    }
}

#[derive(Default)]
struct PerCoreDownloadRegistry {
    tasks: HashMap<String, DownloadTaskState>,
    last_model_id: Option<String>,
}

static DOWNLOAD_REGISTRY: OnceLock<Mutex<HashMap<PathBuf, PerCoreDownloadRegistry>>> =
    OnceLock::new();

fn download_registry() -> &'static Mutex<HashMap<PathBuf, PerCoreDownloadRegistry>> {
    DOWNLOAD_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Strictly validate `model_id` so path traversal (`../`, `/`, `\`, etc.) is impossible.
pub fn validate_safe_model_id(model_id: &str) -> anyhow::Result<()> {
    let trimmed = model_id.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        anyhow::bail!("无效的语音模型 ID（长度需在 1..=64 之间）");
    }
    if trimmed.starts_with('-') || trimmed.starts_with('_') {
        anyhow::bail!("非法的语音模型 ID: {}", model_id);
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        anyhow::bail!(
            "非法的语音模型 ID '{}'：仅允许小写字母、数字、下划线与连字符 [a-z0-9_-]",
            model_id
        );
    }
    Ok(())
}

/// Validate a relative file path inside a model bundle (e.g. `onnx/encoder_model_quantized.onnx`).
pub fn validate_safe_rel_path(rel_path: &str) -> anyhow::Result<PathBuf> {
    let p = Path::new(rel_path);
    if rel_path.trim().is_empty() || p.is_absolute() {
        anyhow::bail!("非法的模型内部相对路径: {}", rel_path);
    }
    let mut clean = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s.is_empty() || s == "." || s == ".." || s.ends_with(".part") {
                    anyhow::bail!("非法的模型文件组件: {}", rel_path);
                }
                clean.push(seg);
            }
            _ => anyhow::bail!("检测到越界模型相对路径: {}", rel_path),
        }
    }
    if clean.as_os_str().is_empty() {
        anyhow::bail!("空的模型相对路径");
    }
    Ok(clean)
}

pub fn speech_models_root(data_dir: &Path) -> PathBuf {
    data_dir.join("speech_models")
}

pub fn model_install_dir(data_dir: &Path, model_id: &str) -> anyhow::Result<PathBuf> {
    validate_safe_model_id(model_id)?;
    Ok(speech_models_root(data_dir).join(model_id.trim()))
}

fn whisper_q8_files(hf_repo: &str, enc_min_bytes: u64, dec_min_bytes: u64) -> Vec<ModelFileSpec> {
    let primary_base = format!("https://huggingface.co/{}/resolve/main", hf_repo);
    let mirror_base = format!("https://hf-mirror.com/{}/resolve/main", hf_repo);
    vec![
        ModelFileSpec {
            rel_path: "onnx/encoder_model_quantized.onnx".to_string(),
            expected_min_bytes: enc_min_bytes,
            urls: vec![
                format!("{}/onnx/encoder_model_quantized.onnx", primary_base),
                format!("{}/onnx/encoder_model_quantized.onnx", mirror_base),
            ],
        },
        ModelFileSpec {
            rel_path: "onnx/decoder_model_quantized.onnx".to_string(),
            expected_min_bytes: dec_min_bytes,
            urls: vec![
                format!("{}/onnx/decoder_model_quantized.onnx", primary_base),
                format!("{}/onnx/decoder_model_quantized.onnx", mirror_base),
            ],
        },
        ModelFileSpec {
            rel_path: "tokenizer.json".to_string(),
            expected_min_bytes: 500_000,
            urls: vec![
                format!("{}/tokenizer.json", primary_base),
                format!("{}/tokenizer.json", mirror_base),
            ],
        },
        ModelFileSpec {
            rel_path: "config.json".to_string(),
            expected_min_bytes: 500,
            urls: vec![
                format!("{}/config.json", primary_base),
                format!("{}/config.json", mirror_base),
            ],
        },
    ]
}

/// Built-in verified speech recognition models catalog (ModelScope + HuggingFace + hf-mirror).
pub fn builtin_speech_models() -> Vec<SpeechModelCatalogEntry> {
    vec![
        SpeechModelCatalogEntry {
            id: "sensevoice-small-int8".to_string(),
            name: "SenseVoice Small (INT8 离线多语种)".to_string(),
            badge: "强烈推荐".to_string(),
            languages: vec![
                "zh".into(),
                "en".into(),
                "ja".into(),
                "ko".into(),
                "yue".into(),
            ],
            languages_label: "中文 / 中英混合 / 粤语 / 日语 / 韩语".to_string(),
            engine_kind: "sensevoice_onnx".to_string(),
            approx_size_mb: 228,
            description: "阿里达摩院 SenseVoice Small INT8 量化模型（ModelScope 国内高速直连），中文与中英混合口令识别精准、CPU 推理延迟极低。".to_string(),
            files: vec![
                ModelFileSpec {
                    rel_path: "model.int8.onnx".to_string(),
                    expected_min_bytes: 200_000_000,
                    urls: vec![
                        "https://www.modelscope.cn/models/pengzhendong/sherpa-onnx-sense-voice-zh-en-ja-ko-yue/resolve/master/model.int8.onnx".to_string(),
                        "https://huggingface.co/csukuangfj/sherpa-onnx-sense-voice-zh-en-ja-ko-yue-2024-07-17/resolve/main/model.int8.onnx".to_string(),
                        "https://hf-mirror.com/csukuangfj/sherpa-onnx-sense-voice-zh-en-ja-ko-yue-2024-07-17/resolve/main/model.int8.onnx".to_string(),
                    ],
                },
                ModelFileSpec {
                    rel_path: "tokens.txt".to_string(),
                    expected_min_bytes: 100_000,
                    urls: vec![
                        "https://www.modelscope.cn/models/pengzhendong/sherpa-onnx-sense-voice-zh-en-ja-ko-yue/resolve/master/tokens.txt".to_string(),
                        "https://huggingface.co/csukuangfj/sherpa-onnx-sense-voice-zh-en-ja-ko-yue-2024-07-17/resolve/main/tokens.txt".to_string(),
                        "https://hf-mirror.com/csukuangfj/sherpa-onnx-sense-voice-zh-en-ja-ko-yue-2024-07-17/resolve/main/tokens.txt".to_string(),
                    ],
                },
            ],
        },
        SpeechModelCatalogEntry {
            id: "whisper-tiny-q8".to_string(),
            name: "Whisper Tiny (Q8 轻量极速)".to_string(),
            badge: "轻量极速".to_string(),
            languages: vec!["zh".into(), "en".into(), "auto".into()],
            languages_label: "中文 / 英文 / 多语种自动检测".to_string(),
            engine_kind: "whisper_onnx".to_string(),
            approx_size_mb: 42,
            description: "OpenAI Whisper Tiny INT8 量化版（约 42 MB），下载极快、内存占用极小，适合简短桌面控制口令。".to_string(),
            files: whisper_q8_files("onnx-community/whisper-tiny", 8_000_000, 20_000_000),
        },
        SpeechModelCatalogEntry {
            id: "whisper-base-q8".to_string(),
            name: "Whisper Base (Q8 均衡双语)".to_string(),
            badge: "均衡".to_string(),
            languages: vec!["zh".into(), "en".into(), "auto".into()],
            languages_label: "中文 / 英文 / 多语种自动检测".to_string(),
            engine_kind: "whisper_onnx".to_string(),
            approx_size_mb: 78,
            description: "OpenAI Whisper Base INT8 量化版（约 78 MB），兼顾下载体积与中英文长句识别准确率。".to_string(),
            files: whisper_q8_files("onnx-community/whisper-base", 15_000_000, 40_000_000),
        },
        SpeechModelCatalogEntry {
            id: "whisper-small-q8".to_string(),
            name: "Whisper Small (Q8 高精度)".to_string(),
            badge: "高精度".to_string(),
            languages: vec!["zh".into(), "en".into(), "auto".into()],
            languages_label: "中文 / 英文 / 多语种自动检测".to_string(),
            engine_kind: "whisper_onnx".to_string(),
            approx_size_mb: 244,
            description: "OpenAI Whisper Small INT8 量化版（约 244 MB），复杂语境与专业技术词汇识别准确度更高。".to_string(),
            files: whisper_q8_files("onnx-community/whisper-small", 60_000_000, 120_000_000),
        },
    ]
}

pub fn find_catalog_model(model_id: &str) -> Option<SpeechModelCatalogEntry> {
    let clean = model_id.trim();
    builtin_speech_models().into_iter().find(|m| m.id == clean)
}

pub fn is_model_installed_in_data_dir(data_dir: &Path, entry: &SpeechModelCatalogEntry) -> bool {
    let Ok(dir) = model_install_dir(data_dir, &entry.id) else {
        return false;
    };
    if !dir.is_dir() {
        return false;
    }
    let has_manifest = dir.join("manifest.json").is_file();
    for f in &entry.files {
        let Ok(rel) = validate_safe_rel_path(&f.rel_path) else {
            return false;
        };
        let fp = dir.join(rel);
        let Ok(meta) = std::fs::metadata(&fp) else {
            return false;
        };
        if !meta.is_file() || meta.len() == 0 {
            return false;
        }
        if !has_manifest && meta.len() < f.expected_min_bytes {
            return false;
        }
    }
    true
}

pub fn has_any_installed_model(core: &IntentOsCore) -> bool {
    builtin_speech_models()
        .iter()
        .any(|m| is_model_installed_in_data_dir(&core.paths.data_dir, m))
}

pub fn resolve_installed_model(
    core: &IntentOsCore,
    preferred_id: Option<&str>,
) -> Option<(SpeechModelCatalogEntry, PathBuf)> {
    let catalog = builtin_speech_models();
    if let Some(pref) = preferred_id.map(str::trim).filter(|s| !s.is_empty())
        && let Some(entry) = catalog.iter().find(|m| m.id == pref)
        && is_model_installed_in_data_dir(&core.paths.data_dir, entry)
        && let Ok(dir) = model_install_dir(&core.paths.data_dir, &entry.id)
    {
        return Some((entry.clone(), dir));
    }

    let cfg = crate::speech_hub::load_speech_config(core);
    if let Some(entry) = catalog.iter().find(|m| m.id == cfg.active_model_id)
        && is_model_installed_in_data_dir(&core.paths.data_dir, entry)
        && let Ok(dir) = model_install_dir(&core.paths.data_dir, &entry.id)
    {
        return Some((entry.clone(), dir));
    }

    for entry in catalog {
        if is_model_installed_in_data_dir(&core.paths.data_dir, &entry)
            && let Ok(dir) = model_install_dir(&core.paths.data_dir, &entry.id)
        {
            return Some((entry, dir));
        }
    }
    None
}

pub fn compute_model_disk_bytes(data_dir: &Path, model_id: &str) -> u64 {
    let Ok(dir) = model_install_dir(data_dir, model_id) else {
        return 0;
    };
    if !dir.exists() {
        return 0;
    }
    let mut total = 0u64;
    for entry in walkdir::WalkDir::new(&dir)
        .max_depth(4)
        .into_iter()
        .flatten()
    {
        if entry.file_type().is_file() {
            let name = entry.file_name().to_string_lossy();
            if !name.ends_with(".part")
                && let Ok(meta) = entry.metadata()
            {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

fn clean_part_files_in_dir(dir: &Path) {
    if !dir.exists() {
        return;
    }
    let mut part_paths = Vec::new();
    for entry in walkdir::WalkDir::new(dir).max_depth(4).into_iter().flatten() {
        if entry.file_type().is_file() && entry.file_name().to_string_lossy().ends_with(".part") {
            part_paths.push(entry.path().to_path_buf());
        }
    }
    for p in part_paths {
        let _ = std::fs::remove_file(p);
    }
}

fn task_state_to_json(data_dir: &Path, config_dir: &Path, st: &DownloadTaskState) -> Value {
    let installed = find_catalog_model(&st.model_id)
        .map(|entry| is_model_installed_in_data_dir(data_dir, &entry))
        .unwrap_or(false);
    let cfg = load_speech_config_from_dir(config_dir);
    let pct = (st.progress_pct * 100.0).round() / 100.0;
    let speed_mbps = ((st.speed_bps as f64 / (1024.0 * 1024.0)) * 100.0).round() / 100.0;
    json!({
        "model_id": st.model_id,
        "active": st.status == "downloading",
        "status": st.status,
        "downloaded_bytes": st.downloaded_bytes,
        "total_bytes": st.total_bytes,
        "progress_pct": pct,
        "percent": pct,
        "speed_bps": st.speed_bps,
        "speed_mbps": speed_mbps,
        "current_file": st.current_file,
        "error": st.error,
        "installed": installed,
        "active_model_id": cfg.active_model_id,
    })
}

pub fn get_all_downloads_map(core: &IntentOsCore) -> Value {
    let tasks_snapshot: HashMap<String, DownloadTaskState> = {
        let reg = download_registry().lock().unwrap();
        reg.get(&core.paths.data_dir)
            .map(|r| r.tasks.clone())
            .unwrap_or_default()
    };
    let mut map = serde_json::Map::new();
    for (mid, st) in tasks_snapshot {
        map.insert(
            mid,
            task_state_to_json(&core.paths.data_dir, &core.paths.config_dir, &st),
        );
    }
    Value::Object(map)
}

pub fn list_models_with_status(core: &IntentOsCore) -> Vec<Value> {
    let cfg = crate::speech_hub::load_speech_config(core);
    let tasks_snapshot: HashMap<String, DownloadTaskState> = {
        let reg = download_registry().lock().unwrap();
        reg.get(&core.paths.data_dir)
            .map(|r| r.tasks.clone())
            .unwrap_or_default()
    };

    builtin_speech_models()
        .into_iter()
        .map(|entry| {
            let installed = is_model_installed_in_data_dir(&core.paths.data_dir, &entry);
            let disk_bytes = compute_model_disk_bytes(&core.paths.data_dir, &entry.id);
            let model_dir = model_install_dir(&core.paths.data_dir, &entry.id)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let dl_state = tasks_snapshot.get(&entry.id);
            let is_downloading = dl_state
                .map(|s| s.status == "downloading")
                .unwrap_or(false);
            let progress_pct = dl_state
                .map(|s| (s.progress_pct * 100.0).round() / 100.0)
                .unwrap_or(if installed { 100.0 } else { 0.0 });
            let status_label = if is_downloading {
                "downloading"
            } else if installed {
                "installed"
            } else {
                "not_installed"
            };
            let active_download = dl_state.map(|s| {
                task_state_to_json(&core.paths.data_dir, &core.paths.config_dir, s)
            });

            json!({
                "id": entry.id,
                "name": entry.name,
                "badge": entry.badge,
                "languages": entry.languages,
                "languages_label": entry.languages_label,
                "engine_kind": entry.engine_kind,
                "approx_size_mb": entry.approx_size_mb,
                "description": entry.description,
                "files": entry.files,
                "installed": installed,
                "downloading": is_downloading,
                "progress_pct": progress_pct,
                "is_active": cfg.active_model_id == entry.id,
                "disk_bytes": disk_bytes,
                "model_dir": model_dir,
                "status": status_label,
                "active_download": active_download,
                "download_progress": active_download,
            })
        })
        .collect()
}

pub fn get_download_progress(core: &IntentOsCore, model_id: Option<&str>) -> Value {
    let requested = model_id.map(str::trim).filter(|s| !s.is_empty());
    let downloads_map = get_all_downloads_map(core);
    let state = {
        let reg = download_registry().lock().unwrap();
        if let Some(per_core) = reg.get(&core.paths.data_dir) {
            if let Some(mid) = requested {
                per_core.tasks.get(mid).cloned()
            } else if let Some(active) = per_core
                .tasks
                .values()
                .find(|t| t.status == "downloading")
            {
                Some(active.clone())
            } else if let Some(ref last_id) = per_core.last_model_id {
                per_core.tasks.get(last_id).cloned()
            } else {
                None
            }
        } else {
            None
        }
    };

    let mut out = match state {
        Some(st) => task_state_to_json(&core.paths.data_dir, &core.paths.config_dir, &st),
        None => {
            let mid = requested.unwrap_or("").to_string();
            let installed = find_catalog_model(&mid)
                .map(|e| is_model_installed_in_data_dir(&core.paths.data_dir, &e))
                .unwrap_or(false);
            let cfg = crate::speech_hub::load_speech_config(core);
            let pct = if installed { 100.0 } else { 0.0 };
            json!({
                "model_id": mid,
                "active": false,
                "status": if installed { "completed" } else { "idle" },
                "downloaded_bytes": 0,
                "total_bytes": 0,
                "progress_pct": pct,
                "percent": pct,
                "speed_bps": 0,
                "speed_mbps": 0.0,
                "current_file": "",
                "error": Value::Null,
                "installed": installed,
                "active_model_id": cfg.active_model_id,
            })
        }
    };
    if let Some(obj) = out.as_object_mut() {
        obj.insert("downloads".to_string(), downloads_map);
    }
    out
}

pub fn cancel_model_download(core: &IntentOsCore, model_id: Option<&str>) -> anyhow::Result<Value> {
    let requested = model_id.map(str::trim).filter(|s| !s.is_empty());
    if let Some(mid) = requested {
        validate_safe_model_id(mid)?;
    }

    let cancelled_state = {
        let mut reg = download_registry().lock().unwrap();
        let per_core = reg.entry(core.paths.data_dir.clone()).or_default();
        let target_id = if let Some(mid) = requested {
            Some(mid.to_string())
        } else {
            per_core
                .tasks
                .values()
                .find(|t| t.status == "downloading")
                .map(|t| t.model_id.clone())
                .or_else(|| per_core.last_model_id.clone())
        };

        if let Some(tid) = target_id
            && let Some(st) = per_core.tasks.get_mut(&tid)
        {
            st.cancel_flag.store(true, Ordering::SeqCst);
            st.cancel_notify.notify_waiters();
            if st.status == "downloading" {
                st.status = "cancelled".to_string();
                st.speed_bps = 0;
                st.error = Some("用户已取消模型下载".to_string());
            }
            Some(st.clone())
        } else {
            None
        }
    };

    if let Some(ref st) = cancelled_state
        && let Ok(dir) = model_install_dir(&core.paths.data_dir, &st.model_id)
    {
        clean_part_files_in_dir(&dir);
    }

    let mid = cancelled_state
        .as_ref()
        .map(|s| s.model_id.clone())
        .or_else(|| requested.map(String::from))
        .unwrap_or_default();

    Ok(json!({
        "cancelled": cancelled_state.is_some(),
        "model_id": mid,
        "status": cancelled_state.map(|s| s.status).unwrap_or_else(|| "idle".to_string()),
    }))
}

pub fn delete_model(core: &IntentOsCore, model_id: &str) -> anyhow::Result<Value> {
    validate_safe_model_id(model_id)?;
    let clean_id = model_id.trim();

    // Cancel any active download for this model first
    let _ = cancel_model_download(core, Some(clean_id));

    let dir = model_install_dir(&core.paths.data_dir, clean_id)?;
    let existed = dir.exists();
    if existed {
        std::fs::remove_dir_all(&dir)?;
    }

    {
        let mut reg = download_registry().lock().unwrap();
        if let Some(per_core) = reg.get_mut(&core.paths.data_dir) {
            per_core.tasks.remove(clean_id);
        }
    }

    // If the deleted model was the active model and another installed model exists, switch cleanly
    let mut cfg = crate::speech_hub::load_speech_config(core);
    if cfg.active_model_id == clean_id
        && let Some((fallback_entry, _)) = resolve_installed_model(core, None)
    {
        cfg.active_model_id = fallback_entry.id;
        let _ = crate::speech_hub::save_speech_config(core, &cfg);
    }

    let _ = core.state_db.record_audit(
        None,
        "speech_hub.delete_model",
        "user_explicit",
        "setting",
        "allow",
        "ok",
        &json!({ "model_id": clean_id, "existed": existed }),
        None,
    );

    Ok(json!({
        "deleted": existed,
        "ok": true,
        "model_id": clean_id,
        "active_model_id": cfg.active_model_id,
    }))
}

fn update_task_in_registry<F>(data_dir: &Path, model_id: &str, mutator: F)
where
    F: FnOnce(&mut DownloadTaskState),
{
    let mut reg = download_registry().lock().unwrap();
    if let Some(per_core) = reg.get_mut(data_dir)
        && let Some(st) = per_core.tasks.get_mut(model_id)
    {
        mutator(st);
    }
}

fn is_loopback_url(url: &str) -> bool {
    url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
        || url.starts_with("http://[::1]")
}

pub fn start_model_download(
    core: &IntentOsCore,
    model_id: &str,
    base_url_override: Option<String>,
    enforce_min_bytes_override: Option<bool>,
) -> anyhow::Result<Value> {
    validate_safe_model_id(model_id)?;
    let clean_id = model_id.trim();
    let entry = find_catalog_model(clean_id)
        .ok_or_else(|| anyhow::anyhow!("未知的内置语音模型 ID: {}", clean_id))?;

    if let Some(ref base) = base_url_override {
        let b = base.trim();
        if !b.starts_with("http://") && !b.starts_with("https://") {
            anyhow::bail!("base_url_override 必须以 http:// 或 https:// 开头");
        }
    }

    let data_dir = core.paths.data_dir.clone();
    let config_dir = core.paths.config_dir.clone();

    // Check if already downloading
    {
        let reg = download_registry().lock().unwrap();
        if let Some(per_core) = reg.get(&data_dir)
            && let Some(existing) = per_core.tasks.get(clean_id)
            && existing.status == "downloading"
        {
            let mut out = task_state_to_json(&data_dir, &config_dir, existing);
            if let Some(obj) = out.as_object_mut() {
                obj.insert("started".into(), json!(false));
                obj.insert("already_downloading".into(), json!(true));
            }
            return Ok(out);
        }
    }

    let had_installed_before = builtin_speech_models()
        .iter()
        .any(|m| is_model_installed_in_data_dir(&data_dir, m));

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let cancel_notify = Arc::new(Notify::new());
    let estimated_total = entry.approx_size_mb.saturating_mul(1024 * 1024);
    let first_file = entry
        .files
        .first()
        .map(|f| f.rel_path.clone())
        .unwrap_or_default();

    let init_state = DownloadTaskState {
        model_id: entry.id.clone(),
        status: "downloading".to_string(),
        downloaded_bytes: 0,
        total_bytes: estimated_total,
        progress_pct: 0.0,
        speed_bps: 0,
        current_file: first_file,
        error: None,
        cancel_flag: cancel_flag.clone(),
        cancel_notify: cancel_notify.clone(),
    };

    {
        let mut reg = download_registry().lock().unwrap();
        let per_core = reg.entry(data_dir.clone()).or_default();
        per_core.last_model_id = Some(entry.id.clone());
        per_core.tasks.insert(entry.id.clone(), init_state.clone());
    }

    let enforce_expected_min = enforce_min_bytes_override.unwrap_or(base_url_override.is_none());
    let task_data_dir = data_dir.clone();
    let task_config_dir = config_dir.clone();
    let task_entry = entry.clone();

    tokio::spawn(async move {
        let outcome = run_streaming_download_worker(
            &task_data_dir,
            &task_config_dir,
            &task_entry,
            base_url_override,
            enforce_expected_min,
            had_installed_before,
            cancel_flag.clone(),
            cancel_notify.clone(),
        )
        .await;

        match outcome {
            Ok(final_bytes) => {
                update_task_in_registry(&task_data_dir, &task_entry.id, |st| {
                    st.status = "completed".to_string();
                    st.downloaded_bytes = final_bytes;
                    st.total_bytes = final_bytes;
                    st.progress_pct = 100.0;
                    st.speed_bps = 0;
                    st.current_file.clear();
                    st.error = None;
                });
            }
            Err(err_msg) => {
                let was_cancelled = cancel_flag.load(Ordering::SeqCst);
                if let Ok(dir) = model_install_dir(&task_data_dir, &task_entry.id) {
                    clean_part_files_in_dir(&dir);
                }
                update_task_in_registry(&task_data_dir, &task_entry.id, |st| {
                    if was_cancelled || st.status == "cancelled" {
                        st.status = "cancelled".to_string();
                        st.error = Some("用户已取消模型下载".to_string());
                    } else {
                        st.status = "failed".to_string();
                        st.error = Some(err_msg);
                    }
                    st.speed_bps = 0;
                });
            }
        }
    });

    let mut resp = task_state_to_json(&data_dir, &config_dir, &init_state);
    if let Some(obj) = resp.as_object_mut() {
        obj.insert("started".into(), json!(true));
    }
    Ok(resp)
}

#[allow(clippy::too_many_arguments)]
async fn run_streaming_download_worker(
    data_dir: &Path,
    config_dir: &Path,
    entry: &SpeechModelCatalogEntry,
    base_url_override: Option<String>,
    enforce_expected_min: bool,
    had_installed_before: bool,
    cancel_flag: Arc<AtomicBool>,
    cancel_notify: Arc<Notify>,
) -> Result<u64, String> {
    let target_dir = model_install_dir(data_dir, &entry.id).map_err(|e| e.to_string())?;
    tokio::fs::create_dir_all(&target_dir)
        .await
        .map_err(|e| format!("无法创建语音模型目录: {}", e))?;

    let ua = "Mozilla/5.0 (X11; Linux x86_64) IntentOS/0.1.0";
    let internet_client = reqwest::Client::builder()
        .user_agent(ua)
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(1800))
        .build()
        .map_err(|e| format!("初始化 HTTP 客户端失败: {}", e))?;
    let local_client = reqwest::Client::builder()
        .no_proxy()
        .user_agent(ua)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| format!("初始化本地 HTTP 客户端失败: {}", e))?;

    let started_at = Instant::now();
    let mut completed_files_bytes = 0u64;
    let num_files = entry.files.len();
    let mut known_total_bytes: u64 = if base_url_override.is_some() {
        0
    } else {
        entry.approx_size_mb.saturating_mul(1024 * 1024)
    };

    for (idx, file_spec) in entry.files.iter().enumerate() {
        if cancel_flag.load(Ordering::SeqCst) {
            return Err("cancelled".to_string());
        }

        let safe_rel = validate_safe_rel_path(&file_spec.rel_path).map_err(|e| e.to_string())?;
        let final_path = target_dir.join(&safe_rel);
        if let Some(parent) = final_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("创建模型子目录失败: {}", e))?;
        }
        let part_path = PathBuf::from(format!("{}.part", final_path.to_string_lossy()));

        update_task_in_registry(data_dir, &entry.id, |st| {
            st.current_file = file_spec.rel_path.clone();
        });

        let candidate_urls: Vec<String> = match base_url_override {
            Some(ref base) => vec![format!(
                "{}/{}",
                base.trim_end_matches('/'),
                file_spec.rel_path.trim_start_matches('/')
            )],
            None => file_spec.urls.clone(),
        };

        let mut last_err = String::new();
        let mut file_succeeded = false;

        for url in &candidate_urls {
            if cancel_flag.load(Ordering::SeqCst) {
                let _ = tokio::fs::remove_file(&part_path).await;
                return Err("cancelled".to_string());
            }

            let client = if is_loopback_url(url) {
                &local_client
            } else {
                &internet_client
            };

            let send_res = tokio::select! {
                _ = cancel_notify.notified() => {
                    return Err("cancelled".to_string());
                }
                r = client.get(url).send() => r,
            };

            let mut resp = match send_res {
                Ok(r) => r,
                Err(e) => {
                    last_err = format!("请求 {} 失败: {}", url, e);
                    continue;
                }
            };

            if !resp.status().is_success() {
                last_err = format!("下载 {} 返回 HTTP {}", url, resp.status());
                continue;
            }

            let content_len = resp.content_length();
            let file_expected_total = if let Some(cl) = content_len {
                if base_url_override.is_some() || idx + 1 == num_files {
                    known_total_bytes = completed_files_bytes.saturating_add(cl);
                } else {
                    known_total_bytes = known_total_bytes.max(completed_files_bytes.saturating_add(cl));
                }
                Some(cl)
            } else {
                None
            };

            let mut part_file = match tokio::fs::File::create(&part_path).await {
                Ok(f) => f,
                Err(e) => {
                    return Err(format!("无法创建临时文件 {}: {}", part_path.display(), e));
                }
            };

            let mut file_written = 0u64;
            let mut stream_err: Option<String> = None;

            loop {
                if cancel_flag.load(Ordering::SeqCst) {
                    drop(part_file);
                    let _ = tokio::fs::remove_file(&part_path).await;
                    return Err("cancelled".to_string());
                }

                let next_chunk = tokio::select! {
                    _ = cancel_notify.notified() => {
                        drop(part_file);
                        let _ = tokio::fs::remove_file(&part_path).await;
                        return Err("cancelled".to_string());
                    }
                    c = resp.chunk() => c,
                };

                match next_chunk {
                    Ok(Some(chunk)) => {
                        if let Err(e) = part_file.write_all(&chunk).await {
                            stream_err = Some(format!("写入磁盘失败: {}", e));
                            break;
                        }
                        file_written = file_written.saturating_add(chunk.len() as u64);
                        let total_dl = completed_files_bytes.saturating_add(file_written);
                        let elapsed_s = started_at.elapsed().as_secs_f64().max(0.001);
                        let speed = (total_dl as f64 / elapsed_s) as u64;
                        let denom = known_total_bytes.max(total_dl).max(1);
                        let pct = ((total_dl as f64 / denom as f64) * 100.0).clamp(0.0, 99.9);

                        update_task_in_registry(data_dir, &entry.id, |st| {
                            st.downloaded_bytes = total_dl;
                            st.total_bytes = denom;
                            st.progress_pct = pct;
                            st.speed_bps = speed;
                        });
                    }
                    Ok(None) => break,
                    Err(e) => {
                        stream_err = Some(format!("网络流读取中断 ({}): {}", url, e));
                        break;
                    }
                }
            }

            if let Some(se) = stream_err {
                drop(part_file);
                let _ = tokio::fs::remove_file(&part_path).await;
                last_err = se;
                continue;
            }

            if let Err(e) = part_file.flush().await {
                drop(part_file);
                let _ = tokio::fs::remove_file(&part_path).await;
                last_err = format!("刷新文件缓存失败: {}", e);
                continue;
            }
            drop(part_file);

            if let Some(expected_cl) = file_expected_total
                && file_written != expected_cl
            {
                let _ = tokio::fs::remove_file(&part_path).await;
                last_err = format!(
                    "文件 {} 下载长度不完整 ({} / {} bytes)",
                    file_spec.rel_path, file_written, expected_cl
                );
                continue;
            }

            let min_required = if enforce_expected_min {
                file_spec.expected_min_bytes.max(1)
            } else {
                1
            };
            if file_written < min_required {
                let _ = tokio::fs::remove_file(&part_path).await;
                last_err = format!(
                    "文件 {} 体积异常 ({} bytes < 预期最小 {} bytes)",
                    file_spec.rel_path, file_written, min_required
                );
                continue;
            }

            tokio::fs::rename(&part_path, &final_path)
                .await
                .map_err(|e| format!("原子重命名模型文件失败: {}", e))?;

            completed_files_bytes = completed_files_bytes.saturating_add(file_written);
            file_succeeded = true;
            break;
        }

        if !file_succeeded {
            let _ = tokio::fs::remove_file(&part_path).await;
            return Err(format!(
                "模型文件 {} 下载失败：{}",
                file_spec.rel_path, last_err
            ));
        }
    }

    // Write `manifest.json` atomically so installation integrity is recorded
    let manifest = json!({
        "model_id": entry.id,
        "name": entry.name,
        "engine_kind": entry.engine_kind,
        "downloaded_bytes": completed_files_bytes,
        "installed_at": Utc::now().to_rfc3339(),
        "files": entry.files.iter().map(|f| &f.rel_path).collect::<Vec<_>>(),
    });
    let manifest_path = target_dir.join("manifest.json");
    let manifest_part = target_dir.join("manifest.json.part");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap_or_default();
    tokio::fs::write(&manifest_part, &manifest_bytes)
        .await
        .map_err(|e| format!("写入 manifest.json 失败: {}", e))?;
    tokio::fs::rename(&manifest_part, &manifest_path)
        .await
        .map_err(|e| format!("提交 manifest.json 失败: {}", e))?;

    // Auto-select `active_model_id = entry.id` if no model was installed yet (or active model wasn't installed)
    let mut cfg = load_speech_config_from_dir(config_dir);
    let current_active_installed = find_catalog_model(&cfg.active_model_id)
        .map(|active_entry| {
            active_entry.id != entry.id && is_model_installed_in_data_dir(data_dir, &active_entry)
        })
        .unwrap_or(false);
    if !had_installed_before || !current_active_installed {
        cfg.active_model_id = entry.id.clone();
        let _ = save_speech_config_to_dir(config_dir, &cfg);
    }

    Ok(completed_files_bytes)
}
