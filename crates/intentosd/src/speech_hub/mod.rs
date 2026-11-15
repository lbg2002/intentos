#![forbid(unsafe_code)]

//! Speech Recognition (ASR) Hub (`crates/intentosd/src/speech_hub/`):
//! - Persistent `SpeechConfig` in `${config_dir}/speech.json`
//! - Built-in 4-model offline ONNX catalog & streaming HTTP downloader (`model_manager`)
//! - PipeWire / PulseAudio / ALSA audio capture & local ONNX / cloud fallback transcription (`recorder_and_asr`)
//! - Unified `ModuleRpc` handler (`domain: "speech_hub"`)

pub mod model_manager;
pub mod recorder_and_asr;

use crate::core::IntentOsCore;
use crate::speech_hub::model_manager::{
    builtin_speech_models, cancel_model_download, delete_model, get_all_downloads_map,
    get_download_progress, list_models_with_status, start_model_download, validate_safe_model_id,
};
use crate::speech_hub::recorder_and_asr::{
    cancel_recording, get_recording_status, get_runtime_readiness, list_audio_sources,
    run_asr_runner_self_test, start_recording, stop_and_transcribe, transcribe_wav_file,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn default_speech_enabled() -> bool {
    false
}

fn default_active_model_id() -> String {
    "sensevoice-small-int8".to_string()
}

fn default_speech_language() -> String {
    "zh".to_string()
}

fn default_auto_send() -> bool {
    false
}

fn default_audio_source() -> String {
    "default".to_string()
}

fn default_allow_cloud_fallback() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpeechConfig {
    #[serde(default = "default_speech_enabled")]
    pub enabled: bool,
    #[serde(default = "default_active_model_id")]
    pub active_model_id: String,
    #[serde(default = "default_speech_language")]
    pub language: String,
    #[serde(default = "default_auto_send")]
    pub auto_send_after_transcribe: bool,
    #[serde(default = "default_audio_source")]
    pub audio_source: String,
    #[serde(default = "default_allow_cloud_fallback")]
    pub allow_cloud_fallback: bool,
}

impl Default for SpeechConfig {
    fn default() -> Self {
        Self {
            enabled: default_speech_enabled(),
            active_model_id: default_active_model_id(),
            language: default_speech_language(),
            auto_send_after_transcribe: default_auto_send(),
            audio_source: default_audio_source(),
            allow_cloud_fallback: default_allow_cloud_fallback(),
        }
    }
}

fn normalize_speech_language(raw: &str) -> anyhow::Result<String> {
    let clean = raw.trim().to_ascii_lowercase();
    match clean.as_str() {
        "" => Ok("zh".to_string()),
        "zh" | "zh-cn" | "cn" => Ok("zh".to_string()),
        "auto" => Ok("auto".to_string()),
        "en" | "en-us" => Ok("en".to_string()),
        "ja" | "ko" | "yue" => Ok(clean),
        other => anyhow::bail!("不支持的语音识别语言 '{}'（支持 zh / auto / en）", other),
    }
}

pub fn speech_config_path_in_dir(config_dir: &Path) -> PathBuf {
    config_dir.join("speech.json")
}

pub fn speech_config_path(core: &IntentOsCore) -> PathBuf {
    speech_config_path_in_dir(&core.paths.config_dir)
}

pub fn load_speech_config_from_dir(config_dir: &Path) -> SpeechConfig {
    let path = speech_config_path_in_dir(config_dir);
    if let Ok(raw) = std::fs::read_to_string(&path)
        && let Ok(mut parsed) = serde_json::from_str::<SpeechConfig>(&raw)
    {
        if parsed.active_model_id.trim().is_empty()
            || validate_safe_model_id(&parsed.active_model_id).is_err()
        {
            parsed.active_model_id = default_active_model_id();
        }
        parsed.language =
            normalize_speech_language(&parsed.language).unwrap_or_else(|_| "zh".to_string());
        if parsed.audio_source.trim().is_empty() {
            parsed.audio_source = "default".to_string();
        }
        return parsed;
    }
    SpeechConfig::default()
}

pub fn load_speech_config(core: &IntentOsCore) -> SpeechConfig {
    load_speech_config_from_dir(&core.paths.config_dir)
}

pub fn save_speech_config_to_dir(
    config_dir: &Path,
    cfg: &SpeechConfig,
) -> anyhow::Result<SpeechConfig> {
    std::fs::create_dir_all(config_dir)?;
    let mut normalized = cfg.clone();
    if normalized.active_model_id.trim().is_empty() {
        normalized.active_model_id = default_active_model_id();
    } else {
        validate_safe_model_id(&normalized.active_model_id)?;
        normalized.active_model_id = normalized.active_model_id.trim().to_string();
    }
    normalized.language = normalize_speech_language(&normalized.language)?;
    normalized.audio_source = if normalized.audio_source.trim().is_empty() {
        "default".to_string()
    } else {
        normalized.audio_source.trim().to_string()
    };

    let final_path = speech_config_path_in_dir(config_dir);
    let tmp_path = config_dir.join("speech.json.tmp");
    let bytes = serde_json::to_vec_pretty(&normalized)?;
    std::fs::write(&tmp_path, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(normalized)
}

pub fn save_speech_config(core: &IntentOsCore, cfg: &SpeechConfig) -> anyhow::Result<SpeechConfig> {
    save_speech_config_to_dir(&core.paths.config_dir, cfg)
}

pub fn update_speech_config_patch(
    core: &IntentOsCore,
    payload: &Value,
) -> anyhow::Result<SpeechConfig> {
    let mut cfg = load_speech_config(core);
    let src = payload.get("config").unwrap_or(payload);

    if let Some(enabled) = src.get("enabled").and_then(|v| v.as_bool()) {
        cfg.enabled = enabled;
    }
    if let Some(mid) = src.get("active_model_id").and_then(|v| v.as_str()) {
        let trimmed = mid.trim();
        if !trimmed.is_empty() {
            validate_safe_model_id(trimmed)?;
            cfg.active_model_id = trimmed.to_string();
        }
    }
    if let Some(lang) = src.get("language").and_then(|v| v.as_str()) {
        cfg.language = normalize_speech_language(lang)?;
    }
    if let Some(auto_send) = src
        .get("auto_send_after_transcribe")
        .and_then(|v| v.as_bool())
    {
        cfg.auto_send_after_transcribe = auto_send;
    }
    if let Some(audio_src) = src.get("audio_source").and_then(|v| v.as_str()) {
        let trimmed = audio_src.trim();
        cfg.audio_source = if trimmed.is_empty() {
            "default".to_string()
        } else {
            trimmed.to_string()
        };
    }
    if let Some(cloud_fb) = src.get("allow_cloud_fallback").and_then(|v| v.as_bool()) {
        cfg.allow_cloud_fallback = cloud_fb;
    }

    let saved = save_speech_config(core, &cfg)?;
    let _ = core.state_db.record_audit(
        None,
        "speech_hub.update_speech_config",
        "user_explicit",
        "setting",
        "allow",
        "ok",
        &serde_json::to_value(&saved).unwrap_or_else(|_| json!({})),
        None,
    );
    Ok(saved)
}

pub fn build_speech_overview(core: &IntentOsCore) -> Value {
    let cfg = load_speech_config(core);
    let models = list_models_with_status(core);
    let sources = list_audio_sources();
    let runtime_ready = get_runtime_readiness(core);
    let recording = get_recording_status(core);
    let active_download = get_download_progress(core, None);
    let downloads = get_all_downloads_map(core);

    json!({
        "config": cfg,
        "enabled": cfg.enabled,
        "active_model_id": cfg.active_model_id,
        "language": cfg.language,
        "auto_send_after_transcribe": cfg.auto_send_after_transcribe,
        "audio_source": cfg.audio_source,
        "models": models,
        "audio_sources": sources,
        "runtime_ready": runtime_ready,
        "recording": recording,
        "active_download": active_download,
        "downloads": downloads,
    })
}

pub async fn handle_module_rpc(
    core: &IntentOsCore,
    action: &str,
    payload: Value,
) -> anyhow::Result<Value> {
    match action {
        "ping" => Ok(json!({
            "module": "speech_hub",
            "status": "ready",
            "catalog_count": builtin_speech_models().len(),
            "payload": payload,
        })),

        "get_speech_overview" => Ok(build_speech_overview(core)),

        "get_speech_config" => Ok(serde_json::to_value(load_speech_config(core))?),

        "update_speech_config" => {
            let saved = update_speech_config_patch(core, &payload)?;
            Ok(json!({
                "ok": true,
                "saved": true,
                "config": saved,
                "enabled": saved.enabled,
                "active_model_id": saved.active_model_id,
                "language": saved.language,
                "auto_send_after_transcribe": saved.auto_send_after_transcribe,
                "audio_source": saved.audio_source,
                "allow_cloud_fallback": saved.allow_cloud_fallback,
            }))
        }

        "download_model" => {
            let model_id = payload
                .get("model_id")
                .or_else(|| payload.get("id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("download_model 缺少 model_id"))?;
            let base_url_override = payload
                .get("base_url_override")
                .or_else(|| payload.get("base_url"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from);
            let enforce_min = payload
                .get("enforce_expected_min_bytes")
                .and_then(|v| v.as_bool());

            start_model_download(core, model_id, base_url_override, enforce_min)
        }

        "get_download_progress" => {
            let model_id = payload
                .get("model_id")
                .or_else(|| payload.get("id"))
                .and_then(|v| v.as_str());
            Ok(get_download_progress(core, model_id))
        }

        "cancel_download" => {
            let model_id = payload
                .get("model_id")
                .or_else(|| payload.get("id"))
                .and_then(|v| v.as_str());
            cancel_model_download(core, model_id)
        }

        "delete_model" => {
            let model_id = payload
                .get("model_id")
                .or_else(|| payload.get("id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("delete_model 缺少 model_id"))?;
            delete_model(core, model_id)
        }

        "list_audio_sources" => {
            let sources = list_audio_sources();
            Ok(json!({
                "sources": sources,
                "audio_sources": sources,
            }))
        }

        "start_recording" => start_recording(core, &payload).await,

        "get_recording_status" => Ok(get_recording_status(core)),

        "stop_and_transcribe" => stop_and_transcribe(core, &payload).await,

        "cancel_recording" => Ok(cancel_recording(core)),

        "transcribe_wav_file" => transcribe_wav_file(core, &payload).await,

        "run_self_test" => run_asr_runner_self_test(core).await,

        other => anyhow::bail!("speech_hub: unknown action '{}'", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, BrainConfig, XdgPaths};
    use crate::speech_hub::recorder_and_asr::{
        inspect_wav_audio_quality, repair_wav_header_if_needed,
    };
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn setup_test_core() -> (tempfile::TempDir, Arc<IntentOsCore>) {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().join("intentos_speech_test");
        let ws = base.join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let xdg = XdgPaths::resolve(Some(&base), repo_root.clone());
        xdg.ensure_dirs().unwrap();
        let cfg = AppConfig {
            authorized_directories: vec![ws.to_string_lossy().to_string()],
            allow_simulated_hardware_fallback: true,
            ..AppConfig::default()
        };
        std::fs::write(
            xdg.config_dir.join("config.toml"),
            toml::to_string_pretty(&cfg).unwrap(),
        )
        .unwrap();
        std::fs::write(
            xdg.config_dir.join("brain.toml"),
            toml::to_string_pretty(&BrainConfig::default()).unwrap(),
        )
        .unwrap();

        let core = IntentOsCore::initialize(Some(&base), repo_root).expect("init core");
        (temp, core)
    }

    fn build_pcm16_wav_bytes(samples: &[i16], sample_rate: u32) -> Vec<u8> {
        let data_len = (samples.len() * 2) as u32;
        let riff_len = 36u32.saturating_add(data_len);
        let byte_rate = sample_rate * 2;
        let mut out = Vec::with_capacity(44 + data_len as usize);
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&riff_len.to_le_bytes());
        out.extend_from_slice(b"WAVE");
        out.extend_from_slice(b"fmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // PCM
        out.extend_from_slice(&1u16.to_le_bytes()); // mono
        out.extend_from_slice(&sample_rate.to_le_bytes());
        out.extend_from_slice(&byte_rate.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes()); // block align
        out.extend_from_slice(&16u16.to_le_bytes()); // 16-bit
        out.extend_from_slice(b"data");
        out.extend_from_slice(&data_len.to_le_bytes());
        for &s in samples {
            out.extend_from_slice(&s.to_le_bytes());
        }
        out
    }

    #[tokio::test]
    async fn test_speech_config_persistence_and_overview() {
        let (_tmp, core) = setup_test_core();

        // 1. Default config is disabled with sensevoice-small-int8 & zh
        let ov = handle_module_rpc(&core, "get_speech_overview", json!({}))
            .await
            .unwrap();
        assert_eq!(ov["config"]["enabled"], false);
        assert_eq!(ov["config"]["active_model_id"], "sensevoice-small-int8");
        assert_eq!(ov["config"]["language"], "zh");
        assert_eq!(ov["models"].as_array().unwrap().len(), 4);
        assert!(!ov["audio_sources"].as_array().unwrap().is_empty());

        // 2. Partial update persists to speech.json
        let upd = handle_module_rpc(
            &core,
            "update_speech_config",
            json!({
                "enabled": true,
                "language": "auto",
                "auto_send_after_transcribe": true
            }),
        )
        .await
        .unwrap();
        assert_eq!(upd["saved"], true);
        assert_eq!(upd["config"]["enabled"], true);
        assert_eq!(upd["config"]["language"], "auto");
        assert_eq!(upd["config"]["auto_send_after_transcribe"], true);
        assert!(speech_config_path(&core).is_file());

        // 3. Reload from disk confirms persistence
        let reloaded = load_speech_config(&core);
        assert!(reloaded.enabled);
        assert_eq!(reloaded.language, "auto");
        assert!(reloaded.auto_send_after_transcribe);
    }

    #[tokio::test]
    async fn test_path_traversal_and_invalid_model_id_rejected() {
        let (_tmp, core) = setup_test_core();

        for evil in [
            "../etc",
            "../../passwd",
            "sensevoice/../../x",
            ".hidden",
            "-flag",
            "UPPERCASE_ID",
            "model with space",
            "",
        ] {
            let dl_err =
                handle_module_rpc(&core, "download_model", json!({ "model_id": evil })).await;
            assert!(dl_err.is_err(), "download_model must reject '{}'", evil);

            let del_err =
                handle_module_rpc(&core, "delete_model", json!({ "model_id": evil })).await;
            assert!(del_err.is_err(), "delete_model must reject '{}'", evil);
        }
    }

    #[tokio::test]
    async fn test_streaming_download_progress_and_delete_against_mock_http() {
        let (_tmp, core) = setup_test_core();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    let body: Vec<u8> = if req.starts_with("GET /model.int8.onnx ") {
                        vec![0x4Fu8; 32_768]
                    } else if req.starts_with("GET /tokens.txt ") {
                        b"<unk> 0\n<s> 1\n</s> 2\n\xe2\x96\x81hello 3\n".to_vec()
                    } else {
                        let not_found = b"not found";
                        let hdr = format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            not_found.len()
                        );
                        let _ = stream.write_all(hdr.as_bytes()).await;
                        let _ = stream.write_all(not_found).await;
                        return;
                    };

                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(hdr.as_bytes()).await;
                    for chunk in body.chunks(4096) {
                        let _ = stream.write_all(chunk).await;
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                });
            }
        });

        // Switch active_model_id to whisper-tiny-q8 initially so we can verify auto-switch to first installed model
        let _ = handle_module_rpc(
            &core,
            "update_speech_config",
            json!({ "active_model_id": "whisper-tiny-q8" }),
        )
        .await
        .unwrap();

        let base_url = format!("http://{}", addr);
        let start_res = handle_module_rpc(
            &core,
            "download_model",
            json!({
                "model_id": "sensevoice-small-int8",
                "base_url_override": base_url,
            }),
        )
        .await
        .unwrap();
        assert_eq!(start_res["started"], true);

        // Poll progress until completed
        let mut final_prog = json!({});
        for _ in 0..80 {
            let p = handle_module_rpc(
                &core,
                "get_download_progress",
                json!({ "model_id": "sensevoice-small-int8" }),
            )
            .await
            .unwrap();
            if p["status"] == "completed" {
                final_prog = p;
                break;
            }
            assert_ne!(p["status"], "failed", "Download failed unexpectedly: {}", p);
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(final_prog["status"], "completed");
        assert_eq!(final_prog["installed"], true);
        assert_eq!(final_prog["progress_pct"], 100.0);

        // Verify files & manifest on disk and auto-selected active_model_id
        let model_dir = core
            .paths
            .data_dir
            .join("speech_models/sensevoice-small-int8");
        assert!(model_dir.join("model.int8.onnx").is_file());
        assert!(model_dir.join("tokens.txt").is_file());
        assert!(model_dir.join("manifest.json").is_file());
        assert_eq!(
            load_speech_config(&core).active_model_id,
            "sensevoice-small-int8"
        );

        // Delete model & verify cleanup
        let del = handle_module_rpc(
            &core,
            "delete_model",
            json!({ "model_id": "sensevoice-small-int8" }),
        )
        .await
        .unwrap();
        assert_eq!(del["deleted"], true);
        assert!(!model_dir.exists());
    }

    #[tokio::test]
    async fn test_streaming_download_cancellation_cleans_part_files() {
        let (_tmp, core) = setup_test_core();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let total = 1024 * 1024usize;
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    total
                );
                let _ = stream.write_all(hdr.as_bytes()).await;
                let chunk = vec![0xABu8; 4096];
                for _ in 0..256 {
                    if stream.write_all(&chunk).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(60)).await;
                }
            }
        });

        let base_url = format!("http://{}", addr);
        let _ = handle_module_rpc(
            &core,
            "download_model",
            json!({
                "model_id": "sensevoice-small-int8",
                "base_url_override": base_url,
            }),
        )
        .await
        .unwrap();

        // Wait until first chunks arrive
        for _ in 0..40 {
            let p = handle_module_rpc(&core, "get_download_progress", json!({}))
                .await
                .unwrap();
            if p["downloaded_bytes"].as_u64().unwrap_or(0) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Cancel mid-stream
        let cancel_res = handle_module_rpc(
            &core,
            "cancel_download",
            json!({ "model_id": "sensevoice-small-int8" }),
        )
        .await
        .unwrap();
        assert_eq!(cancel_res["cancelled"], true);
        assert_eq!(cancel_res["status"], "cancelled");

        tokio::time::sleep(Duration::from_millis(50)).await;
        let prog = handle_module_rpc(
            &core,
            "get_download_progress",
            json!({ "model_id": "sensevoice-small-int8" }),
        )
        .await
        .unwrap();
        assert_eq!(prog["status"], "cancelled");
        assert_eq!(prog["installed"], false);

        let part_file = core
            .paths
            .data_dir
            .join("speech_models/sensevoice-small-int8/model.int8.onnx.part");
        assert!(!part_file.exists(), ".part file must be cleaned on cancel");
    }

    #[tokio::test]
    async fn test_wav_header_repair_rms_silence_detection_and_recording_guards() {
        let (tmp, core) = setup_test_core();

        // 1. Recording rejected when disabled & test_mode == false
        let disabled_err = handle_module_rpc(&core, "start_recording", json!({}))
            .await
            .unwrap_err();
        assert!(disabled_err.to_string().contains("尚未开启"));

        // 2. Recording rejected with clear download prompt when no local model & no cloud key
        let _ = handle_module_rpc(
            &core,
            "update_speech_config",
            json!({ "enabled": true, "allow_cloud_fallback": false }),
        )
        .await
        .unwrap();
        let no_model_err = handle_module_rpc(&core, "start_recording", json!({}))
            .await
            .unwrap_err();
        assert!(
            no_model_err
                .to_string()
                .contains("请先在设置中下载离线语音识别模型")
        );

        // 3. Silence WAV rejected with friendly message
        let silent_wav = tmp.path().join("silent.wav");
        let silence_samples = vec![0i16; 8000];
        std::fs::write(&silent_wav, build_pcm16_wav_bytes(&silence_samples, 16000)).unwrap();
        let silence_err = inspect_wav_audio_quality(&silent_wav).unwrap_err();
        assert!(silence_err.to_string().contains("未检测到有效人声输入"));

        // 4. Valid speech-amplitude WAV with 0xFFFFFFFF streamed RIFF size is repaired & accepted
        let tone_wav = tmp.path().join("tone.wav");
        let tone_samples: Vec<i16> = (0..8000)
            .map(|i| {
                ((i as f64 * 2.0 * std::f64::consts::PI * 440.0 / 16000.0).sin() * 9000.0) as i16
            })
            .collect();
        let mut raw_wav = build_pcm16_wav_bytes(&tone_samples, 16000);
        raw_wav[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        raw_wav[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&tone_wav, &raw_wav).unwrap();

        repair_wav_header_if_needed(&tone_wav).unwrap();
        let stats = inspect_wav_audio_quality(&tone_wav).unwrap();
        assert_eq!(stats.sample_rate, 16000);
        assert!(stats.rms > 0.15);
        assert!((stats.duration_sec - 0.5).abs() < 0.02);
    }

    #[tokio::test]
    async fn test_asr_runner_script_self_test_passes() {
        let (_tmp, core) = setup_test_core();
        let res = handle_module_rpc(&core, "run_self_test", json!({}))
            .await
            .unwrap();
        assert_eq!(res["ok"], true);
        assert_eq!(res["onnxruntime_available"], true);
        assert_eq!(res["bpe_roundtrip_ok"], true);
        assert_eq!(res["ctc_decode_ok"], true);
    }

    #[tokio::test]
    async fn test_whisper_nested_subdir_download_and_cloud_fallback_transcribe() {
        let (tmp, core) = setup_test_core();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    if req.starts_with("POST /v1/audio/transcriptions ") {
                        let json_body = r#"{"text":"打开文档目录查找硕士论文"}"#;
                        let hdr = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            json_body.len(),
                            json_body
                        );
                        let _ = stream.write_all(hdr.as_bytes()).await;
                        return;
                    }

                    let body: Vec<u8> =
                        if req.starts_with("GET /onnx/encoder_model_quantized.onnx ") {
                            vec![0x11u8; 4096]
                        } else if req.starts_with("GET /onnx/decoder_model_quantized.onnx ") {
                            vec![0x22u8; 4096]
                        } else if req.starts_with("GET /tokenizer.json ") {
                            br#"{"model":{"vocab":{}},"added_tokens":[]}"#.to_vec()
                        } else if req.starts_with("GET /config.json ") {
                            br#"{"num_mel_bins":80}"#.to_vec()
                        } else {
                            b"missing".to_vec()
                        };

                    let status = if body == b"missing" {
                        "HTTP/1.1 404 Not Found"
                    } else {
                        "HTTP/1.1 200 OK"
                    };
                    let hdr = format!(
                        "{}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status,
                        body.len()
                    );
                    let _ = stream.write_all(hdr.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                });
            }
        });

        // 1. Test cloud fallback `/v1/audio/transcriptions` when no local model is installed yet
        let mut brain = BrainConfig::default();
        if let Some(prov) = brain.providers.first_mut() {
            prov.base_url = format!("http://{}/v1", addr);
        }
        core.gateway.update_brain_config(brain.clone());
        std::fs::write(
            core.paths.config_dir.join("brain.toml"),
            toml::to_string_pretty(&brain).unwrap(),
        )
        .unwrap();

        let speech_wav = tmp.path().join("sample_voice.wav");
        let tone_samples: Vec<i16> = (0..8000)
            .map(|i| {
                ((i as f64 * 2.0 * std::f64::consts::PI * 300.0 / 16000.0).sin() * 10000.0) as i16
            })
            .collect();
        std::fs::write(&speech_wav, build_pcm16_wav_bytes(&tone_samples, 16000)).unwrap();

        let tr = handle_module_rpc(
            &core,
            "transcribe_wav_file",
            json!({ "wav_path": speech_wav.to_string_lossy().to_string() }),
        )
        .await
        .unwrap();
        assert_eq!(tr["ok"], true);
        assert_eq!(tr["text"], "打开文档目录查找硕士论文");
        assert_eq!(tr["transcript"], "打开文档目录查找硕士论文");

        // 2. Test nested subpath download for `whisper-tiny-q8` (`onnx/encoder_model_quantized.onnx`)
        let _ = handle_module_rpc(
            &core,
            "download_model",
            json!({
                "model_id": "whisper-tiny-q8",
                "base_url_override": format!("http://{}", addr),
            }),
        )
        .await
        .unwrap();

        for _ in 0..80 {
            let p = handle_module_rpc(
                &core,
                "get_download_progress",
                json!({ "model_id": "whisper-tiny-q8" }),
            )
            .await
            .unwrap();
            if p["status"] == "completed" {
                assert!(p["downloads"]["whisper-tiny-q8"].is_object());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let w_dir = core.paths.data_dir.join("speech_models/whisper-tiny-q8");
        assert!(w_dir.join("onnx/encoder_model_quantized.onnx").is_file());
        assert!(w_dir.join("onnx/decoder_model_quantized.onnx").is_file());
        assert!(w_dir.join("tokenizer.json").is_file());
        assert!(w_dir.join("config.json").is_file());
    }
}
