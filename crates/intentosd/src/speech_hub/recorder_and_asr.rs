#![forbid(unsafe_code)]

//! PipeWire / PulseAudio / ALSA Audio Capture, WAV Header & RMS Validator,
//! and Local ONNX / Cloud Fallback Speech-to-Text Engine
//! (`crates/intentosd/src/speech_hub/recorder_and_asr.rs`).

use crate::config_center::brain_manager::lookup_provider_credential;
use crate::core::IntentOsCore;
use crate::speech_hub::load_speech_config;
use crate::speech_hub::model_manager::{
    has_any_installed_model, list_models_with_status, resolve_installed_model,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioSourceInfo {
    pub id: String,
    pub name: String,
    pub label: String,
    pub driver: String,
    pub state: String,
    pub is_monitor: bool,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WavAudioStats {
    pub file_bytes: u64,
    pub sample_rate: u32,
    pub channels: u16,
    pub bits_per_sample: u16,
    pub sample_count: usize,
    pub duration_sec: f64,
    pub rms: f64,
    pub peak_norm: f64,
    pub peak_i16: i32,
}

#[derive(Debug, Clone)]
struct PythonRuntimeProbe {
    python_bin: Option<String>,
    onnxruntime: bool,
    onnxruntime_version: Option<String>,
}

struct ActiveRecordingSession {
    child: Child,
    pid: u32,
    wav_path: PathBuf,
    audio_source: String,
    backend: String,
    started_at: Instant,
}

static PYTHON_PROBE_CACHE: OnceLock<PythonRuntimeProbe> = OnceLock::new();
static RECORDING_SESSIONS: OnceLock<Mutex<HashMap<PathBuf, ActiveRecordingSession>>> =
    OnceLock::new();

fn recording_sessions() -> &'static Mutex<HashMap<PathBuf, ActiveRecordingSession>> {
    RECORDING_SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Apply clean desktop audio environment (stripping Conda `LD_LIBRARY_PATH` so system PipeWire/PulseAudio loads cleanly).
fn apply_clean_audio_env(cmd: &mut Command) {
    cmd.env_remove("LD_LIBRARY_PATH")
        .env_remove("PYTHONHOME")
        .env_remove("PYTHONPATH");
    if std::env::var_os("PATH").is_none() {
        cmd.env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        );
    }
}

/// Apply clean Python environment so Conda / virtualenv Python loads its own stdlib + `onnxruntime` + `numpy`.
fn apply_clean_python_env(cmd: &mut Command) {
    cmd.env_remove("PYTHONHOME")
        .env_remove("PYTHONPATH")
        .env_remove("LD_LIBRARY_PATH");
}

fn apply_clean_tokio_python_env(cmd: &mut tokio::process::Command) {
    cmd.env_remove("PYTHONHOME")
        .env_remove("PYTHONPATH")
        .env_remove("LD_LIBRARY_PATH");
}

fn probe_recorder_binary() -> Option<String> {
    for candidate in [
        "/usr/bin/pw-record",
        "/usr/bin/parecord",
        "/usr/bin/ffmpeg",
        "/usr/bin/arecord",
    ] {
        let p = Path::new(candidate);
        if p.is_file() {
            return Some(candidate.to_string());
        }
    }
    None
}

fn discover_python_candidates() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push_unique = |p: PathBuf| {
        if !out.iter().any(|x| x == &p) {
            out.push(p);
        }
    };

    if let Ok(custom) = std::env::var("INTENTOS_ASR_PYTHON")
        && !custom.trim().is_empty()
    {
        push_unique(PathBuf::from(custom.trim()));
    }

    if let Ok(conda_prefix) = std::env::var("CONDA_PREFIX")
        && !conda_prefix.trim().is_empty()
    {
        push_unique(PathBuf::from(conda_prefix.trim()).join("bin/python3"));
    }

    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        push_unique(home.join("miniconda3/envs/myenv0/bin/python3"));
        for base in [
            home.join("miniconda3/envs"),
            home.join("anaconda3/envs"),
            home.join("miniforge3/envs"),
        ] {
            if let Ok(entries) = std::fs::read_dir(base) {
                let mut env_dirs: Vec<PathBuf> =
                    entries.flatten().map(|e| e.path()).collect();
                env_dirs.sort();
                for dir in env_dirs {
                    push_unique(dir.join("bin/python3"));
                }
            }
        }
        push_unique(home.join("miniconda3/bin/python3"));
        push_unique(home.join("anaconda3/bin/python3"));
        push_unique(home.join("miniforge3/bin/python3"));
    }

    push_unique(PathBuf::from("/usr/bin/python3"));
    out
}

fn probe_python_onnx_runtime() -> &'static PythonRuntimeProbe {
    PYTHON_PROBE_CACHE.get_or_init(|| {
        let candidates = discover_python_candidates();
        let mut fallback_python: Option<String> = None;

        for cand in candidates {
            if !cand.is_file() {
                continue;
            }
            let cand_str = cand.to_string_lossy().to_string();
            if fallback_python.is_none() {
                fallback_python = Some(cand_str.clone());
            }

            let mut cmd = Command::new(&cand);
            apply_clean_python_env(&mut cmd);
            cmd.args([
                "-c",
                "import onnxruntime, numpy; print(onnxruntime.__version__)",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

            if let Ok(output) = cmd.output()
                && output.status.success()
            {
                let ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
                return PythonRuntimeProbe {
                    python_bin: Some(cand_str),
                    onnxruntime: true,
                    onnxruntime_version: if ver.is_empty() { None } else { Some(ver) },
                };
            }
        }

        PythonRuntimeProbe {
            python_bin: fallback_python,
            onnxruntime: false,
            onnxruntime_version: None,
        }
    })
}

pub fn resolve_asr_runner_script(core: &IntentOsCore) -> PathBuf {
    let from_repo = core.paths.repo_root.join("scripts/intentos_asr_runner.py");
    if from_repo.is_file() {
        return from_repo;
    }
    if let Some(manifest_root) = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
    {
        let dev_path = manifest_root.join("scripts/intentos_asr_runner.py");
        if dev_path.is_file() {
            return dev_path;
        }
    }
    PathBuf::from("/usr/share/intentos/scripts/intentos_asr_runner.py")
}

/// Check if an OpenAI-compatible HTTP endpoint + API key is configured for `/v1/audio/transcriptions` fallback.
fn resolve_cloud_asr_endpoint(core: &IntentOsCore) -> Option<(String, Option<String>)> {
    let (prof, prov) = core.gateway.resolve_profile("main").ok()?;
    let _ = prof;
    let base = prov.base_url.trim().trim_end_matches('/').to_string();
    if base.is_empty() {
        return None;
    }
    if base.contains("127.0.0.1") || base.contains("localhost") {
        let key = lookup_provider_credential(&core.paths, &prov.id);
        return Some((base, key));
    }
    let key = lookup_provider_credential(&core.paths, &prov.id)?;
    if key.trim().is_empty() {
        return None;
    }
    Some((base, Some(key)))
}

pub fn is_cloud_asr_fallback_ready(core: &IntentOsCore) -> bool {
    resolve_cloud_asr_endpoint(core).is_some()
}

pub fn get_runtime_readiness(core: &IntentOsCore) -> Value {
    let recorder_bin = probe_recorder_binary();
    let py = probe_python_onnx_runtime();
    let script_path = resolve_asr_runner_script(core);
    let models = list_models_with_status(core);
    let installed_count = models
        .iter()
        .filter(|m| m.get("installed").and_then(|v| v.as_bool()).unwrap_or(false))
        .count();

    json!({
        "recorder_bin": recorder_bin,
        "recorder_ready": recorder_bin.is_some(),
        "python_bin": py.python_bin,
        "onnxruntime": py.onnxruntime,
        "onnxruntime_version": py.onnxruntime_version,
        "asr_script_path": script_path.to_string_lossy().to_string(),
        "asr_script_exists": script_path.is_file(),
        "installed_model_count": installed_count,
        "cloud_fallback_ready": is_cloud_asr_fallback_ready(core),
    })
}

fn query_pactl_source_descriptions() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut cmd = Command::new("/usr/bin/pactl");
    apply_clean_audio_env(&mut cmd);
    cmd.env("LANG", "C")
        .env("LC_ALL", "C")
        .args(["list", "sources"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let Ok(out) = cmd.output() else {
        return map;
    };
    if !out.status.success() {
        return map;
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut current_name: Option<String> = None;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if let Some(rest) = line.strip_prefix("Name:") {
            current_name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Description:")
            && let Some(ref name) = current_name
        {
            let desc = rest.trim();
            if !desc.is_empty() {
                map.insert(name.clone(), desc.to_string());
            }
        }
    }
    map
}

/// Enumerate audio input sources (`default` + PipeWire/PulseAudio `pactl` sources, falling back to `arecord -l`).
/// Non-monitor physical/virtual microphones (`is_monitor: false`) are ordered before `.monitor` output loopbacks.
pub fn list_audio_sources() -> Vec<AudioSourceInfo> {
    let mut real_mics: Vec<AudioSourceInfo> = Vec::new();
    let mut monitors: Vec<AudioSourceInfo> = Vec::new();

    let descriptions = query_pactl_source_descriptions();
    let mut pactl_cmd = Command::new("/usr/bin/pactl");
    apply_clean_audio_env(&mut pactl_cmd);
    pactl_cmd
        .args(["list", "short", "sources"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    if let Ok(out) = pactl_cmd.output()
        && out.status.success()
    {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 2 {
                continue;
            }
            let src_name = cols[1].trim();
            if src_name.is_empty() {
                continue;
            }
            let driver = cols.get(2).copied().unwrap_or("PipeWire").trim().to_string();
            let state = cols.get(4).copied().unwrap_or("IDLE").trim().to_string();
            let is_monitor = src_name.ends_with(".monitor") || src_name.contains(".monitor");

            let friendly = descriptions
                .get(src_name)
                .cloned()
                .unwrap_or_else(|| src_name.to_string());
            let label = if is_monitor {
                format!("{} (系统输出回环)", friendly)
            } else if friendly != src_name {
                format!("{} ({})", friendly, src_name)
            } else {
                friendly.clone()
            };

            let item = AudioSourceInfo {
                id: src_name.to_string(),
                name: friendly,
                label,
                driver,
                state,
                is_monitor,
                is_default: false,
            };
            if is_monitor {
                monitors.push(item);
            } else {
                real_mics.push(item);
            }
        }
    }

    // Fallback to `arecord -l` if `pactl` found no real input sources
    if real_mics.is_empty() {
        let mut arecord_cmd = Command::new("/usr/bin/arecord");
        apply_clean_audio_env(&mut arecord_cmd);
        arecord_cmd
            .env("LANG", "C")
            .arg("-l")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        if let Ok(out) = arecord_cmd.output()
            && out.status.success()
        {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("card ")
                    && let Some((card_part, after_card)) = rest.split_once(':')
                    && let Some((card_title, dev_part)) = after_card.split_once(", device ")
                    && let Some((dev_num, dev_title)) = dev_part.split_once(':')
                {
                    let c_idx = card_part.trim();
                    let d_idx = dev_num.trim();
                    if c_idx.chars().all(|c| c.is_ascii_digit())
                        && d_idx.chars().all(|c| c.is_ascii_digit())
                    {
                        let hw_id = format!("plughw:{},{}", c_idx, d_idx);
                        let friendly = format!("{} - {}", card_title.trim(), dev_title.trim());
                        real_mics.push(AudioSourceInfo {
                            id: hw_id.clone(),
                            name: friendly.clone(),
                            label: format!("{} ({})", friendly, hw_id),
                            driver: "ALSA".to_string(),
                            state: "READY".to_string(),
                            is_monitor: false,
                            is_default: false,
                        });
                    }
                }
            }
        }
    }

    let mut result = vec![AudioSourceInfo {
        id: "default".to_string(),
        name: "系统默认麦克风".to_string(),
        label: "系统默认麦克风 (自动优选)".to_string(),
        driver: "system".to_string(),
        state: "READY".to_string(),
        is_monitor: false,
        is_default: true,
    }];
    result.extend(real_mics);
    result.extend(monitors);
    result
}

fn send_sigint_safe(pid: u32) {
    for kill_bin in ["/bin/kill", "/usr/bin/kill"] {
        if Path::new(kill_bin).is_file() {
            let _ = Command::new(kill_bin)
                .args(["-INT", &pid.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            return;
        }
    }
}

fn set_private_wav_permissions(wav_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if wav_path.exists() {
            let _ = std::fs::set_permissions(wav_path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

pub fn get_recording_status(core: &IntentOsCore) -> Value {
    let mut map = recording_sessions().lock().unwrap();
    if let Some(sess) = map.get_mut(&core.paths.runtime_dir) {
        match sess.child.try_wait() {
            Ok(None) => {
                let elapsed_ms = sess.started_at.elapsed().as_millis() as u64;
                return json!({
                    "active": true,
                    "recording": true,
                    "elapsed_ms": elapsed_ms,
                    "wav_path": sess.wav_path.to_string_lossy().to_string(),
                    "audio_source": sess.audio_source,
                    "backend": sess.backend,
                });
            }
            _ => {
                // Child already exited prematurely
                map.remove(&core.paths.runtime_dir);
            }
        }
    }
    json!({
        "active": false,
        "recording": false,
        "elapsed_ms": 0,
        "wav_path": Value::Null,
        "audio_source": Value::Null,
        "backend": Value::Null,
    })
}

pub fn cancel_recording(core: &IntentOsCore) -> Value {
    let removed = recording_sessions()
        .lock()
        .unwrap()
        .remove(&core.paths.runtime_dir);

    if let Some(mut sess) = removed {
        send_sigint_safe(sess.pid);
        let _ = sess.child.kill();
        let _ = sess.child.wait();
        let _ = std::fs::remove_file(&sess.wav_path);
        return json!({
            "cancelled": true,
            "active": false,
            "recording": false,
        });
    }
    let stale_wav = core.paths.runtime_dir.join("intentos_voice_capture.wav");
    let _ = std::fs::remove_file(stale_wav);
    json!({
        "cancelled": false,
        "active": false,
        "recording": false,
    })
}

fn spawn_recorder_candidate(
    backend: &str,
    audio_source: &str,
    wav_path: &Path,
) -> std::io::Result<Child> {
    let wav_str = wav_path.to_string_lossy().to_string();
    let is_custom_target = !audio_source.is_empty() && audio_source != "default";

    match backend {
        "pw-record" => {
            let mut cmd = Command::new("/usr/bin/pw-record");
            apply_clean_audio_env(&mut cmd);
            cmd.args(["--rate", "16000", "--channels", "1", "--format", "s16"]);
            if is_custom_target && !audio_source.starts_with("plughw:") {
                cmd.args(["--target", audio_source]);
            }
            cmd.arg(&wav_str)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        }
        "parecord" => {
            let mut cmd = Command::new("/usr/bin/parecord");
            apply_clean_audio_env(&mut cmd);
            cmd.args([
                "--rate=16000",
                "--channels=1",
                "--format=s16le",
                "--file-format=wav",
            ]);
            if is_custom_target && !audio_source.starts_with("plughw:") {
                cmd.arg(format!("--device={}", audio_source));
            }
            cmd.arg(&wav_str)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        }
        "ffmpeg" => {
            let mut cmd = Command::new("/usr/bin/ffmpeg");
            apply_clean_audio_env(&mut cmd);
            let input_dev = if is_custom_target && !audio_source.starts_with("plughw:") {
                audio_source
            } else {
                "default"
            };
            cmd.args([
                "-nostdin",
                "-loglevel",
                "error",
                "-f",
                "pulse",
                "-i",
                input_dev,
                "-ar",
                "16000",
                "-ac",
                "1",
                "-c:a",
                "pcm_s16le",
                "-y",
                &wav_str,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        }
        "arecord" => {
            let mut cmd = Command::new("/usr/bin/arecord");
            apply_clean_audio_env(&mut cmd);
            cmd.args(["-q", "-f", "S16_LE", "-r", "16000", "-c", "1"]);
            if audio_source.starts_with("plughw:") || audio_source.starts_with("hw:") {
                cmd.args(["-D", audio_source]);
            }
            cmd.arg(&wav_str)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "unknown recorder backend",
        )),
    }
}

pub async fn start_recording(core: &IntentOsCore, payload: &Value) -> anyhow::Result<Value> {
    let test_mode = payload
        .get("test_mode")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let cfg = load_speech_config(core);

    if !cfg.enabled && !test_mode {
        anyhow::bail!("语音识别功能尚未开启，请先在设置中打开「开启悬浮窗语音识别输入功能」开关");
    }

    let local_ready = has_any_installed_model(core);
    let cloud_ready = cfg.allow_cloud_fallback && is_cloud_asr_fallback_ready(core);
    if !local_ready && !cloud_ready {
        anyhow::bail!("请先在设置中下载离线语音识别模型（如 SenseVoice 或 Whisper Tiny）");
    }

    // Stop any previous dangling capture on this runtime_dir
    let _ = cancel_recording(core);

    std::fs::create_dir_all(&core.paths.runtime_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &core.paths.runtime_dir,
            std::fs::Permissions::from_mode(0o700),
        );
    }

    let wav_path = core.paths.runtime_dir.join("intentos_voice_capture.wav");
    let _ = std::fs::remove_file(&wav_path);
    std::fs::write(&wav_path, b"")?;
    set_private_wav_permissions(&wav_path);

    let chosen_source = payload
        .get("audio_source")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(cfg.audio_source.as_str())
        .to_string();

    let backends = [
        ("pw-record", "/usr/bin/pw-record"),
        ("parecord", "/usr/bin/parecord"),
        ("ffmpeg", "/usr/bin/ffmpeg"),
        ("arecord", "/usr/bin/arecord"),
    ];

    let mut last_err = String::from("未找到可用的录音工具（pw-record / parecord / ffmpeg / arecord）");
    for (backend_name, bin_path) in backends {
        if !Path::new(bin_path).is_file() {
            continue;
        }
        match spawn_recorder_candidate(backend_name, &chosen_source, &wav_path) {
            Ok(mut child) => {
                tokio::time::sleep(Duration::from_millis(65)).await;
                match child.try_wait() {
                    Ok(None) => {
                        set_private_wav_permissions(&wav_path);
                        let pid = child.id();
                        let sess = ActiveRecordingSession {
                            child,
                            pid,
                            wav_path: wav_path.clone(),
                            audio_source: chosen_source.clone(),
                            backend: backend_name.to_string(),
                            started_at: Instant::now(),
                        };
                        recording_sessions()
                            .lock()
                            .unwrap()
                            .insert(core.paths.runtime_dir.clone(), sess);

                        return Ok(json!({
                            "ok": true,
                            "active": true,
                            "recording": true,
                            "backend": backend_name,
                            "audio_source": chosen_source,
                            "wav_path": wav_path.to_string_lossy().to_string(),
                        }));
                    }
                    Ok(Some(status)) => {
                        last_err = format!("{} 启动后立即退出 ({})", backend_name, status);
                    }
                    Err(e) => {
                        let _ = child.kill();
                        last_err = format!("{} 状态探测失败: {}", backend_name, e);
                    }
                }
            }
            Err(e) => {
                last_err = format!("启动 {} 失败: {}", backend_name, e);
            }
        }
    }

    let _ = std::fs::remove_file(&wav_path);
    anyhow::bail!("无法启动麦克风录音会话：{}", last_err)
}

/// Repair streamed RIFF/WAVE chunk sizes (`0xFFFFFFFF` / `0` / truncated) if recorder exited mid-flush.
pub fn repair_wav_header_if_needed(wav_path: &Path) -> anyhow::Result<()> {
    let mut buf = std::fs::read(wav_path)?;
    if buf.len() < 44 || &buf[0..4] != b"RIFF" || &buf[8..12] != b"WAVE" {
        return Ok(());
    }
    let total_len = buf.len();
    let expected_riff_size = (total_len.saturating_sub(8)).min(u32::MAX as usize) as u32;
    let cur_riff_size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let mut modified = false;

    if cur_riff_size == 0 || cur_riff_size == u32::MAX || cur_riff_size == 0x7FFF_FFFF {
        buf[4..8].copy_from_slice(&expected_riff_size.to_le_bytes());
        modified = true;
    }

    let mut pos = 12usize;
    while pos + 8 <= total_len {
        let chunk_id = [buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]];
        let chunk_sz =
            u32::from_le_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        if &chunk_id == b"data" {
            let actual_data = (total_len.saturating_sub(pos + 8)).min(u32::MAX as usize) as u32;
            if chunk_sz == 0
                || chunk_sz == u32::MAX
                || chunk_sz == 0x7FFF_FFFF
                || (pos + 8 + chunk_sz as usize) > total_len
            {
                buf[pos + 4..pos + 8].copy_from_slice(&actual_data.to_le_bytes());
                modified = true;
            }
            break;
        }
        let step = 8usize.saturating_add(chunk_sz as usize) + ((chunk_sz as usize) & 1);
        if step == 0 || pos + step > total_len {
            break;
        }
        pos += step;
    }

    if modified {
        std::fs::write(wav_path, &buf)?;
        set_private_wav_permissions(wav_path);
    }
    Ok(())
}

/// Inspect a PCM WAV file header and compute duration, peak amplitude, and normalized RMS energy.
pub fn inspect_wav_audio_quality(wav_path: &Path) -> anyhow::Result<WavAudioStats> {
    let raw = std::fs::read(wav_path)
        .map_err(|e| anyhow::anyhow!("无法读取录音文件 {}: {}", wav_path.display(), e))?;
    let file_bytes = raw.len() as u64;
    if file_bytes < 1600 {
        anyhow::bail!("未检测到有效人声输入，请检查麦克风音量后重试");
    }
    if raw.len() < 44 || &raw[0..4] != b"RIFF" || &raw[8..12] != b"WAVE" {
        anyhow::bail!("录音文件格式异常（非标准 RIFF/WAVE 音频）");
    }

    let mut pos = 12usize;
    let mut audio_format: u16 = 1;
    let mut channels: u16 = 1;
    let mut sample_rate: u32 = 16000;
    let mut bits_per_sample: u16 = 16;
    let mut data_slice: &[u8] = &[];

    while pos + 8 <= raw.len() {
        let cid = &raw[pos..pos + 4];
        let csz =
            u32::from_le_bytes([raw[pos + 4], raw[pos + 5], raw[pos + 6], raw[pos + 7]]) as usize;
        pos += 8;
        if cid == b"fmt " && pos + 16 <= raw.len() {
            let end = raw.len().min(pos.saturating_add(csz));
            let fmt = &raw[pos..end];
            audio_format = u16::from_le_bytes([fmt[0], fmt[1]]);
            channels = u16::from_le_bytes([fmt[2], fmt[3]]).max(1);
            sample_rate = u32::from_le_bytes([fmt[4], fmt[5], fmt[6], fmt[7]]).max(1);
            bits_per_sample = u16::from_le_bytes([fmt[14], fmt[15]]).max(8);
            if audio_format == 0xFFFE && fmt.len() >= 26 {
                audio_format = u16::from_le_bytes([fmt[24], fmt[25]]);
            }
        } else if cid == b"data" {
            let end = if csz == 0 || csz >= 0x7FFF_FFFF || pos.saturating_add(csz) > raw.len() {
                raw.len()
            } else {
                pos + csz
            };
            data_slice = &raw[pos..end];
            break;
        }

        let step = csz.saturating_add(csz & 1);
        if pos.saturating_add(step) > raw.len() {
            break;
        }
        pos += step;
    }

    if data_slice.len() < 800 {
        anyhow::bail!("未检测到有效人声输入，请检查麦克风音量后重试");
    }

    let bytes_per_sample = (bits_per_sample as usize / 8).max(1);
    let mut sum_sq = 0.0f64;
    let mut peak_norm = 0.0f64;
    let mut sample_count = 0usize;

    if audio_format == 3 && bytes_per_sample == 4 {
        for chunk in data_slice.chunks_exact(4) {
            let v = f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as f64;
            let clamped = v.clamp(-1.0, 1.0);
            sum_sq += clamped * clamped;
            peak_norm = peak_norm.max(clamped.abs());
            sample_count += 1;
        }
    } else if bytes_per_sample == 2 {
        for chunk in data_slice.chunks_exact(2) {
            let s = i16::from_le_bytes([chunk[0], chunk[1]]) as f64 / 32768.0;
            sum_sq += s * s;
            peak_norm = peak_norm.max(s.abs());
            sample_count += 1;
        }
    } else if bytes_per_sample == 1 {
        for &b in data_slice {
            let s = (b as f64 - 128.0) / 128.0;
            sum_sq += s * s;
            peak_norm = peak_norm.max(s.abs());
            sample_count += 1;
        }
    } else if bytes_per_sample == 4 {
        for chunk in data_slice.chunks_exact(4) {
            let s =
                i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as f64 / 2147483648.0;
            sum_sq += s * s;
            peak_norm = peak_norm.max(s.abs());
            sample_count += 1;
        }
    } else {
        anyhow::bail!("不支持的 WAV 采样位深: {} bits", bits_per_sample);
    }

    if sample_count == 0 {
        anyhow::bail!("未检测到有效人声输入，请检查麦克风音量后重试");
    }

    let rms = (sum_sq / sample_count as f64).sqrt();
    let peak_i16 = (peak_norm * 32768.0).round() as i32;
    let frames = sample_count / (channels as usize).max(1);
    let duration_sec = frames as f64 / sample_rate as f64;

    if rms < 0.0008 && peak_i16 < 45 {
        anyhow::bail!("未检测到有效人声输入，请检查麦克风音量后重试");
    }

    Ok(WavAudioStats {
        file_bytes,
        sample_rate,
        channels,
        bits_per_sample,
        sample_count,
        duration_sec,
        rms,
        peak_norm,
        peak_i16,
    })
}

pub async fn stop_and_transcribe(core: &IntentOsCore, payload: &Value) -> anyhow::Result<Value> {
    let session = recording_sessions()
        .lock()
        .unwrap()
        .remove(&core.paths.runtime_dir)
        .ok_or_else(|| anyhow::anyhow!("当前没有正在进行的录音会话"))?;

    let mut child = session.child;
    send_sigint_safe(session.pid);

    // Wait up to 800ms for graceful WAV header flush on SIGINT
    let mut exited = false;
    for _ in 0..16 {
        if let Ok(Some(_)) = child.try_wait() {
            exited = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
    }

    let keep_wav = payload
        .get("keep_wav")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let lang_override = payload
        .get("language")
        .and_then(|v| v.as_str())
        .map(String::from);
    let model_override = payload
        .get("model_id")
        .and_then(|v| v.as_str())
        .map(String::from);

    let _ = repair_wav_header_if_needed(&session.wav_path);
    let wav_check = inspect_wav_audio_quality(&session.wav_path);
    let stats = match wav_check {
        Ok(s) => s,
        Err(e) => {
            if !keep_wav {
                let _ = std::fs::remove_file(&session.wav_path);
            }
            return Err(e);
        }
    };

    let transcribe_res = transcribe_wav_internal(
        core,
        &session.wav_path,
        model_override.as_deref(),
        lang_override.as_deref(),
        Some(&stats),
    )
    .await;

    if !keep_wav {
        let _ = std::fs::remove_file(&session.wav_path);
    }

    transcribe_res
}

pub async fn transcribe_wav_file(core: &IntentOsCore, payload: &Value) -> anyhow::Result<Value> {
    let wav_str = payload
        .get("wav_path")
        .or_else(|| payload.get("path"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("transcribe_wav_file 缺少 wav_path 参数"))?;

    let wav_path = PathBuf::from(wav_str);
    if !wav_path.is_file() {
        anyhow::bail!("指定的 WAV 文件不存在: {}", wav_str);
    }

    let skip_silence_check = payload
        .get("skip_silence_check")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let _ = repair_wav_header_if_needed(&wav_path);
    let stats_opt = if skip_silence_check {
        inspect_wav_audio_quality(&wav_path).ok()
    } else {
        Some(inspect_wav_audio_quality(&wav_path)?)
    };

    let model_override = payload
        .get("model_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    let lang_override = payload
        .get("language")
        .and_then(|v| v.as_str())
        .map(String::from);

    transcribe_wav_internal(
        core,
        &wav_path,
        model_override.as_deref(),
        lang_override.as_deref(),
        stats_opt.as_ref(),
    )
    .await
}

async fn transcribe_wav_internal(
    core: &IntentOsCore,
    wav_path: &Path,
    model_override: Option<&str>,
    language_override: Option<&str>,
    stats: Option<&WavAudioStats>,
) -> anyhow::Result<Value> {
    let cfg = load_speech_config(core);
    let lang = language_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(cfg.language.as_str());

    if let Some((entry, model_dir)) = resolve_installed_model(core, model_override) {
        let py = probe_python_onnx_runtime();
        let python_bin = py.python_bin.clone().ok_or_else(|| {
            anyhow::anyhow!("未检测到可用的 Python3 运行时，无法执行本地 ONNX 语音推理")
        })?;
        let script = resolve_asr_runner_script(core);
        if !script.is_file() {
            anyhow::bail!("缺少本地语音推理脚本: {}", script.display());
        }

        let mut cmd = tokio::process::Command::new(&python_bin);
        apply_clean_tokio_python_env(&mut cmd);
        cmd.args([
            script.to_string_lossy().as_ref(),
            "--engine",
            &entry.engine_kind,
            "--model-dir",
            model_dir.to_string_lossy().as_ref(),
            "--wav",
            wav_path.to_string_lossy().as_ref(),
            "--language",
            lang,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        let output = tokio::time::timeout(Duration::from_secs(60), cmd.output())
            .await
            .map_err(|_| anyhow::anyhow!("本地语音模型推理超时 (>60s)"))?
            .map_err(|e| anyhow::anyhow!("启动本地语音推理进程失败: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        let parsed: Value = serde_json::from_str(&stdout).map_err(|_| {
            anyhow::anyhow!(
                "语音推理引擎返回异常 (exit={:?}): {} {}",
                output.status.code(),
                stdout,
                stderr
            )
        })?;

        if !parsed.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            let err_msg = parsed
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("未知本地语音推理错误");
            anyhow::bail!("本地语音识别失败: {}", err_msg);
        }

        let text = parsed
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if text.is_empty() {
            anyhow::bail!("未识别到清晰的语音文字内容，请靠近麦克风重试");
        }

        let elapsed_val = parsed.get("elapsed_ms").cloned().unwrap_or_else(|| json!(0));
        return Ok(json!({
            "ok": true,
            "text": text,
            "transcript": text,
            "model_id": entry.id,
            "model_used": entry.id,
            "model_name": entry.name,
            "engine": entry.engine_kind,
            "language": lang,
            "duration_sec": parsed.get("duration_sec").cloned().or_else(|| stats.map(|s| json!(s.duration_sec))),
            "elapsed_ms": elapsed_val,
            "duration_ms": elapsed_val,
            "rms": stats.map(|s| s.rms),
            "auto_send": cfg.auto_send_after_transcribe,
            "auto_send_after_transcribe": cfg.auto_send_after_transcribe,
        }));
    }

    if cfg.allow_cloud_fallback
        && let Some((base_url, api_key)) = resolve_cloud_asr_endpoint(core)
    {
        return transcribe_via_cloud_endpoint(
            &base_url,
            api_key.as_deref(),
            wav_path,
            lang,
            cfg.auto_send_after_transcribe,
            stats,
        )
        .await;
    }

    anyhow::bail!("请先在设置中下载离线语音识别模型（如 SenseVoice 或 Whisper Tiny）")
}

async fn transcribe_via_cloud_endpoint(
    base_url: &str,
    api_key: Option<&str>,
    wav_path: &Path,
    language: &str,
    auto_send: bool,
    stats: Option<&WavAudioStats>,
) -> anyhow::Result<Value> {
    let started = Instant::now();
    let wav_bytes = tokio::fs::read(wav_path).await?;
    let boundary = format!("----IntentOsAsrBoundary{}", uuid::Uuid::new_v4().simple());

    let mut body: Vec<u8> = Vec::with_capacity(wav_bytes.len() + 512);
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"voice.wav\"\r\nContent-Type: audio/wav\r\n\r\n",
    );
    body.extend_from_slice(&wav_bytes);
    body.extend_from_slice(b"\r\n");

    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n",
    );

    if language != "auto" && !language.is_empty() {
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"language\"\r\n\r\n{}\r\n",
                language
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    let target_url = if base_url.ends_with("/audio/transcriptions") {
        base_url.to_string()
    } else {
        format!("{}/audio/transcriptions", base_url.trim_end_matches('/'))
    };

    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(45));
    if target_url.starts_with("http://127.0.0.1") || target_url.starts_with("http://localhost") {
        builder = builder.no_proxy();
    }
    let client = builder.build()?;

    let mut req = client
        .post(&target_url)
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={}", boundary),
        )
        .body(body);
    if let Some(key) = api_key {
        req = req.bearer_auth(key);
    }

    let resp = req.send().await.map_err(|e| {
        anyhow::anyhow!(
            "本地尚未下载离线语音模型，且云端语音转写回退请求失败 ({})；请先在设置中下载 SenseVoice 或 Whisper 离线模型",
            e
        )
    })?;
    let status = resp.status();
    let resp_json: Value = resp.json().await.unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        anyhow::bail!(
            "本地尚未下载离线语音模型，且当前云端接口不支持 /audio/transcriptions (HTTP {})；请先在设置中下载 SenseVoice 或 Whisper 离线模型",
            status
        );
    }

    let text = resp_json
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if text.is_empty() {
        anyhow::bail!("未识别到清晰的语音文字内容，请检查麦克风音量后重试");
    }

    let elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(json!({
        "ok": true,
        "text": text,
        "transcript": text,
        "model_id": "cloud-whisper-fallback",
        "model_used": "cloud-whisper-fallback",
        "model_name": "Cloud Whisper Fallback",
        "engine": "cloud_openai_audio",
        "language": language,
        "duration_sec": stats.map(|s| s.duration_sec),
        "elapsed_ms": elapsed_ms,
        "duration_ms": elapsed_ms,
        "auto_send": auto_send,
        "auto_send_after_transcribe": auto_send,
    }))
}

pub async fn run_asr_runner_self_test(core: &IntentOsCore) -> anyhow::Result<Value> {
    let py = probe_python_onnx_runtime();
    let python_bin = py
        .python_bin
        .clone()
        .unwrap_or_else(|| "/usr/bin/python3".to_string());
    let script = resolve_asr_runner_script(core);
    if !script.is_file() {
        anyhow::bail!("找不到 scripts/intentos_asr_runner.py: {}", script.display());
    }

    let mut cmd = tokio::process::Command::new(&python_bin);
    apply_clean_tokio_python_env(&mut cmd);
    cmd.args([script.to_string_lossy().as_ref(), "--self-test"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let out = tokio::time::timeout(Duration::from_secs(25), cmd.output())
        .await
        .map_err(|_| anyhow::anyhow!("intentos_asr_runner.py --self-test 超时"))??;

    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !out.status.success() {
        anyhow::bail!(
            "intentos_asr_runner.py --self-test 失败 (code={:?}): {} {}",
            out.status.code(),
            stdout,
            stderr
        );
    }
    let val: Value = serde_json::from_str(&stdout)
        .map_err(|e| anyhow::anyhow!("解析 self-test JSON 失败 ({}): {}", e, stdout))?;
    Ok(val)
}
