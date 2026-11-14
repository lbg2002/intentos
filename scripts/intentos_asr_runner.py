#!/usr/bin/env python3
"""
IntentOS Local Offline Speech Recognition (ASR) ONNX Runner (`scripts/intentos_asr_runner.py`).

Self-contained pure `onnxruntime` + `numpy` (+ optional `scipy`) inference engine supporting:
1. `sensevoice_onnx` (`model.int8.onnx` + `tokens.txt`):
   - Kaldi-compatible 80-dim log-mel filterbank (`frame_length=400`, `frame_shift=160`,
     Povey window, `32768.0` waveform scaling, 20Hz..8000Hz mel scale).
   - Low Frame Rate (LFR) stacking (`m=7, n=6` -> 560-dim features, configurable from ONNX metadata).
   - Dynamic CMVN (`neg_mean` & `inv_stddev` read from `modelmeta.custom_metadata_map`).
   - Dynamic input tensor inspection (`x`, `x_length`, `language`, `text_norm` / `with_itn`).
   - CTC greedy collapse, SentencePiece `▁` decoding, and `<|...|>` control tag stripping.
2. `whisper_onnx` (`onnx/encoder_model_quantized.onnx` + `onnx/decoder_model_quantized.onnx` + `tokenizer.json`):
   - OpenAI/HuggingFace `WhisperFeatureExtractor`-compatible 80-bin (or `config.json` `num_mel_bins`)
     Slaney log-mel spectrogram (`n_fft=400`, `hop_length=160`, 30s = 3000 frames).
   - Encoder pass + autoregressive decoder pass (up to 128 tokens) with `<|startoftranscript|>`,
     language token, `<|transcribe|>`, `<|notimestamps|>`, stopping at `<|endoftext|>`.
   - Exact GPT-2 byte-level BPE UTF-8 decoding via `tokenizer.json`.
3. `--self-test` diagnostic mode verifying WAV loading, resampling, Kaldi 80-mel + LFR,
   Whisper Slaney 80-mel, CTC collapse, and GPT-2 UTF-8 BPE decoding on synthetic audio.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import struct
import sys
import tempfile
import time
import wave
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _maybe_reexec_into_onnx_python() -> None:
    """
    If invoked under system `/usr/bin/python3` where `numpy`/`onnxruntime` are absent,
    automatically re-exec into a discovered local Conda/venv Python that has `onnxruntime` + `numpy`.
    """
    if os.environ.get("_INTENTOS_ASR_REEXEC") == "1":
        return
    import glob
    import importlib.util
    import subprocess

    has_np = importlib.util.find_spec("numpy") is not None
    has_ort = importlib.util.find_spec("onnxruntime") is not None
    if has_np and has_ort:
        return

    home = os.path.expanduser("~")
    candidates: List[str] = []
    conda_prefix = os.environ.get("CONDA_PREFIX", "").strip()
    if conda_prefix:
        candidates.append(os.path.join(conda_prefix, "bin", "python3"))
    candidates.append(os.path.join(home, "miniconda3", "envs", "myenv0", "bin", "python3"))
    for pattern in (
        os.path.join(home, "miniconda3", "envs", "*", "bin", "python3"),
        os.path.join(home, "anaconda3", "envs", "*", "bin", "python3"),
        os.path.join(home, "miniforge3", "envs", "*", "bin", "python3"),
        os.path.join(home, ".venv*", "bin", "python3"),
        os.path.join(home, "miniconda3", "bin", "python3"),
        os.path.join(home, "anaconda3", "bin", "python3"),
        os.path.join(home, "miniforge3", "bin", "python3"),
    ):
        for match in sorted(glob.glob(pattern)):
            if match not in candidates:
                candidates.append(match)

    clean_env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("PYTHONHOME", "PYTHONPATH")
    }
    clean_env["_INTENTOS_ASR_REEXEC"] = "1"

    cur_real = os.path.realpath(sys.executable)
    for cand in candidates:
        if not os.path.isfile(cand) or not os.access(cand, os.X_OK):
            continue
        if os.path.realpath(cand) == cur_real:
            continue
        try:
            probe = subprocess.run(
                [cand, "-c", "import numpy, onnxruntime"],
                env=clean_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            if probe.returncode == 0:
                os.execve(cand, [cand, os.path.abspath(__file__), *sys.argv[1:]], clean_env)
        except Exception:
            continue


_maybe_reexec_into_onnx_python()

import numpy as np

try:
    import onnxruntime as ort  # type: ignore

    ORT_AVAILABLE = True
    ORT_VERSION = getattr(ort, "__version__", "unknown")
except Exception as _ort_err:  # pragma: no cover
    ort = None  # type: ignore
    ORT_AVAILABLE = False
    ORT_VERSION = None
    _ORT_IMPORT_ERROR = str(_ort_err)

try:
    from scipy.signal import resample_poly as _scipy_resample_poly  # type: ignore
except Exception:
    _scipy_resample_poly = None


TARGET_SAMPLE_RATE = 16000


# ============================================================================
# 1. WAV Loading & Resampling (16kHz Mono Float32 in [-1.0, 1.0])
# ============================================================================


def _resample_to_16k(waveform: np.ndarray, orig_sr: int) -> np.ndarray:
    if orig_sr == TARGET_SAMPLE_RATE or waveform.size == 0:
        return waveform.astype(np.float32, copy=False)
    if orig_sr <= 0:
        raise ValueError(f"Invalid WAV sample rate: {orig_sr}")

    if _scipy_resample_poly is not None:
        from math import gcd

        g = gcd(int(orig_sr), TARGET_SAMPLE_RATE)
        up = TARGET_SAMPLE_RATE // g
        down = int(orig_sr) // g
        out = _scipy_resample_poly(waveform.astype(np.float64), up, down)
        return out.astype(np.float32)

    # Pure numpy linear interpolation fallback
    duration = waveform.shape[0] / float(orig_sr)
    target_len = max(1, int(round(duration * TARGET_SAMPLE_RATE)))
    old_idx = np.linspace(0.0, 1.0, num=waveform.shape[0], endpoint=False)
    new_idx = np.linspace(0.0, 1.0, num=target_len, endpoint=False)
    return np.interp(new_idx, old_idx, waveform).astype(np.float32)


def _decode_pcm_bytes(
    raw_bytes: bytes, sampwidth: int, nchannels: int, audio_format: int = 1
) -> np.ndarray:
    if len(raw_bytes) == 0:
        return np.zeros((0,), dtype=np.float32)

    frame_bytes = sampwidth * max(1, nchannels)
    usable = (len(raw_bytes) // frame_bytes) * frame_bytes
    raw_bytes = raw_bytes[:usable]

    if audio_format == 3 and sampwidth == 4:
        samples = np.frombuffer(raw_bytes, dtype="<f4").astype(np.float32)
    elif sampwidth == 1:
        u8 = np.frombuffer(raw_bytes, dtype=np.uint8).astype(np.float32)
        samples = (u8 - 128.0) / 128.0
    elif sampwidth == 2:
        i16 = np.frombuffer(raw_bytes, dtype="<i2").astype(np.float32)
        samples = i16 / 32768.0
    elif sampwidth == 3:
        b = np.frombuffer(raw_bytes, dtype=np.uint8).reshape(-1, 3)
        val = (
            b[:, 0].astype(np.int32)
            | (b[:, 1].astype(np.int32) << 8)
            | (b[:, 2].astype(np.int32) << 16)
        )
        neg = val & 0x800000
        val = val - (neg << 1)
        samples = val.astype(np.float32) / 8388608.0
    elif sampwidth == 4:
        i32 = np.frombuffer(raw_bytes, dtype="<i4").astype(np.float32)
        samples = i32 / 2147483648.0
    else:
        raise ValueError(f"Unsupported WAV sample width: {sampwidth}")

    if nchannels > 1:
        samples = samples.reshape(-1, nchannels).mean(axis=1)
    return np.clip(samples, -1.0, 1.0).astype(np.float32)


def _parse_riff_wav_fallback(file_bytes: bytes) -> Tuple[np.ndarray, int]:
    if len(file_bytes) < 44 or file_bytes[:4] != b"RIFF" or file_bytes[8:12] != b"WAVE":
        raise ValueError("Invalid RIFF/WAVE header")

    pos = 12
    audio_format = 1
    nchannels = 1
    samplerate = TARGET_SAMPLE_RATE
    bits_per_sample = 16
    data_payload = b""

    while pos + 8 <= len(file_bytes):
        chunk_id = file_bytes[pos : pos + 4]
        chunk_size = struct.unpack("<I", file_bytes[pos + 4 : pos + 8])[0]
        pos += 8
        if chunk_id == b"fmt " and pos + 16 <= len(file_bytes):
            fmt_slice = file_bytes[pos : min(len(file_bytes), pos + chunk_size)]
            audio_format, nchannels, samplerate, _, _, bits_per_sample = struct.unpack(
                "<HHIIHH", fmt_slice[:16]
            )
            if audio_format == 0xFFFE and len(fmt_slice) >= 26:
                # WAVE_FORMAT_EXTENSIBLE subformat first uint16
                audio_format = struct.unpack("<H", fmt_slice[24:26])[0]
        elif chunk_id == b"data":
            if chunk_size in (0, 0xFFFFFFFF, 0x7FFFFFFF) or pos + chunk_size > len(file_bytes):
                data_payload = file_bytes[pos:]
            else:
                data_payload = file_bytes[pos : pos + chunk_size]
            break

        step = chunk_size + (chunk_size & 1)
        if step <= 0 or pos + step > len(file_bytes):
            break
        pos += step

    sampwidth = max(1, bits_per_sample // 8)
    samples = _decode_pcm_bytes(data_payload, sampwidth, nchannels, audio_format=audio_format)
    return samples, int(samplerate)


def load_wav_mono_16k(wav_path: str) -> Tuple[np.ndarray, float]:
    """Load WAV file into mono 16kHz float32 waveform in [-1.0, 1.0] and return (waveform, duration_sec)."""
    raw_file = Path(wav_path).read_bytes()
    try:
        with wave.open(io.BytesIO(raw_file), "rb") as wf:
            nchannels = wf.getnchannels()
            sampwidth = wf.getsampwidth()
            orig_sr = wf.getframerate()
            nframes = wf.getnframes()
            pcm_bytes = wf.readframes(nframes)
        samples = _decode_pcm_bytes(pcm_bytes, sampwidth, nchannels, audio_format=1)
    except Exception:
        samples, orig_sr = _parse_riff_wav_fallback(raw_file)

    duration_sec = float(samples.shape[0]) / float(max(1, orig_sr))
    wav_16k = _resample_to_16k(samples, orig_sr)
    return wav_16k, duration_sec


# ============================================================================
# 2. Engine 1: SenseVoice ONNX (`sensevoice_onnx`)
# ============================================================================


def _kaldi_mel_scale(freq: np.ndarray) -> np.ndarray:
    return 1127.0 * np.log(1.0 + freq / 700.0)


def _build_kaldi_mel_filterbank(
    num_bins: int = 80,
    sample_rate: int = 16000,
    n_fft: int = 512,
    low_freq: float = 20.0,
    high_freq: float = 8000.0,
) -> np.ndarray:
    """Build Kaldi-compatible triangular Mel filterbank of shape [num_bins, n_fft // 2]."""
    nyquist = 0.5 * sample_rate
    hi = high_freq if high_freq > 0.0 else nyquist + high_freq
    hi = min(hi, nyquist)

    mel_low = float(_kaldi_mel_scale(np.array(low_freq, dtype=np.float64)))
    mel_high = float(_kaldi_mel_scale(np.array(hi, dtype=np.float64)))
    mel_points = np.linspace(mel_low, mel_high, num_bins + 2, dtype=np.float64)

    num_fft_bins = n_fft // 2
    fft_bin_width = float(sample_rate) / float(n_fft)
    fft_freqs = np.arange(num_fft_bins, dtype=np.float64) * fft_bin_width
    fft_mels = _kaldi_mel_scale(fft_freqs)

    fb = np.zeros((num_bins, num_fft_bins), dtype=np.float32)
    for b in range(num_bins):
        left_mel = mel_points[b]
        center_mel = mel_points[b + 1]
        right_mel = mel_points[b + 2]
        up_slope = (fft_mels - left_mel) / max(1e-8, (center_mel - left_mel))
        down_slope = (right_mel - fft_mels) / max(1e-8, (right_mel - center_mel))
        weights = np.maximum(0.0, np.minimum(up_slope, down_slope))
        fb[b, :] = weights.astype(np.float32)
    return fb


def compute_kaldi_fbank_80(
    waveform_16k: np.ndarray,
    frame_length: int = 400,
    frame_shift: int = 160,
    num_mel_bins: int = 80,
    preemph_coeff: float = 0.97,
) -> np.ndarray:
    """
    Compute 80-dim Kaldi-compatible log-mel filterbank features:
    - Waveform scaled by 32768.0 (matching Kaldi / sherpa-onnx SenseVoice)
    - snip_edges=True, DC offset removal, pre-emphasis 0.97, Povey window
    """
    samples = (waveform_16k.astype(np.float32) * 32768.0).copy()
    if samples.shape[0] < frame_length:
        samples = np.pad(samples, (0, frame_length - samples.shape[0]), mode="constant")

    num_frames = 1 + (samples.shape[0] - frame_length) // frame_shift
    strides = (samples.strides[0] * frame_shift, samples.strides[0])
    frames = np.lib.stride_tricks.as_strided(
        samples, shape=(num_frames, frame_length), strides=strides
    ).copy()

    # Remove per-frame DC offset
    frames -= np.mean(frames, axis=1, keepdims=True)

    # Pre-emphasis
    if preemph_coeff > 0.0:
        preemph = np.empty_like(frames)
        preemph[:, 0] = frames[:, 0] * (1.0 - preemph_coeff)
        preemph[:, 1:] = frames[:, 1:] - preemph_coeff * frames[:, :-1]
        frames = preemph

    # Povey window: (0.5 - 0.5 * cos(2*pi*n/(N-1))) ** 0.85
    n = np.arange(frame_length, dtype=np.float32)
    povey = np.power(0.5 - 0.5 * np.cos(2.0 * np.pi * n / float(frame_length - 1)), 0.85).astype(
        np.float32
    )
    frames *= povey[None, :]

    n_fft = 1
    while n_fft < frame_length:
        n_fft <<= 1

    spec = np.fft.rfft(frames, n=n_fft, axis=1)
    power_spec = (spec.real.astype(np.float32) ** 2) + (spec.imag.astype(np.float32) ** 2)
    power_bins = power_spec[:, : n_fft // 2]

    fb = _build_kaldi_mel_filterbank(
        num_bins=num_mel_bins, sample_rate=TARGET_SAMPLE_RATE, n_fft=n_fft
    )
    mel_energy = np.matmul(power_bins, fb.T)
    mel_energy = np.maximum(mel_energy, np.finfo(np.float32).eps)
    return np.log(mel_energy).astype(np.float32)


def apply_lfr(fbank: np.ndarray, lfr_m: int = 7, lfr_n: int = 6) -> np.ndarray:
    """
    Stack `lfr_m` frames with shift `lfr_n` (FunASR / SenseVoice Low Frame Rate frontend).
    Input: [T, D] -> Output: [T_lfr, D * lfr_m] (e.g., [T_lfr, 560]).
    """
    if fbank.shape[0] == 0:
        return np.zeros((1, fbank.shape[1] * lfr_m), dtype=np.float32)

    left_pad_count = (lfr_m - 1) // 2
    if left_pad_count > 0:
        left_pad = np.repeat(fbank[:1, :], left_pad_count, axis=0)
        padded = np.vstack([left_pad, fbank])
    else:
        padded = fbank

    orig_t = fbank.shape[0]
    t_lfr = int(np.ceil(orig_t / float(lfr_n)))
    required_len = (t_lfr - 1) * lfr_n + lfr_m
    if padded.shape[0] < required_len:
        right_pad = np.repeat(padded[-1:, :], required_len - padded.shape[0], axis=0)
        padded = np.vstack([padded, right_pad])

    feat_dim = fbank.shape[1]
    out = np.empty((t_lfr, feat_dim * lfr_m), dtype=np.float32)
    for i in range(t_lfr):
        start = i * lfr_n
        out[i, :] = padded[start : start + lfr_m, :].reshape(-1)
    return out


def load_sensevoice_tokens(tokens_path: Path) -> Dict[int, str]:
    id_to_tok: Dict[int, str] = {}
    for raw_line in tokens_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            continue
        parts = line.strip().split()
        if len(parts) == 1 and parts[0].isdigit():
            id_to_tok[int(parts[0])] = " "
        elif len(parts) >= 2:
            if parts[-1].lstrip("-").isdigit():
                tok_id = int(parts[-1])
                tok_str = " ".join(parts[:-1])
                id_to_tok[tok_id] = tok_str
            elif parts[0].lstrip("-").isdigit():
                tok_id = int(parts[0])
                tok_str = " ".join(parts[1:])
                id_to_tok[tok_id] = tok_str
    return id_to_tok


def decode_sensevoice_ctc_ids(
    pred_ids: List[int], id_to_tok: Dict[int, str], blank_id: int = 0
) -> str:
    collapsed: List[int] = []
    prev_id: Optional[int] = None
    for cur in pred_ids:
        if cur != prev_id and cur != blank_id:
            collapsed.append(cur)
        prev_id = cur

    pieces: List[str] = []
    for tid in collapsed:
        tok = id_to_tok.get(tid, "")
        if not tok or tok in ("<unk>", "<s>", "</s>", "<blk>", "<blank>"):
            continue
        pieces.append(tok)

    raw_text = "".join(pieces).replace("▁", " ")
    # Strip SenseVoice language / emotion / event / ITN control tags `<|...|>`
    cleaned = re.sub(r"<\|[^|]*\|>", "", raw_text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _parse_float_vector_metadata(raw: Optional[str], expected_dim: int) -> Optional[np.ndarray]:
    if not raw:
        return None
    vals = [float(x) for x in raw.replace("[", "").replace("]", "").split(",") if x.strip()]
    if len(vals) != expected_dim:
        return None
    return np.array(vals, dtype=np.float32)


def transcribe_sensevoice_onnx(
    model_dir: Path, wav_16k: np.ndarray, language: str
) -> str:
    if not ORT_AVAILABLE:
        raise RuntimeError(f"onnxruntime is not installed: {_ORT_IMPORT_ERROR}")

    onnx_candidates = [
        model_dir / "model.int8.onnx",
        model_dir / "model.onnx",
    ]
    onnx_path = next((p for p in onnx_candidates if p.is_file()), None)
    if onnx_path is None:
        raise FileNotFoundError(f"SenseVoice ONNX model not found under {model_dir}")

    tokens_path = model_dir / "tokens.txt"
    if not tokens_path.is_file():
        raise FileNotFoundError(f"SenseVoice tokens.txt not found under {model_dir}")

    sess_opts = ort.SessionOptions()
    sess_opts.intra_op_num_threads = min(4, max(1, os.cpu_count() or 2))
    sess_opts.inter_op_num_threads = 1
    session = ort.InferenceSession(
        str(onnx_path), sess_options=sess_opts, providers=["CPUExecutionProvider"]
    )

    meta_map: Dict[str, str] = {}
    try:
        meta = session.get_modelmeta()
        if meta and getattr(meta, "custom_metadata_map", None):
            meta_map = dict(meta.custom_metadata_map)
    except Exception:
        meta_map = {}

    lfr_m = int(meta_map.get("lfr_window_size", "7") or 7)
    lfr_n = int(meta_map.get("lfr_window_shift", "6") or 6)
    blank_id = int(meta_map.get("blank_id", "0") or 0)

    fbank = compute_kaldi_fbank_80(wav_16k)
    feats = apply_lfr(fbank, lfr_m=lfr_m, lfr_n=lfr_n)

    neg_mean = _parse_float_vector_metadata(meta_map.get("neg_mean"), feats.shape[1])
    inv_stddev = _parse_float_vector_metadata(meta_map.get("inv_stddev"), feats.shape[1])
    if neg_mean is not None and inv_stddev is not None:
        feats = (feats + neg_mean[None, :]) * inv_stddev[None, :]

    # Resolve language ID from model metadata (defaults match sherpa-onnx SenseVoice)
    lang_norm = (language or "zh").strip().lower()
    default_lang_ids = {
        "auto": 0,
        "zh": 3,
        "en": 4,
        "yue": 7,
        "ja": 11,
        "ko": 12,
    }
    meta_lang_key = f"lang_{lang_norm}"
    if meta_lang_key in meta_map and str(meta_map[meta_lang_key]).lstrip("-").isdigit():
        lang_id = int(meta_map[meta_lang_key])
    else:
        lang_id = default_lang_ids.get(lang_norm, 0)

    with_itn_raw = meta_map.get("with_itn", meta_map.get("withitn", "14"))
    text_norm_id = int(with_itn_raw) if str(with_itn_raw).lstrip("-").isdigit() else 14

    feed: Dict[str, Any] = {}
    t_len = feats.shape[0]
    for inp in session.get_inputs():
        name = inp.name
        dtype = np.int64 if "int64" in inp.type else np.int32
        rank = len(inp.shape) if inp.shape is not None else 1

        if name in ("x", "speech", "feats"):
            feed[name] = feats[None, :, :].astype(np.float32)
        elif name in ("x_length", "speech_lengths", "feats_length"):
            arr = np.array([t_len], dtype=dtype)
            feed[name] = arr.reshape((1, 1)) if rank == 2 else arr
        elif name in ("language", "lang"):
            arr = np.array([lang_id], dtype=dtype)
            feed[name] = arr.reshape((1, 1)) if rank == 2 else arr
        elif name in ("text_norm", "use_itn"):
            arr = np.array([text_norm_id], dtype=dtype)
            feed[name] = arr.reshape((1, 1)) if rank == 2 else arr

    outputs = session.run(None, feed)
    logits = outputs[0]
    if logits.ndim == 3:
        pred_ids = np.argmax(logits[0], axis=-1).astype(int).tolist()
    elif logits.ndim == 2:
        pred_ids = np.argmax(logits, axis=-1).astype(int).tolist()
    else:
        pred_ids = np.asarray(logits).reshape(-1).astype(int).tolist()

    id_to_tok = load_sensevoice_tokens(tokens_path)
    return decode_sensevoice_ctc_ids(pred_ids, id_to_tok, blank_id=blank_id)


# ============================================================================
# 3. Engine 2: Whisper ONNX (`whisper_onnx`)
# ============================================================================


def _hz_to_mel_slaney(freq: np.ndarray) -> np.ndarray:
    f_sp = 200.0 / 3.0
    min_log_hz = 1000.0
    min_log_mel = min_log_hz / f_sp
    logstep = np.log(6.4) / 27.0

    freq_arr = np.asarray(freq, dtype=np.float64)
    mels = freq_arr / f_sp
    log_mask = freq_arr >= min_log_hz
    if np.any(log_mask):
        mels = np.where(
            log_mask,
            min_log_mel + np.log(np.maximum(freq_arr, 1e-10) / min_log_hz) / logstep,
            mels,
        )
    return mels


def _mel_to_hz_slaney(mels: np.ndarray) -> np.ndarray:
    f_sp = 200.0 / 3.0
    min_log_hz = 1000.0
    min_log_mel = min_log_hz / f_sp
    logstep = np.log(6.4) / 27.0

    mel_arr = np.asarray(mels, dtype=np.float64)
    freqs = f_sp * mel_arr
    log_mask = mel_arr >= min_log_mel
    if np.any(log_mask):
        freqs = np.where(
            log_mask,
            min_log_hz * np.exp(logstep * (mel_arr - min_log_mel)),
            freqs,
        )
    return freqs


def _build_whisper_slaney_mel_filters(
    num_mel_bins: int = 80, sample_rate: int = 16000, n_fft: int = 400
) -> np.ndarray:
    """Exact Slaney-normalized Mel filterbank matching HuggingFace `WhisperFeatureExtractor`."""
    num_freq_bins = 1 + n_fft // 2
    fft_freqs = np.linspace(0.0, sample_rate / 2.0, num_freq_bins, dtype=np.float64)

    mel_min = _hz_to_mel_slaney(np.array(0.0))
    mel_max = _hz_to_mel_slaney(np.array(sample_rate / 2.0))
    mel_pts = np.linspace(mel_min, mel_max, num_mel_bins + 2, dtype=np.float64)
    filter_freqs = _mel_to_hz_slaney(mel_pts)
    filter_diff = np.diff(filter_freqs)

    ramps = filter_freqs[:, None] - fft_freqs[None, :]
    lower = -ramps[:-2] / filter_diff[:-1, None]
    upper = ramps[2:] / filter_diff[1:, None]
    weights = np.maximum(0.0, np.minimum(lower, upper))

    enorm = 2.0 / (filter_freqs[2 : num_mel_bins + 2] - filter_freqs[:num_mel_bins])
    weights *= enorm[:, None]
    return weights.astype(np.float32)


def compute_whisper_log_mel(
    waveform_16k: np.ndarray,
    num_mel_bins: int = 80,
    n_fft: int = 400,
    hop_length: int = 160,
    n_samples: int = 480000,
) -> np.ndarray:
    """
    Compute OpenAI Whisper log-mel spectrogram of shape [1, num_mel_bins, 3000].
    Pads or trims audio to 30 seconds (`480,000` samples at 16kHz).
    """
    audio = waveform_16k.astype(np.float32)
    if audio.shape[0] >= n_samples:
        audio = audio[:n_samples]
    else:
        audio = np.pad(audio, (0, n_samples - audio.shape[0]), mode="constant")

    pad = n_fft // 2
    padded = np.pad(audio, (pad, pad), mode="reflect")

    num_frames = 1 + (padded.shape[0] - n_fft) // hop_length
    strides = (padded.strides[0] * hop_length, padded.strides[0])
    frames = np.lib.stride_tricks.as_strided(
        padded, shape=(num_frames, n_fft), strides=strides
    ).copy()

    # Periodic Hann window matching torch.hann_window(400, periodic=True)
    window = (0.5 - 0.5 * np.cos(2.0 * np.pi * np.arange(n_fft, dtype=np.float32) / float(n_fft)))
    windowed = frames * window[None, :]

    stft = np.fft.rfft(windowed, n=n_fft, axis=1)
    # Drop final frame so 3001 -> 3000 frames, matching WhisperFeatureExtractor
    magnitudes = (np.abs(stft[:-1, :]) ** 2).T.astype(np.float32)  # [201, 3000]

    mel_filters = _build_whisper_slaney_mel_filters(
        num_mel_bins=num_mel_bins, sample_rate=TARGET_SAMPLE_RATE, n_fft=n_fft
    )
    mel_spec = np.matmul(mel_filters, magnitudes)

    log_spec = np.log10(np.maximum(mel_spec, 1e-10))
    log_spec = np.maximum(log_spec, log_spec.max() - 8.0)
    log_spec = (log_spec + 4.0) / 4.0
    return log_spec[None, :, :].astype(np.float32)


def gpt2_bytes_to_unicode() -> Dict[int, str]:
    bs = (
        list(range(ord("!"), ord("~") + 1))
        + list(range(ord("¡"), ord("¬") + 1))
        + list(range(ord("®"), ord("ÿ") + 1))
    )
    cs = bs[:]
    n = 0
    for b in range(256):
        if b not in bs:
            bs.append(b)
            cs.append(256 + n)
            n += 1
    return {b: chr(c) for b, c in zip(bs, cs)}


def decode_gpt2_byte_level_bpe(tokens: List[str]) -> str:
    u2b = {ch: b for b, ch in gpt2_bytes_to_unicode().items()}
    joined = "".join(tokens)
    out_bytes = bytearray()
    for ch in joined:
        if ch in u2b:
            out_bytes.append(u2b[ch])
        else:
            out_bytes.extend(ch.encode("utf-8"))
    return out_bytes.decode("utf-8", errors="replace").strip()


def load_whisper_tokenizer_tables(
    tokenizer_json_path: Path,
) -> Tuple[Dict[str, int], Dict[int, str], set]:
    data = json.loads(tokenizer_json_path.read_text(encoding="utf-8"))
    tok_to_id: Dict[str, int] = {}
    special_ids: set = set()

    vocab = data.get("model", {}).get("vocab", {})
    for tok_str, tid in vocab.items():
        tok_to_id[tok_str] = int(tid)

    for added in data.get("added_tokens", []):
        content = added.get("content")
        tid = added.get("id")
        if content is not None and tid is not None:
            tok_to_id[str(content)] = int(tid)
            if added.get("special", False) or (
                str(content).startswith("<|") and str(content).endswith("|>")
            ):
                special_ids.add(int(tid))

    id_to_tok = {tid: tok for tok, tid in tok_to_id.items()}
    return tok_to_id, id_to_tok, special_ids


def _has_repetitive_tail(generated_body: List[int]) -> bool:
    if len(generated_body) >= 6 and len(set(generated_body[-6:])) == 1:
        return True
    for pat_len in (2, 3, 4):
        if len(generated_body) >= pat_len * 4:
            tail = generated_body[-pat_len * 4 :]
            p = tail[:pat_len]
            if tail == p * 4:
                return True
    return False


def _run_whisper_decoder_step(
    decoder_sess: Any,
    input_ids: List[int],
    encoder_hidden_states: np.ndarray,
    config: Dict[str, Any],
) -> np.ndarray:
    feed: Dict[str, Any] = {}
    num_heads = int(config.get("decoder_attention_heads", 6))
    d_model = int(config.get("d_model", encoder_hidden_states.shape[-1]))
    head_dim = max(1, d_model // max(1, num_heads))

    for inp in decoder_sess.get_inputs():
        name = inp.name
        if name == "input_ids":
            dtype = np.int64 if "int64" in inp.type else np.int32
            feed[name] = np.array([input_ids], dtype=dtype)
        elif name == "encoder_hidden_states":
            feed[name] = encoder_hidden_states
        elif name == "encoder_attention_mask":
            feed[name] = np.ones((1, encoder_hidden_states.shape[1]), dtype=np.int64)
        elif name == "use_cache_branch":
            feed[name] = np.array([False], dtype=bool)
        elif name.startswith("past_key_values."):
            if ".encoder." in name:
                feed[name] = np.zeros(
                    (1, num_heads, encoder_hidden_states.shape[1], head_dim),
                    dtype=np.float32,
                )
            else:
                feed[name] = np.zeros((1, num_heads, 0, head_dim), dtype=np.float32)

    outputs = decoder_sess.run(None, feed)
    logits = outputs[0]
    return logits[0, -1, :].astype(np.float32).copy()


def transcribe_whisper_onnx(
    model_dir: Path, wav_16k: np.ndarray, language: str, max_new_tokens: int = 128
) -> str:
    if not ORT_AVAILABLE:
        raise RuntimeError(f"onnxruntime is not installed: {_ORT_IMPORT_ERROR}")

    enc_candidates = [
        model_dir / "onnx" / "encoder_model_quantized.onnx",
        model_dir / "encoder_model_quantized.onnx",
        model_dir / "onnx" / "encoder_model.onnx",
        model_dir / "encoder_model.onnx",
    ]
    dec_candidates = [
        model_dir / "onnx" / "decoder_model_quantized.onnx",
        model_dir / "decoder_model_quantized.onnx",
        model_dir / "onnx" / "decoder_model.onnx",
        model_dir / "decoder_model.onnx",
    ]
    enc_path = next((p for p in enc_candidates if p.is_file()), None)
    dec_path = next((p for p in dec_candidates if p.is_file()), None)
    tok_path = model_dir / "tokenizer.json"
    cfg_path = model_dir / "config.json"

    if enc_path is None or dec_path is None:
        raise FileNotFoundError(f"Whisper encoder/decoder ONNX files missing in {model_dir}")
    if not tok_path.is_file():
        raise FileNotFoundError(f"Whisper tokenizer.json missing in {model_dir}")

    config: Dict[str, Any] = {}
    if cfg_path.is_file():
        try:
            config = json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception:
            config = {}

    num_mel_bins = int(config.get("num_mel_bins", 80))
    input_features = compute_whisper_log_mel(wav_16k, num_mel_bins=num_mel_bins)

    sess_opts = ort.SessionOptions()
    sess_opts.intra_op_num_threads = min(4, max(1, os.cpu_count() or 2))
    sess_opts.inter_op_num_threads = 1

    encoder_sess = ort.InferenceSession(
        str(enc_path), sess_options=sess_opts, providers=["CPUExecutionProvider"]
    )
    decoder_sess = ort.InferenceSession(
        str(dec_path), sess_options=sess_opts, providers=["CPUExecutionProvider"]
    )

    enc_in_name = encoder_sess.get_inputs()[0].name
    encoder_hidden_states = encoder_sess.run(None, {enc_in_name: input_features})[0]

    tok_to_id, id_to_tok, special_ids = load_whisper_tokenizer_tables(tok_path)
    sot_id = tok_to_id.get(
        "<|startoftranscript|>", int(config.get("decoder_start_token_id", 50258))
    )
    eot_id = tok_to_id.get("<|endoftext|>", int(config.get("eos_token_id", 50257)))
    transcribe_id = tok_to_id.get("<|transcribe|>", 50359)
    notimestamps_id = tok_to_id.get("<|notimestamps|>", 50363)

    lang_norm = (language or "zh").strip().lower()
    if lang_norm == "auto":
        # Detect spoken language from first decoder step over `<|startoftranscript|>`
        lang_candidates = [
            tid
            for tok, tid in tok_to_id.items()
            if tok.startswith("<|")
            and tok.endswith("|>")
            and sot_id < tid < transcribe_id
        ]
        if lang_candidates:
            first_logits = _run_whisper_decoder_step(
                decoder_sess, [sot_id], encoder_hidden_states, config
            )
            best_lang_id = max(lang_candidates, key=lambda tid: float(first_logits[tid]))
        else:
            best_lang_id = tok_to_id.get("<|zh|>", 50260)
    else:
        best_lang_id = tok_to_id.get(f"<|{lang_norm}|>", tok_to_id.get("<|zh|>", 50260))

    prompt_ids = [sot_id, best_lang_id, transcribe_id, notimestamps_id]
    generated = list(prompt_ids)

    suppress_ids = [int(x) for x in config.get("suppress_tokens", []) if isinstance(x, int)]
    begin_suppress_ids = [
        int(x)
        for x in config.get("begin_suppress_tokens", [220, eot_id])
        if isinstance(x, int)
    ]

    for step in range(max_new_tokens):
        next_logits = _run_whisper_decoder_step(
            decoder_sess, generated, encoder_hidden_states, config
        )
        vocab_size = next_logits.shape[0]

        for sid in suppress_ids:
            if 0 <= sid < vocab_size and sid != eot_id:
                next_logits[sid] = -np.inf

        if step == 0:
            for sid in begin_suppress_ids:
                if 0 <= sid < vocab_size:
                    next_logits[sid] = -np.inf

        # Suppress timestamp tokens (`> <|notimestamps|>`) when decoding in `<|notimestamps|>` mode
        if notimestamps_id + 1 < vocab_size:
            next_logits[notimestamps_id + 1 :] = -np.inf

        next_id = int(np.argmax(next_logits))
        if next_id == eot_id:
            break

        generated.append(next_id)
        if _has_repetitive_tail(generated[len(prompt_ids) :]):
            break

    text_tokens: List[str] = []
    for tid in generated[len(prompt_ids) :]:
        if tid in special_ids or tid == eot_id:
            continue
        tok_str = id_to_tok.get(tid, "")
        if tok_str and not (tok_str.startswith("<|") and tok_str.endswith("|>")):
            text_tokens.append(tok_str)

    return decode_gpt2_byte_level_bpe(text_tokens)


# ============================================================================
# 4. Self-Test & CLI Entrypoint
# ============================================================================


def run_self_test() -> int:
    # 1. Generate synthetic 48kHz stereo WAV, load & resample to 16kHz mono
    sr_in = 48000
    dur = 0.65
    t = np.linspace(0.0, dur, int(sr_in * dur), endpoint=False, dtype=np.float32)
    wave_sig = 0.35 * np.sin(2.0 * np.pi * 220.0 * t) + 0.25 * np.sin(2.0 * np.pi * 660.0 * t)
    pcm_i16 = np.clip(wave_sig * 32767.0, -32768, 32767).astype("<i2")
    stereo_i16 = np.column_stack([pcm_i16, pcm_i16]).reshape(-1)

    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
        tmp_wav = tf.name
    try:
        with wave.open(tmp_wav, "wb") as wf:
            wf.setnchannels(2)
            wf.setsampwidth(2)
            wf.setframerate(sr_in)
            wf.writeframes(stereo_i16.tobytes())

        wav_16k, loaded_dur = load_wav_mono_16k(tmp_wav)
    finally:
        try:
            os.remove(tmp_wav)
        except OSError:
            pass

    assert abs(loaded_dur - dur) < 0.05, f"Unexpected WAV duration: {loaded_dur}"
    assert wav_16k.ndim == 1 and wav_16k.shape[0] > 9000

    # 2. Test Kaldi 80-mel filterbank + LFR(7, 6) stacking
    fbank = compute_kaldi_fbank_80(wav_16k)
    assert fbank.ndim == 2 and fbank.shape[1] == 80, f"Bad fbank shape: {fbank.shape}"
    assert np.all(np.isfinite(fbank)), "Non-finite values in Kaldi fbank"

    lfr = apply_lfr(fbank, lfr_m=7, lfr_n=6)
    assert lfr.ndim == 2 and lfr.shape[1] == 560, f"Bad LFR shape: {lfr.shape}"
    assert np.all(np.isfinite(lfr)), "Non-finite values in LFR features"

    # 3. Test Whisper 80-mel Slaney spectrogram
    w_mel = compute_whisper_log_mel(wav_16k, num_mel_bins=80)
    assert w_mel.shape == (1, 80, 3000), f"Bad Whisper mel shape: {w_mel.shape}"
    assert np.all(np.isfinite(w_mel)), "Non-finite values in Whisper mel"

    # 4. Test SenseVoice CTC collapse & control-tag stripping
    sample_vocab = {
        0: "<unk>",
        10: "<|zh|>",
        11: "<|NEUTRAL|>",
        12: "<|Speech|>",
        13: "<|withitn|>",
        20: "打",
        21: "开",
        22: "▁IntentOS",
        23: "设",
        24: "置",
    }
    ctc_out = decode_sensevoice_ctc_ids(
        [0, 10, 10, 11, 12, 13, 0, 20, 20, 21, 0, 22, 23, 24, 0],
        sample_vocab,
        blank_id=0,
    )
    assert ctc_out == "打开 IntentOS设置", f"Unexpected CTC output: {ctc_out}"

    # 5. Test GPT-2 byte-level BPE UTF-8 roundtrip on Chinese + English text
    target_text = "打开我的硕士论文第四章 IntentOS 123"
    b2u = gpt2_bytes_to_unicode()
    encoded_chars = "".join(b2u[b] for b in target_text.encode("utf-8"))
    # Split into arbitrary multi-char BPE chunks splitting mid-UTF8 sequence!
    fake_bpe_tokens = [encoded_chars[i : i + 3] for i in range(0, len(encoded_chars), 3)]
    decoded_text = decode_gpt2_byte_level_bpe(fake_bpe_tokens)
    assert decoded_text == target_text, f"BPE roundtrip mismatch: {decoded_text} != {target_text}"

    report = {
        "ok": True,
        "onnxruntime_available": ORT_AVAILABLE,
        "onnxruntime_version": ORT_VERSION,
        "numpy_version": getattr(np, "__version__", "unknown"),
        "kaldi_fbank_shape": list(fbank.shape),
        "kaldi_lfr_shape": list(lfr.shape),
        "whisper_mel_shape": list(w_mel.shape),
        "ctc_decode_ok": True,
        "bpe_roundtrip_ok": True,
    }
    print(json.dumps(report, ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="IntentOS Offline ONNX ASR Runner")
    parser.add_argument("--self-test", action="store_true", help="Run self-contained DSP/BPE/ORT self-test")
    parser.add_argument(
        "--engine",
        type=str,
        default="sensevoice_onnx",
        choices=["sensevoice_onnx", "whisper_onnx"],
        help="ASR ONNX engine kind",
    )
    parser.add_argument("--model-dir", type=str, default="", help="Path to installed speech model directory")
    parser.add_argument("--wav", type=str, default="", help="Path to input WAV file")
    parser.add_argument("--language", type=str, default="zh", help="Language hint: zh | auto | en")
    args = parser.parse_args()

    if args.self_test:
        try:
            return run_self_test()
        except Exception as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
            return 1

    if not args.model_dir or not args.wav:
        print(
            json.dumps(
                {"ok": False, "error": "Both --model-dir and --wav are required unless --self-test is passed"},
                ensure_ascii=False,
            )
        )
        return 2

    started = time.monotonic()
    try:
        model_dir = Path(args.model_dir)
        wav_path = Path(args.wav)
        if not wav_path.is_file():
            raise FileNotFoundError(f"WAV file does not exist: {wav_path}")

        wav_16k, duration_sec = load_wav_mono_16k(str(wav_path))
        if wav_16k.size < 400:
            raise ValueError("录音时长过短，未检测到有效语音片段")

        if args.engine == "sensevoice_onnx":
            text = transcribe_sensevoice_onnx(model_dir, wav_16k, args.language)
        elif args.engine == "whisper_onnx":
            text = transcribe_whisper_onnx(model_dir, wav_16k, args.language)
        else:
            raise ValueError(f"Unsupported engine: {args.engine}")

        elapsed_ms = int(round((time.monotonic() - started) * 1000.0))
        print(
            json.dumps(
                {
                    "ok": True,
                    "text": text.strip(),
                    "engine": args.engine,
                    "language": args.language,
                    "duration_sec": round(duration_sec, 3),
                    "elapsed_ms": elapsed_ms,
                },
                ensure_ascii=False,
            )
        )
        return 0
    except Exception as exc:
        elapsed_ms = int(round((time.monotonic() - started) * 1000.0))
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                    "engine": args.engine,
                    "elapsed_ms": elapsed_ms,
                },
                ensure_ascii=False,
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
