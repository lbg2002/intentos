#!/usr/bin/env python3
"""IntentOS 11-Page Comprehensive GTK4 Settings Center (`WP14` + Wave 3 Upgrades).

Full 11-domain native GTK4 desktop application (`Gtk.StackSidebar` + `Gtk.Stack`) with
high-contrast Dark & Light theme support, zero `PyGIWarning`, zero invalid `TextView` calls, and:
  - Page 2 (`_build_page_02_brain`): Live `/v1/models` auto-discovery & interactive searchable
    model selector (`backend_bridge.get_backends_catalog({"refresh_remote": True})`,
    `refresh_models`, `set_active_backend`) + Multi-Provider CRUD + 5 Roles + Egress Matrix.
  - Page 4 & Page 8 (`_build_page_04_skills` / `_build_page_08_permissions`): Global User-Space Path
    Visibility vs Sensitive Approval vs Hard-Forbidden posture, interactive Security Mode switcher
    (`strict` / `balanced` / `developer`), and Session Scope Grants with 1-click revoke.
  - Page 5 (`_build_page_05_capabilities`): Personalized Non-CLI Desktop Software Translation Center
    (`app_adapter.discover_personal_apps`, `save_custom_adapter`, `close_app_verified`).
  - Supports `--smoke-ui` (instantiates all 11 pages on real GTK4 with 0 warnings) and `--dump-json`.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import warnings
from pathlib import Path
from typing import Any

SETTINGS_CSS = """
window.intentos-settings-win {
  background-color: #141824;
  background-image: none;
  color: #f1f5f9;
}

window.intentos-settings-win.intentos-light-theme {
  background-color: #f8fafc;
  background-image: none;
  color: #0f172a;
}

/* Strip GTK4 Adwaita dark charcoal background-image gradients across custom settings controls */
window.intentos-settings-win button,
window.intentos-settings-win button:hover,
window.intentos-settings-win button:active,
window.intentos-settings-win button:checked,
window.intentos-settings-win button:focus,
window.intentos-settings-win button:disabled,
window.intentos-settings-win button:backdrop,
window.intentos-settings-win entry,
window.intentos-settings-win entry:focus,
window.intentos-settings-win dropdown > button {
  background-image: none;
  box-shadow: none;
  text-shadow: none;
  -gtk-icon-shadow: none;
}

window.intentos-settings-win button,
window.intentos-settings-win dropdown > button {
  background-color: rgba(255, 255, 255, 0.08);
  border: 1px solid rgba(148, 163, 184, 0.26);
  color: #f1f5f9;
  border-radius: 8px;
  padding: 5px 11px;
  font-weight: 600;
}

window.intentos-settings-win button:hover,
window.intentos-settings-win dropdown > button:hover {
  background-color: rgba(249, 115, 22, 0.22);
  border-color: rgba(249, 115, 22, 0.62);
  color: #ffffff;
}

window.intentos-settings-win.intentos-light-theme button,
window.intentos-settings-win.intentos-light-theme dropdown > button {
  background-color: #f1f5f9;
  border: 1px solid #cbd5e1;
  color: #0f172a;
}

window.intentos-settings-win.intentos-light-theme button:hover,
window.intentos-settings-win.intentos-light-theme dropdown > button:hover {
  background-color: #fff7ed;
  border-color: #ea580c;
  color: #ea580c;
}

window.intentos-settings-win button.intentos-primary-btn {
  background-color: #ea580c;
  background-image: none;
  border: 1px solid #f97316;
  color: #ffffff;
  font-weight: 700;
}

window.intentos-settings-win button.intentos-primary-btn:hover {
  background-color: #f97316;
  background-image: none;
  color: #ffffff;
}

window.intentos-settings-win button.intentos-mode-active {
  background-color: rgba(234, 88, 12, 0.28);
  background-image: none;
  border: 1px solid #f97316;
  color: #ffedd5;
}

window.intentos-settings-win.intentos-light-theme button.intentos-mode-active {
  background-color: #ffedd5;
  background-image: none;
  border: 1px solid #ea580c;
  color: #c2410c;
}

window.intentos-settings-win button.intentos-danger-btn {
  background-color: rgba(220, 38, 38, 0.85);
  background-image: none;
  border: 1px solid #ef4444;
  color: #ffffff;
}

window.intentos-settings-win entry {
  background-color: rgba(15, 23, 42, 0.72);
  border: 1px solid rgba(148, 163, 184, 0.28);
  color: #f8fafc;
  border-radius: 8px;
  padding: 4px 8px;
}

window.intentos-settings-win.intentos-light-theme entry {
  background-color: #ffffff;
  border: 1px solid #cbd5e1;
  color: #0f172a;
}

.intentos-sidebar-panel {
  background-color: #10141f;
  background-image: none;
  border-right: 1px solid rgba(148, 163, 184, 0.18);
}

.intentos-light-theme .intentos-sidebar-panel {
  background-color: #f1f5f9;
  background-image: none;
  border-right: 1px solid #cbd5e1;
}

.intentos-sidebar {
  background-color: transparent;
}

.intentos-page-title {
  font-size: 15pt;
  font-weight: 800;
  color: #fb923c;
  margin-bottom: 4px;
}

.intentos-light-theme .intentos-page-title {
  color: #ea580c;
}

.intentos-section-card {
  background-color: #1c2230;
  background-image: none;
  border: 1px solid rgba(148, 163, 184, 0.22);
  border-radius: 12px;
  padding: 12px 14px;
  margin-bottom: 8px;
}

.intentos-light-theme .intentos-section-card {
  background-color: #ffffff;
  background-image: none;
  border: 1px solid rgba(15, 23, 42, 0.12);
}

.intentos-section-header {
  font-size: 11pt;
  font-weight: 700;
  color: #93c5fd;
  margin-bottom: 6px;
}

.intentos-light-theme .intentos-section-header {
  color: #1e40af;
}

.intentos-tier-ok {
  background-color: rgba(16, 185, 129, 0.12);
  border: 1px solid rgba(16, 185, 129, 0.40);
  border-radius: 8px;
  padding: 8px 10px;
}

.intentos-light-theme .intentos-tier-ok {
  background-color: #ecfdf5;
  border: 1px solid #6ee7b7;
  color: #065f46;
}

.intentos-tier-warn {
  background-color: rgba(245, 158, 11, 0.12);
  border: 1px solid rgba(245, 158, 11, 0.42);
  border-radius: 8px;
  padding: 8px 10px;
}

.intentos-light-theme .intentos-tier-warn {
  background-color: #fffbeb;
  border: 1px solid #fcd34d;
  color: #92400e;
}

.intentos-tier-deny {
  background-color: rgba(239, 68, 68, 0.12);
  border: 1px solid rgba(239, 68, 68, 0.42);
  border-radius: 8px;
  padding: 8px 10px;
}

.intentos-light-theme .intentos-tier-deny {
  background-color: #fef2f2;
  border: 1px solid #fca5a5;
  color: #991b1b;
}

.intentos-status-ok {
  color: #34d399;
  font-weight: 700;
}

.intentos-light-theme .intentos-status-ok {
  color: #047857;
}

.intentos-status-warn {
  color: #fbbf24;
  font-weight: 700;
}

.intentos-light-theme .intentos-status-warn {
  color: #b45309;
}

.intentos-mono-scroll {
  border: 1px solid rgba(148, 163, 184, 0.22);
  border-radius: 8px;
  background-color: #0f131d;
}

.intentos-light-theme .intentos-mono-scroll {
  border: 1px solid #e2e8f0;
  background-color: #f8fafc;
}

textview.intentos-mono-box,
textview.intentos-mono-box text {
  font-family: monospace;
  font-size: 9.5pt;
  background-color: #0f131d;
  background-image: none;
  color: #e2e8f0;
  padding: 6px;
}

.intentos-light-theme textview.intentos-mono-box,
.intentos-light-theme textview.intentos-mono-box text {
  background-color: #f8fafc;
  background-image: none;
  color: #1e293b;
}

.intentos-muted-lbl {
  font-size: 9pt;
  color: #94a3b8;
}

.intentos-light-theme .intentos-muted-lbl {
  color: #475569;
}

.intentos-tray-card {
  background-color: rgba(15, 23, 42, 0.55);
  border: 1px solid rgba(56, 189, 248, 0.30);
  border-radius: 8px;
  padding: 8px 10px;
}

.intentos-light-theme .intentos-tray-card {
  background-color: #f8fafc;
  border: 1px solid rgba(2, 132, 199, 0.30);
}

button.intentos-tray-btn {
  padding: 2px 8px;
  border-radius: 6px;
  background-color: rgba(56, 189, 248, 0.14);
  background-image: none;
  border: 1px solid rgba(56, 189, 248, 0.42);
  color: #7dd3fc;
  font-size: 9pt;
  font-weight: 700;
}

button.intentos-tray-btn:hover {
  background-color: rgba(56, 189, 248, 0.26);
  color: #e0f2fe;
}

.intentos-light-theme button.intentos-tray-btn {
  background-color: #e0f2fe;
  border: 1px solid #0284c7;
  color: #0369a1;
}

window.intentos-settings-win button:disabled {
  opacity: 0.48;
}

.intentos-asr-card,
.intentos-app-inv-card {
  background-color: rgba(15, 23, 42, 0.58);
  border: 1px solid rgba(148, 163, 184, 0.24);
  border-radius: 10px;
  padding: 9px 12px;
}

.intentos-light-theme .intentos-asr-card,
.intentos-light-theme .intentos-app-inv-card {
  background-color: #f8fafc;
  border: 1px solid #cbd5e1;
}

.intentos-badge-pill {
  background-color: rgba(249, 115, 22, 0.18);
  border: 1px solid rgba(249, 115, 22, 0.45);
  color: #fdba74;
  border-radius: 999px;
  padding: 1px 8px;
  font-size: 8.5pt;
  font-weight: 700;
}

.intentos-light-theme .intentos-badge-pill {
  background-color: #ffedd5;
  border: 1px solid #fb923c;
  color: #c2410c;
}

.intentos-badge-running {
  background-color: rgba(16, 185, 129, 0.18);
  border: 1px solid rgba(16, 185, 129, 0.48);
  color: #6ee7b7;
  border-radius: 999px;
  padding: 1px 8px;
  font-size: 8.5pt;
  font-weight: 700;
}

.intentos-light-theme .intentos-badge-running {
  background-color: #d1fae5;
  border: 1px solid #10b981;
  color: #065f46;
}

.intentos-badge-source {
  background-color: rgba(148, 163, 184, 0.16);
  border: 1px solid rgba(148, 163, 184, 0.34);
  color: #cbd5e1;
  border-radius: 6px;
  padding: 1px 7px;
  font-size: 8.5pt;
  font-weight: 600;
}

.intentos-light-theme .intentos-badge-source {
  background-color: #e2e8f0;
  border: 1px solid #94a3b8;
  color: #334155;
}
"""

DEEP_SCAN_CATEGORIES: list[tuple[str, str]] = [
    ("all", "全部"),
    ("media_entertainment", "🎵 影音娱乐"),
    ("social_collab", "💬 社交会议"),
    ("office_notes_doc", "📄 办公笔记"),
    ("cloud_transfer", "☁ 云盘互传"),
    ("network_browser", "🌐 网络代理"),
    ("dev_ai_ide", "💻 开发与AI"),
    ("creative_disc", "🎨 创意刻录"),
    ("remote_vm", "🖥 远程虚拟机"),
    ("hardware_system", "🛠 硬件系统"),
]

DEEP_SCAN_CATEGORY_LABELS: dict[str, str] = dict(DEEP_SCAN_CATEGORIES)

DECAY_PRESETS: list[tuple[str, float, float]] = [
    ("温和衰减 (λ=0.15, γ=1.2)", 0.15, 1.2),
    ("标准非线性衰减·推荐 (λ=0.24, γ=1.35)", 0.24, 1.35),
    ("紧凑省流衰减 (λ=0.38, γ=1.55)", 0.38, 1.55),
]

SPEECH_LANGUAGES: list[tuple[str, str]] = [
    ("zh", "zh · 中文与中英混合（推荐）"),
    ("auto", "auto · 自动多语种识别"),
    ("en", "en · English 英语"),
]

DEFAULT_SPEECH_MODELS_CATALOG: list[dict[str, Any]] = [
    {
        "id": "sensevoice-small-int8",
        "name": "SenseVoice-Small (INT8 离线量化版)",
        "badge": "强烈推荐 · 中英高准度",
        "approx_size_mb": 228,
        "languages": ["zh", "en", "yue", "ja", "ko"],
        "installed": False,
        "status": "not_installed",
    },
    {
        "id": "whisper-tiny-q8",
        "name": "Whisper-Tiny (Q8 极速轻量版)",
        "badge": "轻量极速",
        "approx_size_mb": 42,
        "languages": ["zh", "en", "auto"],
        "installed": False,
        "status": "not_installed",
    },
    {
        "id": "whisper-base-q8",
        "name": "Whisper-Base (Q8 均衡通用版)",
        "badge": "均衡推荐",
        "approx_size_mb": 78,
        "languages": ["zh", "en", "auto"],
        "installed": False,
        "status": "not_installed",
    },
    {
        "id": "whisper-small-q8",
        "name": "Whisper-Small (Q8 高精度多语种版)",
        "badge": "高精度",
        "approx_size_mb": 244,
        "languages": ["zh", "en", "auto"],
        "installed": False,
        "status": "not_installed",
    },
]


def normalize_settings_page_name(raw_page: str) -> str:
    key = (raw_page or "").strip().lower()
    if not key:
        return ""
    alias_map = {
        "1": "overview",
        "page1": "overview",
        "overview": "overview",
        "entry": "overview",
        "speech": "overview",
        "voice": "overview",
        "asr": "overview",
        "mic": "overview",
        "2": "brain",
        "page2": "brain",
        "brain": "brain",
        "models": "brain",
        "3": "memories",
        "page3": "memories",
        "memories": "memories",
        "memory": "memories",
        "compression": "memories",
        "context": "memories",
        "4": "skills",
        "page4": "skills",
        "skills": "skills",
        "5": "capabilities",
        "page5": "capabilities",
        "capabilities": "capabilities",
        "adapter": "capabilities",
        "adapters": "capabilities",
        "software": "capabilities",
        "apps": "capabilities",
        "6": "resources",
        "resources": "resources",
        "7": "web",
        "web": "web",
        "8": "permissions",
        "permissions": "permissions",
        "security": "permissions",
        "9": "undo",
        "undo": "undo",
        "10": "automation",
        "automation": "automation",
        "11": "maintenance",
        "maintenance": "maintenance",
    }
    return alias_map.get(key, key)

BACKEND_OPTIONS: list[tuple[str, str]] = [
    ("auto", "自动选择 (Auto)"),
    ("zcode", "ZCode 本地网关"),
    ("codex", "Codex CLI / Proxy"),
    ("pi", "Pi Agent 引擎"),
    ("openai", "OpenAI API 兼容"),
]

EFFORT_OPTIONS: list[tuple[str, str]] = [
    ("default", "默认"),
    ("fast", "快 (Fast)"),
    ("medium", "标准 (Medium)"),
    ("high", "深入 (High)"),
]

SECURITY_MODES: list[tuple[str, str, str]] = [
    ("strict", "严格逐次审批 (strict)", "所有文件写入、敏感路径及关闭进程均需人工逐次确认"),
    ("balanced", "平衡受控防护 (推荐)", "常规用户目录直接通行；隐藏配置/外部路径与 AI 修改触发内联审批"),
    ("developer", "信任目录免批 (developer)", "授权工作区内可逆修改自动生成回滚点免批；禁区仍严格封锁"),
]

ADAPTER_CHANNELS: list[tuple[str, str]] = [
    ("sni_dbusmenu", "sni_dbusmenu — StatusNotifierItem / dbusmenu 托盘菜单点击"),
    ("dbus_mpris", "dbus_mpris — MPRIS2 D-Bus 媒体播放控制"),
    ("dbus_freedesktop", "dbus_freedesktop — Freedesktop D-Bus 会话激活"),
    ("desktop_action", "desktop_action — .desktop 快捷动作"),
    ("uri_scheme", "uri_scheme — URI Deep-Link 协议唤起"),
    ("gui_atspi", "gui_atspi — AT-SPI2 控件 / 快捷键桥接"),
    ("cli_wrapper", "cli_wrapper — 命令行参数 / 进程验证关闭"),
]


def normalize_menu_items_settings(raw_items: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_items, list):
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw_items:
        if isinstance(item, str):
            lbl = item.strip()
            if lbl and lbl not in ("-", "separator") and lbl not in seen:
                seen.add(lbl)
                out.append({"id": None, "label": lbl, "enabled": True})
        elif isinstance(item, dict):
            if item.get("is_separator") or item.get("type") == "separator" or item.get("visible") is False:
                continue
            lbl = str(item.get("label") or item.get("title") or item.get("name") or item.get("action") or "").replace("_", "").strip()
            if lbl and lbl not in seen:
                seen.add(lbl)
                out.append(
                    {
                        "id": item.get("id") if item.get("id") is not None else item.get("menu_id"),
                        "label": lbl,
                        "enabled": item.get("enabled", True) is not False,
                    }
                )
    return out


def normalize_live_tray_apps_settings(raw: Any) -> list[dict[str, Any]]:
    arr: list[Any] = []
    if isinstance(raw, list):
        arr = raw
    elif isinstance(raw, dict):
        for k in ("apps", "tray_apps", "items", "live_apps"):
            if isinstance(raw.get(k), list):
                arr = raw[k]
                break
    out: list[dict[str, Any]] = []
    for item in arr:
        if not isinstance(item, dict):
            continue
        app_id = str(item.get("app_id") or item.get("id") or item.get("desktop_id") or item.get("name") or item.get("title") or "tray_app")
        name = str(item.get("display_name") or item.get("zh_name") or item.get("app_name") or item.get("name") or item.get("title") or app_id)
        live_title = str(item.get("live_title") or item.get("status_title") or item.get("tooltip") or item.get("media_title") or item.get("now_playing") or "").strip()
        menu_raw = (
            item.get("menu_items")
            or item.get("dbusmenu_items")
            or item.get("clickable_items")
            or item.get("actions")
            or ((item.get("tray") or {}).get("menu_items") if isinstance(item.get("tray"), dict) else None)
            or []
        )
        out.append(
            {
                "app_id": app_id,
                "name": name,
                "live_title": live_title if live_title != name else "",
                "service": str(item.get("service") or item.get("bus_name") or item.get("sni_service") or ""),
                "pid": item.get("pid") or ((item.get("pids") or [None])[0] if isinstance(item.get("pids"), list) else None),
                "mpris_service": str(item.get("mpris_service") or item.get("mpris") or ""),
                "menu_items": normalize_menu_items_settings(menu_raw),
            }
        )
    return out

MODEL_ROLES: list[tuple[str, str]] = [
    ("main", "Main · 主推理与规划模型"),
    ("fast", "Fast · L1 快速解析与摘要"),
    ("decision", "Decision · L1 类型化路由判断"),
    ("vision", "Vision · 截图与视觉理解"),
    ("memory", "Memory · 记忆提炼与会话压缩"),
]

DATA_CLASSES: list[str] = ["public", "personal", "sensitive", "forbidden"]
PROVIDER_TRUSTS: list[str] = ["trusted", "standard", "untrusted"]


def resolve_ui_socket() -> Path:
    base = os.environ.get("INTENTOS_BASE_DIR")
    if base:
        return Path(base) / "run" / "ui.sock"
    xdg_run = os.environ.get("XDG_RUNTIME_DIR") or f"/tmp/intentos-run-{os.getuid()}"
    return Path(xdg_run) / "intentos" / "ui.sock"


def detect_system_light_theme() -> bool:
    if os.environ.get("INTENTOS_LIGHT_THEME") == "1":
        return True
    if os.environ.get("INTENTOS_DARK_THEME") == "1":
        return False
    if shutil.which("gsettings"):
        try:
            res = subprocess.run(
                ["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"],
                capture_output=True,
                text=True,
                timeout=1.2,
                check=False,
            )
            scheme = (res.stdout or "").strip().lower()
            if "prefer-dark" in scheme:
                return False
            if "prefer-light" in scheme:
                return True
        except Exception:
            pass
        try:
            res_gtk = subprocess.run(
                ["gsettings", "get", "org.gnome.desktop.interface", "gtk-theme"],
                capture_output=True,
                text=True,
                timeout=1.2,
                check=False,
            )
            gtk_theme = (res_gtk.stdout or "").strip().lower()
            if "dark" in gtk_theme:
                return False
            if gtk_theme:
                return True
        except Exception:
            pass
    return False


def call_ui_rpc(method: str, params: Any = None, timeout: float = 12.0) -> dict[str, Any]:
    sock_path = resolve_ui_socket()
    payload: dict[str, Any] = {"id": f"cfg_{int(time.time() * 1000)}", "method": method}
    if params is not None:
        payload["params"] = params
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(str(sock_path))
        s.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf.decode("utf-8"))


def call_module_rpc(
    domain: str,
    action: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 12.0,
) -> dict[str, Any]:
    return call_ui_rpc(
        "module_rpc",
        {
            "domain": domain,
            "action": action,
            "payload": payload or {},
        },
        timeout=timeout,
    )


def fetch_combined_settings() -> dict[str, Any]:
    """Fetch legacy `get_settings_overview` merged with `config_center`, `memory_hub`, `app_adapter`, and `backend_bridge`."""
    try:
        base_res = call_ui_rpc("get_settings_overview", timeout=4.0)
    except Exception as exc:
        return {"id": "cfg_offline", "ok": False, "result": {}, "error": str(exc)}
    overview = base_res.get("result", {}) if base_res.get("ok") else {}
    try:
        dom_res = call_module_rpc("config_center", "get_all_domains", {}, timeout=4.0)
        if dom_res.get("ok") and isinstance(dom_res.get("result"), dict):
            overview["domains"] = dom_res["result"]
    except Exception:
        pass
    try:
        mem_dash = call_module_rpc("memory_hub", "get_memory_dashboard", {}, timeout=4.0)
        if mem_dash.get("ok") and isinstance(mem_dash.get("result"), dict):
            overview["memory_hub"] = mem_dash["result"]
    except Exception:
        pass
    try:
        ad_res = call_module_rpc("app_adapter", "list_adapters", {}, timeout=4.0)
        if ad_res.get("ok"):
            overview["app_adapter"] = ad_res.get("result")
    except Exception:
        pass
    try:
        bb_res = call_module_rpc("backend_bridge", "get_backends_catalog", {"refresh_remote": True}, timeout=6.0)
        if bb_res.get("ok") and isinstance(bb_res.get("result"), dict):
            overview["backend_bridge"] = bb_res["result"]
    except Exception:
        pass
    try:
        sec_res = call_module_rpc("execution_hub", "get_security_posture", {}, timeout=4.0)
        if sec_res.get("ok") and isinstance(sec_res.get("result"), dict):
            overview["security_posture"] = sec_res["result"]
    except Exception:
        pass
    try:
        sp_res = call_module_rpc("speech_hub", "get_speech_overview", {}, timeout=4.0)
        if sp_res.get("ok") and isinstance(sp_res.get("result"), dict):
            overview["speech_hub"] = sp_res["result"]
    except Exception:
        pass
    try:
        cc_res = call_module_rpc("memory_hub", "get_context_compression_config", {}, timeout=4.0)
        if cc_res.get("ok") and isinstance(cc_res.get("result"), dict):
            overview["context_compression"] = cc_res["result"]
    except Exception:
        pass
    return {
        "id": base_res.get("id", "cfg_dump"),
        "ok": bool(base_res.get("ok", True)),
        "result": overview,
        "error": base_res.get("error"),
    }


def parse_catalog_for_settings(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Parse `backend_bridge` catalog preserving full provider metadata and ALL `/v1/models`."""
    data = raw if isinstance(raw, dict) else {}
    act_raw = data.get("active") if isinstance(data.get("active"), dict) else {}
    active = {
        "backend": str(act_raw.get("backend") or data.get("active_backend") or "auto").lower(),
        "provider": str(act_raw.get("provider") or data.get("active_provider") or ""),
        "model": str(act_raw.get("model") or data.get("active_model") or ""),
        "reasoning_effort": str(act_raw.get("reasoning_effort") or data.get("reasoning_effort") or "default").lower(),
    }

    raw_backends = data.get("backends")
    bmap: dict[str, dict[str, Any]] = {}
    if isinstance(raw_backends, dict):
        for k, v in raw_backends.items():
            if isinstance(v, dict):
                bmap[str(k).lower()] = v
    elif isinstance(raw_backends, list):
        for item in raw_backends:
            if isinstance(item, dict):
                bid = str(item.get("id") or item.get("backend") or item.get("name") or "").lower()
                if bid:
                    bmap[bid] = item

    backends_out: dict[str, dict[str, Any]] = {}
    all_providers: list[dict[str, Any]] = []
    all_models: list[tuple[str, str]] = []

    for bid, blabel in BACKEND_OPTIONS:
        b = bmap.get(bid, {})
        providers_parsed: list[dict[str, Any]] = []
        models_parsed: list[tuple[str, str]] = []

        raw_provs = b.get("providers")
        if isinstance(raw_provs, list):
            prov_iter = [p for p in raw_provs if isinstance(p, dict)]
        elif isinstance(raw_provs, dict):
            prov_iter = [{"id": k, **v} for k, v in raw_provs.items() if isinstance(v, dict)]
        else:
            prov_iter = []

        for p in prov_iter:
            pid = str(p.get("id") or p.get("provider") or p.get("name") or "default")
            pname = str(p.get("name") or pid)
            burl = str(p.get("base_url") or b.get("base_url") or "")
            source = str(p.get("source") or bid)
            live_ok = bool(p.get("live_models_fetched"))
            p_models_raw = p.get("models") or p.get("available_models") or []
            p_models: list[str] = []
            if isinstance(p_models_raw, list):
                for m in p_models_raw:
                    mid = str(m.get("id") or m.get("name") if isinstance(m, dict) else m)
                    if mid and mid not in p_models:
                        p_models.append(mid)
            def_m = str(p.get("default_model") or p.get("model") or "")
            if def_m and def_m not in p_models:
                p_models.insert(0, def_m)

            p_entry = {
                "id": pid,
                "name": pname,
                "backend": bid,
                "base_url": burl,
                "source": source,
                "live_models_fetched": live_ok,
                "models": p_models,
            }
            providers_parsed.append(p_entry)
            if bid != "auto":
                all_providers.append(p_entry)
            for mid in p_models:
                if (pid, mid) not in models_parsed:
                    models_parsed.append((pid, mid))
                if bid != "auto" and not any(em == mid for _, em in all_models):
                    all_models.append((pid, mid))

        flat_models = b.get("models") or b.get("available_models") or []
        if isinstance(flat_models, list):
            def_p = str(b.get("default_provider") or (providers_parsed[0]["id"] if providers_parsed else ""))
            for m in flat_models:
                mid = str(m.get("id") or m.get("name") if isinstance(m, dict) else m)
                if mid and not any(em == mid for _, em in models_parsed):
                    models_parsed.append((def_p, mid))
                if bid != "auto" and mid and not any(em == mid for _, em in all_models):
                    all_models.append((def_p, mid))

        backends_out[bid] = {
            "id": bid,
            "label": blabel,
            "available": bool(b.get("available", bid in ("auto", "openai"))),
            "providers": providers_parsed,
            "models": models_parsed,
        }

    if not backends_out["auto"]["providers"] and all_providers:
        backends_out["auto"]["providers"] = list(all_providers)
    if not backends_out["auto"]["models"] and all_models:
        backends_out["auto"]["models"] = list(all_models)

    return {"active": active, "backends": backends_out}


def run_settings_ui(
    smoke_ui: bool = False,
    initial_page: str = "",
    initial_inspect_app: str = "",
) -> int:
    if smoke_ui and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        print(json.dumps({"ok": True, "skipped": "no DISPLAY or WAYLAND_DISPLAY"}, ensure_ascii=False))
        return 0

    try:
        import gi

        if smoke_ui:
            warnings.simplefilter("error", gi.PyGIWarning)
        gi.require_version("Gtk", "4.0")
        gi.require_version("Gdk", "4.0")
        gi.require_version("Pango", "1.0")
        from gi.repository import Gdk, GLib, Gtk, Pango  # type: ignore
    except Exception as exc:
        sys_py = "/usr/bin/python3"
        if (
            os.environ.get("_INTENTOS_SYS_PY_TRIED") != "1"
            and Path(sys_py).exists()
            and os.path.realpath(sys.executable) != os.path.realpath(sys_py)
        ):
            env = {**os.environ, "_INTENTOS_SYS_PY_TRIED": "1"}
            os.execve(sys_py, [sys_py, str(Path(__file__).resolve()), *sys.argv[1:]], env)
        print(
            f"[intentos-settings] 未检测到 GTK4 环境 ({exc})；可通过 `intentosctl settings` 或 http://127.0.0.1:8787 设置中心配置。",
            file=sys.stderr,
        )
        return 1

    if smoke_ui and not Gtk.init_check():
        print(json.dumps({"ok": True, "skipped": "Gtk.init_check() returned False"}, ensure_ascii=False))
        return 0

    class SettingsCenterApp(Gtk.Application):
        def __init__(self, is_smoke: bool = False) -> None:
            super().__init__(application_id="org.intentos.Settings")
            self.smoke_mode: bool = is_smoke
            self.initial_page: str = normalize_settings_page_name(initial_page)
            self.initial_inspect_app: str = initial_inspect_app
            self.light_theme: bool = detect_system_light_theme()
            self.ov: dict[str, Any] = {}
            self.domains: dict[str, Any] = {}
            self.css_errors: list[str] = []
            self.win: Gtk.Window | None = None
            self._page01_speech_switch: Any = None
            self._page01_asr_models_count: int = 0
            self._page03_save_decay_btn: Any = None
            self._page05_inspect_fn: Any = None
            self._page05_fill_btn: Any = None
            self._page05_deep_cat_btns: dict[str, Any] = {}
            self._page05_deep_search_entry: Any = None

        def _load_css(self) -> None:
            provider = Gtk.CssProvider()
            provider.connect(
                "parsing-error",
                lambda _p, sec, err: self.css_errors.append(
                    f"line {sec.get_start_location().lines}: {err.message if hasattr(err, 'message') else err}"
                ),
            )
            if hasattr(provider, "load_from_string"):
                provider.load_from_string(SETTINGS_CSS)
            else:
                provider.load_from_data(SETTINGS_CSS.encode("utf-8"))
            display = Gdk.Display.get_default()
            if display is not None:
                Gtk.StyleContext.add_provider_for_display(
                    display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
                )

        def _apply_theme(self, light: bool) -> None:
            self.light_theme = light
            try:
                settings = Gtk.Settings.get_default()
                if settings is not None:
                    settings.set_property("gtk-application-prefer-dark-theme", not light)
            except Exception:
                pass
            if self.win is not None:
                if light:
                    self.win.add_css_class("intentos-light-theme")
                else:
                    self.win.remove_css_class("intentos-light-theme")

        def _refresh_state(self) -> None:
            if self.smoke_mode:
                self.ov = {}
                self.domains = {}
                return
            try:
                combined = fetch_combined_settings()
                self.ov = combined.get("result", {}) or {}
                self.domains = self.ov.get("domains", {}) or {}
            except Exception:
                self.ov = {}
                self.domains = {}

        def _make_scrolled_page(self, title: str, subtitle: str) -> tuple[Gtk.ScrolledWindow, Gtk.Box]:
            scroll = Gtk.ScrolledWindow()
            scroll.set_vexpand(True)
            scroll.set_hexpand(True)
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            box.set_margin_top(16)
            box.set_margin_bottom(16)
            box.set_margin_start(18)
            box.set_margin_end(18)

            title_lbl = Gtk.Label(label=title, xalign=0.0)
            title_lbl.add_css_class("intentos-page-title")
            box.append(title_lbl)

            sub_lbl = Gtk.Label(label=subtitle, xalign=0.0)
            sub_lbl.add_css_class("intentos-muted-lbl")
            sub_lbl.set_wrap(True)
            box.append(sub_lbl)

            scroll.set_child(box)
            return scroll, box

        def _make_card(self, header: str) -> Gtk.Box:
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            card.add_css_class("intentos-section-card")
            hdr = Gtk.Label(label=header, xalign=0.0)
            hdr.add_css_class("intentos-section-header")
            hdr.set_wrap(True)
            card.append(hdr)
            return card

        def _make_scrolled_textview(
            self,
            buf: Gtk.TextBuffer,
            editable: bool = False,
            min_height: int = 140,
            vexpand: bool = False,
        ) -> tuple[Gtk.ScrolledWindow, Gtk.TextView]:
            """GTK4-safe ScrolledWindow wrapper around `Gtk.TextView` (never calls invalid set_min_content_height on TextView)."""
            sw = Gtk.ScrolledWindow(min_content_height=min_height, hexpand=True)
            sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
            sw.set_propagate_natural_height(True)
            sw.set_vexpand(vexpand)
            sw.add_css_class("intentos-mono-scroll")

            tv = Gtk.TextView(buffer=buf, editable=editable, monospace=True)
            tv.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
            tv.add_css_class("intentos-mono-box")
            sw.set_child(tv)
            return sw, tv

        def _clear_box(self, box: Gtk.Box) -> None:
            child = box.get_first_child()
            while child is not None:
                nxt = child.get_next_sibling()
                box.remove(child)
                child = nxt

        def _clear_flowbox(self, flow: Gtk.FlowBox) -> None:
            child = flow.get_first_child()
            while child is not None:
                nxt = child.get_next_sibling()
                flow.remove(child)
                child = nxt

        def build_all_pages_onto_window(self, win: Gtk.Window) -> Gtk.Stack:
            self.win = win
            win.set_title("IntentOS 设置中心 (11 页全要素配置 · v0.3)")
            win.set_default_size(1040, 720)
            win.add_css_class("intentos-settings-win")
            self._apply_theme(self.light_theme)

            main_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
            win.set_child(main_hbox)

            left_panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            left_panel.add_css_class("intentos-sidebar-panel")
            left_panel.set_size_request(230, -1)

            sidebar = Gtk.StackSidebar()
            sidebar.set_vexpand(True)
            sidebar.add_css_class("intentos-sidebar")

            theme_toggle_btn = Gtk.Button(label="◑ 切换深色/浅色主题")
            theme_toggle_btn.set_margin_start(10)
            theme_toggle_btn.set_margin_end(10)
            theme_toggle_btn.set_margin_bottom(10)
            theme_toggle_btn.connect("clicked", lambda _b: self._apply_theme(not self.light_theme))

            left_panel.append(sidebar)
            left_panel.append(theme_toggle_btn)

            stack = Gtk.Stack()
            stack.set_transition_type(Gtk.StackTransitionType.SLIDE_UP_DOWN)
            stack.set_hexpand(True)
            stack.set_vexpand(True)
            sidebar.set_stack(stack)

            main_hbox.append(left_panel)
            main_hbox.append(stack)

            # Build all 11 Pages (§14.2)
            self._build_page_01_overview(stack)
            self._build_page_02_brain(stack)
            self._build_page_03_memories(stack)
            self._build_page_04_skills(stack)
            self._build_page_05_capabilities(stack)
            self._build_page_06_resources(stack)
            self._build_page_07_web(stack)
            self._build_page_08_permissions(stack)
            self._build_page_09_undo(stack)
            self._build_page_10_automation(stack)
            self._build_page_11_maintenance(stack)
            return stack

        def do_activate(self) -> None:
            self._load_css()
            self._refresh_state()
            win = Gtk.ApplicationWindow(application=self)
            stack = self.build_all_pages_onto_window(win)
            target_page = normalize_settings_page_name(self.initial_page)
            if target_page and stack.get_child_by_name(target_page) is not None:
                stack.set_visible_child_name(target_page)
            if self.initial_inspect_app and callable(self._page05_inspect_fn):
                if stack.get_child_by_name("capabilities") is not None:
                    stack.set_visible_child_name("capabilities")
                self._page05_inspect_fn(self.initial_inspect_app)
            win.present()

        # ------------------------------------------------------------------
        # Page 1: 概览与本地离线语音识别 (`_build_page_01_overview` / `_build_page_01_entry`)
        # ------------------------------------------------------------------
        def _build_page_01_overview(self, stack: Gtk.Stack) -> None:
            scroll, page = self._make_scrolled_page(
                "1. 入口与语音识别 · 系统概览 (Entry, Offline ASR & Overview)",
                "管理本地离线语音识别 (ASR) 开关、麦克风输入源与 SenseVoice / Whisper 模型一键下载管理，并查看 intentosd 守护进程健康指标。",
            )

            # --------------------------------------------------------------
            # Flagship Card: 🎙️ 本地离线语音识别 (ASR) 与模型下载中心 (`speech_hub`)
            # --------------------------------------------------------------
            card_asr = self._make_card("🎙️ 本地离线语音识别 (ASR) 与模型下载中心 (speech_hub)")
            asr_state: dict[str, Any] = {
                "updating_ui": False,
                "active_model_id": "sensevoice-small-int8",
                "audio_source_ids": ["default"],
                "models": [dict(m) for m in DEFAULT_SPEECH_MODELS_CATALOG],
                "progress_map": {},
                "poll_source_id": 0,
                "test_recording": False,
                "test_timer_id": 0,
            }

            pref_grid = Gtk.Grid(column_spacing=12, row_spacing=8)

            sw_speech_enabled = Gtk.Switch()
            sw_speech_enabled.set_valign(Gtk.Align.CENTER)
            self._page01_speech_switch = sw_speech_enabled

            sw_auto_send = Gtk.Switch()
            sw_auto_send.set_valign(Gtk.Align.CENTER)

            lang_sl = Gtk.StringList.new([lbl for _, lbl in SPEECH_LANGUAGES])
            lang_dd = Gtk.DropDown(model=lang_sl)
            lang_dd.set_hexpand(True)

            mic_sl = Gtk.StringList.new(["系统默认麦克风 (default)"])
            mic_dd = Gtk.DropDown(model=mic_sl)
            mic_dd.set_hexpand(True)

            pref_rows: list[tuple[str, Gtk.Widget]] = [
                ("🎙 开启悬浮窗语音识别输入功能:", sw_speech_enabled),
                ("识别完成后自动发送提问:", sw_auto_send),
                ("识别语言偏好:", lang_dd),
                ("麦克风输入源:", mic_dd),
            ]
            for r_i, (r_lbl_txt, r_widget) in enumerate(pref_rows):
                lbl_w = Gtk.Label(label=r_lbl_txt, xalign=0.0)
                lbl_w.set_hexpand(False)
                pref_grid.attach(lbl_w, 0, r_i, 1, 1)
                if isinstance(r_widget, Gtk.Switch):
                    wrap_h = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                    wrap_h.append(r_widget)
                    hint_w = Gtk.Label(
                        label=(
                            "开启后，随问悬浮窗底部输入框右侧「🎙」按钮可直接语音提问（即时自动保存）"
                            if r_i == 0
                            else "开启后语音识别出文字将直接提交对话；关闭则先填入输入框供您确认修改"
                        ),
                        xalign=0.0,
                    )
                    hint_w.add_css_class("intentos-muted-lbl")
                    hint_w.set_wrap(True)
                    hint_w.set_hexpand(True)
                    wrap_h.append(hint_w)
                    pref_grid.attach(wrap_h, 1, r_i, 1, 1)
                else:
                    pref_grid.attach(r_widget, 1, r_i, 1, 1)
            card_asr.append(pref_grid)

            # Live 3-second Mic Recording & ASR Test Bar
            test_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            btn_test_asr = Gtk.Button(label="🎙 按下试录 3 秒测试识别")
            btn_test_asr.add_css_class("intentos-primary-btn")
            btn_refresh_asr = Gtk.Button(label="↻ 刷新语音与麦克风状态")
            asr_status_lbl = Gtk.Label(label="就绪：下载任一离线模型并开启开关即可在悬浮窗使用语音输入。", xalign=0.0)
            asr_status_lbl.add_css_class("intentos-status-ok")
            asr_status_lbl.set_wrap(True)
            asr_status_lbl.set_hexpand(True)
            test_row.append(btn_test_asr)
            test_row.append(btn_refresh_asr)
            test_row.append(asr_status_lbl)
            card_asr.append(test_row)

            models_hdr = Gtk.Label(
                label="⬇ 离线语音识别模型库（100% 本机离线推理，语音绝不外发云端）：",
                xalign=0.0,
            )
            models_hdr.add_css_class("intentos-section-header")
            card_asr.append(models_hdr)

            asr_models_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            card_asr.append(asr_models_box)
            page.append(card_asr)

            def _collect_speech_config_payload() -> dict[str, Any]:
                l_idx = int(lang_dd.get_selected())
                lang_val = SPEECH_LANGUAGES[l_idx][0] if 0 <= l_idx < len(SPEECH_LANGUAGES) else "zh"
                m_idx = int(mic_dd.get_selected())
                src_ids = asr_state["audio_source_ids"]
                src_val = src_ids[m_idx] if 0 <= m_idx < len(src_ids) else "default"
                return {
                    "enabled": bool(sw_speech_enabled.get_active()),
                    "auto_send_after_transcribe": bool(sw_auto_send.get_active()),
                    "language": lang_val,
                    "audio_source": src_val,
                }

            def _save_speech_prefs_async(extra: dict[str, Any] | None = None) -> None:
                if asr_state["updating_ui"] or self.smoke_mode:
                    return
                payload = _collect_speech_config_payload()
                if extra:
                    payload.update(extra)

                def _w() -> None:
                    msg = ""
                    ov_next: dict[str, Any] | None = None
                    try:
                        res = call_module_rpc("speech_hub", "update_speech_config", payload, timeout=6.0)
                        if res.get("ok"):
                            msg = "✓ 语音识别配置已实时保存"
                            if isinstance(res.get("result"), dict) and "models" in res["result"]:
                                ov_next = res["result"]
                        else:
                            msg = f"⚠ 保存返回: {res.get('error')}"
                    except Exception as exc:
                        msg = f"⚠ 语音配置保存失败: {exc}"

                    def _ui() -> bool:
                        if msg:
                            asr_status_lbl.set_text(msg)
                        if ov_next:
                            _apply_speech_overview_ui(ov_next)
                        return False

                    GLib.idle_add(_ui)

                threading.Thread(target=_w, daemon=True).start()

            def _ensure_download_poller() -> None:
                if self.smoke_mode or asr_state["poll_source_id"]:
                    return
                asr_state["poll_source_id"] = GLib.timeout_add(450, _poll_download_progress_tick)

            def _stop_download_poller() -> None:
                if asr_state["poll_source_id"]:
                    try:
                        GLib.source_remove(asr_state["poll_source_id"])
                    except Exception:
                        pass
                    asr_state["poll_source_id"] = 0

            def _render_asr_model_cards() -> None:
                self._clear_box(asr_models_box)
                active_mid = str(asr_state.get("active_model_id") or "")
                prog_map: dict[str, dict[str, Any]] = asr_state.get("progress_map") or {}
                models_list: list[dict[str, Any]] = asr_state.get("models") or []
                self._page01_asr_models_count = len(models_list)

                for m in models_list:
                    if not isinstance(m, dict):
                        continue
                    mid = str(m.get("id") or m.get("model_id") or "")
                    if not mid:
                        continue
                    mname = str(m.get("name") or m.get("title") or mid)
                    badge_txt = str(m.get("badge") or m.get("tier") or "")
                    size_mb = m.get("approx_size_mb") or m.get("size_mb") or 0
                    langs_raw = m.get("languages") or ["zh", "en"]
                    langs_txt = "/".join(str(x) for x in langs_raw) if isinstance(langs_raw, list) else str(langs_raw)

                    p_info = prog_map.get(mid) or (m.get("download_progress") if isinstance(m.get("download_progress"), dict) else {}) or {}
                    p_status = str(p_info.get("status") or m.get("status") or "")
                    is_installed = bool(m.get("installed")) or p_status == "installed"
                    is_downloading = p_status in ("downloading", "starting", "in_progress", "verifying", "extracting") or bool(m.get("downloading"))
                    pct = float(p_info.get("percent") if p_info.get("percent") is not None else (m.get("progress_pct") or 0.0))
                    speed_mbps = p_info.get("speed_mbps") or p_info.get("speed_mb_s")

                    m_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
                    m_card.add_css_class("intentos-asr-card")

                    top_r = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                    t_lbl = Gtk.Label(label=mname, xalign=0.0)
                    t_lbl.add_css_class("intentos-section-header")
                    top_r.append(t_lbl)

                    if badge_txt:
                        b_pill = Gtk.Label(label=badge_txt)
                        b_pill.add_css_class("intentos-badge-pill")
                        top_r.append(b_pill)

                    meta_lbl = Gtk.Label(label=f"~{size_mb} MB · 语种: {langs_txt}", xalign=0.0)
                    meta_lbl.add_css_class("intentos-muted-lbl")
                    meta_lbl.set_hexpand(True)
                    top_r.append(meta_lbl)

                    if is_downloading:
                        spd_str = f" · {float(speed_mbps):.1f} MB/s" if speed_mbps else ""
                        st_text = f"⬇ 下载中 {pct:.0f}%{spd_str}"
                        st_cls = "intentos-badge-pill"
                    elif is_installed:
                        st_text = "✓ 已安装 · 当前模型" if mid == active_mid else "✓ 已安装"
                        st_cls = "intentos-badge-running"
                    else:
                        st_text = "未安装"
                        st_cls = "intentos-badge-source"

                    st_pill = Gtk.Label(label=st_text)
                    st_pill.add_css_class(st_cls)
                    top_r.append(st_pill)
                    m_card.append(top_r)

                    pbar = Gtk.ProgressBar()
                    pbar.set_show_text(True)
                    pbar.set_hexpand(True)
                    if is_downloading:
                        pbar.set_fraction(max(0.0, min(1.0, pct / 100.0)))
                        pbar.set_text(st_text)
                        pbar.set_visible(True)
                    elif is_installed:
                        pbar.set_fraction(1.0)
                        pbar.set_text("100% 本地模型就绪")
                        pbar.set_visible(False)
                    else:
                        pbar.set_fraction(0.0)
                        pbar.set_visible(False)
                    m_card.append(pbar)

                    act_r = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                    if is_downloading:
                        b_cancel = Gtk.Button(label="⏹ 取消下载")
                        b_cancel.add_css_class("intentos-danger-btn")
                        b_cancel.connect("clicked", lambda _b, model_id=mid: _on_cancel_model_dl(model_id))
                        act_r.append(b_cancel)
                    elif is_installed:
                        b_use = Gtk.Button(label="✓ 当前使用中" if mid == active_mid else "✓ 设为当前模型")
                        if mid != active_mid:
                            b_use.add_css_class("intentos-primary-btn")
                        else:
                            b_use.set_sensitive(False)
                        b_use.connect("clicked", lambda _b, model_id=mid: _on_set_active_asr_model(model_id))
                        b_del = Gtk.Button(label="🗑 删除")
                        b_del.connect("clicked", lambda _b, model_id=mid: _on_delete_asr_model(model_id))
                        act_r.append(b_use)
                        act_r.append(b_del)
                    else:
                        b_dl = Gtk.Button(label="⬇ 下载模型")
                        b_dl.add_css_class("intentos-primary-btn")
                        b_dl.connect("clicked", lambda _b, model_id=mid: _on_start_model_dl(model_id))
                        act_r.append(b_dl)

                    m_card.append(act_r)
                    asr_models_box.append(m_card)

            def _apply_speech_overview_ui(ov: dict[str, Any]) -> None:
                asr_state["updating_ui"] = True
                try:
                    cfg = ov.get("config") if isinstance(ov.get("config"), dict) else {}
                    en_val = bool(cfg.get("enabled") if "enabled" in cfg else ov.get("enabled", False))
                    auto_val = bool(
                        cfg.get("auto_send_after_transcribe")
                        if "auto_send_after_transcribe" in cfg
                        else ov.get("auto_send_after_transcribe", False)
                    )
                    lang_val = str(cfg.get("language") or ov.get("language") or "zh")
                    src_val = str(cfg.get("audio_source") or ov.get("audio_source") or "default")
                    act_mid = str(cfg.get("active_model_id") or ov.get("active_model_id") or "sensevoice-small-int8")
                    asr_state["active_model_id"] = act_mid

                    sw_speech_enabled.set_active(en_val)
                    sw_auto_send.set_active(auto_val)

                    l_idx = next((i for i, (lid, _) in enumerate(SPEECH_LANGUAGES) if lid == lang_val), 0)
                    lang_dd.set_selected(l_idx)

                    raw_sources = ov.get("audio_sources")
                    src_ids: list[str] = []
                    src_labels: list[str] = []
                    if isinstance(raw_sources, list) and raw_sources:
                        for s_item in raw_sources:
                            if isinstance(s_item, dict):
                                sid = str(s_item.get("id") or s_item.get("name") or "default")
                                slbl = str(s_item.get("label") or s_item.get("description") or sid)
                            else:
                                sid = str(s_item)
                                slbl = sid
                            if sid not in src_ids:
                                src_ids.append(sid)
                                src_labels.append(slbl)
                    if "default" not in src_ids:
                        src_ids.insert(0, "default")
                        src_labels.insert(0, "系统默认麦克风 (default)")
                    asr_state["audio_source_ids"] = src_ids
                    mic_dd.set_model(Gtk.StringList.new(src_labels))
                    s_idx = src_ids.index(src_val) if src_val in src_ids else 0
                    mic_dd.set_selected(s_idx)

                    raw_models = ov.get("models")
                    if isinstance(raw_models, list) and raw_models:
                        asr_state["models"] = [m for m in raw_models if isinstance(m, dict)]

                    raw_dl = ov.get("downloads") or ov.get("active_downloads")
                    if isinstance(raw_dl, dict):
                        asr_state["progress_map"] = raw_dl

                    _render_asr_model_cards()
                    any_dl = any(
                        str((asr_state["progress_map"].get(str(m.get("id"))) or {}).get("status") or m.get("status") or "")
                        in ("downloading", "starting", "in_progress", "verifying", "extracting")
                        or bool(m.get("downloading"))
                        for m in asr_state["models"]
                    )
                    if any_dl:
                        _ensure_download_poller()
                finally:
                    asr_state["updating_ui"] = False

            def _load_speech_overview_async() -> None:
                if self.smoke_mode:
                    _apply_speech_overview_ui(
                        {
                            "config": {
                                "enabled": True,
                                "active_model_id": "sensevoice-small-int8",
                                "language": "zh",
                                "audio_source": "default",
                                "auto_send_after_transcribe": False,
                            },
                            "audio_sources": [
                                {"id": "default", "label": "系统默认麦克风 (PipeWire Default)"},
                            ],
                            "models": [
                                {**DEFAULT_SPEECH_MODELS_CATALOG[0], "installed": True, "status": "installed"},
                                *DEFAULT_SPEECH_MODELS_CATALOG[1:],
                            ],
                        }
                    )
                    return

                def _w() -> None:
                    try:
                        res = call_module_rpc("speech_hub", "get_speech_overview", {}, timeout=6.0)
                        if res.get("ok") and isinstance(res.get("result"), dict):
                            GLib.idle_add(lambda r=res["result"]: (_apply_speech_overview_ui(r), False)[1])
                    except Exception as exc:
                        GLib.idle_add(lambda e=str(exc): (asr_status_lbl.set_text(f"读取 speech_hub 状态失败: {e}"), False)[1])

                threading.Thread(target=_w, daemon=True).start()

            def _poll_download_progress_tick() -> bool:
                if self.smoke_mode or (self.win is not None and not self.win.get_visible()):
                    asr_state["poll_source_id"] = 0
                    return False

                def _w() -> None:
                    prog_data: dict[str, Any] = {}
                    ov_refresh: dict[str, Any] | None = None
                    try:
                        res = call_module_rpc("speech_hub", "get_download_progress", {}, timeout=4.0)
                        if res.get("ok") and isinstance(res.get("result"), dict):
                            prog_data = res["result"]
                            downloads = prog_data.get("downloads") if isinstance(prog_data.get("downloads"), dict) else prog_data
                            still_active = False
                            just_completed = False
                            clean_map: dict[str, dict[str, Any]] = {}
                            for k, v in downloads.items():
                                if isinstance(v, dict):
                                    clean_map[str(k)] = v
                                    st = str(v.get("status") or "")
                                    if st in ("downloading", "starting", "in_progress", "verifying", "extracting"):
                                        still_active = True
                                    elif st in ("installed", "completed", "done"):
                                        just_completed = True
                            if just_completed or not still_active:
                                ov_r = call_module_rpc("speech_hub", "get_speech_overview", {}, timeout=5.0)
                                if ov_r.get("ok") and isinstance(ov_r.get("result"), dict):
                                    ov_refresh = ov_r["result"]

                            def _ui_prog() -> bool:
                                asr_state["progress_map"] = clean_map
                                if ov_refresh is not None:
                                    _apply_speech_overview_ui(ov_refresh)
                                else:
                                    _render_asr_model_cards()
                                if not still_active:
                                    _stop_download_poller()
                                return False

                            GLib.idle_add(_ui_prog)
                    except Exception:
                        pass

                threading.Thread(target=_w, daemon=True).start()
                return True

            def _on_start_model_dl(model_id: str) -> None:
                asr_state["progress_map"][model_id] = {"status": "downloading", "percent": 1.0}
                _render_asr_model_cards()
                asr_status_lbl.set_text(f"⬇ 已启动离线语音模型下载: {model_id} …")
                if self.smoke_mode:
                    return
                _ensure_download_poller()

                def _w() -> None:
                    try:
                        res = call_module_rpc("speech_hub", "download_model", {"model_id": model_id}, timeout=12.0)
                        if not res.get("ok"):
                            err = str(res.get("error") or "下载请求失败")
                            GLib.idle_add(lambda m=err: (asr_status_lbl.set_text(f"✕ 下载未启动: {m}"), False)[1])
                    except Exception as exc:
                        GLib.idle_add(lambda m=str(exc): (asr_status_lbl.set_text(f"✕ 下载异常: {m}"), False)[1])

                threading.Thread(target=_w, daemon=True).start()

            def _on_cancel_model_dl(model_id: str) -> None:
                asr_state["progress_map"].pop(model_id, None)
                asr_status_lbl.set_text(f"⏹ 正在取消下载: {model_id}")
                if self.smoke_mode:
                    _render_asr_model_cards()
                    return

                def _w() -> None:
                    try:
                        call_module_rpc("speech_hub", "cancel_download", {"model_id": model_id}, timeout=6.0)
                    except Exception:
                        pass
                    _load_speech_overview_async()

                threading.Thread(target=_w, daemon=True).start()

            def _on_set_active_asr_model(model_id: str) -> None:
                asr_state["active_model_id"] = model_id
                _render_asr_model_cards()
                asr_status_lbl.set_text(f"✓ 已切换当前语音识别模型为: {model_id}")
                _save_speech_prefs_async({"active_model_id": model_id})

            def _on_delete_asr_model(model_id: str) -> None:
                if self.smoke_mode:
                    return

                def _w() -> None:
                    try:
                        res = call_module_rpc("speech_hub", "delete_model", {"model_id": model_id}, timeout=8.0)
                        msg = f"🗑 已删除模型: {model_id}" if res.get("ok") else f"删除返回: {res.get('error')}"
                        GLib.idle_add(lambda m=msg: (asr_status_lbl.set_text(m), False)[1])
                    except Exception as exc:
                        GLib.idle_add(lambda m=str(exc): (asr_status_lbl.set_text(f"删除失败: {m}"), False)[1])
                    _load_speech_overview_async()

                threading.Thread(target=_w, daemon=True).start()

            def _finish_asr_live_test() -> None:
                if asr_state["test_timer_id"]:
                    try:
                        GLib.source_remove(asr_state["test_timer_id"])
                    except Exception:
                        pass
                    asr_state["test_timer_id"] = 0
                if not asr_state["test_recording"]:
                    return
                asr_state["test_recording"] = False
                btn_test_asr.set_label("⏳ 正在离线识别试录语音…")
                btn_test_asr.set_sensitive(False)

                def _w() -> None:
                    msg = ""
                    try:
                        res = call_module_rpc("speech_hub", "stop_and_transcribe", {"test_mode": True}, timeout=25.0)
                        if res.get("ok") and isinstance(res.get("result"), dict):
                            r = res["result"]
                            txt = str(r.get("text") or r.get("transcript") or "").strip()
                            msg = f"✓ 试录识别结果：「{txt or '(未检测到语音)'}」"
                        else:
                            msg = f"⚠ 试录识别未完成：{res.get('error') or '请确认已安装 ASR 模型并连接麦克风'}"
                    except Exception as exc:
                        msg = f"⚠ 试录异常：{exc}"

                    def _done() -> bool:
                        btn_test_asr.set_label("🎙 按下试录 3 秒测试识别")
                        btn_test_asr.set_sensitive(True)
                        asr_status_lbl.set_text(msg)
                        return False

                    GLib.idle_add(_done)

                threading.Thread(target=_w, daemon=True).start()

            def _on_test_asr_clicked(_b: Any) -> None:
                if self.smoke_mode:
                    asr_status_lbl.set_text("✓ [smoke] 试录识别结果：「打开文档目录查找报告」")
                    return
                if asr_state["test_recording"]:
                    _finish_asr_live_test()
                    return
                asr_state["test_recording"] = True
                btn_test_asr.set_label("⏹ 停止并识别 (3 秒自动完成)")
                asr_status_lbl.set_text("🔴 正在试录麦克风语音 (请说话，3 秒后自动识别或点击按钮立即识别)…")

                def _start_w() -> None:
                    err = ""
                    try:
                        res = call_module_rpc("speech_hub", "start_recording", {"test_mode": True}, timeout=8.0)
                        if not res.get("ok"):
                            err = str(res.get("error") or "麦克风未能启动")
                    except Exception as exc:
                        err = str(exc)
                    if err:
                        def _abort_ui() -> bool:
                            asr_state["test_recording"] = False
                            if asr_state["test_timer_id"]:
                                try:
                                    GLib.source_remove(asr_state["test_timer_id"])
                                except Exception:
                                    pass
                                asr_state["test_timer_id"] = 0
                            btn_test_asr.set_label("🎙 按下试录 3 秒测试识别")
                            btn_test_asr.set_sensitive(True)
                            asr_status_lbl.set_text(f"✕ 试录未能启动: {err}")
                            return False

                        GLib.idle_add(_abort_ui)

                threading.Thread(target=_start_w, daemon=True).start()
                asr_state["test_timer_id"] = GLib.timeout_add(
                    3000,
                    lambda: (_finish_asr_live_test(), False)[1],
                )

            sw_speech_enabled.connect("notify::active", lambda _sw, _ps: _save_speech_prefs_async())
            sw_auto_send.connect("notify::active", lambda _sw, _ps: _save_speech_prefs_async())
            lang_dd.connect("notify::selected", lambda _dd, _ps: _save_speech_prefs_async())
            mic_dd.connect("notify::selected", lambda _dd, _ps: _save_speech_prefs_async())
            btn_test_asr.connect("clicked", _on_test_asr_clicked)
            btn_refresh_asr.connect("clicked", lambda _b: _load_speech_overview_async())

            _render_asr_model_cards()
            if isinstance(self.ov.get("speech_hub"), dict) and self.ov["speech_hub"]:
                _apply_speech_overview_ui(self.ov["speech_hub"])
            else:
                _load_speech_overview_async()

            # --------------------------------------------------------------
            # Card 2: 守护进程与资源索引指标
            # --------------------------------------------------------------
            card_stat = self._make_card("守护进程与资源索引指标")
            stat_buf = Gtk.TextBuffer()
            stat_sw, _ = self._make_scrolled_textview(stat_buf, editable=False, min_height=180, vexpand=True)
            card_stat.append(stat_sw)

            btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            refresh_btn = Gtk.Button(label="↻ 刷新健康状态与探测")
            reindex_btn = Gtk.Button(label="⚡ 立即重建全量资源索引")
            reindex_btn.add_css_class("intentos-primary-btn")
            ov_status = Gtk.Label(label="", xalign=0.0)
            btn_row.append(refresh_btn)
            btn_row.append(reindex_btn)
            btn_row.append(ov_status)
            card_stat.append(btn_row)
            page.append(card_stat)

            def load_overview_text() -> None:
                if self.smoke_mode:
                    stat_buf.set_text(json.dumps({"smoke_ui": "ready"}, ensure_ascii=False, indent=2))
                    return
                try:
                    st = call_ui_rpc("get_status", timeout=4.0).get("result", {})
                    pr = call_ui_rpc("probe_capabilities", timeout=4.0).get("result", {})
                    dom_ov = self.domains.get("overview", {})
                    summary = {
                        "daemon_status": st,
                        "sandbox_probe": pr.get("sandbox", {}),
                        "gateway_metrics": pr.get("gateway_metrics", {}),
                        "cli_dependencies": dom_ov.get("cli_dependencies", {}),
                    }
                    stat_buf.set_text(json.dumps(summary, ensure_ascii=False, indent=2))
                except Exception as err:
                    stat_buf.set_text(f"读取状态失败: {err}")

            def on_refresh(_b: Any) -> None:
                self._refresh_state()
                load_overview_text()
                _load_speech_overview_async()
                ov_status.set_text("✓ 已刷新最新状态")

            def on_reindex(_b: Any) -> None:
                try:
                    r = call_ui_rpc("reindex_resources")
                    if r.get("ok"):
                        res = r["result"]
                        ov_status.set_text(f"✓ 重建完成：{res.get('apps', 0)} 应用, {res.get('files', 0)} 文件")
                        load_overview_text()
                except Exception as err:
                    ov_status.set_text(f"重建失败: {err}")

            refresh_btn.connect("clicked", on_refresh)
            reindex_btn.connect("clicked", on_reindex)
            load_overview_text()
            stack.add_titled(scroll, "overview", "1. 入口与语音识别")

        _build_page_01_entry = _build_page_01_overview

        # ------------------------------------------------------------------
        # Page 2: 大脑与网关 (Brain & Live `/v1/models` Model Selector)
        # ------------------------------------------------------------------
        def _build_page_02_brain(self, stack: Gtk.Stack) -> None:
            scroll, page = self._make_scrolled_page(
                "2. 大脑与网关 (Brain & Live /v1/models Selector)",
                "自动探测并实时查询本地与远端 /v1/models 模型列表，一键切换随问与系统活动模型；支持多供应商 CRUD、5 大角色与外发矩阵。",
            )
            brain_ov = self.ov.get("brain", {})
            brain_dom = self.domains.get("brain", brain_ov)

            # Card 0 (TOP): Interactive Live `/v1/models` Active Model Selector
            card_live = self._make_card("✦ 随问与系统活动模型选择器 (自动读取 /v1/models 实时模型库)")
            parsed_cat_holder: dict[str, Any] = {
                "cat": parse_catalog_for_settings(self.ov.get("backend_bridge")),
                "provider_ids": [""],
                "filtered_models": [],  # list[(prov_id, mod_id)]
                "updating": False,
            }

            sel_grid = Gtk.Grid(column_spacing=10, row_spacing=8)

            # 1) Backend DropDown
            backend_sl = Gtk.StringList.new([lbl for _, lbl in BACKEND_OPTIONS])
            backend_dd = Gtk.DropDown(model=backend_sl)
            backend_dd.set_hexpand(True)

            # 2) Provider DropDown
            provider_sl = Gtk.StringList.new(["自动匹配供应商 (0 个模型)"])
            provider_dd = Gtk.DropDown(model=provider_sl)
            provider_dd.set_hexpand(True)

            # 3) Search Entry + Filtered Model DropDown
            model_search_entry = Gtk.Entry(placeholder_text="🔍 搜索或过滤模型 (如 gpt / claude / glm / qwen / deepseek)…")
            model_search_entry.set_hexpand(True)

            model_sl = Gtk.StringList.new(["(点击刷新从 /v1/models 获取全量模型)"])
            model_dd = Gtk.DropDown(model=model_sl)
            model_dd.set_hexpand(True)

            custom_model_entry = Gtk.Entry(placeholder_text="当前选定或自定义输入模型 ID")
            custom_model_entry.set_hexpand(True)

            # 4) Reasoning Effort DropDown
            effort_sl = Gtk.StringList.new([lbl for _, lbl in EFFORT_OPTIONS])
            effort_dd = Gtk.DropDown(model=effort_sl)
            effort_dd.set_hexpand(True)

            selector_rows = [
                ("1. 智能后端引擎:", backend_dd),
                ("2. 已发现供应商与模型源:", provider_dd),
                ("3. 实时模型搜索过滤:", model_search_entry),
                ("4. 选择 /v1/models 模型:", model_dd),
                ("5. 选定模型 ID (可编辑):", custom_model_entry),
                ("6. 推理思考强度:", effort_dd),
            ]
            for r_i, (lbl_txt, w) in enumerate(selector_rows):
                sel_grid.attach(Gtk.Label(label=lbl_txt, xalign=0.0), 0, r_i, 1, 1)
                sel_grid.attach(w, 1, r_i, 1, 1)
            card_live.append(sel_grid)

            # Quick-click scrollable model chips preview
            chips_sw = Gtk.ScrolledWindow(min_content_height=90, hexpand=True)
            chips_sw.set_max_content_height(150)
            chips_sw.set_propagate_natural_height(True)
            chips_sw.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            chips_flow = Gtk.FlowBox()
            chips_flow.set_selection_mode(Gtk.SelectionMode.NONE)
            chips_flow.set_max_children_per_line(4)
            chips_flow.set_column_spacing(6)
            chips_flow.set_row_spacing(6)
            chips_sw.set_child(chips_flow)
            card_live.append(chips_sw)

            live_btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            btn_refresh_live = Gtk.Button(label="🔄 从接口刷新全量模型 (/v1/models)")
            btn_set_active = Gtk.Button(label="✓ 设为当前活动模型")
            btn_set_active.add_css_class("intentos-primary-btn")
            live_status_lbl = Gtk.Label(label="", xalign=0.0)
            live_status_lbl.add_css_class("intentos-status-ok")
            live_status_lbl.set_wrap(True)
            live_status_lbl.set_hexpand(True)
            live_btn_row.append(btn_refresh_live)
            live_btn_row.append(btn_set_active)
            live_btn_row.append(live_status_lbl)
            card_live.append(live_btn_row)
            page.append(card_live)

            bb_buf = Gtk.TextBuffer()

            def _current_backend_id() -> str:
                idx = int(backend_dd.get_selected())
                if 0 <= idx < len(BACKEND_OPTIONS):
                    return BACKEND_OPTIONS[idx][0]
                return "auto"

            def _current_effort_id() -> str:
                idx = int(effort_dd.get_selected())
                if 0 <= idx < len(EFFORT_OPTIONS):
                    return EFFORT_OPTIONS[idx][0]
                return "default"

            def _current_provider_id() -> str:
                pids = parsed_cat_holder["provider_ids"]
                idx = int(provider_dd.get_selected())
                if 0 <= idx < len(pids):
                    return pids[idx]
                return ""

            def _repopulate_models_for_filter() -> None:
                parsed_cat_holder["updating"] = True
                try:
                    cat = parsed_cat_holder["cat"]
                    bid = _current_backend_id()
                    binfo = cat.get("backends", {}).get(bid, {})
                    sel_pid = _current_provider_id()
                    q = model_search_entry.get_text().strip().lower()

                    candidates: list[tuple[str, str]] = []
                    if sel_pid:
                        for p in binfo.get("providers") or []:
                            if p.get("id") == sel_pid:
                                for mid in p.get("models") or []:
                                    candidates.append((sel_pid, mid))
                    if not candidates:
                        candidates = list(binfo.get("models") or [])

                    filtered = [
                        (pid, mid)
                        for pid, mid in candidates
                        if not q or q in mid.lower() or q in pid.lower()
                    ]
                    parsed_cat_holder["filtered_models"] = filtered

                    if filtered:
                        labels = [f"{mid}  [{pid}]" if pid else mid for pid, mid in filtered]
                        model_sl.splice(0, model_sl.get_n_items(), labels)
                        cur_txt = custom_model_entry.get_text().strip()
                        match_idx = next((i for i, (_, m) in enumerate(filtered) if m == cur_txt), 0)
                        model_dd.set_selected(match_idx)
                        if not cur_txt:
                            custom_model_entry.set_text(filtered[match_idx][1])
                    else:
                        model_sl.splice(0, model_sl.get_n_items(), ["(无匹配模型 — 可点击上方刷新或直接输入)"])
                        model_dd.set_selected(0)

                    self._clear_flowbox(chips_flow)
                    for pid, mid in filtered[:48]:
                        cb = Gtk.Button(label=mid if len(mid) <= 24 else mid[:22] + "…")
                        if mid == custom_model_entry.get_text().strip():
                            cb.add_css_class("intentos-mode-active")
                        cb.set_tooltip_text(f"{pid} / {mid}" if pid else mid)
                        cb.connect(
                            "clicked",
                            lambda _b, p_val=pid, m_val=mid: (
                                custom_model_entry.set_text(m_val),
                                _repopulate_models_for_filter(),
                            ),
                        )
                        chips_flow.append(cb)
                    chips_sw.set_visible(len(filtered) > 0)
                finally:
                    parsed_cat_holder["updating"] = False

            def _repopulate_providers_and_models() -> None:
                parsed_cat_holder["updating"] = True
                try:
                    cat = parsed_cat_holder["cat"]
                    bid = _current_backend_id()
                    binfo = cat.get("backends", {}).get(bid, {})
                    provs = binfo.get("providers") or []
                    pids = [""]
                    plabels = [f"全部已发现供应商 (共 {len(binfo.get('models') or [])} 个模型)"]
                    for p in provs:
                        pid = p["id"]
                        live_tag = "实时 /v1/models" if p.get("live_models_fetched") else p.get("source", "配置")
                        burl = f" · {p['base_url']}" if p.get("base_url") else ""
                        pids.append(pid)
                        plabels.append(f"{p['name']} ({pid}){burl} [{live_tag}: {len(p.get('models') or [])} 个]")
                    parsed_cat_holder["provider_ids"] = pids
                    provider_sl.splice(0, provider_sl.get_n_items(), plabels)

                    act_prov = cat.get("active", {}).get("provider", "")
                    sel_p_idx = pids.index(act_prov) if act_prov in pids else 0
                    provider_dd.set_selected(sel_p_idx)
                finally:
                    parsed_cat_holder["updating"] = False
                _repopulate_models_for_filter()

            def _apply_raw_catalog(raw_cat: dict[str, Any], from_refresh: bool = False) -> bool:
                bb_buf.set_text(json.dumps(raw_cat, ensure_ascii=False, indent=2))
                cat = parse_catalog_for_settings(raw_cat)
                parsed_cat_holder["cat"] = cat
                act = cat.get("active", {})

                parsed_cat_holder["updating"] = True
                try:
                    b_ids = [b for b, _ in BACKEND_OPTIONS]
                    if act.get("backend") in b_ids:
                        backend_dd.set_selected(b_ids.index(act["backend"]))
                    e_ids = [e for e, _ in EFFORT_OPTIONS]
                    if act.get("reasoning_effort") in e_ids:
                        effort_dd.set_selected(e_ids.index(act["reasoning_effort"]))
                    if act.get("model"):
                        custom_model_entry.set_text(act["model"])
                finally:
                    parsed_cat_holder["updating"] = False

                _repopulate_providers_and_models()
                total_m = len(cat.get("backends", {}).get(_current_backend_id(), {}).get("models") or [])
                prefix = "✓ 已从 /v1/models 实时刷新" if from_refresh else "✓ 已自动读取模型目录"
                live_status_lbl.set_text(
                    f"{prefix}：当前引擎共 {total_m} 个可选模型 · 活动模型 `{act.get('model') or '默认'}`"
                )
                return False

            def _on_backend_dd_changed(_dd: Any, _pspec: Any) -> None:
                if not parsed_cat_holder["updating"]:
                    _repopulate_providers_and_models()

            def _on_provider_dd_changed(_dd: Any, _pspec: Any) -> None:
                if not parsed_cat_holder["updating"]:
                    _repopulate_models_for_filter()

            def _on_model_dd_changed(_dd: Any, _pspec: Any) -> None:
                if parsed_cat_holder["updating"]:
                    return
                idx = int(model_dd.get_selected())
                fmodels = parsed_cat_holder["filtered_models"]
                if 0 <= idx < len(fmodels):
                    custom_model_entry.set_text(fmodels[idx][1])

            backend_dd.connect("notify::selected", _on_backend_dd_changed)
            provider_dd.connect("notify::selected", _on_provider_dd_changed)
            model_dd.connect("notify::selected", _on_model_dd_changed)
            model_search_entry.connect("changed", lambda _e: _repopulate_models_for_filter())

            def _trigger_live_catalog_fetch(force_refresh: bool) -> None:
                if self.smoke_mode:
                    _apply_raw_catalog(
                        {
                            "active": {
                                "backend": "zcode",
                                "provider": "openai",
                                "model": "gpt-6.1-sol",
                                "reasoning_effort": "default",
                            },
                            "backends": {
                                "zcode": {
                                    "available": True,
                                    "providers": [
                                        {
                                            "id": "openai",
                                            "name": "Local V1 Proxy",
                                            "base_url": "http://localhost:8317/v1",
                                            "live_models_fetched": True,
                                            "models": ["gpt-6.1-sol", "gpt-6-astra", "claude-4-sonnet", "glm-5.3"],
                                        }
                                    ],
                                }
                            },
                        },
                        from_refresh=force_refresh,
                    )
                    return

                live_status_lbl.set_text("正在查询各供应商 /v1/models 接口…")

                def _worker() -> None:
                    raw_res: dict[str, Any] | None = None
                    if force_refresh:
                        try:
                            r1 = call_module_rpc(
                                "backend_bridge", "refresh_models", {"force_refresh": True}, timeout=10.0
                            )
                            if r1.get("ok") and isinstance(r1.get("result"), dict):
                                raw_res = r1["result"]
                        except Exception:
                            raw_res = None
                    if raw_res is None:
                        try:
                            r2 = call_module_rpc(
                                "backend_bridge",
                                "get_backends_catalog",
                                {"refresh_remote": True, "force_refresh": force_refresh},
                                timeout=10.0,
                            )
                            if r2.get("ok") and isinstance(r2.get("result"), dict):
                                raw_res = r2["result"]
                        except Exception as err:
                            GLib.idle_add(live_status_lbl.set_text, f"模型接口读取失败: {err}")
                            return
                    if raw_res is not None:
                        GLib.idle_add(_apply_raw_catalog, raw_res, force_refresh)

                threading.Thread(target=_worker, daemon=True).start()

            def _on_set_active_model(_b: Any) -> None:
                bid = _current_backend_id()
                pid = _current_provider_id()
                fmodels = parsed_cat_holder["filtered_models"]
                sel_idx = int(model_dd.get_selected())
                if not pid and 0 <= sel_idx < len(fmodels):
                    pid = fmodels[sel_idx][0]
                mid = custom_model_entry.get_text().strip()
                eff = _current_effort_id()
                payload = {
                    "backend": bid,
                    "provider": pid,
                    "model": mid,
                    "reasoning_effort": eff,
                }
                try:
                    res = call_module_rpc("backend_bridge", "set_active_backend", payload, timeout=8.0)
                    if mid:
                        try:
                            call_ui_rpc(
                                "update_brain_settings",
                                {
                                    "runtime": str(brain_ov.get("runtime", "pi")),
                                    "main_provider": pid or "default-openai",
                                    "main_model": mid,
                                },
                                timeout=5.0,
                            )
                        except Exception:
                            pass
                    if res.get("ok"):
                        live_status_lbl.set_text(f"✓ 已设为活动模型：{bid} · {pid + '/' if pid else ''}{mid} ({eff})")
                    else:
                        live_status_lbl.set_text(f"设置返回: {res.get('error')}")
                except Exception as err:
                    live_status_lbl.set_text(f"保存失败: {err}")

            btn_refresh_live.connect("clicked", lambda _b: _trigger_live_catalog_fetch(True))
            btn_set_active.connect("clicked", _on_set_active_model)
            self._page02_search_entry = model_search_entry

            # Card A: Multi-Provider CRUD + Connection Test & Tool Test
            card_prov = self._make_card("A. 供应商管理与连接/工具能力检测 (B-01 ~ B-04)")
            grid_p = Gtk.Grid(column_spacing=10, row_spacing=6)

            prov_id_entry = Gtk.Entry(text="default-openai")
            prov_name_entry = Gtk.Entry(text="OpenAI Compatible Proxy")
            prov_kind_entry = Gtk.Entry(text="openai-compatible")
            prov_url_entry = Gtk.Entry(text="http://127.0.0.1:8317/v1")
            prov_trust_entry = Gtk.Entry(text="trusted")
            prov_key_entry = Gtk.Entry()
            prov_key_entry.set_visibility(False)
            prov_key_entry.set_placeholder_text("sk-...（安全存入 Secret Service / 0600 凭据槽，绝不写入 TOML）")

            providers_list = brain_dom.get("providers") or brain_ov.get("providers") or []
            if providers_list and isinstance(providers_list[0], dict):
                p0 = providers_list[0]
                prov_id_entry.set_text(str(p0.get("id", "default-openai")))
                prov_name_entry.set_text(str(p0.get("name", p0.get("id", ""))))
                prov_kind_entry.set_text(str(p0.get("kind", "openai-compatible")))
                prov_url_entry.set_text(str(p0.get("base_url", "http://127.0.0.1:8317/v1")))
                prov_trust_entry.set_text(str(p0.get("trust", "trusted")))

            fields_p = [
                ("供应商 ID:", prov_id_entry),
                ("显示名称:", prov_name_entry),
                ("协议类型 (openai-compatible/anthropic/gemini/ollama-local):", prov_kind_entry),
                ("Base URL:", prov_url_entry),
                ("信任等级 (trusted / standard / untrusted):", prov_trust_entry),
                ("API Key 凭据 (仅走安全存储):", prov_key_entry),
            ]
            for r_idx, (lbl_txt, widget) in enumerate(fields_p):
                grid_p.attach(Gtk.Label(label=lbl_txt, xalign=0.0), 0, r_idx, 1, 1)
                widget.set_hexpand(True)
                grid_p.attach(widget, 1, r_idx, 1, 1)
            card_prov.append(grid_p)

            prov_btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            btn_save_prov = Gtk.Button(label="💾 保存/更新供应商")
            btn_test_conn = Gtk.Button(label="🔌 测试连接 (B-03)")
            btn_test_tools = Gtk.Button(label="🛠 测试工具调用 (B-04)")
            btn_del_prov = Gtk.Button(label="🗑 删除供应商")
            prov_btn_row.append(btn_save_prov)
            prov_btn_row.append(btn_test_conn)
            prov_btn_row.append(btn_test_tools)
            prov_btn_row.append(btn_del_prov)
            card_prov.append(prov_btn_row)

            prov_status = Gtk.Label(label="", xalign=0.0)
            prov_status.set_wrap(True)
            card_prov.append(prov_status)
            page.append(card_prov)

            def on_save_provider(_b: Any) -> None:
                res = call_module_rpc(
                    "config_center",
                    "upsert_provider",
                    {
                        "provider": {
                            "id": prov_id_entry.get_text().strip(),
                            "name": prov_name_entry.get_text().strip(),
                            "kind": prov_kind_entry.get_text().strip(),
                            "base_url": prov_url_entry.get_text().strip(),
                            "trust": prov_trust_entry.get_text().strip(),
                            "enabled": True,
                        },
                        "api_key": prov_key_entry.get_text().strip() or None,
                    },
                )
                if res.get("ok"):
                    prov_status.set_text(f"✓ 供应商 `{prov_id_entry.get_text()}` 已保存（API Key 未写入明文配置）")
                    _trigger_live_catalog_fetch(True)
                else:
                    prov_status.set_text(f"保存状态: {res.get('error')}")

            def on_test_conn(_b: Any) -> None:
                pid = prov_id_entry.get_text().strip()
                res = call_module_rpc("config_center", "test_provider_connection", {"provider_id": pid})
                if res.get("ok"):
                    r = res["result"]
                    prov_status.set_text(
                        f"🔌 连接测试 [{r.get('status', 'ok')}]: 延迟 {r.get('latency_ms', 0)} ms — {r.get('message', '')}"
                    )
                else:
                    prov_status.set_text(f"连接测试失败: {res.get('error')}")

            def on_test_tools(_b: Any) -> None:
                pid = prov_id_entry.get_text().strip()
                target_m = custom_model_entry.get_text().strip() or "gpt-4o-mini"
                res = call_module_rpc(
                    "config_center",
                    "test_provider_tools",
                    {"provider_id": pid, "model": target_m},
                )
                if res.get("ok"):
                    r = res["result"]
                    prov_status.set_text(
                        f"🛠 工具调用实测: supported={r.get('supported')} · {r.get('latency_ms', 0)} ms — {r.get('details', '')}"
                    )
                else:
                    prov_status.set_text(f"工具测试失败: {res.get('error')}")

            def on_del_prov(_b: Any) -> None:
                pid = prov_id_entry.get_text().strip()
                res = call_module_rpc("config_center", "delete_provider", {"provider_id": pid})
                prov_status.set_text(
                    f"✓ 已删除供应商 {pid}" if res.get("ok") else f"无法删除: {res.get('error')}"
                )

            btn_save_prov.connect("clicked", on_save_provider)
            btn_test_conn.connect("clicked", on_test_conn)
            btn_test_tools.connect("clicked", on_test_tools)
            btn_del_prov.connect("clicked", on_del_prov)

            # Card B: 5 Model Roles
            card_roles = self._make_card("B. 5 大模型角色与推理参数 (B-05 & B-06)")
            roles_grid = Gtk.Grid(column_spacing=8, row_spacing=6)
            for col_i, h_txt in enumerate(["角色", "供应商 ID", "模型 ID", "上下文预算", "思考强度 (off/low/medium/high)", "温度"]):
                roles_grid.attach(Gtk.Label(label=h_txt, xalign=0.0), col_i, 0, 1, 1)

            profiles_cfg = brain_dom.get("profiles") or brain_ov.get("profiles") or {}
            role_inputs: dict[str, dict[str, Gtk.Entry]] = {}
            for row_i, (role_key, role_label) in enumerate(MODEL_ROLES, start=1):
                rcfg = profiles_cfg.get(role_key, {}) if isinstance(profiles_cfg, dict) else {}
                e_prov = Gtk.Entry(text=str(rcfg.get("provider", "default-openai")))
                e_model = Gtk.Entry(text=str(rcfg.get("model", "gpt-4o-mini")))
                e_ctx = Gtk.Entry(text=str(rcfg.get("context_budget", 65536)))
                e_think = Gtk.Entry(text=str(rcfg.get("thinking", "medium" if role_key == "main" else "off")))
                e_temp = Gtk.Entry(text=str(rcfg.get("temperature", 0.2)))
                role_inputs[role_key] = {
                    "provider": e_prov,
                    "model": e_model,
                    "context_budget": e_ctx,
                    "thinking": e_think,
                    "temperature": e_temp,
                }
                roles_grid.attach(Gtk.Label(label=role_label, xalign=0.0), 0, row_i, 1, 1)
                roles_grid.attach(e_prov, 1, row_i, 1, 1)
                roles_grid.attach(e_model, 2, row_i, 1, 1)
                roles_grid.attach(e_ctx, 3, row_i, 1, 1)
                roles_grid.attach(e_think, 4, row_i, 1, 1)
                roles_grid.attach(e_temp, 5, row_i, 1, 1)
            card_roles.append(roles_grid)

            save_roles_btn = Gtk.Button(label="💾 保存 5 大模型角色配置")
            roles_status = Gtk.Label(label="", xalign=0.0)

            def on_save_roles(_b: Any) -> None:
                payload_profiles: dict[str, Any] = {}
                for r_key, widgets in role_inputs.items():
                    payload_profiles[r_key] = {
                        "provider": widgets["provider"].get_text().strip(),
                        "model": widgets["model"].get_text().strip(),
                        "context_budget": int(widgets["context_budget"].get_text().strip() or "65536"),
                        "max_output_tokens": 4096,
                        "thinking": widgets["thinking"].get_text().strip() or "off",
                        "temperature": float(widgets["temperature"].get_text().strip() or "0.2"),
                    }
                res = call_module_rpc("config_center", "update_model_profiles", {"profiles": payload_profiles})
                main_w = role_inputs["main"]
                call_ui_rpc(
                    "update_brain_settings",
                    {
                        "runtime": str(brain_ov.get("runtime", "pi")),
                        "main_provider": main_w["provider"].get_text().strip(),
                        "main_model": main_w["model"].get_text().strip(),
                    },
                )
                roles_status.set_text(
                    "✓ 已保存 5 大模型角色及 brain.toml" if res.get("ok") else "✓ 已通过兼容通道更新主角色模型"
                )

            save_roles_btn.connect("clicked", on_save_roles)
            card_roles.append(save_roles_btn)
            card_roles.append(roles_status)
            page.append(card_roles)

            # Card C: Egress Matrix Grid
            card_egress = self._make_card("C. 数据外发矩阵 (DataClass × ProviderTrust，§5.4 B-10)")
            eg_grid = Gtk.Grid(column_spacing=12, row_spacing=6)
            eg_grid.attach(Gtk.Label(label="数据分级 \\ 信任等级", xalign=0.0), 0, 0, 1, 1)
            for c_i, trust_lvl in enumerate(PROVIDER_TRUSTS, start=1):
                eg_grid.attach(Gtk.Label(label=trust_lvl.upper(), xalign=0.0), c_i, 0, 1, 1)

            default_matrix = {
                "public": {"trusted": "allow", "standard": "allow", "untrusted": "allow"},
                "personal": {"trusted": "allow", "standard": "allow", "untrusted": "confirm"},
                "sensitive": {"trusted": "confirm", "standard": "deny", "untrusted": "deny"},
                "forbidden": {"trusted": "deny", "standard": "deny", "untrusted": "deny"},
            }
            eg_entries: dict[tuple[str, str], Gtk.Entry] = {}
            for r_i, d_cls in enumerate(DATA_CLASSES, start=1):
                eg_grid.attach(Gtk.Label(label=d_cls, xalign=0.0), 0, r_i, 1, 1)
                for c_i, t_lvl in enumerate(PROVIDER_TRUSTS, start=1):
                    val = default_matrix[d_cls][t_lvl]
                    ent = Gtk.Entry(text=val)
                    if d_cls == "forbidden":
                        ent.set_editable(False)
                    eg_entries[(d_cls, t_lvl)] = ent
                    eg_grid.attach(ent, c_i, r_i, 1, 1)
            card_egress.append(eg_grid)

            sens_entry = Gtk.Entry(text="~/Private, ~/.config/secret")
            card_egress.append(Gtk.Label(label="用户标记敏感目录 (逗号分隔):", xalign=0.0))
            card_egress.append(sens_entry)
            card_egress.append(
                Gtk.Label(
                    label="永不外发硬性锁定规则 (Forbidden): ~/.ssh, ~/.gnupg, Secret Service 密钥环, 浏览器 Cookie",
                    xalign=0.0,
                )
            )
            save_eg_btn = Gtk.Button(label="💾 保存外发矩阵策略")
            eg_status = Gtk.Label(label="", xalign=0.0)

            def on_save_egress(_b: Any) -> None:
                matrix_payload: dict[str, dict[str, str]] = {}
                for (dc, tl), ent in eg_entries.items():
                    matrix_payload.setdefault(dc, {})[tl] = "deny" if dc == "forbidden" else ent.get_text().strip()
                sens_dirs = [x.strip() for x in sens_entry.get_text().split(",") if x.strip()]
                res = call_module_rpc(
                    "config_center",
                    "update_egress_matrix",
                    {"matrix": matrix_payload, "sensitive_directories": sens_dirs},
                )
                eg_status.set_text(
                    "✓ 外发矩阵已保存（Forbidden 强制锁定为 deny）"
                    if res.get("ok")
                    else f"结果: {res.get('error')}"
                )

            save_eg_btn.connect("clicked", on_save_egress)
            card_egress.append(save_eg_btn)
            card_egress.append(eg_status)
            page.append(card_egress)

            # Card D: Runtime & Budgets
            card_rt = self._make_card("D. Agent Runtime 与调用预算限制 (B-07 ~ B-09)")
            rt_limits = brain_ov.get("runtime_limits", {})
            rt_grid = Gtk.Grid(column_spacing=10, row_spacing=6)
            e_rt_mode = Gtk.Entry(text=str(brain_ov.get("runtime", "pi")))
            e_max_tools = Gtk.Entry(text=str(rt_limits.get("max_tool_calls", 30)))
            e_max_secs = Gtk.Entry(text=str(rt_limits.get("max_runtime_seconds", 180)))
            e_max_conc = Gtk.Entry(text=str(rt_limits.get("max_concurrent_sessions", 2)))
            e_daily_cost = Gtk.Entry(text=str(rt_limits.get("daily_cost_limit", 0.0)))
            for idx, (lbl, w) in enumerate(
                [
                    ("Agent Runtime 类型 (pi / native):", e_rt_mode),
                    ("单任务最大工具调用次数 (max_tool_calls):", e_max_tools),
                    ("单任务最大运行秒数 (max_runtime_seconds):", e_max_secs),
                    ("最大并发会话数 (max_concurrent_sessions):", e_max_conc),
                    ("每日预算上限 USD (0=不限):", e_daily_cost),
                ]
            ):
                rt_grid.attach(Gtk.Label(label=lbl, xalign=0.0), 0, idx, 1, 1)
                rt_grid.attach(w, 1, idx, 1, 1)
            card_rt.append(rt_grid)
            save_rt_btn = Gtk.Button(label="💾 保存运行时与预算")
            rt_status = Gtk.Label(label="", xalign=0.0)

            def on_save_rt(_b: Any) -> None:
                call_module_rpc(
                    "config_center",
                    "update_domain",
                    {
                        "domain_key": "brain",
                        "data": {
                            "runtime": e_rt_mode.get_text().strip(),
                            "runtime_limits": {
                                "max_tool_calls": int(e_max_tools.get_text().strip() or "30"),
                                "max_runtime_seconds": int(e_max_secs.get_text().strip() or "180"),
                                "max_concurrent_sessions": int(e_max_conc.get_text().strip() or "2"),
                                "daily_cost_limit": float(e_daily_cost.get_text().strip() or "0"),
                            },
                        },
                    },
                )
                rt_status.set_text("✓ 运行时与预算参数已保存")

            save_rt_btn.connect("clicked", on_save_rt)
            card_rt.append(save_rt_btn)
            card_rt.append(rt_status)
            page.append(card_rt)

            # Card E: Raw Diagnostic Catalog in GTK4-safe ScrolledWindow
            card_bb = self._make_card("E. 多后端探测诊断明细 (backend_bridge 脱敏 JSON)")
            bb_sw, _ = self._make_scrolled_textview(bb_buf, editable=False, min_height=140)
            card_bb.append(bb_sw)
            page.append(card_bb)

            # Auto-load live `/v1/models` on open!
            _trigger_live_catalog_fetch(False)
            stack.add_titled(scroll, "brain", "2. 大脑与网关")

        # ------------------------------------------------------------------
        # Page 3: 记忆与上下文衰减压缩 (`_build_page_03_memories`)
        # ------------------------------------------------------------------
        def _build_page_03_memories(self, stack: Gtk.Stack) -> None:
            scroll, page = self._make_scrolled_page(
                "3. 记忆与上下文非线性时间衰减管理 (Memory Hub & Non-Linear Context Decay)",
                "配置会话上下文非线性时间衰减压缩策略（自动剥离工具轨迹噪音、保留核心问答语义），并检视个人记忆中枢与文档章节大纲。",
            )

            # --------------------------------------------------------------
            # Issue #3 Card: 📉 会话上下文非线性时间衰减压缩 (Non-Linear Context Decay)
            # --------------------------------------------------------------
            card_decay = self._make_card("📉 会话上下文非线性时间衰减压缩 (Non-Linear Context Decay)")
            decay_grid = Gtk.Grid(column_spacing=12, row_spacing=8)

            sw_decay_enabled = Gtk.Switch()
            sw_decay_enabled.set_active(True)
            sw_decay_enabled.set_valign(Gtk.Align.CENTER)

            sw_drop_tools = Gtk.Switch()
            sw_drop_tools.set_active(True)
            sw_drop_tools.set_valign(Gtk.Align.CENTER)

            adj_max_tokens = Gtk.Adjustment.new(6000.0, 800.0, 64000.0, 200.0, 1000.0, 0.0)
            spin_max_tokens = Gtk.SpinButton(adjustment=adj_max_tokens, climb_rate=200.0, digits=0)
            spin_max_tokens.set_numeric(True)
            spin_max_tokens.set_hexpand(True)

            adj_recent_turns = Gtk.Adjustment.new(3.0, 1.0, 15.0, 1.0, 2.0, 0.0)
            spin_recent_turns = Gtk.SpinButton(adjustment=adj_recent_turns, climb_rate=1.0, digits=0)
            spin_recent_turns.set_numeric(True)
            spin_recent_turns.set_hexpand(True)

            decay_preset_sl = Gtk.StringList.new([lbl for lbl, _, _ in DECAY_PRESETS])
            decay_preset_dd = Gtk.DropDown(model=decay_preset_sl)
            decay_preset_dd.set_selected(1)
            decay_preset_dd.set_hexpand(True)

            decay_rows: list[tuple[str, Gtk.Widget, str]] = [
                (
                    "启用长会话非线性时间衰减压缩:",
                    sw_decay_enabled,
                    "越早的对话保留越精简（按 w(Δk)=exp(-λ·Δk^γ) 阶梯压缩），近期对话完整保留",
                ),
                (
                    "自动剥离历史工具调用与轨迹记录:",
                    sw_drop_tools,
                    "仅记忆用户提问与 AI 核心回答，过滤工具 JSON/stdout 噪音，大幅节省上下文预算",
                ),
                ("单会话最大上下文预算 (Tokens):", spin_max_tokens, ""),
                ("近期完整保留问答轮数:", spin_recent_turns, ""),
                ("非线性衰减曲线预设 (λ, γ):", decay_preset_dd, ""),
            ]
            for r_i, (r_lbl, r_w, r_hint) in enumerate(decay_rows):
                decay_grid.attach(Gtk.Label(label=r_lbl, xalign=0.0), 0, r_i, 1, 1)
                if isinstance(r_w, Gtk.Switch):
                    hb = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                    hb.append(r_w)
                    hl = Gtk.Label(label=r_hint, xalign=0.0)
                    hl.add_css_class("intentos-muted-lbl")
                    hl.set_wrap(True)
                    hl.set_hexpand(True)
                    hb.append(hl)
                    decay_grid.attach(hb, 1, r_i, 1, 1)
                else:
                    decay_grid.attach(r_w, 1, r_i, 1, 1)
            card_decay.append(decay_grid)

            decay_btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            btn_save_decay = Gtk.Button(label="💾 保存上下文压缩策略")
            btn_save_decay.add_css_class("intentos-primary-btn")
            self._page03_save_decay_btn = btn_save_decay
            btn_reload_decay = Gtk.Button(label="↻ 读取当前策略与压缩预览")
            decay_status_lbl = Gtk.Label(
                label="默认策略：标准非线性衰减 (λ=0.24, γ=1.35) · 最大 6000 Tokens · 完整保留最近 3 轮 · 自动剥离工具轨迹",
                xalign=0.0,
            )
            decay_status_lbl.add_css_class("intentos-status-ok")
            decay_status_lbl.set_wrap(True)
            decay_status_lbl.set_hexpand(True)
            decay_btn_row.append(btn_save_decay)
            decay_btn_row.append(btn_reload_decay)
            decay_btn_row.append(decay_status_lbl)
            card_decay.append(decay_btn_row)
            page.append(card_decay)

            def _apply_decay_cfg_ui(cfg: dict[str, Any]) -> None:
                c = cfg.get("config") if isinstance(cfg.get("config"), dict) else cfg
                if not isinstance(c, dict):
                    return
                if "enabled" in c:
                    sw_decay_enabled.set_active(bool(c.get("enabled")))
                if "drop_tool_records" in c:
                    sw_drop_tools.set_active(bool(c.get("drop_tool_records")))
                if c.get("max_context_tokens"):
                    spin_max_tokens.set_value(float(c["max_context_tokens"]))
                if c.get("verbatim_recent_turns") is not None:
                    spin_recent_turns.set_value(float(c["verbatim_recent_turns"]))
                lam = float(c.get("decay_lambda") or 0.24)
                best_idx = min(
                    range(len(DECAY_PRESETS)),
                    key=lambda idx: abs(DECAY_PRESETS[idx][1] - lam),
                )
                decay_preset_dd.set_selected(best_idx)

            def _load_decay_config() -> None:
                if self.smoke_mode:
                    _apply_decay_cfg_ui(
                        {
                            "enabled": True,
                            "drop_tool_records": True,
                            "max_context_tokens": 6000,
                            "verbatim_recent_turns": 3,
                            "decay_lambda": 0.24,
                            "decay_gamma": 1.35,
                        }
                    )
                    return
                try:
                    res = call_module_rpc("memory_hub", "get_context_compression_config", {}, timeout=5.0)
                    if res.get("ok") and isinstance(res.get("result"), dict):
                        _apply_decay_cfg_ui(res["result"])
                        pv = call_module_rpc("memory_hub", "preview_session_compression", {}, timeout=4.0)
                        if pv.get("ok") and isinstance(pv.get("result"), dict):
                            pr = pv["result"]
                            saved = float(pr.get("saved_pct") or 0.0)
                            comp_tok = int(pr.get("compressed_estimated_tokens") or 0)
                            turns_n = int(pr.get("included_qa_turns") or 0)
                            decay_status_lbl.set_text(
                                f"✓ 已加载策略 · 最近会话预览：{turns_n} 轮有效问答 → {comp_tok} tok (节省 {saved:.0f}%)"
                            )
                except Exception as exc:
                    decay_status_lbl.set_text(f"读取上下文压缩策略失败: {exc}")

            def _on_save_decay_config(_b: Any) -> None:
                p_idx = int(decay_preset_dd.get_selected())
                p_lbl, lam_val, gam_val = (
                    DECAY_PRESETS[p_idx] if 0 <= p_idx < len(DECAY_PRESETS) else DECAY_PRESETS[1]
                )
                payload = {
                    "enabled": bool(sw_decay_enabled.get_active()),
                    "drop_tool_records": bool(sw_drop_tools.get_active()),
                    "max_context_tokens": int(spin_max_tokens.get_value()),
                    "verbatim_recent_turns": int(spin_recent_turns.get_value()),
                    "decay_lambda": lam_val,
                    "decay_gamma": gam_val,
                }
                if self.smoke_mode:
                    decay_status_lbl.set_text(
                        f"✓ [smoke] 已保存非线性衰减策略: {p_lbl} · 预算 {payload['max_context_tokens']} tok"
                    )
                    return
                try:
                    res = call_module_rpc("memory_hub", "set_context_compression_config", payload, timeout=6.0)
                    if res.get("ok"):
                        decay_status_lbl.set_text(
                            f"✓ 已保存上下文压缩策略：{p_lbl} · 预算 {payload['max_context_tokens']} tok · 完整保留最近 {payload['verbatim_recent_turns']} 轮"
                        )
                    else:
                        decay_status_lbl.set_text(f"✕ 保存失败: {res.get('error')}")
                except Exception as exc:
                    decay_status_lbl.set_text(f"✕ 保存异常: {exc}")

            btn_save_decay.connect("clicked", _on_save_decay_config)
            btn_reload_decay.connect("clicked", lambda _b: _load_decay_config())
            if isinstance(self.ov.get("context_compression"), dict) and self.ov["context_compression"]:
                _apply_decay_cfg_ui(self.ov["context_compression"])
            else:
                _load_decay_config()

            card_hub = self._make_card("个人记忆与文档章节大纲画像检视 (memory_hub)")
            hub_buf = Gtk.TextBuffer()
            hub_sw, _ = self._make_scrolled_textview(hub_buf, editable=False, min_height=180)
            card_hub.append(hub_sw)

            hub_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            hub_query_e = Gtk.Entry(placeholder_text="搜索提及文件、论文/报告章节大纲或已装软件…")
            hub_query_e.set_hexpand(True)
            hub_kind_e = Gtk.Entry(text="all")
            hub_kind_e.set_width_chars(14)
            hub_kind_e.set_tooltip_text("检索类型: all / mentioned_files / frequent_files / software")
            btn_query_hub = Gtk.Button(label="🔍 检索个人记忆")
            btn_refresh_hub = Gtk.Button(label="↻ 刷新记忆看板")
            btn_sync_xbel = Gtk.Button(label="⚡ 同步 XBEL 与文档大纲")
            hub_status = Gtk.Label(label="", xalign=0.0)
            hub_row.append(hub_query_e)
            hub_row.append(hub_kind_e)
            hub_row.append(btn_query_hub)
            hub_row.append(btn_refresh_hub)
            hub_row.append(btn_sync_xbel)
            card_hub.append(hub_row)
            card_hub.append(hub_status)
            page.append(card_hub)

            def load_memory_hub_dashboard() -> None:
                if self.smoke_mode:
                    return
                try:
                    res = call_module_rpc("memory_hub", "get_memory_dashboard", {}, timeout=5.0)
                    if res.get("ok") and isinstance(res.get("result"), dict):
                        d = res["result"]
                        mentioned = d.get("mentioned_files") or d.get("recent_mentions") or []
                        frequent = d.get("frequent_files") or d.get("long_term_files") or []
                        freq_apps = d.get("frequent_apps") or d.get("top_apps") or []
                        outlines = d.get("document_outlines_preview") or []
                        hub_buf.set_text(
                            json.dumps(
                                {
                                    "document_outlines_preview": outlines[:12],
                                    "mentioned_files_preview": mentioned[:10],
                                    "long_term_frequent_files_preview": frequent[:10],
                                    "frequent_apps_preview": freq_apps[:12],
                                    "installed_apps_summary": d.get("installed_apps_summary", {}),
                                },
                                ensure_ascii=False,
                                indent=2,
                            )
                        )
                        hub_status.set_text(
                            f"✓ 已加载：{len(outlines)} 篇章节大纲索引 · {len(mentioned)} 项提及文件 · {len(frequent)} 项高频文件"
                        )
                    else:
                        hub_buf.set_text(json.dumps(res, ensure_ascii=False, indent=2))
                except Exception as err:
                    hub_buf.set_text(f"读取 memory_hub 看板失败: {err}")

            def on_query_hub(_b: Any) -> None:
                q = hub_query_e.get_text().strip()
                k = hub_kind_e.get_text().strip() or "all"
                try:
                    res = call_module_rpc(
                        "memory_hub",
                        "query_personal_memory",
                        {"query": q, "kind": k, "limit": 15},
                    )
                    hub_buf.set_text(json.dumps(res.get("result", res), ensure_ascii=False, indent=2))
                    hub_status.set_text(f"✓ 检索完成 (kind={k})")
                except Exception as err:
                    hub_status.set_text(f"检索失败: {err}")

            def on_sync_hub(_b: Any) -> None:
                try:
                    res = call_module_rpc("memory_hub", "sync_system_usage", {})
                    load_memory_hub_dashboard()
                    if res.get("ok"):
                        hub_status.set_text("✓ 已同步 recently-used.xbel、中文桌面文档大纲与系统软件库")
                except Exception as err:
                    hub_status.set_text(f"同步失败: {err}")

            btn_refresh_hub.connect("clicked", lambda _b: load_memory_hub_dashboard())
            btn_query_hub.connect("clicked", on_query_hub)
            btn_sync_xbel.connect("clicked", on_sync_hub)
            load_memory_hub_dashboard()

            card_m = self._make_card("显式偏好与项目记忆管理 (M-03 / M-04)")
            mem_buf = Gtk.TextBuffer()
            mem_sw, _ = self._make_scrolled_textview(mem_buf, editable=False, min_height=140)
            card_m.append(mem_sw)

            add_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            subj_entry = Gtk.Entry(placeholder_text="主题 (如 editor.preferred)")
            val_entry = Gtk.Entry(placeholder_text="偏好值 (如 VS Code)")
            del_id_entry = Gtk.Entry(placeholder_text="要删除的记忆 ID (如 mem_...)")
            btn_add_mem = Gtk.Button(label="+ 新增/更新偏好")
            btn_del_mem = Gtk.Button(label="🗑 删除记忆 (写墓碑)")
            add_row.append(subj_entry)
            add_row.append(val_entry)
            add_row.append(btn_add_mem)
            add_row.append(del_id_entry)
            add_row.append(btn_del_mem)
            card_m.append(add_row)

            cand_id_entry = Gtk.Entry(placeholder_text="待确认候选 ID")
            btn_confirm_cand = Gtk.Button(label="✓ 确认写入记忆候选 (M-05)")
            mem_status = Gtk.Label(label="", xalign=0.0)
            cand_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            cand_row.append(cand_id_entry)
            cand_row.append(btn_confirm_cand)
            cand_row.append(mem_status)
            card_m.append(cand_row)
            page.append(card_m)

            def refresh_memories() -> None:
                if self.smoke_mode:
                    return
                try:
                    mems = call_ui_rpc("list_memories", timeout=4.0).get("result", [])
                    cands = []
                    c_res = call_module_rpc("execution_hub", "list_memory_candidates", {}, timeout=4.0)
                    if c_res.get("ok"):
                        cands = c_res.get("result", [])
                    mem_buf.set_text(
                        json.dumps({"active_memories": mems, "pending_candidates": cands}, ensure_ascii=False, indent=2)
                    )
                except Exception as err:
                    mem_buf.set_text(f"读取偏好记忆失败: {err}")

            def on_add_mem(_b: Any) -> None:
                s = subj_entry.get_text().strip()
                v = val_entry.get_text().strip()
                if s and v:
                    call_ui_rpc("upsert_memory", {"subject": s, "value": v})
                    refresh_memories()
                    mem_status.set_text(f"✓ 已保存记忆: {s} = {v}")

            def on_del_mem(_b: Any) -> None:
                mid = del_id_entry.get_text().strip()
                if mid:
                    call_ui_rpc("delete_memory", {"id": mid})
                    refresh_memories()
                    mem_status.set_text(f"✓ 已删除记忆 {mid} 并记录防复活墓碑")

            def on_confirm_cand(_b: Any) -> None:
                cid = cand_id_entry.get_text().strip()
                if cid:
                    call_module_rpc("execution_hub", "confirm_memory_candidate", {"candidate_id": cid})
                    refresh_memories()
                    mem_status.set_text(f"✓ 已确认记忆候选 {cid}")

            btn_add_mem.connect("clicked", on_add_mem)
            btn_del_mem.connect("clicked", on_del_mem)
            btn_confirm_cand.connect("clicked", on_confirm_cand)
            refresh_memories()
            stack.add_titled(scroll, "memories", "3. 记忆与候选")

        # ------------------------------------------------------------------
        # Shared Helper: Interactive Security Mode, Path Tiers & Session Grants
        # ------------------------------------------------------------------
        def _build_security_posture_card(self) -> Gtk.Box:
            card = self._make_card("🛡️ 全局用户空间路径可见性与四级敏感权限审批中心 (execution_hub)")
            sec_state: dict[str, Any] = {
                "mode": str((self.ov.get("security_posture") or {}).get("security_mode") or "balanced").lower()
            }

            mode_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            mode_btns: dict[str, Gtk.Button] = {}
            mode_desc_lbl = Gtk.Label(label="", xalign=0.0)
            mode_desc_lbl.add_css_class("intentos-muted-lbl")
            mode_desc_lbl.set_wrap(True)

            sec_status_lbl = Gtk.Label(label="", xalign=0.0)
            sec_status_lbl.add_css_class("intentos-status-ok")

            roots_lbl = Gtk.Label(label="", xalign=0.0)
            roots_lbl.set_wrap(True)
            roots_lbl.set_selectable(True)

            grants_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)

            def _sync_mode_buttons() -> None:
                cur = sec_state["mode"]
                for mid, _title, desc in SECURITY_MODES:
                    btn = mode_btns[mid]
                    if mid == cur:
                        btn.add_css_class("intentos-mode-active")
                        mode_desc_lbl.set_text(f"当前模式说明：{desc}")
                    else:
                        btn.remove_css_class("intentos-mode-active")

            def _load_posture() -> None:
                posture = self.ov.get("security_posture") or {}
                if not self.smoke_mode:
                    try:
                        r = call_module_rpc("execution_hub", "get_security_posture", {}, timeout=4.0)
                        if r.get("ok") and isinstance(r.get("result"), dict):
                            posture = r["result"]
                    except Exception:
                        pass

                m = str(posture.get("security_mode") or sec_state["mode"] or "balanced").lower()
                if m in mode_btns:
                    sec_state["mode"] = m
                _sync_mode_buttons()

                auth_roots = posture.get("authorized_roots") or [
                    "~/桌面",
                    "~/文档",
                    "~/下载",
                    "~/Desktop",
                    "~/Documents",
                    "~/Downloads",
                    os.path.expanduser("~"),
                ]
                appr_roots = posture.get("approved_roots") or []
                roots_txt = "🟢 全局常规用户空间目录 (NormalUserSpace — 直接可见与打开):\n  " + " , ".join(
                    str(x) for x in auth_roots[:10]
                )
                if appr_roots:
                    roots_txt += "\n  [已临时批准目录]: " + " , ".join(str(x) for x in appr_roots)
                roots_lbl.set_text(roots_txt)

                self._clear_box(grants_box)
                grants = posture.get("session_grants") or []
                if isinstance(grants, list) and grants:
                    for g in grants:
                        if isinstance(g, dict):
                            gid = str(g.get("id") or "")
                            gkind = str(g.get("scope_kind") or "directory")
                            gval = str(g.get("scope_value") or "")
                            exp = str(g.get("expires_at") or "")
                            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                            lbl = Gtk.Label(
                                label=f"⏱ [{gkind}] {gval}  (到期: {exp[:19] if exp else '本会话'})",
                                xalign=0.0,
                            )
                            lbl.set_hexpand(True)
                            lbl.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
                            rev_btn = Gtk.Button(label="✕ 收回授权")
                            rev_btn.connect("clicked", _on_revoke_grant, gid)
                            row.append(lbl)
                            row.append(rev_btn)
                            grants_box.append(row)
                else:
                    empty = Gtk.Label(label="当前暂无临时会话放行范围（在随问卡片点击「⏱ 本会话放行此范围」或下方添加后显示）。", xalign=0.0)
                    empty.add_css_class("intentos-muted-lbl")
                    empty.set_wrap(True)
                    grants_box.append(empty)

            def _on_pick_mode(_b: Any, target_mode: str) -> None:
                sec_state["mode"] = target_mode
                _sync_mode_buttons()
                if self.smoke_mode:
                    return
                try:
                    res = call_module_rpc("execution_hub", "set_security_mode", {"mode": target_mode}, timeout=5.0)
                    if res.get("ok"):
                        sec_status_lbl.set_text(f"✓ 已切换防护模式为：{target_mode}")
                        _load_posture()
                except Exception as err:
                    sec_status_lbl.set_text(f"模式更新失败: {err}")

            def _on_revoke_grant(_b: Any, gid: str) -> None:
                if not gid:
                    return
                try:
                    call_module_rpc("execution_hub", "revoke_session_grant", {"id": gid}, timeout=5.0)
                    sec_status_lbl.set_text(f"✓ 已收回会话授权 {gid}")
                    _load_posture()
                except Exception as err:
                    sec_status_lbl.set_text(f"收回失败: {err}")

            for mid, title_txt, _desc in SECURITY_MODES:
                b = Gtk.Button(label=title_txt)
                b.connect("clicked", _on_pick_mode, mid)
                mode_btns[mid] = b
                mode_row.append(b)

            btn_refresh_sec = Gtk.Button(label="↻ 刷新态势")
            btn_refresh_sec.connect("clicked", lambda _b: _load_posture())
            mode_row.append(btn_refresh_sec)
            card.append(mode_row)
            card.append(mode_desc_lbl)

            # 3-tier visual posture boxes
            tier_ok_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            tier_ok_box.add_css_class("intentos-tier-ok")
            tier_ok_box.append(roots_lbl)
            card.append(tier_ok_box)

            tier_warn_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            tier_warn_box.add_css_class("intentos-tier-warn")
            w_lbl = Gtk.Label(
                label="🟡 敏感配置与外部路径 (RequiresApproval — 自动弹出内联审批卡片，绝不生硬报错或盲目放行):\n  ~/.config/* , ~/.local/* , ~/.bashrc , .env , /etc/hosts , /opt/* , 以及进程强制终止与 AI 发起的批量修改",
                xalign=0.0,
            )
            w_lbl.set_wrap(True)
            tier_warn_box.append(w_lbl)
            card.append(tier_warn_box)

            tier_deny_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            tier_deny_box.add_css_class("intentos-tier-deny")
            d_lbl = Gtk.Label(
                label="🔴 高危凭证与系统禁区 (Hard-Forbidden — 任何安全模式与会话授权均 100% 锁定拒绝):\n  ~/.ssh/* , ~/.gnupg/* , ~/.aws/* , ~/.kube/* , id_rsa / id_ed25519 , /etc/shadow , /etc/sudoers , 浏览器 Cookies / Login Data",
                xalign=0.0,
            )
            d_lbl.set_wrap(True)
            tier_deny_box.append(d_lbl)
            card.append(tier_deny_box)

            # Active Session Scope Grants + Add Grant Row
            card.append(Gtk.Label(label="活动会话放行授权 (Session Scope Grants):", xalign=0.0))
            card.append(grants_box)

            grant_add_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            kind_sl = Gtk.StringList.new(["directory (目录范围)", "app (应用范围)", "capability (能力范围)"])
            kind_dd = Gtk.DropDown(model=kind_sl)
            scope_val_e = Gtk.Entry(placeholder_text="输入临时放行路径/应用/能力 (如 ~/.config/myapp 或 sodam)")
            scope_val_e.set_hexpand(True)
            btn_add_grant = Gtk.Button(label="+ 授权本会话 60 分钟")
            grant_add_row.append(kind_dd)
            grant_add_row.append(scope_val_e)
            grant_add_row.append(btn_add_grant)
            card.append(grant_add_row)
            card.append(sec_status_lbl)

            def _on_add_grant(_b: Any) -> None:
                val = scope_val_e.get_text().strip()
                if not val:
                    return
                k_map = ["directory", "app", "capability"]
                sk = k_map[int(kind_dd.get_selected())] if int(kind_dd.get_selected()) < 3 else "directory"
                try:
                    res = call_module_rpc(
                        "execution_hub",
                        "grant_session_scope",
                        {"scope_kind": sk, "scope_value": val, "ttl_minutes": 60},
                        timeout=5.0,
                    )
                    if res.get("ok"):
                        sec_status_lbl.set_text(f"✓ 已添加会话放行: [{sk}] {val}")
                        scope_val_e.set_text("")
                        _load_posture()
                    else:
                        sec_status_lbl.set_text(f"拒绝放行: {res.get('error')}")
                except Exception as err:
                    sec_status_lbl.set_text(f"授权失败: {err}")

            btn_add_grant.connect("clicked", _on_add_grant)
            _load_posture()
            return card

        # ------------------------------------------------------------------
        # Page 4: 全局路径敏感审批与技能工作流 (`_build_page_04_skills`)
        # ------------------------------------------------------------------
        def _build_page_04_skills(self, stack: Gtk.Stack) -> None:
            scroll, page = self._make_scrolled_page(
                "4. 全局路径审批与技能工作流 (Security Posture & Workflows)",
                "切换全局安全审批模式（严格 / 平衡 / 开发者），检视用户空间可见路径与敏感路径审批边界，并管理可复用 SKILL.md 工作流。",
            )
            page.append(self._build_security_posture_card())

            card_sk = self._make_card("已加载技能与工作流注册表 (§11.4 SKILL.md)")
            sk_buf = Gtk.TextBuffer()
            sk_sw, _ = self._make_scrolled_textview(sk_buf, editable=False, min_height=140)
            card_sk.append(sk_sw)

            learn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            task_id_entry = Gtk.Entry(placeholder_text="源任务 ID (如 task_...)")
            wf_name_entry = Gtk.Entry(placeholder_text="工作流名称 (如 开始做 IntentOS)")
            wf_trig_entry = Gtk.Entry(placeholder_text="触发短语 (如 开始做 IntentOS)")
            btn_learn = Gtk.Button(label="✨ 从任务提炼工作流")
            btn_run_wf = Gtk.Button(label="▶ 运行工作流")
            sk_status = Gtk.Label(label="", xalign=0.0)
            learn_row.append(task_id_entry)
            learn_row.append(wf_name_entry)
            learn_row.append(wf_trig_entry)
            learn_row.append(btn_learn)
            learn_row.append(btn_run_wf)
            card_sk.append(learn_row)
            card_sk.append(sk_status)
            page.append(card_sk)

            def refresh_skills() -> None:
                if self.smoke_mode:
                    return
                try:
                    res = call_module_rpc("execution_hub", "list_skills_and_workflows", {}, timeout=4.0)
                    sk_buf.set_text(json.dumps(res.get("result", {}), ensure_ascii=False, indent=2))
                except Exception as err:
                    sk_buf.set_text(f"读取技能列表失败: {err}")

            def on_learn(_b: Any) -> None:
                res = call_module_rpc(
                    "execution_hub",
                    "learn_workflow_from_task",
                    {
                        "task_id": task_id_entry.get_text().strip(),
                        "name": wf_name_entry.get_text().strip() or "自定义工作流",
                        "trigger_phrase": wf_trig_entry.get_text().strip() or "执行自定义工作流",
                    },
                )
                refresh_skills()
                sk_status.set_text("✓ 已保存为标准 SKILL.md 工作流" if res.get("ok") else f"提炼结果: {res.get('error')}")

            def on_run_wf(_b: Any) -> None:
                wf_id = wf_name_entry.get_text().strip() or "workflow.start-intentos"
                res = call_module_rpc("execution_hub", "run_workflow", {"workflow_id": wf_id})
                sk_status.set_text("✓ 工作流执行完成" if res.get("ok") else f"运行状态: {res.get('error')}")

            btn_learn.connect("clicked", on_learn)
            btn_run_wf.connect("clicked", on_run_wf)
            refresh_skills()
            stack.add_titled(scroll, "skills", "4. 路径审批与技能")

        # ------------------------------------------------------------------
        # Page 5: 本机软件深度扫描与分类转译中心 (`_build_page_05_capabilities`)
        # ------------------------------------------------------------------
        def _build_page_05_capabilities(self, stack: Gtk.Stack) -> None:
            scroll, page = self._make_scrolled_page(
                "5. 本机软件深度扫描与分类转译中心",
                "深度扫描本机全部 APT / Snap / Flatpak / 第三方 / 本地软件并归入 9 大分类，自动识别 SNI 托盘菜单、MPRIS2、.desktop 动作、URI Scheme、AT-SPI2 与 CLI 通道，一键实测或绑定自然语言口令。",
            )

            # --------------------------------------------------------------
            # Issue #2 TOP PANEL: 🧭 本机软件深度扫描与 9 大分类转译目录 (`deep_scan_local_software`)
            # --------------------------------------------------------------
            card_deep_inv = self._make_card(
                "🧭 本机全部软件深度扫描与 9 大分类转译浏览器 (deep_scan_local_software)"
            )
            deep_top_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            btn_deep_scan_all = Gtk.Button(label="🔍 深度扫描本机全部软件")
            btn_deep_scan_all.add_css_class("intentos-primary-btn")
            deep_search_entry = Gtk.Entry(placeholder_text="搜索本机软件/拼音/动作...")
            deep_search_entry.set_hexpand(True)
            self._page05_deep_search_entry = deep_search_entry
            deep_top_bar.append(btn_deep_scan_all)
            deep_top_bar.append(deep_search_entry)
            card_deep_inv.append(deep_top_bar)

            deep_summary_lbl = Gtk.Label(
                label="正在扫描本机软件目录与 9 大分类可转译接口…",
                xalign=0.0,
            )
            deep_summary_lbl.add_css_class("intentos-status-ok")
            deep_summary_lbl.set_wrap(True)
            card_deep_inv.append(deep_summary_lbl)

            # Horizontal / Flow 9-Category Filter Bar (`全部` + 9 categories)
            cat_filter_flow = Gtk.FlowBox()
            cat_filter_flow.set_selection_mode(Gtk.SelectionMode.NONE)
            cat_filter_flow.set_max_children_per_line(5)
            cat_filter_flow.set_column_spacing(6)
            cat_filter_flow.set_row_spacing(6)
            card_deep_inv.append(cat_filter_flow)

            # Scrollable list of discovered categorized software cards
            deep_apps_sw = Gtk.ScrolledWindow(min_content_height=240, hexpand=True)
            deep_apps_sw.set_max_content_height(350)
            deep_apps_sw.set_propagate_natural_height(True)
            deep_apps_sw.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            deep_apps_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            deep_apps_sw.set_child(deep_apps_box)
            card_deep_inv.append(deep_apps_sw)

            deep_exec_status_lbl = Gtk.Label(label="", xalign=0.0)
            deep_exec_status_lbl.add_css_class("intentos-status-ok")
            deep_exec_status_lbl.set_wrap(True)
            card_deep_inv.append(deep_exec_status_lbl)
            page.append(card_deep_inv)

            # --------------------------------------------------------------
            # TOP PANEL: ⚡ 一键扫描运行态软件与托盘菜单接口 (`list_live_tray_apps` + `inspect_live_app`)
            # --------------------------------------------------------------
            card_live_scan = self._make_card(
                "⚡ 一键扫描运行态软件与托盘菜单接口 (list_live_tray_apps + inspect_live_app)"
            )
            scan_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            inspect_app_entry = Gtk.Entry(
                placeholder_text="输入或点选任意已安装/运行中软件 (如 飞书 / FlClash / 轻笺 / WPS 云盘 / 汽水音乐 / Omni Mouse Studio)…"
            )
            inspect_app_entry.set_hexpand(True)
            btn_deep_inspect = Gtk.Button(label="🔍 深度探测该软件可转译能力")
            btn_deep_inspect.add_css_class("intentos-primary-btn")
            btn_refresh_tray = Gtk.Button(label="🔄 刷新运行态托盘")
            scan_bar.append(inspect_app_entry)
            scan_bar.append(btn_deep_inspect)
            scan_bar.append(btn_refresh_tray)
            card_live_scan.append(scan_bar)

            tray_hdr_lbl = Gtk.Label(label="🟢 当前运行态系统托盘与媒体应用 (一键直控真实 dbusmenu 菜单项):", xalign=0.0)
            tray_hdr_lbl.add_css_class("intentos-muted-lbl")
            card_live_scan.append(tray_hdr_lbl)

            tray_cards_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            card_live_scan.append(tray_cards_box)

            inspect_result_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            card_live_scan.append(inspect_result_box)

            live_scan_status = Gtk.Label(label="", xalign=0.0)
            live_scan_status.add_css_class("intentos-status-ok")
            live_scan_status.set_wrap(True)
            card_live_scan.append(live_scan_status)
            page.append(card_live_scan)

            # --------------------------------------------------------------
            # Card 0b: Personalized Desktop Software Discovery & Custom Translation Rule Builder
            # --------------------------------------------------------------
            card_ad = self._make_card(
                "🔌 个性化软件自定义口令与转译规则表单 (支持 tray_menu / MPRIS2 / D-Bus / .desktop / URI / 快捷键)"
            )
            ad_filter_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            ad_query_e = Gtk.Entry(placeholder_text="搜索本机已安装个性化软件 (如 sodam / 汽水音乐 / flclash / 飞书 / wps / qq)…")
            ad_query_e.set_hexpand(True)
            btn_discover_apps = Gtk.Button(label="🔍 扫描本机个性化软件")
            btn_probe_live = Gtk.Button(label="📡 探测实时运行播放器与窗口")
            ad_filter_row.append(ad_query_e)
            ad_filter_row.append(btn_discover_apps)
            ad_filter_row.append(btn_probe_live)
            card_ad.append(ad_filter_row)

            # Interactive discovered personalized app pills (click to populate form & inspect)
            apps_chips_sw = Gtk.ScrolledWindow(min_content_height=80, hexpand=True)
            apps_chips_sw.set_max_content_height(140)
            apps_chips_sw.set_propagate_natural_height(True)
            apps_chips_sw.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            apps_flow = Gtk.FlowBox()
            apps_flow.set_selection_mode(Gtk.SelectionMode.NONE)
            apps_flow.set_max_children_per_line(4)
            apps_flow.set_column_spacing(6)
            apps_flow.set_row_spacing(6)
            apps_chips_sw.set_child(apps_flow)
            card_ad.append(apps_chips_sw)

            ad_status = Gtk.Label(label="", xalign=0.0)
            ad_status.add_css_class("intentos-status-ok")
            ad_status.set_wrap(True)
            card_ad.append(ad_status)

            # Interactive Custom Software Translation Rule Form (`save_custom_adapter`)
            rule_hdr = Gtk.Label(label="新增 / 编辑个性化软件指令转译规则 (保存至 adapters/custom_apps.json，零手写 JSON):", xalign=0.0)
            rule_hdr.add_css_class("intentos-section-header")
            card_ad.append(rule_hdr)

            rule_grid = Gtk.Grid(column_spacing=10, row_spacing=6)
            f_app_id = Gtk.Entry(text="sodam", placeholder_text="软件 ID (如 sodam / flclash / feishu)")
            f_app_name = Gtk.Entry(text="SodaM, 汽水音乐", placeholder_text="显示名称与别名，逗号分隔 (如 SodaM,汽水音乐)")
            f_binary = Gtk.Entry(text="sodam", placeholder_text="可执行文件/进程名 (如 sodam)")
            chan_sl = Gtk.StringList.new([lbl for _, lbl in ADAPTER_CHANNELS])
            f_chan_dd = Gtk.DropDown(model=chan_sl)
            f_action_name = Gtk.Entry(text="show_main_window", placeholder_text="语义动作名 (如 show_main_window / play_pause / next_track)")
            f_phrase_aliases = Gtk.Entry(
                text="显示汽水音乐主窗口, 打开汽水音乐界面",
                placeholder_text="绑定个性化语音/聊天口令，逗号分隔 (如 切歌, 切换FlClash规则模式, 打开飞书主窗口)",
            )
            f_target_cmd = Gtk.Entry(
                text="显示主窗口",
                placeholder_text="dbusmenu 菜单项名 / MPRIS 服务 / URI 模板 / 快捷键 / CLI 参数",
            )
            f_req_approval = Gtk.CheckButton(label="该自定义动作属于敏感控制，执行前需弹出人工审批确认")

            for r_i, (l_txt, w_item) in enumerate(
                [
                    ("软件标识 (App ID):", f_app_id),
                    ("显示名称与别名:", f_app_name),
                    ("进程 / 二进制名 (/proc 匹配):", f_binary),
                    ("指令转译通道:", f_chan_dd),
                    ("自定义语义动作名:", f_action_name),
                    ("个性化语音/对话口令绑定:", f_phrase_aliases),
                    ("转译目标 (菜单项/D-Bus/URI/快捷键):", f_target_cmd),
                ]
            ):
                rule_grid.attach(Gtk.Label(label=l_txt, xalign=0.0), 0, r_i, 1, 1)
                w_item.set_hexpand(True)
                rule_grid.attach(w_item, 1, r_i, 1, 1)
            card_ad.append(rule_grid)
            card_ad.append(f_req_approval)

            rule_btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            btn_save_rule = Gtk.Button(label="💾 保存个性化转译规则")
            btn_save_rule.add_css_class("intentos-primary-btn")
            btn_test_action = Gtk.Button(label="▶ 测试执行动作")
            btn_test_close = Gtk.Button(label="🛑 一键测试验证关闭软件")
            btn_del_rule = Gtk.Button(label="🗑 删除规则")
            rule_btn_row.append(btn_save_rule)
            rule_btn_row.append(btn_test_action)
            rule_btn_row.append(btn_test_close)
            rule_btn_row.append(btn_del_rule)
            card_ad.append(rule_btn_row)

            ad_buf = Gtk.TextBuffer()
            ad_sw, _ = self._make_scrolled_textview(ad_buf, editable=False, min_height=145)
            card_ad.append(ad_sw)
            page.append(card_ad)

            def _set_channel_dropdown(chan_key: str) -> None:
                idx = next((i for i, (cid, _) in enumerate(ADAPTER_CHANNELS) if cid == chan_key), 0)
                f_chan_dd.set_selected(idx)

            def _fill_custom_rule_form(
                app_id_val: str,
                disp_name_val: str,
                aliases_list: list[str],
                binary_val: str,
                chan_key: str,
                action_key: str,
                target_val: str,
                phrases_val: str = "",
            ) -> None:
                clean_id = re.sub(r"\.desktop$", "", app_id_val.strip().lower()).replace(" ", "-") or "custom-app"
                f_app_id.set_text(clean_id)
                merged_names = [disp_name_val.strip()] + [a.strip() for a in aliases_list if a.strip() and a.strip() != disp_name_val.strip()]
                f_app_name.set_text(", ".join(x for x in merged_names if x))
                if binary_val.strip():
                    f_binary.set_text(Path(binary_val.strip().split()[0]).name)
                _set_channel_dropdown(chan_key)
                f_action_name.set_text(action_key)
                f_target_cmd.set_text(target_val)
                if phrases_val:
                    f_phrase_aliases.set_text(phrases_val)
                else:
                    f_phrase_aliases.set_text(f"{disp_name_val}{target_val}, 用{disp_name_val}执行{target_val}")
                ad_status.set_text(
                    f"✨ 已一键填入自定义转译规则表单：「{disp_name_val}」[{chan_key}] → {target_val}，确认口令后点击「💾 保存个性化转译规则」即可生效！"
                )

            deep_scan_state: dict[str, Any] = {
                "selected_category": "all",
                "apps": [],
                "summary": {},
                "cat_counts": {},
            }

            def _execute_discovered_app_action(
                app_obj: dict[str, Any],
                act_obj: dict[str, Any],
            ) -> None:
                app_id_v = str(app_obj.get("app_id") or app_obj.get("id") or "")
                disp_v = str(app_obj.get("display_name") or app_obj.get("name") or app_id_v)
                desk_id_v = str(app_obj.get("desktop_id") or "")
                chan_v = str(act_obj.get("channel") or "cli_wrapper")
                act_id_v = str(act_obj.get("action_id") or act_obj.get("id") or act_obj.get("action") or "launch")
                act_lbl_v = str(act_obj.get("label") or act_obj.get("title") or act_id_v)
                target_v = str(act_obj.get("target") or act_obj.get("exec") or act_lbl_v)

                if self.smoke_mode:
                    deep_exec_status_lbl.set_text(f"✓ [smoke] 已执行软件动作: {disp_v} → {act_lbl_v} [{chan_v}]")
                    return

                deep_exec_status_lbl.set_text(f"⏳ 正在执行：{disp_v} → {act_lbl_v} ({chan_v})…")

                def _w() -> None:
                    msg = ""
                    dump_txt = ""
                    try:
                        if chan_v == "sni_dbusmenu":
                            res = call_module_rpc(
                                "app_adapter",
                                "trigger_tray_menu",
                                {"app": disp_v, "app_hint": app_id_v or disp_v, "action": target_v, "menu_label": target_v},
                                timeout=8.0,
                            )
                        elif chan_v == "desktop_action" and desk_id_v:
                            res = call_module_rpc(
                                "app_adapter",
                                "execute_desktop_action",
                                {"desktop_id": desk_id_v, "action_id": act_id_v, "app_id": app_id_v},
                                timeout=8.0,
                            )
                            if not res.get("ok"):
                                res = call_module_rpc(
                                    "app_adapter",
                                    "translate_and_execute",
                                    {"app_hint": app_id_v or disp_v, "intent_action": act_id_v, "params": {}, "approved": True},
                                    timeout=8.0,
                                )
                        else:
                            res = call_module_rpc(
                                "app_adapter",
                                "translate_and_execute",
                                {"app_hint": app_id_v or disp_v, "intent_action": act_id_v, "params": {}, "approved": True},
                                timeout=10.0,
                            )
                        body = res.get("result", res)
                        dump_txt = json.dumps(body, ensure_ascii=False, indent=2)
                        if res.get("ok"):
                            s_txt = body.get("summary") if isinstance(body, dict) else ""
                            msg = f"✓ 已触发「{disp_v}」动作：{s_txt or act_lbl_v}"
                        else:
                            msg = f"⚠ 执行返回：{res.get('error') or '请确认目标软件状态'}"
                    except Exception as exc:
                        msg = f"✕ 执行异常：{exc}"

                    def _ui() -> bool:
                        deep_exec_status_lbl.set_text(msg)
                        if dump_txt:
                            ad_buf.set_text(dump_txt)
                        return False

                    GLib.idle_add(_ui)

                threading.Thread(target=_w, daemon=True).start()

            def _rebuild_deep_category_bar() -> None:
                self._clear_flowbox(cat_filter_flow)
                self._page05_deep_cat_btns = {}
                counts: dict[str, int] = deep_scan_state.get("cat_counts") or {}
                total_n = len(deep_scan_state.get("apps") or [])
                cur_cat = str(deep_scan_state.get("selected_category") or "all")

                for cid, clabel in DEEP_SCAN_CATEGORIES:
                    cnt = total_n if cid == "all" else int(counts.get(cid, 0))
                    btn_c = Gtk.Button(label=f"{clabel} ({cnt})")
                    if cid == cur_cat:
                        btn_c.add_css_class("intentos-mode-active")

                    def _on_cat(_b: Any, target_cat: str = cid) -> None:
                        deep_scan_state["selected_category"] = target_cat
                        _rebuild_deep_category_bar()
                        _render_deep_scan_app_cards()

                    btn_c.connect("clicked", _on_cat)
                    self._page05_deep_cat_btns[cid] = btn_c
                    cat_filter_flow.append(btn_c)

            def _render_deep_scan_app_cards() -> None:
                self._clear_box(deep_apps_box)
                all_apps: list[dict[str, Any]] = deep_scan_state.get("apps") or []
                cur_cat = str(deep_scan_state.get("selected_category") or "all")
                q = deep_search_entry.get_text().strip().lower()

                filtered: list[dict[str, Any]] = []
                for ap in all_apps:
                    if not isinstance(ap, dict):
                        continue
                    ap_cat = str(ap.get("category") or ap.get("category_id") or "hardware_system")
                    if cur_cat != "all" and ap_cat != cur_cat:
                        continue
                    if q:
                        hay = " ".join(
                            [
                                str(ap.get("display_name") or ap.get("name") or ""),
                                str(ap.get("app_id") or ap.get("id") or ""),
                                str(ap.get("desktop_id") or ""),
                                " ".join(str(x) for x in (ap.get("aliases") or [])),
                                " ".join(str(x) for x in (ap.get("pinyin_hints") or ap.get("keywords") or [])),
                                " ".join(
                                    str(a.get("label") or a.get("action") or "")
                                    for a in (ap.get("translatable_actions") or ap.get("actions") or [])
                                    if isinstance(a, dict)
                                ),
                            ]
                        ).lower()
                        if q not in hay:
                            continue
                    filtered.append(ap)

                if not filtered:
                    empty_l = Gtk.Label(
                        label="当前筛选条件下暂无匹配软件（可切换分类或清空搜索词，或点击「🔍 深度扫描本机全部软件」刷新）。",
                        xalign=0.0,
                    )
                    empty_l.add_css_class("intentos-muted-lbl")
                    empty_l.set_wrap(True)
                    deep_apps_box.append(empty_l)
                    return

                for ap in filtered[:60]:
                    ap_id = str(ap.get("app_id") or ap.get("id") or ap.get("desktop_id") or "app")
                    ap_name = str(ap.get("display_name") or ap.get("name") or ap_id)
                    ap_cat = str(ap.get("category") or ap.get("category_id") or "hardware_system")
                    cat_badge_txt = DEEP_SCAN_CATEGORY_LABELS.get(ap_cat, str(ap.get("category_label") or ap_cat))
                    src_raw = str(ap.get("source_badge") or ap.get("install_source") or ap.get("source") or "APT")
                    src_map = {
                        "apt_dpkg": "APT",
                        "system_apt": "APT",
                        "apt": "APT",
                        "snap": "Snap",
                        "flatpak": "Flatpak",
                        "opt_vendor": "Vendor",
                        "user_local": "Local",
                        "browser_pwa": "PWA",
                        "chrome_pwa": "PWA",
                    }
                    src_badge_txt = src_map.get(src_raw.lower(), src_raw)
                    is_running = bool(ap.get("running")) or bool(ap.get("pids"))
                    chans = [str(c) for c in (ap.get("channels") or []) if str(c).strip()]
                    aliases_list = [str(a) for a in (ap.get("aliases") or []) if str(a).strip()]
                    bin_v = str(ap.get("exec_binary") or ap.get("binary") or ap_id)

                    row_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
                    row_card.add_css_class("intentos-app-inv-card")

                    hdr_r = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                    nm_lbl = Gtk.Label(label=ap_name, xalign=0.0)
                    nm_lbl.add_css_class("intentos-section-header")
                    hdr_r.append(nm_lbl)

                    c_pill = Gtk.Label(label=cat_badge_txt)
                    c_pill.add_css_class("intentos-badge-pill")
                    hdr_r.append(c_pill)

                    s_pill = Gtk.Label(label=src_badge_txt)
                    s_pill.add_css_class("intentos-badge-source")
                    hdr_r.append(s_pill)

                    if is_running:
                        r_pill = Gtk.Label(label="🟢 运行中")
                        r_pill.add_css_class("intentos-badge-running")
                        hdr_r.append(r_pill)

                    ch_lbl = Gtk.Label(
                        label=f"通道: {', '.join(chans) if chans else 'desktop_action'}",
                        xalign=0.0,
                    )
                    ch_lbl.add_css_class("intentos-muted-lbl")
                    ch_lbl.set_hexpand(True)
                    ch_lbl.set_ellipsize(Pango.EllipsizeMode.END)
                    hdr_r.append(ch_lbl)

                    b_insp_app = Gtk.Button(label="🔎 探测")
                    b_insp_app.connect(
                        "clicked",
                        lambda _b, q_name=ap_name: (
                            inspect_app_entry.set_text(q_name),
                            inspect_live_app_by_query(q_name),
                        ),
                    )
                    hdr_r.append(b_insp_app)
                    row_card.append(hdr_r)

                    raw_acts = (
                        ap.get("translatable_actions")
                        or ap.get("actions")
                        or ap.get("supported_actions")
                        or []
                    )
                    act_items: list[dict[str, Any]] = []
                    for ra in raw_acts:
                        if isinstance(ra, dict):
                            act_items.append(ra)
                        elif isinstance(ra, str) and ra.strip():
                            act_items.append({"action": ra.strip(), "label": ra.strip(), "channel": chans[0] if chans else "desktop_action"})
                    if not act_items:
                        for da in (ap.get("desktop_actions") or [])[:3]:
                            if isinstance(da, dict):
                                act_items.append(
                                    {
                                        "action_id": da.get("id") or da.get("action_id") or da.get("name") or "launch",
                                        "label": da.get("label") or da.get("name") or "快捷动作",
                                        "channel": "desktop_action",
                                        "target": da.get("exec") or da.get("name") or "",
                                    }
                                )
                    if not act_items:
                        act_items.append(
                            {
                                "action": "launch",
                                "label": f"启动 {ap_name}",
                                "channel": chans[0] if chans else "desktop_action",
                                "target": bin_v,
                            }
                        )

                    act_flow = Gtk.FlowBox()
                    act_flow.set_selection_mode(Gtk.SelectionMode.NONE)
                    act_flow.set_max_children_per_line(3)
                    act_flow.set_column_spacing(6)
                    act_flow.set_row_spacing(4)

                    for act_item in act_items[:6]:
                        a_lbl = str(act_item.get("label") or act_item.get("summary") or act_item.get("action") or "动作")
                        a_id = str(act_item.get("action") or act_item.get("action_id") or "custom_action")
                        a_ch = str(act_item.get("channel") or (chans[0] if chans else "desktop_action"))
                        a_tgt = str(act_item.get("target") or act_item.get("target_template") or a_lbl)
                        a_phrases = act_item.get("phrases") or act_item.get("aliases") or []
                        phrases_str = (
                            ", ".join(str(p) for p in a_phrases[:3])
                            if isinstance(a_phrases, list) and a_phrases
                            else f"{ap_name}{a_lbl}, 打开{ap_name}"
                        )

                        chip_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
                        b_exec = Gtk.Button(label=f"▶ 执行/测试 · {a_lbl[:16]}")
                        b_exec.add_css_class("intentos-tray-btn")
                        b_exec.connect(
                            "clicked",
                            lambda _b, app_o=ap, act_o=act_item: _execute_discovered_app_action(app_o, act_o),
                        )
                        b_bind = Gtk.Button(label="✨ 绑定口令")
                        b_bind.connect(
                            "clicked",
                            lambda _b, i_id=ap_id, i_nm=ap_name, i_al=aliases_list, i_bn=bin_v, i_ch=a_ch, i_act=a_id, i_tg=a_tgt, i_ph=phrases_str: _fill_custom_rule_form(
                                i_id, i_nm, i_al, i_bn, i_ch, i_act, i_tg, i_ph
                            ),
                        )
                        chip_box.append(b_exec)
                        chip_box.append(b_bind)
                        act_flow.append(chip_box)

                    row_card.append(act_flow)
                    deep_apps_box.append(row_card)

            def _apply_deep_scan_result(res_dict: dict[str, Any]) -> None:
                apps_raw = res_dict.get("apps") if isinstance(res_dict.get("apps"), list) else []
                apps_clean = [x for x in apps_raw if isinstance(x, dict)]
                deep_scan_state["apps"] = apps_clean

                cat_counts: dict[str, int] = {}
                raw_cats = res_dict.get("categories")
                if isinstance(raw_cats, list):
                    for c_entry in raw_cats:
                        if isinstance(c_entry, dict) and c_entry.get("id"):
                            cat_counts[str(c_entry["id"])] = int(c_entry.get("count") or 0)
                if not cat_counts:
                    for ap in apps_clean:
                        cid = str(ap.get("category") or ap.get("category_id") or "hardware_system")
                        cat_counts[cid] = cat_counts.get(cid, 0) + 1
                deep_scan_state["cat_counts"] = cat_counts

                total_apps = int(res_dict.get("total_apps") or len(apps_clean))
                running_n = int(
                    res_dict.get("running_apps")
                    if res_dict.get("running_apps") is not None
                    else sum(1 for a in apps_clean if a.get("running") or a.get("pids"))
                )
                trans_n = int(
                    res_dict.get("translatable_actions_total")
                    if res_dict.get("translatable_actions_total") is not None
                    else sum(len(a.get("translatable_actions") or a.get("actions") or [1]) for a in apps_clean)
                )
                deep_summary_lbl.set_text(
                    f"已扫描 {total_apps} 款本机软件 · 9 大分类 · {running_n} 款运行中 · {trans_n} 项可转译接口"
                )
                _rebuild_deep_category_bar()
                _render_deep_scan_app_cards()

            def run_deep_local_software_scan(force_refresh: bool = False) -> None:
                if self.smoke_mode:
                    smoke_apps = [
                        {
                            "app_id": "sodam",
                            "display_name": "汽水音乐 SodaM",
                            "category": "media_entertainment",
                            "install_source": "opt_vendor",
                            "running": True,
                            "channels": ["sni_dbusmenu", "dbus_mpris"],
                            "translatable_actions": [{"action": "play_pause", "label": "播放/暂停", "channel": "dbus_mpris"}],
                        },
                        {
                            "app_id": "feishu",
                            "display_name": "飞书 Feishu",
                            "category": "social_collab",
                            "install_source": "apt_dpkg",
                            "running": True,
                            "channels": ["sni_dbusmenu", "uri_scheme"],
                            "translatable_actions": [{"action": "open_uri", "label": "唤起飞书窗口", "channel": "uri_scheme"}],
                        },
                        {
                            "app_id": "wps-office",
                            "display_name": "WPS Office",
                            "category": "office_notes_doc",
                            "install_source": "apt_dpkg",
                            "running": False,
                            "channels": ["desktop_action", "cli_wrapper"],
                            "translatable_actions": [{"action": "new_writer", "label": "新建文字文档", "channel": "desktop_action"}],
                        },
                        {
                            "app_id": "localsend",
                            "display_name": "LocalSend 互传",
                            "category": "cloud_transfer",
                            "install_source": "flatpak",
                            "running": False,
                            "channels": ["desktop_action"],
                            "translatable_actions": [{"action": "launch", "label": "打开局域网互传", "channel": "desktop_action"}],
                        },
                        {
                            "app_id": "flclash",
                            "display_name": "FlClash",
                            "category": "network_browser",
                            "install_source": "opt_vendor",
                            "running": True,
                            "channels": ["sni_dbusmenu"],
                            "translatable_actions": [{"action": "rule_mode", "label": "切换规则模式", "channel": "sni_dbusmenu"}],
                        },
                        {
                            "app_id": "code",
                            "display_name": "Visual Studio Code",
                            "category": "dev_ai_ide",
                            "install_source": "apt_dpkg",
                            "running": True,
                            "channels": ["desktop_action", "cli_wrapper"],
                            "translatable_actions": [{"action": "new-empty-window", "label": "新建窗口", "channel": "desktop_action"}],
                        },
                        {
                            "app_id": "gimp",
                            "display_name": "GIMP 图像创作",
                            "category": "creative_disc",
                            "install_source": "apt_dpkg",
                            "running": False,
                            "channels": ["desktop_action"],
                            "translatable_actions": [{"action": "launch", "label": "启动 GIMP", "channel": "desktop_action"}],
                        },
                        {
                            "app_id": "remmina",
                            "display_name": "Remmina 远程桌面",
                            "category": "remote_vm",
                            "install_source": "apt_dpkg",
                            "running": False,
                            "channels": ["desktop_action"],
                            "translatable_actions": [{"action": "launch", "label": "连接远程主机", "channel": "desktop_action"}],
                        },
                        {
                            "app_id": "gnome-system-monitor",
                            "display_name": "系统监视器",
                            "category": "hardware_system",
                            "install_source": "apt_dpkg",
                            "running": False,
                            "channels": ["desktop_action"],
                            "translatable_actions": [{"action": "launch", "label": "查看进程与资源", "channel": "desktop_action"}],
                        },
                    ]
                    _apply_deep_scan_result({"apps": smoke_apps, "total_apps": 9, "running_apps": 4, "translatable_actions_total": 18})
                    return

                deep_summary_lbl.set_text("⏳ 正在深度扫描本机全部 APT / Snap / Flatpak / 第三方软件与可转译接口…")
                btn_deep_scan_all.set_sensitive(False)

                def _w() -> None:
                    res_payload: dict[str, Any] | None = None
                    err_txt = ""
                    try:
                        r = call_module_rpc(
                            "app_adapter",
                            "deep_scan_local_software",
                            {"force_refresh": force_refresh},
                            timeout=20.0,
                        )
                        if r.get("ok") and isinstance(r.get("result"), dict):
                            res_payload = r["result"]
                        else:
                            err_txt = str(r.get("error") or "未返回分类扫描结果")
                    except Exception as exc:
                        err_txt = str(exc)

                    def _ui() -> bool:
                        btn_deep_scan_all.set_sensitive(True)
                        if res_payload is not None:
                            _apply_deep_scan_result(res_payload)
                        else:
                            deep_summary_lbl.set_text(f"⚠ 深度扫描暂未连接守护进程：{err_txt}")
                            _rebuild_deep_category_bar()
                        return False

                    GLib.idle_add(_ui)

                threading.Thread(target=_w, daemon=True).start()

            btn_deep_scan_all.connect("clicked", lambda _b: run_deep_local_software_scan(True))
            deep_search_entry.connect("changed", lambda _e: _render_deep_scan_app_cards())
            run_deep_local_software_scan(False)

            def _trigger_tray_menu_item(app_key: str, action_lbl: str, svc: str = "", mid: Any = None) -> None:
                if self.smoke_mode:
                    live_scan_status.set_text(f"✓ [smoke] 已触发托盘菜单: {app_key} → {action_lbl}")
                    return
                payload: dict[str, Any] = {
                    "app": app_key,
                    "app_hint": app_key,
                    "action": action_lbl,
                    "menu_label": action_lbl,
                }
                if svc:
                    payload["service"] = svc
                if mid is not None:
                    payload["menu_id"] = mid
                try:
                    res = call_module_rpc("app_adapter", "trigger_tray_menu", payload, timeout=8.0)
                    body = res.get("result", res)
                    ad_buf.set_text(json.dumps(body, ensure_ascii=False, indent=2))
                    ver_state = str(((body.get("verification") or {}) if isinstance(body, dict) else {}).get("state") or "")
                    if "Unverified" in ver_state or (isinstance(body, dict) and body.get("simulated") is True):
                        live_scan_status.set_text(f"⏳ 已发送请求（待桌面响应）: {app_key} → {action_lbl}")
                    elif res.get("ok"):
                        live_scan_status.set_text(f"✓ 已触发并验证托盘动作: {app_key} → {action_lbl}")
                    else:
                        live_scan_status.set_text(f"✕ 触发失败: {res.get('error')}")
                    refresh_live_tray_panel()
                except Exception as err:
                    live_scan_status.set_text(f"✕ 托盘菜单触发异常: {err}")

            def _render_inspected_app_card(ins: dict[str, Any], query_fallback: str = "") -> None:
                self._clear_box(inspect_result_box)
                card_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
                card_box.add_css_class("intentos-tray-card")

                ins_id = str(ins.get("app_id") or ins.get("id") or ins.get("desktop_id") or query_fallback or "custom_app")
                ins_name = str(ins.get("display_name") or ins.get("zh_name") or ins.get("name") or ins_id)
                ins_aliases = [str(a) for a in (ins.get("aliases") or []) if str(a).strip()]
                desk_id = str(ins.get("desktop_id") or ins.get("desktop_file") or "未发现 .desktop")
                exec_bin = str(
                    ins.get("exec_binary")
                    or ins.get("binary")
                    or ins.get("exec")
                    or ((ins.get("cli_executables") or [""])[0] if isinstance(ins.get("cli_executables"), list) else "")
                    or ins_id
                )
                pids = ins.get("pids") or ins.get("running_pids") or ([ins["pid"]] if ins.get("pid") else [])
                mpris_list = ins.get("mpris_services") or ([ins["mpris_service"]] if ins.get("mpris_service") else [])
                if isinstance(ins.get("mpris"), dict) and ins["mpris"].get("service"):
                    mpris_list = [ins["mpris"]["service"]]

                tray_menus = normalize_menu_items_settings(
                    ins.get("tray_menu_items")
                    or ins.get("dbusmenu_items")
                    or ins.get("menu_items")
                    or ((ins.get("tray") or {}).get("menu_items") if isinstance(ins.get("tray"), dict) else [])
                )
                desk_actions = ins.get("desktop_actions") or []
                uri_schemes = ins.get("uri_schemes") or []
                atspi_ctrls = ins.get("atspi_controls") or (
                    (ins.get("atspi") or {}).get("controls") if isinstance(ins.get("atspi"), dict) else []
                ) or []

                top_hdr = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                summary_lbl = Gtk.Label(
                    label=(
                        f"🔎 深度探测报告：{ins_name}  |  .desktop: {desk_id}  |  Exec: {Path(exec_bin.split()[0]).name if exec_bin else '未知'}  |  运行态 PID: {pids if pids else '未运行'}"
                    ),
                    xalign=0.0,
                )
                summary_lbl.add_css_class("intentos-section-header")
                summary_lbl.set_wrap(True)
                summary_lbl.set_hexpand(True)
                top_hdr.append(summary_lbl)

                default_chan = "sni_dbusmenu" if tray_menus else ("dbus_mpris" if mpris_list else ("uri_scheme" if uri_schemes else "gui_atspi"))
                default_act = "tray_action" if tray_menus else ("play_pause" if mpris_list else "activate_app")
                default_target = (
                    tray_menus[0]["label"]
                    if tray_menus
                    else (str(mpris_list[0]) if mpris_list else (f"{uri_schemes[0]}://" if uri_schemes else exec_bin))
                )
                btn_fill_main = Gtk.Button(label="✨ 填入自定义转译规则表单")
                btn_fill_main.add_css_class("intentos-primary-btn")
                btn_fill_main.connect(
                    "clicked",
                    lambda _b: _fill_custom_rule_form(
                        ins_id,
                        ins_name,
                        ins_aliases,
                        exec_bin,
                        default_chan,
                        default_act,
                        default_target,
                        f"打开{ins_name}, 控制{ins_name}{default_target}",
                    ),
                )
                self._page05_fill_btn = btn_fill_main
                top_hdr.append(btn_fill_main)
                card_box.append(top_hdr)

                # 1) Discovered StatusNotifierItem / dbusmenu items
                if tray_menus:
                    tm_lbl = Gtk.Label(
                        label=f"• StatusNotifierItem / dbusmenu 实时菜单项 ({len(tray_menus)} 项 — 点击「▶ 实测」立即触发，或点击「✨ 填入表单」绑定口令):",
                        xalign=0.0,
                    )
                    tm_lbl.add_css_class("intentos-muted-lbl")
                    card_box.append(tm_lbl)
                    tm_flow = Gtk.FlowBox()
                    tm_flow.set_selection_mode(Gtk.SelectionMode.NONE)
                    tm_flow.set_max_children_per_line(3)
                    tm_flow.set_column_spacing(6)
                    tm_flow.set_row_spacing(4)
                    for mi in tray_menus[:12]:
                        ml = str(mi.get("label") or "")
                        if not ml:
                            continue
                        pair_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
                        b_run = Gtk.Button(label=f"▶ {ml}")
                        b_run.add_css_class("intentos-tray-btn")
                        b_run.connect(
                            "clicked",
                            lambda _b, ak=ins_name, al=ml, mid=mi.get("id"): _trigger_tray_menu_item(ak, al, "", mid),
                        )
                        b_bind = Gtk.Button(label="✨ 填入表单")
                        b_bind.connect(
                            "clicked",
                            lambda _b, al=ml: _fill_custom_rule_form(
                                ins_id,
                                ins_name,
                                ins_aliases,
                                exec_bin,
                                "sni_dbusmenu",
                                f"tray_{al}",
                                al,
                                f"{ins_name}{al}, 帮我把{ins_name}{al}",
                            ),
                        )
                        pair_box.append(b_run)
                        pair_box.append(b_bind)
                        tm_flow.append(pair_box)
                    card_box.append(tm_flow)

                # 2) Discovered MPRIS2 / .desktop Actions / URI / AT-SPI2 summary & 1-click fill buttons
                extra_flow = Gtk.FlowBox()
                extra_flow.set_selection_mode(Gtk.SelectionMode.NONE)
                extra_flow.set_max_children_per_line(3)
                extra_flow.set_column_spacing(6)
                extra_flow.set_row_spacing(4)
                has_extra = False
                for mp in mpris_list[:2]:
                    has_extra = True
                    b_mp = Gtk.Button(label=f"🎵 MPRIS2 ({mp}) → ✨ 填入表单")
                    b_mp.connect(
                        "clicked",
                        lambda _b, m_srv=str(mp): _fill_custom_rule_form(
                            ins_id,
                            ins_name,
                            ins_aliases,
                            exec_bin,
                            "dbus_mpris",
                            "play_pause",
                            m_srv,
                            f"暂停{ins_name}, 播放{ins_name}",
                        ),
                    )
                    extra_flow.append(b_mp)
                for da in desk_actions[:4]:
                    da_name = str(da.get("name") or da.get("label") or da.get("id") or da) if isinstance(da, dict) else str(da)
                    da_exec = str(da.get("exec") or da_name) if isinstance(da, dict) else da_name
                    if da_name:
                        has_extra = True
                        b_da = Gtk.Button(label=f"📄 .desktop 动作 ({da_name}) → ✨ 填入表单")
                        b_da.connect(
                            "clicked",
                            lambda _b, dn=da_name, de=da_exec: _fill_custom_rule_form(
                                ins_id,
                                ins_name,
                                ins_aliases,
                                exec_bin,
                                "desktop_action",
                                f"desktop_{dn}",
                                de,
                                f"{ins_name}{dn}",
                            ),
                        )
                        extra_flow.append(b_da)
                for us in uri_schemes[:3]:
                    has_extra = True
                    b_us = Gtk.Button(label=f"🔗 URI ({us}://) → ✨ 填入表单")
                    b_us.connect(
                        "clicked",
                        lambda _b, u_s=str(us): _fill_custom_rule_form(
                            ins_id,
                            ins_name,
                            ins_aliases,
                            exec_bin,
                            "uri_scheme",
                            "open_uri",
                            f"{u_s}://",
                            f"唤起{ins_name}",
                        ),
                    )
                    extra_flow.append(b_us)
                for ctrl in atspi_ctrls[:4]:
                    c_name = str(ctrl.get("name") or ctrl.get("label") or ctrl) if isinstance(ctrl, dict) else str(ctrl)
                    if c_name:
                        has_extra = True
                        b_at = Gtk.Button(label=f"🪟 AT-SPI 控件 ({c_name}) → ✨ 填入表单")
                        b_at.connect(
                            "clicked",
                            lambda _b, cn=c_name: _fill_custom_rule_form(
                                ins_id,
                                ins_name,
                                ins_aliases,
                                exec_bin,
                                "gui_atspi",
                                f"click_{cn}",
                                cn,
                                f"点击{ins_name}的{cn}",
                            ),
                        )
                        extra_flow.append(b_at)
                if has_extra:
                    card_box.append(extra_flow)

                if not tray_menus and not has_extra:
                    fallback_note = Gtk.Label(
                        label="提示：该软件当前未暴露活动托盘菜单或 MPRIS，您仍可点击右上角「✨ 填入自定义转译规则表单」绑定快捷键、命令行参数或进程验证关闭规则。",
                        xalign=0.0,
                    )
                    fallback_note.add_css_class("intentos-muted-lbl")
                    fallback_note.set_wrap(True)
                    card_box.append(fallback_note)

                inspect_result_box.append(card_box)

            def inspect_live_app_by_query(app_q: str) -> None:
                q = app_q.strip() or inspect_app_entry.get_text().strip()
                if not q:
                    live_scan_status.set_text("请输入要深度探测的软件名（例如 汽水音乐 / FlClash / 飞书 / WPS 云盘）")
                    return
                inspect_app_entry.set_text(q)
                if self.smoke_mode:
                    _render_inspected_app_card(
                        {
                            "app_id": "sodam",
                            "display_name": "汽水音乐 SodaM",
                            "aliases": ["汽水音乐", "SodaMusic"],
                            "desktop_id": "sodam.desktop",
                            "exec_binary": "/opt/sodam/sodam",
                            "pids": [3108],
                            "mpris_services": ["org.mpris.MediaPlayer2.sodam"],
                            "tray_menu_items": ["暂停", "上一首", "下一首", "显示主窗口", "退出"],
                            "desktop_actions": [{"name": "NewWindow", "exec": "sodam --new-window"}],
                            "atspi_controls": ["播放/暂停按钮"],
                        },
                        q,
                    )
                    return
                try:
                    res = call_module_rpc(
                        "app_adapter",
                        "inspect_live_app",
                        {"app": q, "app_hint": q, "query": q},
                        timeout=9.0,
                    )
                    body = res.get("result", res)
                    ad_buf.set_text(json.dumps(body, ensure_ascii=False, indent=2))
                    if res.get("ok") and isinstance(body, dict):
                        _render_inspected_app_card(body, q)
                        live_scan_status.set_text(f"✓ 已完成「{q}」的托盘菜单 / MPRIS2 / .desktop / AT-SPI2 深度探测")
                    else:
                        live_scan_status.set_text(f"✕ 深度探测返回: {res.get('error', '未找到匹配软件')}")
                except Exception as err:
                    live_scan_status.set_text(f"✕ 深度探测失败: {err}")

            self._page05_inspect_fn = inspect_live_app_by_query

            def refresh_live_tray_panel() -> None:
                self._clear_box(tray_cards_box)
                if self.smoke_mode:
                    trays = normalize_live_tray_apps_settings(
                        {
                            "apps": [
                                {
                                    "app_id": "sodam",
                                    "display_name": "汽水音乐 SodaM",
                                    "live_title": "如果当时 · 许嵩",
                                    "menu_items": ["暂停", "上一首", "下一首", "显示主窗口", "退出"],
                                },
                                {
                                    "app_id": "wpscloud",
                                    "display_name": "WPS 云盘",
                                    "menu_items": ["启动 WPS Office", "查看传输详情", "退出"],
                                },
                            ]
                        }
                    )
                else:
                    trays = []
                    try:
                        r_tray = call_module_rpc("app_adapter", "list_live_tray_apps", {}, timeout=6.0)
                        if r_tray.get("ok"):
                            trays = normalize_live_tray_apps_settings(r_tray.get("result"))
                    except Exception:
                        trays = []

                if not trays:
                    empty_lbl = Gtk.Label(
                        label="当前暂无暴露 StatusNotifierItem / dbusmenu 的运行态托盘软件（可在上方输入框探测任意已安装应用）。",
                        xalign=0.0,
                    )
                    empty_lbl.add_css_class("intentos-muted-lbl")
                    empty_lbl.set_wrap(True)
                    tray_cards_box.append(empty_lbl)
                    return

                for tr in trays[:8]:
                    tc = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
                    tc.add_css_class("intentos-tray-card")
                    hdr = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                    app_nm = str(tr.get("name") or tr.get("app_id") or "托盘软件")
                    live_t = str(tr.get("live_title") or "").strip()
                    h_lbl = Gtk.Label(
                        label=f"🟢 {app_nm}" + (f" · {live_t}" if live_t else ""),
                        xalign=0.0,
                    )
                    h_lbl.add_css_class("intentos-section-header")
                    h_lbl.set_hexpand(True)
                    hdr.append(h_lbl)

                    b_insp = Gtk.Button(label="🔍 深度探测")
                    b_insp.add_css_class("intentos-tray-btn")
                    b_insp.connect("clicked", lambda _b, q=app_nm: inspect_live_app_by_query(q))
                    hdr.append(b_insp)
                    tc.append(hdr)

                    m_items = tr.get("menu_items") or []
                    if m_items:
                        m_flow = Gtk.FlowBox()
                        m_flow.set_selection_mode(Gtk.SelectionMode.NONE)
                        m_flow.set_max_children_per_line(6)
                        m_flow.set_column_spacing(4)
                        m_flow.set_row_spacing(4)
                        svc = str(tr.get("service") or "")
                        ak = str(tr.get("app_id") or app_nm)
                        for mi in m_items[:10]:
                            ml = str(mi.get("label") or "")
                            if not ml:
                                continue
                            mb = Gtk.Button(label=ml)
                            mb.add_css_class("intentos-tray-btn")
                            mb.set_sensitive(bool(mi.get("enabled", True)))
                            mb.connect(
                                "clicked",
                                lambda _b, k=ak, l=ml, s=svc, mid=mi.get("id"): _trigger_tray_menu_item(k, l, s, mid),
                            )
                            m_flow.append(mb)
                        tc.append(m_flow)
                    tray_cards_box.append(tc)

            def _select_app_into_form(app_obj: dict[str, Any]) -> None:
                aid = str(app_obj.get("id") or app_obj.get("app_id") or "")
                aname = str(app_obj.get("display_name") or app_obj.get("name") or aid)
                aliases = app_obj.get("aliases") or []
                full_names = ", ".join([aname, *[str(a) for a in aliases[:3] if str(a) != aname]])
                bins = app_obj.get("cli_executables") or []
                bin_name = str(
                    app_obj.get("binary")
                    or app_obj.get("binary_name")
                    or (bins[0] if isinstance(bins, list) and bins else aid)
                )
                if aid:
                    f_app_id.set_text(aid)
                if full_names:
                    f_app_name.set_text(full_names)
                if bin_name:
                    f_binary.set_text(Path(bin_name).name)
                inspect_app_entry.set_text(aname or aid)
                ad_status.set_text(f"已载入软件「{aname}」({aid})，可点击上方「🔍 深度探测该软件可转译能力」获取实时托盘菜单项。")

            def load_personal_adapters(query_str: str = "") -> None:
                if self.smoke_mode:
                    _select_app_into_form({"id": "sodam", "name": "SodaM", "aliases": ["汽水音乐"], "binary": "sodam"})
                    refresh_live_tray_panel()
                    inspect_live_app_by_query("汽水音乐")
                    return
                items: list[dict[str, Any]] = []
                raw_dump: Any = {}
                try:
                    payload = {"query": query_str} if query_str else {}
                    r1 = call_module_rpc("app_adapter", "discover_personal_apps", payload, timeout=6.0)
                    if r1.get("ok") and r1.get("result") is not None:
                        raw_dump = r1["result"]
                        if isinstance(raw_dump, dict):
                            items = raw_dump.get("apps") or raw_dump.get("adapters") or []
                        elif isinstance(raw_dump, list):
                            items = raw_dump
                except Exception:
                    items = []

                if not items:
                    try:
                        payload = {"query": query_str} if query_str else {}
                        r2 = call_module_rpc("app_adapter", "list_adapters", payload, timeout=6.0)
                        raw_dump = r2.get("result", r2)
                        if isinstance(raw_dump, dict):
                            items = raw_dump.get("adapters") or []
                        elif isinstance(raw_dump, list):
                            items = raw_dump
                    except Exception as err:
                        ad_buf.set_text(f"读取软件转译中心失败: {err}")
                        return

                def _priority_key(x: dict[str, Any]) -> tuple[int, str]:
                    blob = json.dumps(x, ensure_ascii=False).lower()
                    is_star = any(
                        k in blob
                        for k in ("sodam", "汽水", "flclash", "wps", "feishu", "飞书", "qq", "wechat", "betternotes", "轻笺", "custom", "music")
                    )
                    return (0 if is_star else 1, str(x.get("name") or x.get("id") or ""))

                dict_items = [x for x in items if isinstance(x, dict)]
                dict_items.sort(key=_priority_key)

                self._clear_flowbox(apps_flow)
                for app_entry in dict_items[:32]:
                    nm = str(app_entry.get("display_name") or app_entry.get("name") or app_entry.get("id") or "App")
                    chans = app_entry.get("channels") or []
                    ch_tag = chans[0] if isinstance(chans, list) and chans else app_entry.get("source", "desktop")
                    lbl_chip = f"⚡ {nm} [{ch_tag}]" if len(nm) <= 16 else f"⚡ {nm[:14]}… [{ch_tag}]"
                    b_chip = Gtk.Button(label=lbl_chip)
                    b_chip.connect("clicked", lambda _b, obj=app_entry: _select_app_into_form(obj))
                    apps_flow.append(b_chip)

                ad_buf.set_text(json.dumps(raw_dump, ensure_ascii=False, indent=2))
                ad_status.set_text(f"✓ 已剖析 {len(dict_items)} 款桌面与个性化软件（点击软件标签可载入表单或深度探测接口）")

            def on_save_custom_rule(_b: Any) -> None:
                aid = f_app_id.get_text().strip() or "custom-app"
                raw_names = [x.strip() for x in re.split(r"[,，]", f_app_name.get_text()) if x.strip()]
                disp_name = raw_names[0] if raw_names else aid
                aliases = raw_names[1:] if len(raw_names) > 1 else []
                bin_name = f_binary.get_text().strip() or aid
                ch_idx = int(f_chan_dd.get_selected())
                chan_enum = ADAPTER_CHANNELS[ch_idx][0] if 0 <= ch_idx < len(ADAPTER_CHANNELS) else "sni_dbusmenu"
                short_chan_map = {
                    "sni_dbusmenu": "sni_dbusmenu",
                    "dbus_mpris": "mpris",
                    "dbus_freedesktop": "dbus_freedesktop",
                    "desktop_action": "desktop_action",
                    "uri_scheme": "uri",
                    "gui_atspi": "shortcut",
                    "cli_wrapper": "argv",
                }
                act_name = f_action_name.get_text().strip() or "custom_action"
                phrase_list = [x.strip() for x in re.split(r"[,，]", f_phrase_aliases.get_text()) if x.strip()]
                action_aliases = list(dict.fromkeys([act_name, *phrase_list]))
                target_str = f_target_cmd.get_text().strip()
                req_appr = bool(f_req_approval.get_active())

                payload = {
                    "id": aid,
                    "app_id": aid,
                    "name": disp_name,
                    "display_name": disp_name,
                    "aliases": aliases,
                    "phrase_aliases": phrase_list,
                    "binary": bin_name,
                    "binary_name": bin_name,
                    "channel": short_chan_map.get(chan_enum, chan_enum),
                    "channels": [chan_enum],
                    "cli_executables": [bin_name],
                    "mpris_bus_hints": [target_str] if chan_enum == "dbus_mpris" and target_str else [aid],
                    "uri_schemes": [target_str.split("://")[0]] if "://" in target_str else [],
                    "requires_approval": req_appr,
                    "custom_actions": {
                        act_name: {
                            "channel": short_chan_map.get(chan_enum, chan_enum),
                            "command_or_target": target_str,
                            "menu_label": target_str if chan_enum == "sni_dbusmenu" else None,
                            "aliases": action_aliases,
                            "phrase_aliases": phrase_list,
                            "requires_approval": req_appr,
                        }
                    },
                    "supported_actions": [
                        {
                            "action": act_name,
                            "aliases": action_aliases,
                            "channel": chan_enum,
                            "summary": f"{disp_name} 自定义动作 ({act_name} → {target_str})",
                            "target_template": target_str or None,
                            "requires_approval": req_appr,
                            "reversible": False,
                        }
                    ],
                    "source": "custom",
                }
                try:
                    res = call_module_rpc("app_adapter", "save_custom_adapter", payload, timeout=6.0)
                    if res.get("ok"):
                        ad_status.set_text(
                            f"✓ 已保存「{disp_name}」({aid}) 个性化口令转译规则（口令: {', '.join(action_aliases[:3])}）"
                        )
                        load_personal_adapters(ad_query_e.get_text().strip())
                    else:
                        ad_status.set_text(f"保存返回: {res.get('error')}")
                except Exception as err:
                    ad_status.set_text(f"保存失败: {err}")

            def on_del_custom_rule(_b: Any) -> None:
                aid = f_app_id.get_text().strip()
                if not aid:
                    return
                try:
                    res = call_module_rpc(
                        "app_adapter", "delete_custom_adapter", {"id": aid, "app_id": aid}, timeout=6.0
                    )
                    ad_status.set_text(
                        f"✓ 已删除自定义规则 {aid}" if res.get("ok") else f"删除返回: {res.get('error')}"
                    )
                    load_personal_adapters(ad_query_e.get_text().strip())
                except Exception as err:
                    ad_status.set_text(f"删除失败: {err}")

            def on_test_close_app(_b: Any) -> None:
                target_app = f_app_id.get_text().strip() or f_binary.get_text().strip()
                if not target_app:
                    return
                try:
                    res = call_module_rpc(
                        "app_adapter",
                        "close_app_verified",
                        {"app_query": target_app, "app_hint": target_app, "force_kill_approved": False},
                        timeout=8.0,
                    )
                    if not res.get("ok"):
                        res = call_module_rpc(
                            "app_adapter",
                            "translate_and_execute",
                            {"app_hint": target_app, "intent_action": "quit", "params": {}, "approved": True},
                            timeout=8.0,
                        )
                    r_body = res.get("result", res)
                    ad_buf.set_text(json.dumps(r_body, ensure_ascii=False, indent=2))
                    summary = r_body.get("summary") if isinstance(r_body, dict) else str(r_body)
                    ad_status.set_text(f"🛑 关闭验证结果: {summary}")
                except Exception as err:
                    ad_status.set_text(f"测试关闭失败: {err}")

            def on_test_custom_action(_b: Any) -> None:
                aid = f_app_id.get_text().strip()
                ch_idx = int(f_chan_dd.get_selected())
                chan_enum = ADAPTER_CHANNELS[ch_idx][0] if 0 <= ch_idx < len(ADAPTER_CHANNELS) else "sni_dbusmenu"
                target_val = f_target_cmd.get_text().strip()
                if chan_enum == "sni_dbusmenu" and target_val:
                    _trigger_tray_menu_item(aid, target_val)
                    return
                act = f_action_name.get_text().strip() or "get_now_playing"
                try:
                    res = call_module_rpc(
                        "app_adapter",
                        "translate_and_execute",
                        {"app_hint": aid, "intent_action": act, "params": {}, "approved": True},
                        timeout=8.0,
                    )
                    r_body = res.get("result", res)
                    ad_buf.set_text(json.dumps(r_body, ensure_ascii=False, indent=2))
                    summary = r_body.get("summary") if isinstance(r_body, dict) else str(r_body)
                    ad_status.set_text(f"▶ 动作实测结果: {summary}")
                except Exception as err:
                    ad_status.set_text(f"动作测试失败: {err}")

            def on_probe_live_apps(_b: Any) -> None:
                refresh_live_tray_panel()
                try:
                    res = call_module_rpc("app_adapter", "probe_live_controllable_apps", {}, timeout=6.0)
                    ad_buf.set_text(json.dumps(res.get("result", res), ensure_ascii=False, indent=2))
                    ad_status.set_text("✓ 已完成实时托盘菜单、MPRIS2 播放器、D-Bus 应用与桌面窗口探测")
                except Exception as err:
                    ad_status.set_text(f"实时探测失败: {err}")

            btn_deep_inspect.connect("clicked", lambda _b: inspect_live_app_by_query(inspect_app_entry.get_text()))
            inspect_app_entry.connect("activate", lambda _e: inspect_live_app_by_query(inspect_app_entry.get_text()))
            btn_refresh_tray.connect("clicked", lambda _b: refresh_live_tray_panel())
            btn_discover_apps.connect("clicked", lambda _b: load_personal_adapters(ad_query_e.get_text().strip()))
            ad_query_e.connect("activate", lambda _e: load_personal_adapters(ad_query_e.get_text().strip()))
            btn_probe_live.connect("clicked", on_probe_live_apps)
            btn_save_rule.connect("clicked", on_save_custom_rule)
            btn_del_rule.connect("clicked", on_del_custom_rule)
            btn_test_close.connect("clicked", on_test_close_app)
            btn_test_action.connect("clicked", on_test_custom_action)
            if not self.smoke_mode:
                refresh_live_tray_panel()
            load_personal_adapters("")

            # Card 1: Composite Scenes
            card_sc = self._make_card("组合场景模式 (§7.8.3)")
            sc_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            sc_status = Gtk.Label(label="", xalign=0.0)
            for sc_name in ("护眼模式", "演示模式", "安静模式", "会议模式", "专注模式"):
                b = Gtk.Button(label=f"进入{sc_name}")
                b.connect(
                    "clicked",
                    lambda _btn, sn=sc_name: (
                        call_ui_rpc("submit_intent", {"protocol_version": 1, "text": f"进入{sn}", "incognito": False}),
                        sc_status.set_text(f"✓ 已激活场景：{sn}"),
                    ),
                )
                sc_row.append(b)
            custom_sc_entry = Gtk.Entry(placeholder_text="新场景名称 (如 深夜编码模式)")
            save_sc_btn = Gtk.Button(label="+ 保存当前状态为场景")
            save_sc_btn.connect(
                "clicked",
                lambda _b: (
                    call_ui_rpc("save_scene", {"name": custom_sc_entry.get_text().strip() or "自定义场景"}),
                    sc_status.set_text("✓ 已快照保存当前系统设置为自定义场景"),
                ),
            )
            sc_row.append(custom_sc_entry)
            sc_row.append(save_sc_btn)
            card_sc.append(sc_row)
            card_sc.append(sc_status)
            page.append(card_sc)

            # Card 2: 87+ Capability Descriptors
            card_caps = self._make_card("系统能力注册表与效应等级 (87+ Capability Descriptors)")
            caps_buf = Gtk.TextBuffer()
            if not self.smoke_mode:
                try:
                    pr = call_ui_rpc("probe_capabilities", timeout=4.0).get("result", {})
                    caps_buf.set_text(json.dumps(pr.get("capabilities", [])[:40], ensure_ascii=False, indent=2))
                except Exception:
                    pass
            caps_sw, _ = self._make_scrolled_textview(caps_buf, editable=False, min_height=150)
            card_caps.append(caps_sw)
            page.append(card_caps)
            stack.add_titled(scroll, "capabilities", "5. 本机软件深度扫描与分类转译中心")

        # ------------------------------------------------------------------
        # Page 6: 资源与项目 (Resources & Projects)
        # ------------------------------------------------------------------
        def _build_page_06_resources(self, stack: Gtk.Stack) -> None:
            scroll, page = self._make_scrolled_page(
                "6. 资源与项目 (Resources & Git Projects)",
                "管理全局用户目录索引（自动支持中文 桌面/文档/下载 与 XDG 目录）及自动发现本地 Git 代码仓库（R-05）。",
            )
            rcfg = self.ov.get("resources", {})
            card_dirs = self._make_card(
                f"授权文件目录（已索引 {rcfg.get('indexed_apps', 0)} 应用 · {rcfg.get('indexed_files', 0)} 文件 · {rcfg.get('indexed_fonts', 0)} 字体）"
            )
            dirs_buf = Gtk.TextBuffer()
            dirs_buf.set_text("\n".join(rcfg.get("authorized_directories", [])))
            dirs_sw, _ = self._make_scrolled_textview(dirs_buf, editable=True, min_height=120)
            card_dirs.append(dirs_sw)

            save_dirs_btn = Gtk.Button(label="💾 保存授权目录并重建索引")
            save_dirs_btn.add_css_class("intentos-primary-btn")
            res_status = Gtk.Label(label="", xalign=0.0)

            def on_save_dirs(_b: Any) -> None:
                start_it, end_it = dirs_buf.get_bounds()
                lines = [x.strip() for x in dirs_buf.get_text(start_it, end_it, False).splitlines() if x.strip()]
                r = call_ui_rpc("update_authorized_directories", {"directories": lines})
                call_ui_rpc("reindex_resources")
                res_status.set_text(
                    r.get("result", {}).get("message", "✓ 已保存并重建索引") if r.get("ok") else str(r.get("error"))
                )

            save_dirs_btn.connect("clicked", on_save_dirs)
            card_dirs.append(save_dirs_btn)
            card_dirs.append(res_status)
            page.append(card_dirs)

            card_proj = self._make_card("已发现的 Git 项目仓库 (R-05)")
            proj_buf = Gtk.TextBuffer()
            proj_sw, _ = self._make_scrolled_textview(proj_buf, editable=False, min_height=140)
            rescan_proj_btn = Gtk.Button(label="🔍 重新扫描授权目录下的 Git 仓库")

            def load_projects(rescan: bool = False) -> None:
                if self.smoke_mode:
                    return
                try:
                    pr = call_module_rpc("execution_hub", "list_projects", {"rescan": rescan}, timeout=5.0)
                    proj_buf.set_text(json.dumps(pr.get("result", []), ensure_ascii=False, indent=2))
                except Exception as err:
                    proj_buf.set_text(f"读取项目列表失败: {err}")

            rescan_proj_btn.connect("clicked", lambda _b: load_projects(True))
            card_proj.append(rescan_proj_btn)
            card_proj.append(proj_sw)
            page.append(card_proj)
            load_projects(False)
            stack.add_titled(scroll, "resources", "6. 资源与项目")

        # ------------------------------------------------------------------
        # Page 7: 网站与搜索 (Web & Search)
        # ------------------------------------------------------------------
        def _build_page_07_web(self, stack: Gtk.Stack) -> None:
            scroll, page = self._make_scrolled_page(
                "7. 网站与搜索 (Web & Search Shortcuts)",
                "配置默认搜索引擎、自定义站点直达别名与站内搜索模板（仅限 http/https），以及浏览器书签索引授权（§4.7）。",
            )
            wcfg = self.ov.get("web", {})
            card_se = self._make_card("默认搜索引擎与浏览器配置")
            se_entry = Gtk.Entry(text=str(wcfg.get("default_search", "google")))
            browser_entry = Gtk.Entry(text=str(wcfg.get("open_with", "default")))
            bm_check = Gtk.CheckButton(label="授权只读索引浏览器书签 (R-10)")
            hist_check = Gtk.CheckButton(label="授权本地匹配浏览器历史记录 (R-11，敏感数据永不外发)")
            card_se.append(Gtk.Label(label="默认搜索引擎 ID (google / bing / baidu / duckduckgo):", xalign=0.0))
            card_se.append(se_entry)
            card_se.append(Gtk.Label(label="打开网页浏览器 (default / firefox / chromium / brave):", xalign=0.0))
            card_se.append(browser_entry)
            card_se.append(bm_check)
            card_se.append(hist_check)

            save_se_btn = Gtk.Button(label="💾 保存搜索引擎与浏览器设置")
            web_status = Gtk.Label(label="", xalign=0.0)

            def on_save_se(_b: Any) -> None:
                se_id = se_entry.get_text().strip()
                r = call_ui_rpc("update_web_settings", {"default_search": se_id})
                call_module_rpc(
                    "config_center",
                    "update_domain",
                    {
                        "domain_key": "web",
                        "data": {
                            "default_search": se_id,
                            "open_with": browser_entry.get_text().strip(),
                            "bookmark_index_enabled": bm_check.get_active(),
                            "history_index_enabled": hist_check.get_active(),
                        },
                    },
                )
                web_status.set_text("✓ 已更新默认搜索引擎与浏览器设置" if r.get("ok") else f"错误: {r.get('error')}")

            save_se_btn.connect("clicked", on_save_se)
            card_se.append(save_se_btn)
            card_se.append(web_status)
            page.append(card_se)

            card_sites = self._make_card("自定义网站别名与站内搜索模板 CRUD")
            site_id_e = Gtk.Entry(placeholder_text="站点 ID (如 rust-docs)")
            site_names_e = Gtk.Entry(placeholder_text="触发别名，逗号分隔 (如 docs.rs,rust文档)")
            site_url_e = Gtk.Entry(placeholder_text="主页 URL (https://docs.rs)")
            site_search_e = Gtk.Entry(placeholder_text="站内搜索模板 (https://docs.rs/releases/search?query={query})")
            site_btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            btn_upsert_site = Gtk.Button(label="+ 添加/更新站点别名")
            btn_del_site = Gtk.Button(label="🗑 删除站点")
            site_btn_row.append(btn_upsert_site)
            site_btn_row.append(btn_del_site)

            for w in (site_id_e, site_names_e, site_url_e, site_search_e, site_btn_row):
                card_sites.append(w)

            def on_upsert_site(_b: Any) -> None:
                res = call_module_rpc(
                    "config_center",
                    "upsert_site_shortcut",
                    {
                        "site": {
                            "id": site_id_e.get_text().strip(),
                            "names": [x.strip() for x in site_names_e.get_text().split(",") if x.strip()],
                            "url": site_url_e.get_text().strip(),
                            "search": site_search_e.get_text().strip() or None,
                        }
                    },
                )
                web_status.set_text("✓ 已保存站点快捷方式" if res.get("ok") else f"拦截: {res.get('error')}")

            def on_del_site(_b: Any) -> None:
                res = call_module_rpc(
                    "config_center",
                    "delete_site_shortcut",
                    {"site_id": site_id_e.get_text().strip()},
                )
                web_status.set_text("✓ 已删除站点" if res.get("ok") else f"错误: {res.get('error')}")

            btn_upsert_site.connect("clicked", on_upsert_site)
            btn_del_site.connect("clicked", on_del_site)
            page.append(card_sites)
            stack.add_titled(scroll, "web", "7. 网站与搜索")

        # ------------------------------------------------------------------
        # Page 8: 权限与安全 (Permissions, GrantEnvelopes & Audit)
        # ------------------------------------------------------------------
        def _build_page_08_permissions(self, stack: Gtk.Stack) -> None:
            scroll, page = self._make_scrolled_page(
                "8. 权限与安全 (Security Mode, GrantEnvelopes & Audit)",
                "统一管理安全防护模式、会话范围授权（Session Scope Grants）、多步任务包络（GrantEnvelope）与策略审计日志。",
            )
            page.append(self._build_security_posture_card())

            pcfg = self.ov.get("permissions_and_undo", {})
            card_env = self._make_card("多步授权包络与渐进信任规则 (§10.3)")
            env_buf = Gtk.TextBuffer()
            env_sw, _ = self._make_scrolled_textview(env_buf, editable=False, min_height=140)
            card_env.append(env_sw)

            act_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            rule_id_e = Gtk.Entry(placeholder_text="提议 ID / 授权包络 ID")
            btn_confirm_rule = Gtk.Button(label="✓ 确认渐进信任规则")
            btn_revoke_rule = Gtk.Button(label="✕ 撤销包络或规则")
            perm_status = Gtk.Label(label="", xalign=0.0)
            act_row.append(rule_id_e)
            act_row.append(btn_confirm_rule)
            act_row.append(btn_revoke_rule)
            act_row.append(perm_status)
            card_env.append(act_row)
            page.append(card_env)

            def load_envelopes() -> None:
                if self.smoke_mode:
                    return
                try:
                    r = call_module_rpc("execution_hub", "list_envelopes_and_rules", {}, timeout=4.0)
                    env_buf.set_text(json.dumps(r.get("result", {}), ensure_ascii=False, indent=2))
                except Exception as err:
                    env_buf.set_text(f"读取授权包络失败: {err}")

            btn_confirm_rule.connect(
                "clicked",
                lambda _b: (
                    call_module_rpc("execution_hub", "confirm_rule_proposal", {"proposal_id": rule_id_e.get_text().strip()}),
                    load_envelopes(),
                    perm_status.set_text("✓ 已确认长期信任规则"),
                ),
            )
            btn_revoke_rule.connect(
                "clicked",
                lambda _b: (
                    call_module_rpc("execution_hub", "revoke_grant_or_rule", {"id": rule_id_e.get_text().strip()}),
                    load_envelopes(),
                    perm_status.set_text("✓ 已撤销指定授权或规则"),
                ),
            )
            load_envelopes()

            card_audit = self._make_card("最近安全策略审计日志 (Audit Trail)")
            audit_buf = Gtk.TextBuffer()
            audit_buf.set_text(json.dumps(pcfg.get("recent_audit", [])[:15], ensure_ascii=False, indent=2))
            audit_sw, _ = self._make_scrolled_textview(audit_buf, editable=False, min_height=150)
            card_audit.append(audit_sw)
            page.append(card_audit)
            stack.add_titled(scroll, "permissions", "8. 权限与安全")

        # ------------------------------------------------------------------
        # Page 9: 撤销与备份 (Undo & Backup)
        # ------------------------------------------------------------------
        def _build_page_09_undo(self, stack: Gtk.Stack) -> None:
            scroll, page = self._make_scrolled_page(
                "9. 撤销与备份 (ChangeSet Undo & Backup Quota)",
                "配置可逆操作备份区配额（默认 4 GB / 30 天），浏览全部可撤销变更集（ChangeSets）并执行一键回滚。",
            )
            pcfg = self.ov.get("permissions_and_undo", {})
            card_q = self._make_card(
                f"备份区配额与占用（当前可撤销变更集: {pcfg.get('undo_changesets_available', 0)} 个 · 已用 {pcfg.get('undo_backup_bytes', 0)} Bytes）"
            )
            quota_e = Gtk.Entry(text=str(pcfg.get("undo_quota_gb", 4)))
            ret_e = Gtk.Entry(text=str(pcfg.get("undo_retention_days", 30)))
            card_q.append(Gtk.Label(label="备份区容量上限 (GB):", xalign=0.0))
            card_q.append(quota_e)
            card_q.append(Gtk.Label(label="变更集保留天数 (Days):", xalign=0.0))
            card_q.append(ret_e)

            btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            btn_save_undo = Gtk.Button(label="💾 保存备份配额")
            btn_undo_latest = Gtk.Button(label="↶ 立即撤销最近一次变更")
            btn_undo_latest.add_css_class("intentos-primary-btn")
            undo_status = Gtk.Label(label="", xalign=0.0)
            btn_row.append(btn_save_undo)
            btn_row.append(btn_undo_latest)
            btn_row.append(undo_status)
            card_q.append(btn_row)
            page.append(card_q)

            card_cs = self._make_card("最近变更集历史 (ChangeSets)")
            cs_buf = Gtk.TextBuffer()
            cs_buf.set_text(json.dumps(pcfg.get("recent_changesets", [])[:15], ensure_ascii=False, indent=2))
            cs_sw, _ = self._make_scrolled_textview(cs_buf, editable=False, min_height=180)
            card_cs.append(cs_sw)
            page.append(card_cs)

            def on_save_undo(_b: Any) -> None:
                call_module_rpc(
                    "config_center",
                    "update_domain",
                    {
                        "domain_key": "undo",
                        "data": {
                            "quota_gb": int(quota_e.get_text().strip() or "4"),
                            "retention_days": int(ret_e.get_text().strip() or "30"),
                        },
                    },
                )
                undo_status.set_text("✓ 已更新备份区配额设置")

            def on_undo_now(_b: Any) -> None:
                r = call_ui_rpc("undo", {"target_id": None})
                undo_status.set_text(
                    f"↶ {r['result'].get('message', '已撤销')}" if r.get("ok") else f"无法撤销: {r.get('error')}"
                )

            btn_save_undo.connect("clicked", on_save_undo)
            btn_undo_latest.connect("clicked", on_undo_now)
            stack.add_titled(scroll, "undo", "9. 撤销与备份")

        # ------------------------------------------------------------------
        # Page 10: 自动化与驱动 (Automation & Drive Engine)
        # ------------------------------------------------------------------
        def _build_page_10_automation(self, stack: Gtk.Stack) -> None:
            scroll, page = self._make_scrolled_page(
                "10. 自动化与驱动 (Drive Engine & Autonomy Level)",
                "配置全局自主性等级（L0 手动 / L1 建议 / L2 授权自动），管理定时与文件系统事件触发规则（§13.3–§13.4）。",
            )
            card_auto = self._make_card("全局自主性等级与事件触发器")
            autonomy_e = Gtk.Entry(text="L1_Suggest")
            card_auto.append(Gtk.Label(label="全局自主性等级 (L0_Manual / L1_Suggest / L2_Authorized_Auto):", xalign=0.0))
            card_auto.append(autonomy_e)

            trig_buf = Gtk.TextBuffer()
            trig_sw, _ = self._make_scrolled_textview(trig_buf, editable=False, min_height=140)
            card_auto.append(trig_sw)

            sim_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            rule_id_e = Gtk.Entry(text="research.pdf-arrival")
            sample_path_e = Gtk.Entry(text="~/Downloads/trajectory_prediction_2026.pdf")
            btn_dry_run = Gtk.Button(label="🧪 模拟触发事件 (Dry-Run)")
            auto_status = Gtk.Label(label="", xalign=0.0)
            sim_row.append(rule_id_e)
            sim_row.append(sample_path_e)
            sim_row.append(btn_dry_run)
            card_auto.append(sim_row)
            card_auto.append(auto_status)
            page.append(card_auto)

            def load_triggers() -> None:
                if self.smoke_mode:
                    return
                try:
                    r = call_module_rpc("execution_hub", "list_drive_triggers", {}, timeout=4.0)
                    trig_buf.set_text(json.dumps(r.get("result", {}), ensure_ascii=False, indent=2))
                except Exception as err:
                    trig_buf.set_text(f"读取触发器失败: {err}")

            def on_dry_run(_b: Any) -> None:
                r = call_module_rpc(
                    "execution_hub",
                    "trigger_dry_run",
                    {
                        "rule_id": rule_id_e.get_text().strip(),
                        "sample_path": sample_path_e.get_text().strip(),
                    },
                )
                if r.get("ok"):
                    auto_status.set_text(f"✓ 模拟触发完成: {json.dumps(r.get('result', {}), ensure_ascii=False)[:120]}")
                else:
                    auto_status.set_text(f"模拟错误: {r.get('error')}")

            btn_dry_run.connect("clicked", on_dry_run)
            load_triggers()
            stack.add_titled(scroll, "automation", "10. 自动化与驱动")

        # ------------------------------------------------------------------
        # Page 11: 交互与维护 (Interaction & Maintenance)
        # ------------------------------------------------------------------
        def _build_page_11_maintenance(self, stack: Gtk.Stack) -> None:
            scroll, page = self._make_scrolled_page(
                "11. 交互与维护 (Hotkeys, Debug Transcript & Config Export/Import)",
                "检测全局唤起热键与中文输入法冲突（§3.1），管理 7 天自动清理的调试转录，以及导出/导入不含凭据的配置包。",
            )
            rcfg = self.ov.get("resources", {})
            card_hk = self._make_card("全局唤起快捷键与输入法冲突检测 (§3.1)")
            hk_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            hk_entry = Gtk.Entry(text=str(rcfg.get("hotkey", "<Super><Shift>space")))
            hk_entry.set_hexpand(True)
            btn_check_hk = Gtk.Button(label="🔍 检测热键冲突")
            hk_status = Gtk.Label(label="", xalign=0.0)
            hk_row.append(hk_entry)
            hk_row.append(btn_check_hk)
            card_hk.append(hk_row)
            card_hk.append(hk_status)

            def on_check_hk(_b: Any) -> None:
                hk = hk_entry.get_text().strip()
                try:
                    res = call_module_rpc("config_center", "check_hotkey_conflict", {"hotkey": hk})
                    if res.get("ok"):
                        r = res["result"]
                        hk_status.set_text(
                            f"检测结果: conflict={r.get('has_conflict', r.get('conflict'))} — {r.get('message') or r.get('recommendation', '')}"
                        )
                        return
                except Exception:
                    pass
                if hk.lower() in ("<super>space", "super+space"):
                    hk_status.set_text("⚠ 冲突警告：<Super>space 与 Ubuntu/IBus 中文输入法切换冲突，强烈建议使用 <Super><Shift>space")
                else:
                    hk_status.set_text(f"✓ 快捷键 {hk} 无已知系统冲突")

            btn_check_hk.connect("clicked", on_check_hk)
            page.append(card_hk)

            card_maint = self._make_card("开发者调试模式与无密钥配置包导入/导出 (§5.6, §6.4, M-08)")
            dbg_switch = Gtk.CheckButton(label="开启开发者调试模型交互转录 (record_transcripts，7 天后自动清理)")
            card_maint.append(dbg_switch)

            bundle_buf = Gtk.TextBuffer()
            bundle_sw, _ = self._make_scrolled_textview(bundle_buf, editable=True, min_height=150)

            maint_btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            btn_export = Gtk.Button(label="📤 导出无密钥配置包")
            btn_import = Gtk.Button(label="📥 导入配置包")
            btn_reset = Gtk.Button(label="↺ 恢复默认配置")
            btn_reset.add_css_class("intentos-danger-btn")
            maint_status = Gtk.Label(label="", xalign=0.0)
            maint_btn_row.append(btn_export)
            maint_btn_row.append(btn_import)
            maint_btn_row.append(btn_reset)
            card_maint.append(maint_btn_row)
            card_maint.append(bundle_sw)
            card_maint.append(maint_status)
            page.append(card_maint)

            def on_export(_b: Any) -> None:
                res = call_module_rpc("config_center", "export_config_bundle", {})
                if res.get("ok"):
                    bundle_buf.set_text(json.dumps(res["result"], ensure_ascii=False, indent=2))
                    maint_status.set_text("✓ 已导出脱敏配置包（不含任何 API Key 与私密凭据）")
                else:
                    maint_status.set_text(f"导出失败: {res.get('error')}")

            def on_import(_b: Any) -> None:
                start_it, end_it = bundle_buf.get_bounds()
                raw = bundle_buf.get_text(start_it, end_it, False).strip()
                if not raw:
                    return
                try:
                    parsed = json.loads(raw)
                    bundle_obj = parsed.get("bundle", parsed)
                    res = call_module_rpc("config_center", "import_config_bundle", {"bundle": bundle_obj})
                    maint_status.set_text("✓ 配置包导入成功" if res.get("ok") else f"导入拒绝: {res.get('error')}")
                except Exception as err:
                    maint_status.set_text(f"JSON 格式错误: {err}")

            def on_reset(_b: Any) -> None:
                res = call_module_rpc("config_center", "reset_to_defaults", {"domain_key": "all"})
                maint_status.set_text("✓ 已恢复安全出厂默认设置" if res.get("ok") else f"错误: {res.get('error')}")

            btn_export.connect("clicked", on_export)
            btn_import.connect("clicked", on_import)
            btn_reset.connect("clicked", on_reset)
            stack.add_titled(scroll, "maintenance", "11. 交互与维护")

    if smoke_ui:
        app = SettingsCenterApp(is_smoke=True)
        app._load_css()
        if app.css_errors:
            print(f"[smoke-ui] Settings CSS errors: {app.css_errors}", file=sys.stderr)
            return 1
        win = Gtk.Window()
        stack = app.build_all_pages_onto_window(win)

        expected_pages = [
            "overview",
            "brain",
            "memories",
            "skills",
            "capabilities",
            "resources",
            "web",
            "permissions",
            "undo",
            "automation",
            "maintenance",
        ]
        for pname in expected_pages:
            child_page = stack.get_child_by_name(pname)
            assert child_page is not None, f"Missing stack page: {pname}"
            stack.set_visible_child_name(pname)

        # Exercise `--page speech` alias routing, Page 1 ASR Speech Hub, Page 3 Non-Linear Decay, Page 5 9-Category Deep Scan & Theme
        assert normalize_settings_page_name("speech") == "overview"
        assert normalize_settings_page_name("compression") == "memories"
        assert normalize_settings_page_name("software") == "capabilities"
        assert app._page01_speech_switch is not None and app._page01_asr_models_count == 4
        assert app._page03_save_decay_btn is not None
        app._page03_save_decay_btn.emit("clicked")

        app._page02_search_entry.set_text("gpt-6")
        assert len(app._page05_deep_cat_btns) == 10, f"Expected all + 9 categories, got {list(app._page05_deep_cat_btns)}"
        app._page05_deep_cat_btns["media_entertainment"].emit("clicked")
        app._page05_deep_cat_btns["all"].emit("clicked")
        if app._page05_deep_search_entry is not None:
            app._page05_deep_search_entry.set_text("汽水")
            app._page05_deep_search_entry.set_text("")
        assert app._page05_fill_btn is not None, "Page 5 1-click fill button must be mounted"
        app._page05_fill_btn.emit("clicked")
        app._apply_theme(True)
        assert "intentos-light-theme" in win.get_css_classes()
        app._apply_theme(False)
        assert "intentos-light-theme" not in win.get_css_classes()

        ctx = GLib.MainContext.default()
        for _ in range(20):
            if not ctx.pending():
                break
            ctx.iteration(False)
        win.destroy()
        print(
            json.dumps(
                {
                    "ok": True,
                    "app": "org.intentos.Settings",
                    "pages_verified": len(expected_pages),
                    "page01_speech_hub_verified": True,
                    "page03_context_decay_verified": True,
                    "page05_deep_scan_9categories_verified": True,
                    "css_errors": 0,
                    "pygi_warnings": 0,
                },
                ensure_ascii=False,
            )
        )
        return 0

    app = SettingsCenterApp(is_smoke=False)
    return app.run(sys.argv[:1])


if __name__ == "__main__":
    if "--dump-json" in sys.argv:
        print(json.dumps(fetch_combined_settings(), ensure_ascii=False, indent=2))
        sys.exit(0)
    if "--smoke-ui" in sys.argv:
        sys.exit(run_settings_ui(smoke_ui=True))
    init_page = ""
    init_app = ""
    argv_list = sys.argv[1:]
    for idx_a, arg_v in enumerate(argv_list):
        if arg_v == "--page" and idx_a + 1 < len(argv_list):
            init_page = argv_list[idx_a + 1]
        elif arg_v == "--inspect-app" and idx_a + 1 < len(argv_list):
            init_app = argv_list[idx_a + 1]
    sys.exit(run_settings_ui(smoke_ui=False, initial_page=init_page, initial_inspect_app=init_app))
