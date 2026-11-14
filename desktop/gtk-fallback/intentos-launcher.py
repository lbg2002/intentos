#!/usr/bin/env python3
"""IntentOS · 随问 — GTK4 Native Desktop Floating Quick-Chat AIOS Dialog (Wave 3).

Frameless, glassmorphic, draggable desktop-floating single-dialog AIOS window (`480x640`)
powered by `intentosd` over `${XDG_RUNTIME_DIR}/intentos/ui.sock`:
  - Top Bar (`Gtk.WindowHandle` draggable): `✦ IntentOS` + inline `▾` Live `/v1/models`
    Searchable Switcher (`自动 / ZCode / Codex / Pi / OpenAI API`, `↻ 刷新`, Search + Scrollable
    Model Chips, `默认/快/标准/深入`), `🛡` Security Mode Posture (`严格 / 平衡 / 开发`),
    `📋` Clipboard Quick-Ask (`--clipboard-ask`), `🧠` Personal Memory & App Adapter popover,
    `🔒` Incognito, `+` New Session, `📌` Always-on-top Pin, `◑` High-Contrast Dark/Light theme,
    `⚙` Settings (`intentos-settings.py`).
  - Scrollable Chat Stream: User bubbles & Markdown-formatted Assistant bubbles with
    `20px` Horizontal Colored `Trace Dots` (`●`, compactly collapsing `> 6` dots into `+N`) and
    Auto-Expanded Trustworthy Inline Approval Cards (`🛡️ 敏感权限与安全执行审批`:
    `[✓ 批准本次]` `[⏱ 本会话放行此范围]` `[✕ 拒绝]` + `[↶ 撤销]`).
  - Supports `--smoke-ui` (real GTK4 widget + CSS + zero-warning verification) and `--smoke-rpc`.
"""

from __future__ import annotations

import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import warnings
from pathlib import Path
from typing import Any

BACKEND_ORDER: list[tuple[str, str]] = [
    ("auto", "自动"),
    ("zcode", "ZCode"),
    ("codex", "Codex"),
    ("pi", "Pi"),
    ("openai", "OpenAI API"),
]

EFFORT_OPTIONS: list[tuple[str, str]] = [
    ("default", "默认"),
    ("fast", "快"),
    ("medium", "标准"),
    ("high", "深入"),
]

SECURITY_MODE_OPTIONS: list[tuple[str, str, str]] = [
    ("strict", "严格", "严格逐次审批"),
    ("balanced", "平衡", "平衡受控防护(推荐)"),
    ("developer", "开发者", "信任目录免批"),
]

STARTER_PROMPTS: list[tuple[str, str]] = [
    ("📂 最近与长期常用文件", "我之前说的文件和长期高频使用的文件有哪些？"),
    ("🧩 本机已装与常用软件", "我电脑上装了哪些软件？最常用的软件是什么？"),
    ("🎵 控制当前音乐播放", "用软件转译层查看或暂停当前正在播放的音乐"),
    ("🌙 调暗屏幕并开启护眼", "屏幕太亮了，帮我把亮度调低一点并开启护眼模式"),
]

TRACE_COLOR_MAP: dict[str, str] = {
    "thinking": "gray",
    "gray": "gray",
    "memory": "purple",
    "purple": "purple",
    "adapter": "cyan",
    "cyan": "cyan",
    "approval": "amber",
    "amber": "amber",
    "yellow": "amber",
    "orange": "amber",
    "tool_unverified": "blue",
    "requested_unverified": "blue",
    "requestedunverified": "blue",
    "unverified": "blue",
    "blue": "blue",
    "sky": "blue",
    "tool_ok": "green",
    "green": "green",
    "emerald": "green",
    "tool_err": "red",
    "error": "red",
    "red": "red",
}

FALLBACK_CSS = """
window.intentos-launcher-win { background: transparent; background-color: transparent; background-image: none; box-shadow: none; color: #f1f5f9; }
.intentos-floating-card { background-color: #141824; background-image: none; color: #f1f5f9; border-radius: 20px; border: 1px solid #334155; }
.intentos-floating-card button { background-image: none; box-shadow: none; text-shadow: none; -gtk-icon-shadow: none; }
.intentos-top-bar { padding: 10px 12px; }
button.intentos-trace-dot { min-width: 20px; min-height: 20px; padding: 0; border-radius: 999px; background-image: none; }
button.intentos-dot-blue { background-color: rgba(56, 189, 248, 0.28); border: 1px solid #38bdf8; color: #38bdf8; }
button.intentos-dot-green { background-color: rgba(16, 185, 129, 0.26); border: 1px solid #10b981; color: #10b981; }
button.intentos-dot-red { background-color: rgba(239, 68, 68, 0.28); border: 1px solid #ef4444; color: #ef4444; }
"""


def resolve_ui_socket() -> Path:
    base = os.environ.get("INTENTOS_BASE_DIR")
    if base:
        return Path(base) / "run" / "ui.sock"
    xdg_run = os.environ.get("XDG_RUNTIME_DIR") or f"/tmp/intentos-run-{os.getuid()}"
    return Path(xdg_run) / "intentos" / "ui.sock"


def detect_system_light_theme() -> bool:
    """Auto-detect Ubuntu GNOME light/dark theme (`org.gnome.desktop.interface color-scheme`)."""
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


def call_ui_rpc(method: str, params: Any = None, timeout: float = 45.0) -> dict[str, Any]:
    sock_path = resolve_ui_socket()
    payload: dict[str, Any] = {"id": f"gtk_{int(time.time() * 1000)}", "method": method}
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
    timeout: float = 45.0,
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


def launch_settings_window(initial_page: str = "", app_query: str = "") -> None:
    settings_script = Path(__file__).resolve().parent.parent / "settings" / "intentos-settings.py"
    extra: list[str] = []
    if initial_page:
        extra.extend(["--page", initial_page])
    if app_query:
        extra.extend(["--inspect-app", app_query])
    if settings_script.exists():
        subprocess.Popen([sys.executable, str(settings_script), *extra])
    else:
        subprocess.Popen(["intentos-settings", *extra])


def read_system_clipboard_fallback() -> str:
    """Best-effort CLI clipboard/selection reader when GDK async clipboard is empty or starting up."""
    cmds = [
        ["wl-paste", "--no-newline", "--primary"],
        ["wl-paste", "--no-newline"],
        ["xclip", "-o", "-selection", "primary"],
        ["xclip", "-o", "-selection", "clipboard"],
    ]
    for cmd in cmds:
        if shutil.which(cmd[0]):
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=1.2, check=False)
                if res.returncode == 0 and res.stdout.strip():
                    return res.stdout.strip()
            except Exception:
                continue
    return ""


def normalize_backends_catalog(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize `backend_bridge.get_backends_catalog` / `refresh_models` retaining ALL live `/v1/models`."""
    data = raw if isinstance(raw, dict) else {}
    active_raw = data.get("active") if isinstance(data.get("active"), dict) else {}
    active = {
        "backend": str(active_raw.get("backend") or data.get("active_backend") or "auto").lower(),
        "provider": str(active_raw.get("provider") or data.get("active_provider") or ""),
        "model": str(active_raw.get("model") or data.get("active_model") or ""),
        "reasoning_effort": str(
            active_raw.get("reasoning_effort") or data.get("reasoning_effort") or "default"
        ).lower(),
    }

    raw_backends = data.get("backends")
    normalized_map: dict[str, dict[str, Any]] = {}
    if isinstance(raw_backends, dict):
        for k, v in raw_backends.items():
            if isinstance(v, dict):
                normalized_map[str(k).lower()] = v
    elif isinstance(raw_backends, list):
        for entry in raw_backends:
            if isinstance(entry, dict):
                bid = str(entry.get("id") or entry.get("backend") or entry.get("name") or "").lower()
                if bid:
                    normalized_map[bid] = entry

    backends_out: dict[str, dict[str, Any]] = {}
    all_discovered_models: list[tuple[str, str]] = []

    for bid, blabel in BACKEND_ORDER:
        binfo = normalized_map.get(bid, {})
        available = bool(
            binfo.get("available", binfo.get("installed", binfo.get("detected", bid in ("auto", "openai"))))
        )
        models: list[tuple[str, str]] = []  # (provider_id, model_id)
        seen_pairs: set[tuple[str, str]] = set()

        def _add_model(pid_val: str, mid_val: str, front: bool = False) -> None:
            pair = (pid_val, mid_val)
            if not mid_val or pair in seen_pairs:
                return
            seen_pairs.add(pair)
            if front:
                models.insert(0, pair)
            else:
                models.append(pair)

        providers_field = binfo.get("providers")
        if isinstance(providers_field, list):
            for p in providers_field:
                if isinstance(p, dict):
                    pid = str(p.get("id") or p.get("provider") or p.get("name") or "")
                    def_m = p.get("default_model") or p.get("model")
                    if def_m:
                        _add_model(pid, str(def_m), front=False)
                    p_models = p.get("models") or p.get("available_models") or []
                    if isinstance(p_models, list):
                        for m in p_models:
                            mid = str(m.get("id") or m.get("name") if isinstance(m, dict) else m)
                            _add_model(pid, mid)
        elif isinstance(providers_field, dict):
            for pid, p in providers_field.items():
                if isinstance(p, dict):
                    p_models = p.get("models") or p.get("available_models") or []
                    if isinstance(p_models, list):
                        for m in p_models:
                            mid = str(m.get("id") or m.get("name") if isinstance(m, dict) else m)
                            _add_model(str(pid), mid)

        flat_models = binfo.get("models") or binfo.get("available_models") or []
        if isinstance(flat_models, list):
            def_prov = str(binfo.get("default_provider") or binfo.get("provider") or "")
            for m in flat_models:
                mid = str(m.get("id") or m.get("name") if isinstance(m, dict) else m)
                if mid and not any(existing_m == mid for _, existing_m in models):
                    _add_model(def_prov, mid)

        def_m = binfo.get("default_model") or binfo.get("active_model")
        if def_m:
            def_p = str(binfo.get("default_provider") or binfo.get("provider") or "")
            if not any(existing_m == str(def_m) for _, existing_m in models):
                _add_model(def_p, str(def_m), front=True)

        if bid != "auto":
            for pair in models:
                if not any(existing_m == pair[1] for _, existing_m in all_discovered_models):
                    all_discovered_models.append(pair)

        backends_out[bid] = {
            "id": bid,
            "label": blabel,
            "available": available,
            "models": models,  # Keep ALL live-queried /v1/models without truncation!
            "default_provider": str(binfo.get("default_provider") or (models[0][0] if models else "")),
            "default_model": str(binfo.get("default_model") or (models[0][1] if models else "")),
            "base_url": str(binfo.get("base_url") or ""),
        }

    if not backends_out["auto"]["models"] and all_discovered_models:
        backends_out["auto"]["models"] = list(all_discovered_models)
        if not backends_out["auto"]["default_model"]:
            backends_out["auto"]["default_provider"] = all_discovered_models[0][0]
            backends_out["auto"]["default_model"] = all_discovered_models[0][1]

    return {"active": active, "backends": backends_out}


def extract_approval_scope(pa: dict[str, Any]) -> tuple[str, str, str]:
    """Extract (`scope_kind`, `scope_value`, `human_target`) from `PendingApproval`."""
    args = pa.get("arguments") if isinstance(pa.get("arguments"), dict) else {}
    params = pa.get("params") if isinstance(pa.get("params"), dict) else {}
    merged = {**params, **args}

    for key in ("directory", "path", "source", "target", "destination", "output", "archive"):
        raw_p = merged.get(key)
        if isinstance(raw_p, str) and raw_p.strip():
            expanded = os.path.expanduser(raw_p.strip())
            p_obj = Path(expanded)
            if key == "directory" or (p_obj.exists() and p_obj.is_dir()):
                scope_dir = str(p_obj)
            else:
                parent = str(p_obj.parent)
                scope_dir = parent if parent and parent != "." else expanded
            return ("directory", scope_dir, expanded)

    for app_key in ("app", "app_hint", "app_name"):
        app_val = merged.get(app_key) or pa.get(app_key)
        if isinstance(app_val, str) and app_val.strip():
            return ("app", app_val.strip(), app_val.strip())

    cap_id = str(pa.get("capability_id") or pa.get("intent_action") or "capability")
    return ("capability", cap_id, cap_id)


def is_unverified_step_or_dot(d: dict[str, Any]) -> bool:
    """Return True when a step or trace dot is RequestedUnverified or simulated (never show green!)."""
    if not isinstance(d, dict):
        return False
    if d.get("simulated") is True or d.get("unverified") is True:
        return True
    kind = str(d.get("kind") or "").lower()
    if kind in ("tool_unverified", "requested_unverified", "unverified", "simulated"):
        return True
    ver = d.get("verification")
    if isinstance(ver, dict):
        v_state = str(ver.get("state") or ver.get("status") or "").lower()
        v_note = str(ver.get("note") or ver.get("reason") or ver.get("summary") or "").lower()
        if "unverified" in v_state or "pending" in v_state or "simulated" in v_state:
            return True
        if ver.get("simulated") is True or "requestedunverified" in v_note or "未验证" in v_note or "待桌面响应" in v_note:
            return True
    elif isinstance(ver, str):
        vl = ver.lower()
        if "unverified" in vl or "未验证" in vl or "待桌面响应" in vl or "simulated" in vl:
            return True
    status_str = str(d.get("status") or d.get("verification_state") or "").lower()
    if "unverified" in status_str or status_str == "simulated":
        return True
    combined_txt = f"{d.get('title') or ''} {d.get('label') or ''} {d.get('detail') or ''} {d.get('summary') or ''}".lower()
    if (
        "requestedunverified" in combined_txt
        or "requested_unverified" in combined_txt
        or "未验证" in combined_txt
        or "待桌面响应" in combined_txt
        or '"simulated": true' in combined_txt
        or '"simulated":true' in combined_txt
    ):
        return True
    return False


def normalize_menu_items_py(raw_items: Any) -> list[dict[str, Any]]:
    """Normalize dbusmenu items from strings or dicts into uniform [{'id', 'label', 'enabled'}]."""
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


def normalize_live_tray_apps_py(raw: Any) -> list[dict[str, Any]]:
    """Normalize `app_adapter.list_live_tray_apps` payload across multiple schema variants."""
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
                "menu_items": normalize_menu_items_py(menu_raw),
            }
        )
    return out


def normalize_trace_dots(turn_res: dict[str, Any]) -> list[dict[str, Any]]:
    """Ensure standardized 20px colored trace dots list from turn response (honest sky-blue for RequestedUnverified!)."""
    raw_dots = turn_res.get("trace_dots")
    dots: list[dict[str, Any]] = []
    if isinstance(raw_dots, list):
        for d in raw_dots:
            if isinstance(d, dict):
                kind = str(d.get("kind") or "tool_ok").lower()
                raw_color = str(d.get("color") or kind).lower()
                color = TRACE_COLOR_MAP.get(raw_color, TRACE_COLOR_MAP.get(kind, "green"))
                detail_val = d.get("detail") or d.get("summary") or d.get("output") or ""
                if isinstance(detail_val, (dict, list)):
                    detail_str = json.dumps(detail_val, ensure_ascii=False, indent=2)
                else:
                    detail_str = str(detail_val)
                title_str = str(d.get("title") or d.get("label") or kind)

                # Honest verification coloring: NEVER paint emerald green when RequestedUnverified or simulated!
                if kind not in ("thinking", "memory", "approval", "tool_err", "error") and color != "red":
                    if is_unverified_step_or_dot(d):
                        kind = "tool_unverified"
                        color = "blue"
                        if "待桌面响应" not in title_str and "未验证" not in title_str:
                            title_str = f"{title_str} · 已发送请求（待桌面响应）"
                        if "已发送请求（待桌面响应）" not in detail_str:
                            detail_str = (
                                f"⏳ 验证状态: 已发送请求（待桌面响应 / RequestedUnverified）\n{detail_str}".strip()
                            )
                dots.append(
                    {
                        "kind": kind,
                        "color": color,
                        "title": title_str,
                        "detail": detail_str,
                        "changeset_id": d.get("changeset_id"),
                        "duration_ms": d.get("duration_ms"),
                        "pending_approval": d.get("pending_approval")
                        if isinstance(d.get("pending_approval"), dict)
                        else None,
                    }
                )

    raw_steps = turn_res.get("steps")
    if isinstance(raw_steps, list) and not any(
        d["kind"] in ("tool_ok", "tool_unverified", "tool_err") for d in dots
    ):
        for st in raw_steps:
            if not isinstance(st, dict):
                continue
            cap = str(st.get("capability_id") or st.get("tool") or st.get("name") or "系统调用")
            failed = st.get("ok") is False or str(st.get("status") or "").lower() in ("failed", "error", "denied")
            unver = (not failed) and is_unverified_step_or_dot(st)
            s_kind = "tool_err" if failed else ("tool_unverified" if unver else "tool_ok")
            s_color = "red" if failed else ("blue" if unver else "green")
            s_badge = "执行失败" if failed else ("已发送请求（待桌面响应）" if unver else "已验证完成")
            s_detail = str(st.get("summary") or st.get("detail") or json.dumps(st, ensure_ascii=False, indent=2))
            dots.append(
                {
                    "kind": s_kind,
                    "color": s_color,
                    "title": f"{cap} · {s_badge}",
                    "detail": s_detail,
                    "changeset_id": st.get("changeset_id"),
                    "duration_ms": st.get("duration_ms"),
                }
            )

    thinking = str(turn_res.get("thinking") or "").strip()
    if thinking and not any(d["kind"] == "thinking" for d in dots):
        dots.insert(
            0,
            {
                "kind": "thinking",
                "color": "gray",
                "title": "深度思考链路",
                "detail": thinking,
                "changeset_id": None,
                "duration_ms": None,
            },
        )

    mem_hits = turn_res.get("memory_hits")
    if isinstance(mem_hits, list) and mem_hits and not any(d["kind"] == "memory" for d in dots):
        lines = []
        for h in mem_hits[:8]:
            if isinstance(h, dict):
                nm = (
                    h.get("display_name")
                    or h.get("doc_title")
                    or h.get("title")
                    or h.get("name")
                    or h.get("canonical_value")
                    or h.get("path")
                    or ""
                )
                lines.append(f"• {nm}")
            else:
                lines.append(f"• {h}")
        dots.append(
            {
                "kind": "memory",
                "color": "purple",
                "title": f"记忆召回: {len(mem_hits)} 项个人数据",
                "detail": "\n".join(lines),
                "changeset_id": None,
                "duration_ms": None,
            }
        )

    adapter_acts = turn_res.get("adapter_actions")
    if isinstance(adapter_acts, list) and adapter_acts and not any(d["kind"] == "adapter" for d in dots):
        any_unverified = any(isinstance(a, dict) and is_unverified_step_or_dot(a) for a in adapter_acts)
        dots.append(
            {
                "kind": "adapter",
                "color": "blue" if any_unverified else "cyan",
                "title": (
                    f"软件转译层: {len(adapter_acts)} 项调用 · 已发送请求（待桌面响应）"
                    if any_unverified
                    else f"软件转译层: {len(adapter_acts)} 项调用"
                ),
                "detail": json.dumps(adapter_acts, ensure_ascii=False, indent=2),
                "changeset_id": None,
                "duration_ms": None,
            }
        )

    pa = turn_res.get("pending_approval")
    if isinstance(pa, dict) and pa and not any(d["kind"] == "approval" for d in dots):
        dots.append(
            {
                "kind": "approval",
                "color": "amber",
                "title": f"待审批权限: {pa.get('capability_id') or pa.get('intent_action') or '受控操作'}",
                "detail": str(pa.get("summary") or pa.get("diff_preview") or json.dumps(pa, ensure_ascii=False)),
                "changeset_id": None,
                "duration_ms": None,
            }
        )

    return dots


def inline_markdown_to_pango(text: str, light_theme: bool = False) -> str:
    """Convert inline Markdown (`code`, **bold**, *italic*) safely to Pango markup."""
    placeholders: list[str] = []
    code_bg = "#f1f5f9" if light_theme else "#1e293b"
    code_fg = "#c2410c" if light_theme else "#93c5fd"

    def _stash_code(match: re.Match[str]) -> str:
        code_txt = html.escape(match.group(1))
        idx = len(placeholders)
        placeholders.append(f'<tt><span background="{code_bg}" foreground="{code_fg}"> {code_txt} </span></tt>')
        return f"\x00CODE{idx}\x00"

    step = re.sub(r"`([^`\n]+)`", _stash_code, text)
    escaped = html.escape(step)
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped)
    escaped = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<i>\1</i>", escaped)
    for idx, repl in enumerate(placeholders):
        escaped = escaped.replace(f"\x00CODE{idx}\x00", repl)
    return escaped


def parse_markdown_segments(md_text: str, light_theme: bool = False) -> list[tuple[str, str, str]]:
    """Split Markdown into ('text', pango_markup, plain_text) and ('code', lang, code_body) blocks."""
    text = (md_text or "").strip()
    if not text:
        return [("text", "", "")]

    segments: list[tuple[str, str, str]] = []
    pattern = re.compile(r"```([a-zA-Z0-9_+-]*)\n?(.*?)```", re.DOTALL)
    last_end = 0
    quote_fg = "#475569" if light_theme else "#94a3b8"

    def _format_prose(prose: str) -> tuple[str, str]:
        plain = prose.strip("\n")
        if not plain.strip():
            return "", ""
        pango_lines: list[str] = []
        for raw_line in plain.splitlines():
            s = raw_line.rstrip()
            if s.startswith("### "):
                pango_lines.append(f"<b>{inline_markdown_to_pango(s[4:], light_theme)}</b>")
            elif s.startswith("## "):
                pango_lines.append(f'<span size="large"><b>{inline_markdown_to_pango(s[3:], light_theme)}</b></span>')
            elif s.startswith("# "):
                pango_lines.append(f'<span size="x-large"><b>{inline_markdown_to_pango(s[2:], light_theme)}</b></span>')
            elif s.startswith("- ") or s.startswith("* "):
                pango_lines.append(f"  • {inline_markdown_to_pango(s[2:], light_theme)}")
            elif s.startswith("> "):
                pango_lines.append(
                    f'<i><span foreground="{quote_fg}">▎ {inline_markdown_to_pango(s[2:], light_theme)}</span></i>'
                )
            else:
                pango_lines.append(inline_markdown_to_pango(s, light_theme))
        return "\n".join(pango_lines), plain

    for m in pattern.finditer(text):
        before = text[last_end : m.start()]
        pango_str, plain_str = _format_prose(before)
        if plain_str:
            segments.append(("text", pango_str, plain_str))
        lang = m.group(1).strip() or "code"
        code_body = m.group(2).rstrip("\n")
        segments.append(("code", lang, code_body))
        last_end = m.end()

    tail = text[last_end:]
    pango_str, plain_str = _format_prose(tail)
    if plain_str:
        segments.append(("text", pango_str, plain_str))

    return segments or [("text", html.escape(text), text)]


def format_context_compression_tag(cc: Any) -> str:
    """Format non-linear context compression telemetry for bubble footer."""
    if not isinstance(cc, dict):
        return ""
    saved_pct = float(cc.get("saved_pct") or 0.0)
    inc_turns = int(cc.get("included_qa_turns") or 0)
    comp_tok = int(cc.get("compressed_estimated_tokens") or 0)
    if saved_pct <= 0.0 and inc_turns <= 0:
        return ""
    if saved_pct > 0.0:
        return f"📉 上下文 {comp_tok} tok (省 {int(round(saved_pct))}%)"
    return f"📉 上下文 {comp_tok} tok ({inc_turns} 轮)"


def execute_chat_turn_sync(
    text: str,
    session_id: str | None,
    clipboard_context: str | None,
    incognito: bool,
    reasoning_effort: str,
) -> dict[str, Any]:
    """Call `backend_bridge.send_quick_chat_turn` with seamless fallback to `submit_intent`."""
    req_payload: dict[str, Any] = {
        "session_id": None if incognito else session_id,
        "text": text,
        "clipboard_context": clipboard_context or None,
        "incognito": incognito,
        "reasoning_effort": reasoning_effort,
    }
    try:
        bridge_res = call_module_rpc("backend_bridge", "send_quick_chat_turn", req_payload, timeout=60.0)
        if bridge_res.get("ok") and isinstance(bridge_res.get("result"), dict):
            r = bridge_res["result"]
            if any(k in r for k in ("reply_markdown", "reply", "assistant_message", "trace_dots", "pending_approval")):
                pa_obj = r.get("pending_approval") if isinstance(r.get("pending_approval"), dict) else None
                reply_md = str(
                    r.get("reply_markdown")
                    or r.get("reply")
                    or r.get("assistant_message")
                    or r.get("message")
                    or ("🛡️ 该操作涉及敏感路径或系统控制权限，请在下方审批卡片中确认。" if pa_obj else "✓ 已完成")
                )
                return {
                    "ok": True,
                    "session_id": r.get("session_id") or session_id,
                    "backend_used": r.get("backend_used") or r.get("backend") or "auto",
                    "model_used": r.get("model_used") or r.get("model") or "",
                    "reply_markdown": reply_md,
                    "trace_dots": normalize_trace_dots(r),
                    "pending_approval": pa_obj,
                    "context_compression": r.get("context_compression")
                    if isinstance(r.get("context_compression"), dict)
                    else None,
                    "changeset_ids": r.get("changeset_ids") if isinstance(r.get("changeset_ids"), list) else [],
                }
    except Exception:
        pass

    combined_text = text
    if clipboard_context:
        combined_text = f"{text}\n\n[剪贴板/选区上下文]:\n{clipboard_context[:2000]}"

    intent_res = call_ui_rpc(
        "submit_intent",
        {
            "protocol_version": 1,
            "text": combined_text,
            "session_id": None if incognito else session_id,
            "force_agent": False,
            "incognito": incognito,
        },
        timeout=60.0,
    )
    if not intent_res.get("ok"):
        err_msg = str(intent_res.get("error") or "请求失败")
        return {
            "ok": False,
            "session_id": session_id,
            "backend_used": "core",
            "model_used": "",
            "reply_markdown": f"请求未能完成：`{err_msg}`",
            "trace_dots": [
                {
                    "kind": "tool_err",
                    "color": "red",
                    "title": "执行错误",
                    "detail": err_msg,
                    "changeset_id": None,
                    "duration_ms": None,
                }
            ],
            "pending_approval": None,
        }

    r = intent_res.get("result") or {}
    if r.get("kind") == "passthrough" and isinstance(r.get("passthrough"), dict):
        pt = r["passthrough"]
        stdout = str(pt.get("stdout") or "").strip()
        reply_md = str(pt.get("message") or "命令已执行")
        if stdout:
            reply_md += f"\n```text\n{stdout}\n```"
    else:
        reply_md = str(r.get("assistant_message") or r.get("goal") or "✓ 已执行完成")
        if r.get("handoff_command"):
            reply_md += f"\n\n建议终端命令：\n```bash\n{r['handoff_command']}\n```"

    synth_dots: list[dict[str, Any]] = []
    csets = r.get("changeset_ids") or []
    latest_cs = csets[-1] if isinstance(csets, list) and csets else None
    route = str(r.get("route") or "L0")
    pa_pending = (
        r.get("pending_approval")
        if isinstance(r.get("pending_approval"), dict) and r.get("pending_approval")
        else None
    )
    if r.get("status") == "awaiting_approval" or pa_pending is not None:
        pa = pa_pending or {}
        synth_dots.append(
            {
                "kind": "approval",
                "color": "amber",
                "title": f"待审批: {pa.get('capability_id', '受控操作')}",
                "detail": f"{pa.get('summary', '')}\n{pa.get('diff_preview', '')}".strip(),
                "changeset_id": None,
                "duration_ms": None,
            }
        )
    else:
        raw_steps = r.get("steps")
        if isinstance(raw_steps, list) and raw_steps:
            for st in raw_steps:
                if not isinstance(st, dict):
                    continue
                cap = str(st.get("capability_id") or st.get("tool") or st.get("name") or route)
                failed = st.get("ok") is False or str(st.get("status") or "").lower() in ("failed", "error", "denied")
                unver = (not failed) and is_unverified_step_or_dot(st)
                synth_dots.append(
                    {
                        "kind": "tool_err" if failed else ("tool_unverified" if unver else "tool_ok"),
                        "color": "red" if failed else ("blue" if unver else "green"),
                        "title": (
                            f"{cap} · 执行失败"
                            if failed
                            else (f"{cap} · 已发送请求（待桌面响应）" if unver else f"{cap} · 已验证完成")
                        ),
                        "detail": str(st.get("summary") or st.get("detail") or json.dumps(st, ensure_ascii=False, indent=2)),
                        "changeset_id": st.get("changeset_id") or latest_cs,
                        "duration_ms": st.get("duration_ms"),
                    }
                )
        if not synth_dots:
            failed_turn = str(r.get("status") or "").lower() in ("failed", "error", "denied")
            unver_turn = (not failed_turn) and (is_unverified_step_or_dot(r) or "待桌面响应" in reply_md or "未验证" in reply_md)
            synth_dots.append(
                {
                    "kind": "tool_err" if failed_turn else ("tool_unverified" if unver_turn else "tool_ok"),
                    "color": "red" if failed_turn else ("blue" if unver_turn else "green"),
                    "title": (
                        f"{route} 执行失败"
                        if failed_turn
                        else (f"{route} 已发送请求（待桌面响应）" if unver_turn else f"{route} 系统执行完成")
                    ),
                    "detail": (
                        ("⏳ 验证状态: 已发送请求（待桌面响应 / RequestedUnverified）\n" if unver_turn else "")
                        + f"状态: {r.get('status', 'completed')}"
                        + (f"\n变更集: {latest_cs}" if latest_cs else "")
                    ),
                    "changeset_id": latest_cs,
                    "duration_ms": None,
                }
            )

    out_sid = r.get("session_id") or session_id
    if not incognito:
        try:
            call_module_rpc(
                "memory_hub",
                "record_conversation_turn",
                {
                    "session_id": out_sid or "gtk_quick_chat",
                    "user_text": text,
                    "assistant_text": reply_md,
                    "tool_steps": synth_dots,
                    "incognito": False,
                },
                timeout=4.0,
            )
        except Exception:
            pass

    return {
        "ok": True,
        "session_id": out_sid,
        "backend_used": route,
        "model_used": "",
        "reply_markdown": reply_md,
        "trace_dots": synth_dots,
        "pending_approval": pa_pending,
    }


def run_gtk_app(clipboard_ask: bool = False, initial_prompt: str = "", smoke_ui: bool = False) -> int:
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
            f"[intentos-launcher] 未检测到 PyGObject / GTK4 环境 ({exc})；可改用 `intentosctl ui` 或打开 http://127.0.0.1:8787。",
            file=sys.stderr,
        )
        return 1

    if smoke_ui and not Gtk.init_check():
        print(json.dumps({"ok": True, "skipped": "Gtk.init_check() returned False"}, ensure_ascii=False))
        return 0

    class FloatingQuickChatApp(Gtk.Application):
        def __init__(self) -> None:
            super().__init__(application_id="org.intentos.Launcher")
            self.session_id: str = f"ses_{int(time.time())}"
            self.incognito: bool = False
            self.pinned: bool = False
            self.light_theme: bool = detect_system_light_theme()
            self.turn_busy: bool = False
            self.active_turn_token: int = 0

            self.catalog: dict[str, Any] = normalize_backends_catalog(None)
            self.selected_backend: str = "auto"
            self.selected_provider: str = ""
            self.selected_model: str = ""
            self.selected_effort: str = "default"
            self.model_filter_query: str = ""

            self.security_mode: str = "balanced"
            self.security_posture: dict[str, Any] = {}

            self.clipboard_context: str = ""
            self.input_history: list[str] = []
            self.history_cursor: int = -1
            self.last_changeset_id: str | None = None
            self.mention_candidates: list[dict[str, str]] = []
            self.memory_cache: dict[str, Any] = {}
            self.adapters_cache: list[dict[str, Any]] = []
            self.live_tray_apps: list[dict[str, Any]] = []
            self.deep_scan_summary: dict[str, Any] = {}
            self.session_compression_preview: dict[str, Any] = {}
            self.speech_overview: dict[str, Any] = {}
            self.voice_recording: bool = False
            self.voice_transcribing: bool = False
            self.voice_started_ts: float = 0.0
            self.voice_timer_source_id: int = 0
            self.default_placeholder_text: str = (
                "随问 AIOS… (Enter 发送 · Shift+Enter 换行 · @ 引用文件/软件 · 🎙 语音)"
            )
            self.inspect_app_query: str = ""
            self.last_inspected_app: dict[str, Any] | None = None
            self.live_adapter_status: str = ""
            self.message_count: int = 0
            self.suppress_buffer_signal: bool = False
            self.css_errors: list[str] = []
            self._last_approval_ui_bundle: dict[str, Any] | None = None

        def _load_css(self) -> None:
            provider = Gtk.CssProvider()
            provider.connect(
                "parsing-error",
                lambda _p, sec, err: self.css_errors.append(
                    f"line {sec.get_start_location().lines}: {err.message if hasattr(err, 'message') else err}"
                ),
            )
            css_path = Path(__file__).resolve().parent / "launcher_style.css"
            if css_path.exists():
                provider.load_from_path(str(css_path))
            elif hasattr(provider, "load_from_string"):
                provider.load_from_string(FALLBACK_CSS)
            else:
                provider.load_from_data(FALLBACK_CSS.encode("utf-8"))
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
            if hasattr(self, "win") and self.win is not None:
                if light:
                    self.win.add_css_class("intentos-light-theme")
                else:
                    self.win.remove_css_class("intentos-light-theme")

        def build_ui_onto_window(self, win: Gtk.Window, start_workers: bool = True) -> None:
            win.set_title("✦ IntentOS · 随问")
            win.set_default_size(480, 640)
            win.set_decorated(False)
            win.set_resizable(True)
            win.add_css_class("intentos-launcher-win")
            self.win = win

            self._apply_theme(self.light_theme)

            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            card.add_css_class("intentos-floating-card")
            card.set_margin_top(6)
            card.set_margin_bottom(6)
            card.set_margin_start(6)
            card.set_margin_end(6)
            win.set_child(card)

            # 1. Draggable Top Bar (`Gtk.WindowHandle`)
            drag_handle = Gtk.WindowHandle()
            top_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
            top_bar.add_css_class("intentos-top-bar")

            brand_lbl = Gtk.Label(label="✦ IntentOS", xalign=0.0)
            brand_lbl.add_css_class("intentos-brand-mark")
            top_bar.append(brand_lbl)

            self.status_dot = Gtk.Label(label="●")
            self.status_dot.add_css_class("intentos-status-dot-idle")
            self.status_dot.set_tooltip_text("就绪")
            top_bar.append(self.status_dot)

            self.model_pill_btn = Gtk.ToggleButton(label="自动 · 默认 ▾")
            self.model_pill_btn.add_css_class("intentos-model-pill")
            self.model_pill_btn.set_tooltip_text("切换后端引擎与实时查询的 /v1/models 模型列表")
            self.model_pill_btn.connect("toggled", self.on_model_pill_toggled)
            top_bar.append(self.model_pill_btn)

            spacer = Gtk.Box()
            spacer.set_hexpand(True)
            top_bar.append(spacer)

            self.shield_btn = Gtk.ToggleButton(label="🛡 平衡")
            self.shield_btn.add_css_class("intentos-shield-btn")
            self.shield_btn.set_tooltip_text("安全防护模式：平衡受控防护 (点击切换 严格 / 平衡 / 开发者 及查看会话授权)")
            self.shield_btn.connect("toggled", self.on_shield_toggled)
            top_bar.append(self.shield_btn)

            clip_btn = Gtk.Button(label="📋")
            clip_btn.add_css_class("intentos-icon-btn")
            clip_btn.set_tooltip_text("剪贴板/选区随问 (附加当前复制或选中的文本)")
            clip_btn.connect("clicked", lambda _b: self._capture_clipboard_context())
            top_bar.append(clip_btn)

            self.mem_btn = Gtk.ToggleButton(label="🧠")
            self.mem_btn.add_css_class("intentos-icon-btn")
            self.mem_btn.set_tooltip_text("个人记忆与软件转译层快照 (之前提到的文件 / 长期高频文件 / 常用软件)")
            self.mem_btn.connect("toggled", self.on_memory_toggled)
            top_bar.append(self.mem_btn)

            self.incog_btn = Gtk.ToggleButton(label="🔒")
            self.incog_btn.add_css_class("intentos-icon-btn")
            self.incog_btn.set_tooltip_text("隐私会话开关 (开启后不记录会话与文件记忆)")
            self.incog_btn.connect("toggled", self.on_incog_toggled)
            top_bar.append(self.incog_btn)

            new_btn = Gtk.Button(label="+")
            new_btn.add_css_class("intentos-icon-btn")
            new_btn.set_tooltip_text("新建对话 (Ctrl+N)")
            new_btn.connect("clicked", lambda _b: self.start_new_session())
            top_bar.append(new_btn)

            self.pin_btn = Gtk.ToggleButton(label="📌")
            self.pin_btn.add_css_class("intentos-icon-btn")
            self.pin_btn.set_tooltip_text("置顶悬浮窗 (Always on Top)")
            self.pin_btn.connect("toggled", self.on_pin_toggled)
            top_bar.append(self.pin_btn)

            theme_btn = Gtk.Button(label="◑")
            theme_btn.add_css_class("intentos-icon-btn")
            theme_btn.set_tooltip_text("切换深色/浅色高对比主题 (同步 GTK 主题偏好)")
            theme_btn.connect("clicked", self.on_theme_clicked)
            top_bar.append(theme_btn)

            cfg_btn = Gtk.Button(label="⚙")
            cfg_btn.add_css_class("intentos-icon-btn")
            cfg_btn.set_tooltip_text("打开 IntentOS 11 页设置中心")
            cfg_btn.connect("clicked", lambda _b: launch_settings_window())
            top_bar.append(cfg_btn)

            close_btn = Gtk.Button(label="✕")
            close_btn.add_css_class("intentos-icon-btn")
            close_btn.set_tooltip_text("收起悬浮窗 (Esc)")
            close_btn.connect("clicked", lambda _b: win.close())
            top_bar.append(close_btn)

            drag_handle.set_child(top_bar)
            card.append(drag_handle)

            # 2. Collapsible Inline Live `/v1/models` Switcher Strip (`▾`)
            self.switcher_revealer = Gtk.Revealer()
            self.switcher_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_DOWN)
            self.switcher_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            self.switcher_box.add_css_class("intentos-drawer-strip")
            self._build_switcher_strip()
            self.switcher_revealer.set_child(self.switcher_box)
            card.append(self.switcher_revealer)

            # 2b. Collapsible Trust Shield Posture & Session Scope Strip (`🛡`)
            self.security_revealer = Gtk.Revealer()
            self.security_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_DOWN)
            self.security_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            self.security_box.add_css_class("intentos-drawer-strip")
            self._render_security_panel()
            self.security_revealer.set_child(self.security_box)
            card.append(self.security_revealer)

            # 3. Collapsible Memory & Live Software Adapter Console (`🧠`)
            self.memory_revealer = Gtk.Revealer()
            self.memory_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_DOWN)
            self.memory_scroll = Gtk.ScrolledWindow()
            self.memory_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            self.memory_scroll.set_max_content_height(310)
            self.memory_scroll.set_propagate_natural_height(True)
            self.memory_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            self.memory_box.add_css_class("intentos-drawer-strip")
            self.memory_scroll.set_child(self.memory_box)
            self.memory_revealer.set_child(self.memory_scroll)
            card.append(self.memory_revealer)

            # 4. Scrollable Chat Message Stream
            self.chat_scroll = Gtk.ScrolledWindow()
            self.chat_scroll.set_vexpand(True)
            self.chat_scroll.set_hexpand(True)
            self.chat_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

            self.chat_stream = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            self.chat_stream.set_margin_top(12)
            self.chat_stream.set_margin_bottom(12)
            self.chat_stream.set_margin_start(14)
            self.chat_stream.set_margin_end(14)
            self.chat_scroll.set_child(self.chat_stream)
            card.append(self.chat_scroll)

            self._render_welcome_state()

            # 5. Bottom Input Area (`@` Mention Strip + Clipboard Strip + Multi-line Input)
            bottom_area = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            bottom_area.add_css_class("intentos-bottom-area")

            self.mention_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
            self.mention_bar.add_css_class("intentos-mention-bar")
            self.mention_bar.set_visible(False)
            bottom_area.append(self.mention_bar)

            self.clip_strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            self.clip_strip.add_css_class("intentos-context-strip")
            self.clip_lbl = Gtk.Label(label="", xalign=0.0)
            self.clip_lbl.set_hexpand(True)
            self.clip_lbl.set_ellipsize(Pango.EllipsizeMode.END)
            clip_clear_btn = Gtk.Button(label="✕")
            clip_clear_btn.add_css_class("intentos-icon-btn")
            clip_clear_btn.connect("clicked", lambda _b: self._set_clipboard_context(""))
            self.clip_strip.append(self.clip_lbl)
            self.clip_strip.append(clip_clear_btn)
            self.clip_strip.set_visible(False)
            bottom_area.append(self.clip_strip)

            self.voice_banner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            self.voice_banner.add_css_class("intentos-voice-banner")
            self.voice_banner_lbl = Gtk.Label(label="", xalign=0.0)
            self.voice_banner_lbl.set_hexpand(True)
            self.voice_banner_lbl.set_wrap(True)
            self.voice_banner_lbl.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            self.voice_enable_btn = Gtk.Button(label="⚡ 一键开启并录音")
            self.voice_enable_btn.add_css_class("intentos-seg-btn")
            self.voice_enable_btn.add_css_class("intentos-seg-btn-active")
            self.voice_enable_btn.set_visible(False)
            self.voice_enable_btn.connect("clicked", lambda _b: self._quick_enable_speech_and_record())
            self.voice_settings_btn = Gtk.Button(label="⚙ 打开语音识别模型下载与开关设置")
            self.voice_settings_btn.add_css_class("intentos-seg-btn")
            self.voice_settings_btn.connect("clicked", lambda _b: launch_settings_window("speech"))
            voice_close_btn = Gtk.Button(label="✕")
            voice_close_btn.add_css_class("intentos-icon-btn")
            voice_close_btn.connect("clicked", lambda _b: self.voice_banner.set_visible(False))
            self.voice_banner.append(self.voice_banner_lbl)
            self.voice_banner.append(self.voice_enable_btn)
            self.voice_banner.append(self.voice_settings_btn)
            self.voice_banner.append(voice_close_btn)
            self.voice_banner.set_visible(False)
            bottom_area.append(self.voice_banner)

            input_shell = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            input_shell.add_css_class("intentos-input-shell")

            input_overlay = Gtk.Overlay()
            input_overlay.set_hexpand(True)

            self.input_buf = Gtk.TextBuffer()
            self.input_buf.connect("changed", self.on_input_buffer_changed)
            self.input_view = Gtk.TextView(buffer=self.input_buf)
            self.input_view.add_css_class("intentos-chat-textview")
            self.input_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
            self.input_view.set_accepts_tab(False)

            in_scroll = Gtk.ScrolledWindow()
            in_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            in_scroll.set_max_content_height(110)
            in_scroll.set_propagate_natural_height(True)
            in_scroll.set_child(self.input_view)
            input_overlay.set_child(in_scroll)

            self.placeholder_lbl = Gtk.Label(
                label=self.default_placeholder_text,
                xalign=0.0,
                yalign=0.5,
            )
            self.placeholder_lbl.add_css_class("intentos-placeholder-lbl")
            self.placeholder_lbl.set_can_target(False)
            input_overlay.add_overlay(self.placeholder_lbl)
            input_shell.append(input_overlay)

            self.mic_btn = Gtk.Button(label="🎙")
            self.mic_btn.add_css_class("intentos-mic-btn")
            self.mic_btn.set_valign(Gtk.Align.END)
            self.mic_btn.set_tooltip_text("本地离线语音识别输入 (点击开始说话，再次点击完成识别)")
            self.mic_btn.connect("clicked", self.on_mic_clicked)
            input_shell.append(self.mic_btn)

            self.send_btn = Gtk.Button(label="➤")
            self.send_btn.add_css_class("intentos-send-btn")
            self.send_btn.set_valign(Gtk.Align.END)
            self.send_btn.set_tooltip_text("发送 (Enter)")
            self.send_btn.connect("clicked", self.on_send_or_stop_clicked)
            input_shell.append(self.send_btn)

            bottom_area.append(input_shell)
            card.append(bottom_area)

            tv_key = Gtk.EventControllerKey()
            tv_key.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
            tv_key.connect("key-pressed", self.on_input_key_pressed)
            self.input_view.add_controller(tv_key)

            win_key = Gtk.EventControllerKey()
            win_key.connect("key-pressed", self.on_window_key_pressed)
            win.add_controller(win_key)

            if start_workers:
                self._refresh_backends_async(force_remote=True)
                self._refresh_security_posture_async()
                self._refresh_memory_hints_async()
                self._refresh_speech_overview_async()

        def do_activate(self) -> None:
            if hasattr(self, "win") and self.win is not None:
                self.win.present()
                self.input_view.grab_focus()
                if clipboard_ask:
                    self._capture_clipboard_context()
                return

            self._load_css()
            win = Gtk.ApplicationWindow(application=self)
            self.build_ui_onto_window(win, start_workers=True)
            win.present()
            self.input_view.grab_focus()

            if clipboard_ask:
                self._capture_clipboard_context()
            if initial_prompt.strip():
                self._set_input_text(initial_prompt.strip())

        # ------------------------------------------------------------------
        # Top Switcher (`▾`) — Live `/v1/models` Searchable Selector
        # ------------------------------------------------------------------
        def _build_switcher_strip(self) -> None:
            eng_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
            lbl_e = Gtk.Label(label="引擎:", xalign=0.0)
            lbl_e.add_css_class("intentos-strip-label")
            eng_row.append(lbl_e)
            self.engine_btns: dict[str, Gtk.Button] = {}
            for bid, blabel in BACKEND_ORDER:
                b = Gtk.Button(label=blabel)
                b.add_css_class("intentos-seg-btn")
                b.connect("clicked", self._on_select_backend, bid)
                eng_row.append(b)
                self.engine_btns[bid] = b

            eng_spacer = Gtk.Box()
            eng_spacer.set_hexpand(True)
            eng_row.append(eng_spacer)

            self.refresh_models_btn = Gtk.Button(label="↻ 刷新")
            self.refresh_models_btn.add_css_class("intentos-seg-btn")
            self.refresh_models_btn.set_tooltip_text("实时请求各供应商 /v1/models 接口刷新全量可用模型")
            self.refresh_models_btn.connect("clicked", lambda _b: self._refresh_models_live())
            eng_row.append(self.refresh_models_btn)
            self.switcher_box.append(eng_row)

            # Live `/v1/models` Search Entry + Scrollable Chips Area
            search_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            self.model_search_entry = Gtk.Entry(placeholder_text="搜索模型 (共 0 个)...")
            self.model_search_entry.add_css_class("intentos-compact-entry")
            self.model_search_entry.set_hexpand(True)
            self.model_search_entry.connect("changed", self._on_model_search_changed)
            search_row.append(self.model_search_entry)
            self.switcher_box.append(search_row)

            self.model_scroll = Gtk.ScrolledWindow()
            self.model_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            self.model_scroll.set_max_content_height(180)
            self.model_scroll.set_propagate_natural_height(True)
            self.model_flow = Gtk.FlowBox()
            self.model_flow.set_selection_mode(Gtk.SelectionMode.NONE)
            self.model_flow.set_max_children_per_line(3)
            self.model_flow.set_column_spacing(4)
            self.model_flow.set_row_spacing(4)
            self.model_scroll.set_child(self.model_flow)
            self.switcher_box.append(self.model_scroll)

            # Custom provider + model row
            pm_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            self.prov_entry = Gtk.Entry(placeholder_text="供应商 (可选)")
            self.prov_entry.add_css_class("intentos-compact-entry")
            self.prov_entry.set_width_chars(10)
            self.model_entry = Gtk.Entry(placeholder_text="模型名称 (如 gpt-5.6 / glm-5.3)")
            self.model_entry.add_css_class("intentos-compact-entry")
            self.model_entry.set_hexpand(True)
            apply_btn = Gtk.Button(label="应用")
            apply_btn.add_css_class("intentos-seg-btn")
            apply_btn.add_css_class("intentos-seg-btn-active")
            apply_btn.connect("clicked", lambda _b: self._save_backend_selection())
            pm_row.append(self.prov_entry)
            pm_row.append(self.model_entry)
            pm_row.append(apply_btn)
            self.switcher_box.append(pm_row)

            # OpenAI inline Base URL + API Key row
            self.openai_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            self.base_url_entry = Gtk.Entry(placeholder_text="Base URL (https://.../v1)")
            self.base_url_entry.add_css_class("intentos-compact-entry")
            self.base_url_entry.set_hexpand(True)
            self.api_key_entry = Gtk.Entry(placeholder_text="API Key (安全入库)")
            self.api_key_entry.add_css_class("intentos-compact-entry")
            self.api_key_entry.set_visibility(False)
            self.openai_row.append(self.base_url_entry)
            self.openai_row.append(self.api_key_entry)
            self.openai_row.set_visible(False)
            self.switcher_box.append(self.openai_row)

            # Reasoning effort row
            eff_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
            lbl_ef = Gtk.Label(label="思考:", xalign=0.0)
            lbl_ef.add_css_class("intentos-strip-label")
            eff_row.append(lbl_ef)
            self.effort_btns: dict[str, Gtk.Button] = {}
            for eid, elabel in EFFORT_OPTIONS:
                b = Gtk.Button(label=elabel)
                b.add_css_class("intentos-seg-btn")
                b.connect("clicked", self._on_select_effort, eid)
                eff_row.append(b)
                self.effort_btns[eid] = b
            self.switcher_status_lbl = Gtk.Label(label="", xalign=1.0)
            self.switcher_status_lbl.add_css_class("intentos-trace-summary")
            self.switcher_status_lbl.set_hexpand(True)
            eff_row.append(self.switcher_status_lbl)
            self.switcher_box.append(eff_row)

            self._sync_switcher_widgets()

        def _on_model_search_changed(self, entry: Gtk.Entry) -> None:
            self.model_filter_query = entry.get_text().strip().lower()
            self._render_filtered_model_chips()

        def _clear_flowbox(self, flow: Gtk.FlowBox) -> None:
            child = flow.get_first_child()
            while child is not None:
                nxt = child.get_next_sibling()
                flow.remove(child)
                child = nxt

        def _render_filtered_model_chips(self) -> None:
            self._clear_flowbox(self.model_flow)
            backends_info = self.catalog.get("backends", {})
            cur_b = backends_info.get(self.selected_backend, {})
            models_list: list[tuple[str, str]] = cur_b.get("models") or []
            total = len(models_list)
            self.model_search_entry.set_placeholder_text(f"搜索模型 (共 {total} 个)...")

            q = self.model_filter_query
            filtered = [
                (pid, mid)
                for pid, mid in models_list
                if not q or q in mid.lower() or q in pid.lower()
            ]
            if not filtered:
                self.model_scroll.set_visible(False)
                return

            for prov_id, mod_id in filtered:
                short_m = mod_id if len(mod_id) <= 22 else mod_id[:20] + "…"
                mb = Gtk.Button(label=short_m)
                mb.add_css_class("intentos-seg-btn")
                if mod_id == self.selected_model:
                    mb.add_css_class("intentos-seg-btn-active")
                mb.set_tooltip_text(f"{prov_id + ' / ' if prov_id else ''}{mod_id}")
                mb.connect("clicked", self._on_pick_model_chip, prov_id, mod_id)
                self.model_flow.append(mb)
            self.model_scroll.set_visible(True)

        def _sync_switcher_widgets(self) -> None:
            backends_info = self.catalog.get("backends", {})
            for bid, btn in self.engine_btns.items():
                bdata = backends_info.get(bid, {})
                base_lbl = dict(BACKEND_ORDER).get(bid, bid)
                mark = " ·" if bdata.get("available") and bid not in ("auto", "openai") else ""
                btn.set_label(f"{base_lbl}{mark}")
                if bid == self.selected_backend:
                    btn.add_css_class("intentos-seg-btn-active")
                else:
                    btn.remove_css_class("intentos-seg-btn-active")

            for eid, btn in self.effort_btns.items():
                if eid == self.selected_effort:
                    btn.add_css_class("intentos-seg-btn-active")
                else:
                    btn.remove_css_class("intentos-seg-btn-active")

            self.openai_row.set_visible(self.selected_backend == "openai")
            self._render_filtered_model_chips()

            b_disp = dict(BACKEND_ORDER).get(self.selected_backend, self.selected_backend)
            ef_disp = dict(EFFORT_OPTIONS).get(self.selected_effort, "默认")
            if self.selected_model:
                short_mod = self.selected_model if len(self.selected_model) <= 13 else self.selected_model[:11] + "…"
                pill_txt = f"{b_disp} · {short_mod} ▾"
            else:
                pill_txt = f"{b_disp} · {ef_disp} ▾"
            self.model_pill_btn.set_label(pill_txt)

        def _on_select_backend(self, _btn: Any, bid: str) -> None:
            self.selected_backend = bid
            binfo = self.catalog.get("backends", {}).get(bid, {})
            if binfo.get("default_provider"):
                self.selected_provider = binfo["default_provider"]
                self.prov_entry.set_text(self.selected_provider)
            if binfo.get("default_model"):
                self.selected_model = binfo["default_model"]
                self.model_entry.set_text(self.selected_model)
            if binfo.get("base_url") and not self.base_url_entry.get_text().strip():
                self.base_url_entry.set_text(binfo["base_url"])
            self._sync_switcher_widgets()
            self._save_backend_selection()

        def _on_pick_model_chip(self, _btn: Any, prov_id: str, mod_id: str) -> None:
            self.selected_provider = prov_id
            self.selected_model = mod_id
            self.prov_entry.set_text(prov_id)
            self.model_entry.set_text(mod_id)
            self._sync_switcher_widgets()
            self._save_backend_selection()

        def _on_select_effort(self, _btn: Any, eid: str) -> None:
            self.selected_effort = eid
            self._sync_switcher_widgets()
            self._save_backend_selection()

        def _save_backend_selection(self) -> None:
            self.selected_provider = self.prov_entry.get_text().strip()
            self.selected_model = self.model_entry.get_text().strip()
            self._sync_switcher_widgets()

            payload: dict[str, Any] = {
                "backend": self.selected_backend,
                "provider": self.selected_provider,
                "model": self.selected_model,
                "reasoning_effort": self.selected_effort,
            }
            if self.selected_backend == "openai":
                if self.base_url_entry.get_text().strip():
                    payload["base_url"] = self.base_url_entry.get_text().strip()
                if self.api_key_entry.get_text().strip():
                    payload["api_key"] = self.api_key_entry.get_text().strip()

            def _worker() -> None:
                ok = False
                try:
                    res = call_module_rpc("backend_bridge", "set_active_backend", payload, timeout=8.0)
                    ok = bool(res.get("ok"))
                except Exception:
                    ok = False
                GLib.idle_add(
                    self.switcher_status_lbl.set_text,
                    "✓ 已切换" if ok else "本地已记录",
                )

            threading.Thread(target=_worker, daemon=True).start()

        def _refresh_models_live(self) -> None:
            self.switcher_status_lbl.set_text("正在请求 /v1/models…")

            def _worker() -> None:
                norm: dict[str, Any] | None = None
                try:
                    res = call_module_rpc("backend_bridge", "refresh_models", {"force_refresh": True}, timeout=10.0)
                    if res.get("ok") and isinstance(res.get("result"), dict):
                        norm = normalize_backends_catalog(res["result"])
                except Exception:
                    norm = None
                if norm is None:
                    try:
                        res2 = call_module_rpc(
                            "backend_bridge",
                            "get_backends_catalog",
                            {"refresh_remote": True, "force_refresh": True},
                            timeout=10.0,
                        )
                        if res2.get("ok") and isinstance(res2.get("result"), dict):
                            norm = normalize_backends_catalog(res2["result"])
                    except Exception:
                        norm = None

                def _done() -> bool:
                    if norm is not None:
                        self._apply_catalog(norm)
                        cur_models = norm.get("backends", {}).get(self.selected_backend, {}).get("models") or []
                        self.switcher_status_lbl.set_text(f"✓ 已刷新 ({len(cur_models)} 个模型)")
                    else:
                        self.switcher_status_lbl.set_text("刷新未连接守护进程")
                    return False

                GLib.idle_add(_done)

            threading.Thread(target=_worker, daemon=True).start()

        def _refresh_backends_async(self, force_remote: bool = False) -> None:
            def _worker() -> None:
                try:
                    payload = {"refresh_remote": True} if force_remote else {}
                    res = call_module_rpc("backend_bridge", "get_backends_catalog", payload, timeout=8.0)
                    if res.get("ok") and isinstance(res.get("result"), dict):
                        norm = normalize_backends_catalog(res["result"])
                        GLib.idle_add(self._apply_catalog, norm)
                except Exception:
                    pass

            threading.Thread(target=_worker, daemon=True).start()

        def _apply_catalog(self, norm: dict[str, Any]) -> bool:
            self.catalog = norm
            act = norm.get("active", {})
            if act.get("backend"):
                self.selected_backend = act["backend"]
            if act.get("provider"):
                self.selected_provider = act["provider"]
                self.prov_entry.set_text(self.selected_provider)
            if act.get("model"):
                self.selected_model = act["model"]
                self.model_entry.set_text(self.selected_model)
            if act.get("reasoning_effort") in dict(EFFORT_OPTIONS):
                self.selected_effort = act["reasoning_effort"]
            self._sync_switcher_widgets()
            return False

        # ------------------------------------------------------------------
        # Trust Shield (`🛡`) — Security Mode & Session Scope Grants
        # ------------------------------------------------------------------
        def _update_shield_button(self) -> None:
            mode_short = {"strict": "严格", "balanced": "平衡", "developer": "开发者"}.get(
                self.security_mode, "平衡"
            )
            self.shield_btn.set_label(f"🛡 {mode_short}")
            self.shield_btn.remove_css_class("intentos-shield-strict")
            self.shield_btn.remove_css_class("intentos-shield-dev")
            if self.security_mode == "strict":
                self.shield_btn.add_css_class("intentos-shield-strict")
            elif self.security_mode == "developer":
                self.shield_btn.add_css_class("intentos-shield-dev")

        def _refresh_security_posture_async(self, re_render: bool = False) -> None:
            def _worker() -> None:
                posture: dict[str, Any] = {}
                try:
                    res = call_module_rpc("execution_hub", "get_security_posture", {}, timeout=5.0)
                    if res.get("ok") and isinstance(res.get("result"), dict):
                        posture = res["result"]
                except Exception:
                    pass

                def _apply() -> bool:
                    if posture:
                        self.security_posture = posture
                        mode = str(posture.get("security_mode") or "balanced").lower()
                        if mode in ("strict", "balanced", "developer"):
                            self.security_mode = mode
                        self._update_shield_button()
                    if re_render and self.security_revealer.get_reveal_child():
                        self._render_security_panel()
                    return False

                GLib.idle_add(_apply)

            threading.Thread(target=_worker, daemon=True).start()

        def _render_security_panel(self) -> None:
            self._clear_box(self.security_box)
            hdr = Gtk.Label(
                label="🛡️ 全局路径可见性与敏感操作审批模式 (敏感路径永不盲目放行或生硬报错)",
                xalign=0.0,
            )
            hdr.add_css_class("intentos-strip-label")
            hdr.set_wrap(True)
            self.security_box.append(hdr)

            mode_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            for mid, _short, full_lbl in SECURITY_MODE_OPTIONS:
                mb = Gtk.Button(label=full_lbl)
                mb.add_css_class("intentos-seg-btn")
                if mid == self.security_mode:
                    mb.add_css_class("intentos-seg-btn-active")
                mb.connect("clicked", self._on_set_security_mode, mid)
                mode_row.append(mb)
            self.security_box.append(mode_row)

            grants = self.security_posture.get("session_grants") or []
            if isinstance(grants, list) and grants:
                g_lbl = Gtk.Label(label=f"⏱ 当前会话临时放行范围 ({len(grants)} 项):", xalign=0.0)
                g_lbl.add_css_class("intentos-trace-summary")
                self.security_box.append(g_lbl)
                for g in grants[:4]:
                    if isinstance(g, dict):
                        gid = str(g.get("id") or "")
                        gkind = str(g.get("scope_kind") or "")
                        gval = str(g.get("scope_value") or "")
                        grow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                        txt = Gtk.Label(label=f"• [{gkind}] {gval}", xalign=0.0)
                        txt.add_css_class("intentos-bubble-meta")
                        txt.set_hexpand(True)
                        txt.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
                        rev_b = Gtk.Button(label="收回")
                        rev_b.add_css_class("intentos-seg-btn")
                        rev_b.connect("clicked", self._on_revoke_session_grant, gid)
                        grow.append(txt)
                        grow.append(rev_b)
                        self.security_box.append(grow)
            else:
                info = Gtk.Label(
                    label="常规用户目录(桌面/文档/下载/$HOME)直接可见；~/.config、/etc、/opt 触发内联审批；~/.ssh 等硬性封锁。",
                    xalign=0.0,
                )
                info.add_css_class("intentos-bubble-meta")
                info.set_wrap(True)
                self.security_box.append(info)

        def _on_set_security_mode(self, _btn: Any, mode: str) -> None:
            self.security_mode = mode
            self._update_shield_button()
            self._render_security_panel()

            def _worker() -> None:
                try:
                    call_module_rpc("execution_hub", "set_security_mode", {"mode": mode}, timeout=5.0)
                except Exception:
                    pass
                self._refresh_security_posture_async(re_render=True)

            threading.Thread(target=_worker, daemon=True).start()

        def _on_revoke_session_grant(self, _btn: Any, grant_id: str) -> None:
            if not grant_id:
                return

            def _worker() -> None:
                try:
                    call_module_rpc("execution_hub", "revoke_session_grant", {"id": grant_id}, timeout=5.0)
                except Exception:
                    pass
                self._refresh_security_posture_async(re_render=True)

            threading.Thread(target=_worker, daemon=True).start()

        def on_model_pill_toggled(self, btn: Gtk.ToggleButton) -> None:
            active = btn.get_active()
            if active:
                if self.mem_btn.get_active():
                    self.mem_btn.set_active(False)
                if self.shield_btn.get_active():
                    self.shield_btn.set_active(False)
            self.switcher_revealer.set_reveal_child(active)
            if active:
                self._refresh_backends_async(force_remote=True)

        def on_shield_toggled(self, btn: Gtk.ToggleButton) -> None:
            active = btn.get_active()
            if active:
                if self.model_pill_btn.get_active():
                    self.model_pill_btn.set_active(False)
                if self.mem_btn.get_active():
                    self.mem_btn.set_active(False)
            self.security_revealer.set_reveal_child(active)
            if active:
                self._render_security_panel()
                self._refresh_security_posture_async(re_render=True)

        def on_memory_toggled(self, btn: Gtk.ToggleButton) -> None:
            active = btn.get_active()
            if active:
                if self.model_pill_btn.get_active():
                    self.model_pill_btn.set_active(False)
                if self.shield_btn.get_active():
                    self.shield_btn.set_active(False)
            self.memory_revealer.set_reveal_child(active)
            if active:
                self._render_memory_panel()
                self._refresh_memory_hints_async(re_render=True)

        def _refresh_memory_hints_async(self, re_render: bool = False) -> None:
            sid_now = self.session_id

            def _worker() -> None:
                dash: dict[str, Any] = {}
                adapters: list[dict[str, Any]] = []
                live_trays: list[dict[str, Any]] = []
                deep_scan: dict[str, Any] = {}
                comp_prev: dict[str, Any] = {}
                try:
                    m_res = call_module_rpc("memory_hub", "get_memory_dashboard", {}, timeout=6.0)
                    if m_res.get("ok") and isinstance(m_res.get("result"), dict):
                        dash = m_res["result"]
                except Exception:
                    pass
                try:
                    c_res = call_module_rpc(
                        "memory_hub",
                        "preview_session_compression",
                        {"session_id": sid_now},
                        timeout=4.0,
                    )
                    if c_res.get("ok") and isinstance(c_res.get("result"), dict):
                        comp_prev = c_res["result"]
                except Exception:
                    pass
                try:
                    s_res = call_module_rpc(
                        "app_adapter",
                        "deep_scan_local_software",
                        {"force_refresh": False},
                        timeout=6.0,
                    )
                    if s_res.get("ok") and isinstance(s_res.get("result"), dict):
                        deep_scan = s_res["result"]
                except Exception:
                    pass
                try:
                    a_res = call_module_rpc("app_adapter", "list_adapters", {}, timeout=5.0)
                    if a_res.get("ok"):
                        r = a_res.get("result")
                        if isinstance(r, dict) and isinstance(r.get("adapters"), list):
                            adapters = r["adapters"]
                        elif isinstance(r, list):
                            adapters = r
                except Exception:
                    pass
                try:
                    t_res = call_module_rpc("app_adapter", "list_live_tray_apps", {}, timeout=5.0)
                    if t_res.get("ok"):
                        live_trays = normalize_live_tray_apps_py(t_res.get("result"))
                except Exception:
                    pass
                GLib.idle_add(
                    self._apply_memory_cache,
                    dash,
                    adapters,
                    live_trays,
                    deep_scan,
                    comp_prev,
                    re_render,
                )

            threading.Thread(target=_worker, daemon=True).start()

        def _apply_memory_cache(
            self,
            dash: dict[str, Any],
            adapters: list[dict[str, Any]],
            live_trays: list[dict[str, Any]],
            deep_scan: dict[str, Any],
            comp_prev: dict[str, Any],
            re_render: bool,
        ) -> bool:
            if dash:
                self.memory_cache = dash
            if adapters:
                self.adapters_cache = adapters
            self.live_tray_apps = live_trays
            if deep_scan:
                self.deep_scan_summary = deep_scan
            if comp_prev:
                self.session_compression_preview = comp_prev

            hints: list[dict[str, str]] = []
            for item in (dash.get("mentioned_files") or dash.get("recent_mentions") or [])[:10]:
                if isinstance(item, dict):
                    label = str(item.get("display_name") or item.get("title") or item.get("name") or "")
                    val = str(item.get("canonical_value") or item.get("path") or label)
                    if val:
                        hints.append({"kind": "📂 提及", "label": label or Path(val).name or val, "value": val})
            for item in (dash.get("frequent_files") or dash.get("long_term_files") or [])[:10]:
                if isinstance(item, dict):
                    val = str(item.get("path") or item.get("canonical_value") or "")
                    label = str(item.get("title") or item.get("name") or Path(val).name or val)
                    if val:
                        hints.append({"kind": "🔥 常用", "label": label, "value": val})
            for item in (dash.get("frequent_apps") or dash.get("top_apps") or [])[:10]:
                if isinstance(item, dict):
                    label = str(item.get("zh_name") or item.get("display_name") or item.get("name") or "")
                    if label:
                        hints.append({"kind": "🧩 软件", "label": label, "value": label})
            for tr in live_trays[:8]:
                nm = str(tr.get("name") or tr.get("app_id") or "")
                if nm and not any(h["value"] == nm for h in hints):
                    hints.append({"kind": "🟢 托盘", "label": nm, "value": nm})
            for ad in adapters[:8]:
                if isinstance(ad, dict):
                    label = str(ad.get("display_name") or ad.get("name") or ad.get("id") or "")
                    if label and not any(h["value"] == label for h in hints):
                        hints.append({"kind": "🔌 转译", "label": label, "value": label})

            if hints:
                self.mention_candidates = hints
            if re_render and self.memory_revealer.get_reveal_child():
                self._render_memory_panel()
            return False

        def _trigger_tray_menu_async(
            self,
            app_key: str,
            action_label: str,
            service: str = "",
            menu_id: Any = None,
        ) -> None:
            self.live_adapter_status = f"⏳ 正在触发 {app_key} → 「{action_label}」..."
            if self.memory_revealer.get_reveal_child():
                self._render_memory_panel()

            def _worker() -> None:
                payload: dict[str, Any] = {
                    "app": app_key,
                    "app_hint": app_key,
                    "action": action_label,
                    "menu_label": action_label,
                }
                if service:
                    payload["service"] = service
                if menu_id is not None:
                    payload["menu_id"] = menu_id
                res = call_module_rpc("app_adapter", "trigger_tray_menu", payload, timeout=8.0)
                if res.get("ok"):
                    r = res.get("result") if isinstance(res.get("result"), dict) else {}
                    unv = is_unverified_step_or_dot(r)
                    summary = str(r.get("summary") or r.get("message") or f"{app_key} · {action_label}")
                    msg = (
                        f"⏳ 已发送请求（待桌面响应）: {summary}"
                        if unv
                        else f"✓ 已触发并验证回读: {summary}"
                    )
                else:
                    msg = f"✕ 触发失败: {res.get('error', '未知错误')}"

                def _finish() -> bool:
                    self.live_adapter_status = msg
                    if self.memory_revealer.get_reveal_child():
                        self._render_memory_panel()
                    self._refresh_memory_hints_async(re_render=True)
                    return False

                GLib.idle_add(_finish)

            threading.Thread(target=_worker, daemon=True).start()

        def _inspect_live_app_async(self, app_query: str) -> None:
            q = app_query.strip()
            if not q:
                return
            self.inspect_app_query = q
            self.live_adapter_status = f"🔍 正在深度探测「{q}」的托盘菜单 / MPRIS / AT-SPI 接口..."
            if self.memory_revealer.get_reveal_child():
                self._render_memory_panel()

            def _worker() -> None:
                res = call_module_rpc(
                    "app_adapter",
                    "inspect_live_app",
                    {"app": q, "app_hint": q, "query": q},
                    timeout=9.0,
                )
                if res.get("ok") and isinstance(res.get("result"), dict):
                    inspected = res["result"]
                    nm = str(inspected.get("display_name") or inspected.get("name") or inspected.get("app") or q)
                    status_msg = f"✓ 已完成「{nm}」实时转译能力探测"
                else:
                    inspected = None
                    status_msg = f"✕ 探测失败: {res.get('error', '未找到匹配软件')}"

                def _finish() -> bool:
                    self.last_inspected_app = inspected
                    self.live_adapter_status = status_msg
                    if self.memory_revealer.get_reveal_child():
                        self._render_memory_panel()
                    return False

                GLib.idle_add(_finish)

            threading.Thread(target=_worker, daemon=True).start()

        def _render_memory_panel(self) -> None:
            self._clear_box(self.memory_box)
            hdr_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            title = Gtk.Label(label="🧠 个性化软件实时转译台 & 个人记忆索引", xalign=0.0)
            title.add_css_class("intentos-strip-label")
            title.set_hexpand(True)
            wb_btn = Gtk.Button(label="⚙ 9大分类转译中心")
            wb_btn.add_css_class("intentos-seg-btn")
            wb_btn.set_tooltip_text("打开设置中心第 5 页：本机软件深度扫描与分类转译中心")
            wb_btn.connect("clicked", lambda _b: launch_settings_window("capabilities", self.inspect_app_query))
            sync_btn = Gtk.Button(label="↻ 刷新")
            sync_btn.add_css_class("intentos-seg-btn")
            sync_btn.connect("clicked", self._on_sync_memory_clicked)
            hdr_row.append(title)
            hdr_row.append(wb_btn)
            hdr_row.append(sync_btn)
            self.memory_box.append(hdr_row)

            # Wave 5 Shortcut A: `[🔍 本机软件分类统计]` + 9-Category Deep-Scan Summary
            ds = self.deep_scan_summary or {}
            ds_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            ds_card.add_css_class("intentos-tray-card")
            ds_top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            tot_sc = int(ds.get("total_scanned") or len(ds.get("apps") or []) or len(self.adapters_cache) or 0)
            tot_ad = int(ds.get("total_adapted") or len(self.adapters_cache) or tot_sc)
            run_cnt = int(ds.get("running_count") or len(self.live_tray_apps) or 0)
            cats_arr = ds.get("categories") if isinstance(ds.get("categories"), list) else []
            ds_lbl = Gtk.Label(
                label=f"🔍 本机软件分类统计：已扫描 {tot_sc} 款软件 · 9 大分类 · {run_cnt} 款运行中 · {tot_ad} 项转译接口",
                xalign=0.0,
            )
            ds_lbl.add_css_class("intentos-strip-label")
            ds_lbl.set_hexpand(True)
            ds_lbl.set_wrap(True)
            ds_open_btn = Gtk.Button(label="🔍 分类浏览")
            ds_open_btn.add_css_class("intentos-tray-btn")
            ds_open_btn.connect("clicked", lambda _b: launch_settings_window("capabilities"))
            ds_top.append(ds_lbl)
            ds_top.append(ds_open_btn)
            ds_card.append(ds_top)
            if cats_arr:
                cat_flow = Gtk.FlowBox()
                cat_flow.set_selection_mode(Gtk.SelectionMode.NONE)
                cat_flow.set_max_children_per_line(5)
                cat_flow.set_column_spacing(4)
                cat_flow.set_row_spacing(3)
                for c_obj in cats_arr[:9]:
                    if not isinstance(c_obj, dict):
                        continue
                    c_icon = str(c_obj.get("icon") or "🧩")
                    c_nm = str(c_obj.get("name_zh") or c_obj.get("name") or c_obj.get("id") or "")
                    c_cnt = int(c_obj.get("count") or 0)
                    short_cn = c_nm[:5] if len(c_nm) > 5 else c_nm
                    cb = Gtk.Button(label=f"{c_icon}{short_cn}({c_cnt})")
                    cb.add_css_class("intentos-adapter-chip")
                    cb.set_tooltip_text(f"{c_icon} {c_nm}: {c_cnt} 款本机软件")
                    cb.connect("clicked", lambda _b: launch_settings_window("capabilities"))
                    cat_flow.append(cb)
                ds_card.append(cat_flow)
            self.memory_box.append(ds_card)

            # Wave 5 Shortcut B: Non-Linear Context Decay Session Telemetry
            cp_raw = self.session_compression_preview or {}
            cp_stats = cp_raw.get("stats") if isinstance(cp_raw.get("stats"), dict) else cp_raw
            cfg_cc = (
                cp_raw.get("config")
                if isinstance(cp_raw.get("config"), dict)
                else (self.memory_cache.get("context_compression_config") or {})
            )
            cc_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            cc_en = cfg_cc.get("enabled", True) is not False
            cc_max = int(cfg_cc.get("max_context_tokens") or 6000)
            cc_comp = int(cp_stats.get("compressed_estimated_tokens") or 0)
            cc_saved = int(round(float(cp_stats.get("saved_pct") or 0.0)))
            cc_dropped = int(cp_stats.get("dropped_tool_records") or 0)
            cc_txt = (
                f"📉 非线性时间衰减压缩: {'已启用' if cc_en else '已关闭'} · 预算 {cc_max} tok"
                + (f" · 当前 {cc_comp} tok (省 {cc_saved}% · 剥离工具记录 {cc_dropped} 条)" if (cc_comp or cc_saved or cc_dropped) else " · 自动剥离历史工具轨迹")
            )
            cc_lbl = Gtk.Label(label=cc_txt, xalign=0.0)
            cc_lbl.add_css_class("intentos-bubble-meta")
            cc_lbl.set_hexpand(True)
            cc_lbl.set_wrap(True)
            cc_cfg_btn = Gtk.Button(label="⚙ 压缩策略")
            cc_cfg_btn.add_css_class("intentos-seg-btn")
            cc_cfg_btn.connect("clicked", lambda _b: launch_settings_window("memories"))
            cc_row.append(cc_lbl)
            cc_row.append(cc_cfg_btn)
            self.memory_box.append(cc_row)

            if self.live_adapter_status:
                st_lbl = Gtk.Label(label=self.live_adapter_status, xalign=0.0)
                st_lbl.add_css_class("intentos-trace-summary")
                st_lbl.set_wrap(True)
                self.memory_box.append(st_lbl)

            # Section A: 运行态托盘与软件实时控制 (`list_live_tray_apps`)
            sec_a_lbl = Gtk.Label(
                label=f"🟢 运行态托盘与软件实时控制 ({len(self.live_tray_apps)} 款在线 · 一键直控 dbusmenu):",
                xalign=0.0,
            )
            sec_a_lbl.add_css_class("intentos-trace-summary")
            self.memory_box.append(sec_a_lbl)

            if not self.live_tray_apps:
                no_tray = Gtk.Label(
                    label="  暂未检测到暴露 StatusNotifierItem / MPRIS 的托盘应用（支持下栏直接输入任意软件名探测）",
                    xalign=0.0,
                )
                no_tray.add_css_class("intentos-bubble-meta")
                no_tray.set_wrap(True)
                self.memory_box.append(no_tray)
            else:
                for tr in self.live_tray_apps[:6]:
                    t_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
                    t_card.add_css_class("intentos-tray-card")
                    top_r = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                    app_nm = str(tr.get("name") or tr.get("app_id") or "托盘应用")
                    live_t = str(tr.get("live_title") or "").strip()
                    icon_prefix = "🎵" if tr.get("mpris_service") or "音" in app_nm or "soda" in app_nm.lower() else "🟢"
                    head_txt = f"{icon_prefix} {app_nm}" + (f" · {live_t}" if live_t else "")
                    h_lbl = Gtk.Label(label=head_txt, xalign=0.0)
                    h_lbl.add_css_class("intentos-strip-label")
                    h_lbl.set_ellipsize(Pango.EllipsizeMode.END)
                    h_lbl.set_hexpand(True)
                    top_r.append(h_lbl)

                    insp_mini = Gtk.Button(label="🔍 探测")
                    insp_mini.add_css_class("intentos-tray-btn")
                    insp_mini.connect("clicked", lambda _b, q=app_nm: self._inspect_live_app_async(q))
                    top_r.append(insp_mini)
                    t_card.append(top_r)

                    m_items = tr.get("menu_items") or []
                    if m_items:
                        act_flow = Gtk.FlowBox()
                        act_flow.set_selection_mode(Gtk.SelectionMode.NONE)
                        act_flow.set_max_children_per_line(5)
                        act_flow.set_column_spacing(4)
                        act_flow.set_row_spacing(4)
                        svc = str(tr.get("service") or "")
                        app_key = str(tr.get("app_id") or app_nm)
                        for mi in m_items[:8]:
                            m_lbl = str(mi.get("label") or "")
                            if not m_lbl:
                                continue
                            ab = Gtk.Button(label=m_lbl if len(m_lbl) <= 14 else m_lbl[:13] + "…")
                            ab.add_css_class("intentos-tray-btn")
                            ab.set_sensitive(bool(mi.get("enabled", True)))
                            ab.set_tooltip_text(f"直接触发托盘菜单项: {app_nm} → {m_lbl}")
                            ab.connect(
                                "clicked",
                                lambda _btn, ak=app_key, al=m_lbl, sv=svc, mid=mi.get("id"): self._trigger_tray_menu_async(
                                    ak, al, sv, mid
                                ),
                            )
                            act_flow.append(ab)
                        t_card.append(act_flow)
                    self.memory_box.append(t_card)

            # Section B: 探测并转译任意软件 (`inspect_live_app`)
            sec_b_lbl = Gtk.Label(label="⚡ 探测并转译任意软件 (自动发现 dbusmenu / MPRIS2 / .desktop / AT-SPI):", xalign=0.0)
            sec_b_lbl.add_css_class("intentos-trace-summary")
            self.memory_box.append(sec_b_lbl)

            probe_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            probe_entry = Gtk.Entry()
            probe_entry.set_placeholder_text("输入任意软件名探测接口 (如 飞书 / FlClash / 轻笺 / 汽水音乐)...")
            probe_entry.set_text(self.inspect_app_query)
            probe_entry.set_hexpand(True)
            probe_entry.add_css_class("intentos-model-search")
            probe_btn = Gtk.Button(label="⚡ 探测接口")
            probe_btn.add_css_class("intentos-seg-btn-active")
            probe_entry.connect("activate", lambda e: self._inspect_live_app_async(e.get_text()))
            probe_btn.connect("clicked", lambda _b: self._inspect_live_app_async(probe_entry.get_text()))
            probe_row.append(probe_entry)
            probe_row.append(probe_btn)
            self.memory_box.append(probe_row)

            if isinstance(self.last_inspected_app, dict) and self.last_inspected_app:
                ins = self.last_inspected_app
                ins_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
                ins_card.add_css_class("intentos-tray-card")
                ins_nm = str(ins.get("display_name") or ins.get("name") or ins.get("app") or self.inspect_app_query)
                desk_id = str(ins.get("desktop_id") or ins.get("desktop_file") or "未绑定 .desktop")
                pids = ins.get("pids") or ins.get("running_pids") or ([ins["pid"]] if ins.get("pid") else [])
                chans = ins.get("channels") or ins.get("supported_channels") or []
                meta_txt = (
                    f"📦 {ins_nm} · desktop={desk_id} · PID={pids if pids else '未运行'}"
                    + (f" · 通道={','.join(str(c) for c in chans)}" if chans else "")
                )
                m_lbl = Gtk.Label(label=meta_txt, xalign=0.0)
                m_lbl.add_css_class("intentos-bubble-meta")
                m_lbl.set_wrap(True)
                ins_card.append(m_lbl)

                disc_menus = normalize_menu_items_py(
                    ins.get("tray_menu_items")
                    or ins.get("dbusmenu_items")
                    or ins.get("menu_items")
                    or ((ins.get("tray") or {}).get("menu_items") if isinstance(ins.get("tray"), dict) else [])
                )
                act_row_flow = Gtk.FlowBox()
                act_row_flow.set_selection_mode(Gtk.SelectionMode.NONE)
                act_row_flow.set_max_children_per_line(5)
                act_row_flow.set_column_spacing(4)
                act_row_flow.set_row_spacing(4)
                for dm in disc_menus[:8]:
                    dl = str(dm.get("label") or "")
                    if not dl:
                        continue
                    tb = Gtk.Button(label=f"▶ {dl}")
                    tb.add_css_class("intentos-tray-btn")
                    tb.connect(
                        "clicked",
                        lambda _b, ak=ins_nm, al=dl, mid=dm.get("id"): self._trigger_tray_menu_async(ak, al, "", mid),
                    )
                    act_row_flow.append(tb)
                bind_btn = Gtk.Button(label="⚙ 绑定个性化口令")
                bind_btn.add_css_class("intentos-adapter-chip")
                bind_btn.connect("clicked", lambda _b, q=ins_nm: launch_settings_window("capabilities", q))
                act_row_flow.append(bind_btn)
                ins_card.append(act_row_flow)
                self.memory_box.append(ins_card)

            dash = self.memory_cache
            mentioned = (dash.get("mentioned_files") or dash.get("recent_mentions") or [])[:5]
            frequent = (dash.get("frequent_files") or dash.get("long_term_files") or [])[:5]
            apps = (dash.get("frequent_apps") or dash.get("top_apps") or [])[:6]
            outlines = (dash.get("document_outlines_preview") or [])[:4]
            summary = dash.get("installed_apps_summary") or {}
            total_apps = (
                summary.get("total_count")
                or summary.get("total")
                or dash.get("total_installed_apps")
                or len(apps)
            )

            def _add_chip_section(sec_title: str, items: list[tuple[str, str]], css_cls: str) -> None:
                lbl = Gtk.Label(label=sec_title, xalign=0.0)
                lbl.add_css_class("intentos-trace-summary")
                self.memory_box.append(lbl)
                if not items:
                    empty = Gtk.Label(label="  暂无记录（对话提及或点击同步后自动生成）", xalign=0.0)
                    empty.add_css_class("intentos-bubble-meta")
                    self.memory_box.append(empty)
                    return
                flow = Gtk.FlowBox()
                flow.set_selection_mode(Gtk.SelectionMode.NONE)
                flow.set_max_children_per_line(4)
                flow.set_column_spacing(4)
                flow.set_row_spacing(4)
                for disp, val in items:
                    short_d = disp if len(disp) <= 18 else disp[:16] + "…"
                    b = Gtk.Button(label=short_d)
                    b.add_css_class(css_cls)
                    b.set_tooltip_text(val)
                    b.connect("clicked", lambda _btn, v=val: self._insert_mention_value(v))
                    flow.append(b)
                self.memory_box.append(flow)

            m_pairs = [
                (
                    str(
                        x.get("display_name")
                        or x.get("title")
                        or Path(str(x.get("canonical_value") or x.get("path") or "")).name
                        or "文件"
                    ),
                    str(x.get("canonical_value") or x.get("path") or x.get("display_name") or ""),
                )
                for x in mentioned
                if isinstance(x, dict)
            ]
            f_pairs = [
                (
                    str(x.get("title") or x.get("name") or Path(str(x.get("path") or "")).name or "文件"),
                    str(x.get("path") or x.get("title") or ""),
                )
                for x in frequent
                if isinstance(x, dict)
            ]
            o_pairs = [
                (
                    str(x.get("doc_title") or Path(str(x.get("path") or "")).name or "文档"),
                    str(x.get("path") or ""),
                )
                for x in outlines
                if isinstance(x, dict) and x.get("path")
            ]
            a_pairs = [
                (
                    str(x.get("zh_name") or x.get("display_name") or x.get("name") or "应用"),
                    str(x.get("zh_name") or x.get("display_name") or x.get("name") or ""),
                )
                for x in apps
                if isinstance(x, dict)
            ]
            ad_pairs = [
                (
                    f"{x.get('display_name') or x.get('name') or x.get('id')} ({x.get('channel') or (x.get('channels') or ['dbus'])[0]})",
                    str(x.get("display_name") or x.get("name") or x.get("id") or ""),
                )
                for x in self.adapters_cache[:5]
                if isinstance(x, dict)
            ]

            _add_chip_section("📂 之前对话提到的文件:", m_pairs, "intentos-mem-chip")
            _add_chip_section("🔥 长期高频使用的文件 (XBEL + IntentOS):", f_pairs, "intentos-mem-chip")
            if o_pairs:
                _add_chip_section("📑 已建立章节大纲语义索引的文档:", o_pairs, "intentos-mem-chip")
            _add_chip_section(f"🧩 本机常用与已安装软件 (共识别 {total_apps} 款):", a_pairs, "intentos-mem-chip")
            if ad_pairs:
                _add_chip_section("🔌 已注册个性化转译规则:", ad_pairs, "intentos-adapter-chip")

        def _on_sync_memory_clicked(self, _btn: Any) -> None:
            def _worker() -> None:
                try:
                    call_module_rpc("memory_hub", "sync_system_usage", {}, timeout=12.0)
                except Exception:
                    pass
                self._refresh_memory_hints_async(re_render=True)

            threading.Thread(target=_worker, daemon=True).start()

        # ------------------------------------------------------------------
        # Window Toggles (Incognito / Pin / Theme / Clipboard / Session)
        # ------------------------------------------------------------------
        def on_incog_toggled(self, btn: Gtk.ToggleButton) -> None:
            self.incognito = btn.get_active()
            self.status_dot.set_tooltip_text("隐私无痕会话" if self.incognito else "标准会话")

        def on_pin_toggled(self, btn: Gtk.ToggleButton) -> None:
            self.pinned = btn.get_active()
            if shutil.which("wmctrl"):
                action = "add,above" if self.pinned else "remove,above"
                try:
                    subprocess.Popen(
                        ["wmctrl", "-r", "✦ IntentOS · 随问", "-b", action],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except Exception:
                    pass

        def on_theme_clicked(self, _btn: Any) -> None:
            self._apply_theme(not self.light_theme)

        def _set_clipboard_context(self, text: str) -> None:
            cleaned = text.strip()
            self.clipboard_context = cleaned
            if cleaned:
                one_line = " ".join(cleaned.split())
                preview = one_line if len(one_line) <= 44 else one_line[:42] + "…"
                self.clip_lbl.set_text(f"📋 已附带剪贴板 ({len(cleaned)} 字): {preview}")
                self.clip_strip.set_visible(True)
            else:
                self.clip_strip.set_visible(False)
            self.input_view.grab_focus()

        def _capture_clipboard_context(self) -> None:
            display = Gdk.Display.get_default()
            if display is None:
                fallback_txt = read_system_clipboard_fallback()
                if fallback_txt:
                    self._set_clipboard_context(fallback_txt)
                return

            primary = display.get_primary_clipboard()
            clipboard = display.get_clipboard()

            def _on_clipboard_read(cb_obj: Any, res: Any) -> None:
                txt = ""
                try:
                    txt = cb_obj.read_text_finish(res) or ""
                except Exception:
                    txt = ""
                if not txt.strip():
                    txt = read_system_clipboard_fallback()
                if txt.strip():
                    self._set_clipboard_context(txt)

            def _on_primary_read(p_obj: Any, res: Any) -> None:
                txt = ""
                try:
                    txt = p_obj.read_text_finish(res) or ""
                except Exception:
                    txt = ""
                if txt.strip():
                    self._set_clipboard_context(txt)
                else:
                    clipboard.read_text_async(None, _on_clipboard_read)

            primary.read_text_async(None, _on_primary_read)

        def start_new_session(self) -> None:
            self.active_turn_token += 1
            self._set_busy_state(False)
            self.session_id = f"ses_{int(time.time() * 1000)}"
            self.message_count = 0
            self.history_cursor = -1
            if not self.incognito:
                threading.Thread(
                    target=lambda: self._create_remote_session(self.session_id),
                    daemon=True,
                ).start()
            self._clear_box(self.chat_stream)
            self._render_welcome_state()
            self.input_view.grab_focus()

        def _create_remote_session(self, sid: str) -> None:
            try:
                res = call_module_rpc("memory_hub", "create_session", {"session_id": sid}, timeout=4.0)
                if res.get("ok") and isinstance(res.get("result"), dict):
                    remote_id = res["result"].get("session_id") or res["result"].get("id")
                    if remote_id:
                        self.session_id = str(remote_id)
            except Exception:
                pass

        # ------------------------------------------------------------------
        # Chat Stream Rendering, Compact Trace Dots & Auto-Expanded Approval
        # ------------------------------------------------------------------
        def _clear_box(self, box: Gtk.Box) -> None:
            child = box.get_first_child()
            while child is not None:
                nxt = child.get_next_sibling()
                box.remove(child)
                child = nxt

        def _scroll_to_bottom(self) -> bool:
            adj = self.chat_scroll.get_vadjustment()
            if adj is not None:
                adj.set_value(max(0.0, adj.get_upper() - adj.get_page_size()))
            return False

        def _render_welcome_state(self) -> None:
            self.welcome_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            self.welcome_box.set_valign(Gtk.Align.CENTER)
            self.welcome_box.set_vexpand(True)
            self.welcome_box.set_margin_top(36)
            self.welcome_box.set_margin_bottom(24)

            t_lbl = Gtk.Label(label="✦ IntentOS · 随问", xalign=0.5)
            t_lbl.add_css_class("intentos-welcome-title")
            s_lbl = Gtk.Label(
                label="浮在桌面之上的高可信 AIOS 对话窗\n文档章节大纲召回 · 敏感路径交互审批 · 个性化软件转译层",
                xalign=0.5,
                justify=Gtk.Justification.CENTER,
            )
            s_lbl.add_css_class("intentos-welcome-sub")
            self.welcome_box.append(t_lbl)
            self.welcome_box.append(s_lbl)

            starters = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            starters.set_margin_top(10)
            for short_lbl, full_q in STARTER_PROMPTS:
                b = Gtk.Button(label=short_lbl)
                b.add_css_class("intentos-starter-pill")
                b.connect("clicked", lambda _btn, q=full_q: self._send_prompt(q))
                starters.append(b)
            self.welcome_box.append(starters)
            self.chat_stream.append(self.welcome_box)

        def _append_user_bubble(self, text: str, had_clipboard: bool) -> None:
            if hasattr(self, "welcome_box") and self.welcome_box.get_parent() is not None:
                self.chat_stream.remove(self.welcome_box)
            self.message_count += 1

            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            spacer = Gtk.Box()
            spacer.set_hexpand(True)
            row.append(spacer)

            bub = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            bub.add_css_class("intentos-bubble-user")
            if had_clipboard:
                c_tag = Gtk.Label(label="📋 附带剪贴板文本", xalign=0.0)
                c_tag.add_css_class("intentos-trace-summary")
                bub.append(c_tag)
            lbl = Gtk.Label(label=text, xalign=0.0)
            lbl.set_wrap(True)
            lbl.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            lbl.set_max_width_chars(38)
            lbl.set_selectable(True)
            bub.append(lbl)
            row.append(bub)

            self.chat_stream.append(row)
            GLib.idle_add(self._scroll_to_bottom)

        def _append_thinking_placeholder(self) -> Gtk.Box:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            bub = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            bub.add_css_class("intentos-bubble-assistant")

            dot = Gtk.Button(label="●")
            dot.add_css_class("intentos-trace-dot")
            dot.add_css_class("intentos-dot-gray")
            dot.set_sensitive(False)
            bub.append(dot)

            lbl = Gtk.Label(label="正在思考与调度系统能力… (Esc 中止)", xalign=0.0)
            lbl.add_css_class("intentos-trace-summary")
            bub.append(lbl)
            row.append(bub)
            self.chat_stream.append(row)
            GLib.idle_add(self._scroll_to_bottom)
            return row

        def _render_markdown_into_box(self, md_box: Gtk.Box, reply_md: str) -> None:
            self._clear_box(md_box)
            for seg_kind, arg1, arg2 in parse_markdown_segments(reply_md, light_theme=self.light_theme):
                if seg_kind == "code":
                    code_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
                    code_card.add_css_class("intentos-code-card")
                    chdr = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                    lang_lbl = Gtk.Label(label=arg1, xalign=0.0)
                    lang_lbl.add_css_class("intentos-bubble-meta")
                    lang_lbl.set_hexpand(True)
                    cp_btn = Gtk.Button(label="复制")
                    cp_btn.add_css_class("intentos-seg-btn")
                    cp_btn.connect("clicked", lambda _b, c=arg2: self._copy_text(c))
                    chdr.append(lang_lbl)
                    chdr.append(cp_btn)
                    code_card.append(chdr)

                    c_lbl = Gtk.Label(label=arg2, xalign=0.0)
                    c_lbl.add_css_class("intentos-code-text")
                    c_lbl.set_wrap(True)
                    c_lbl.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
                    c_lbl.set_selectable(True)
                    code_card.append(c_lbl)
                    md_box.append(code_card)
                else:
                    lbl = Gtk.Label(xalign=0.0)
                    lbl.add_css_class("intentos-md-body")
                    lbl.set_wrap(True)
                    lbl.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
                    lbl.set_selectable(True)
                    try:
                        lbl.set_markup(arg1)
                    except Exception:
                        lbl.set_text(arg2)
                    md_box.append(lbl)

        def _append_assistant_turn(self, turn_data: dict[str, Any], orig_prompt: str) -> None:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            bub = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            bub.add_css_class("intentos-bubble-assistant")
            bub.set_hexpand(True)

            # 1. 20px Horizontal Colored Trace Dots (`●`) Bar (compact `> 6` into `+N` pill, dynamically updatable on approval resume!)
            dots_holder: dict[str, Any] = {
                "dots": list(turn_data.get("trace_dots") or []),
                "approval_dot_btn": None,
                "s_lbl": None,
            }
            trace_container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

            def _rebuild_trace_section(new_dots: list[dict[str, Any]]) -> None:
                dots_holder["dots"] = list(new_dots)
                dots_holder["approval_dot_btn"] = None
                self._clear_box(trace_container)
                cur_dots = dots_holder["dots"]
                if not cur_dots:
                    trace_container.set_visible(False)
                    return
                trace_container.set_visible(True)

                detail_revealer = Gtk.Revealer()
                detail_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_DOWN)
                detail_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
                detail_card.add_css_class("intentos-trace-detail")
                detail_revealer.set_child(detail_card)

                trace_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
                dots_strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
                active_idx_holder = {"idx": -1, "expanded": len(cur_dots) <= 6}
                dot_buttons: dict[int, Gtk.Button] = {}

                def _toggle_dot(_b: Any, idx: int) -> None:
                    if active_idx_holder["idx"] == idx:
                        active_idx_holder["idx"] = -1
                        detail_revealer.set_reveal_child(False)
                        for db in dot_buttons.values():
                            db.remove_css_class("intentos-trace-dot-active")
                        return
                    active_idx_holder["idx"] = idx
                    for i_key, db in dot_buttons.items():
                        if i_key == idx:
                            db.add_css_class("intentos-trace-dot-active")
                        else:
                            db.remove_css_class("intentos-trace-dot-active")

                    d = cur_dots[idx]
                    self._clear_box(detail_card)
                    hdr = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                    t_lbl = Gtk.Label(label=f"● {d.get('title', '')}", xalign=0.0)
                    t_lbl.set_hexpand(True)
                    hdr.append(t_lbl)
                    if d.get("duration_ms") is not None:
                        hdr.append(Gtk.Label(label=f"{d['duration_ms']} ms"))
                    cs_id = d.get("changeset_id")
                    if cs_id:
                        self.last_changeset_id = str(cs_id)
                        u_btn = Gtk.Button(label="↶ 撤销")
                        u_btn.add_css_class("intentos-btn-undo-mini")
                        u_btn.connect("clicked", lambda _ub, cid=str(cs_id): self._undo_changeset(cid))
                        hdr.append(u_btn)
                    detail_card.append(hdr)

                    body_txt = str(d.get("detail") or "").strip()
                    if body_txt:
                        d_lbl = Gtk.Label(label=body_txt[:1500], xalign=0.0)
                        d_lbl.set_wrap(True)
                        d_lbl.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
                        d_lbl.set_selectable(True)
                        detail_card.append(d_lbl)
                    detail_revealer.set_reveal_child(True)
                    GLib.idle_add(self._scroll_to_bottom)

                def _rebuild_dots_strip() -> None:
                    self._clear_box(dots_strip)
                    dot_buttons.clear()
                    expanded = active_idx_holder["expanded"]
                    if len(cur_dots) > 6 and not expanded:
                        visible_indices: list[int | str] = [0, 1, 2, "more", len(cur_dots) - 2, len(cur_dots) - 1]
                    else:
                        visible_indices = list(range(len(cur_dots)))
                        if len(cur_dots) > 6:
                            visible_indices.append("less")

                    for item in visible_indices:
                        if item == "more":
                            hidden_n = len(cur_dots) - 5
                            more_btn = Gtk.Button(label=f"+{hidden_n}")
                            more_btn.add_css_class("intentos-trace-more-pill")
                            more_btn.set_tooltip_text(f"展开其余 {hidden_n} 个执行轨迹节点")
                            more_btn.connect(
                                "clicked",
                                lambda _mb: (active_idx_holder.update({"expanded": True}), _rebuild_dots_strip()),
                            )
                            dots_strip.append(more_btn)
                        elif item == "less":
                            less_btn = Gtk.Button(label="收起")
                            less_btn.add_css_class("intentos-trace-more-pill")
                            less_btn.connect(
                                "clicked",
                                lambda _lb: (active_idx_holder.update({"expanded": False}), _rebuild_dots_strip()),
                            )
                            dots_strip.append(less_btn)
                        else:
                            idx = int(item)
                            d = cur_dots[idx]
                            color = d.get("color", "green")
                            dbtn = Gtk.Button(label="●")
                            dbtn.add_css_class("intentos-trace-dot")
                            dbtn.add_css_class(f"intentos-dot-{color}")
                            if active_idx_holder["idx"] == idx:
                                dbtn.add_css_class("intentos-trace-dot-active")
                            dbtn.set_tooltip_text(str(d.get("title") or d.get("kind") or ""))
                            dbtn.connect("clicked", _toggle_dot, idx)
                            dots_strip.append(dbtn)
                            dot_buttons[idx] = dbtn
                            if d.get("kind") == "approval":
                                dots_holder["approval_dot_btn"] = dbtn

                _rebuild_dots_strip()
                trace_bar.append(dots_strip)

                summary_txt = " · ".join(str(d.get("title", "")) for d in cur_dots[:2])
                s_lbl = Gtk.Label(label=summary_txt, xalign=0.0)
                s_lbl.add_css_class("intentos-trace-summary")
                s_lbl.set_ellipsize(Pango.EllipsizeMode.END)
                s_lbl.set_hexpand(True)
                dots_holder["s_lbl"] = s_lbl
                trace_bar.append(s_lbl)

                first_cs = next((d.get("changeset_id") for d in cur_dots if d.get("changeset_id")), None)
                if first_cs:
                    self.last_changeset_id = str(first_cs)
                    quick_undo = Gtk.Button(label="↶ 撤销")
                    quick_undo.add_css_class("intentos-btn-undo-mini")
                    quick_undo.connect("clicked", lambda _b, cid=str(first_cs): self._undo_changeset(cid))
                    trace_bar.append(quick_undo)

                trace_container.append(trace_bar)
                trace_container.append(detail_revealer)

            _rebuild_trace_section(dots_holder["dots"])
            bub.append(trace_container)

            # 2. Markdown-Formatted Reply Body
            reply_md = str(turn_data.get("reply_markdown") or "")
            reply_text_holder: dict[str, str] = {"text": reply_md}
            md_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            self._render_markdown_into_box(md_box, reply_md)
            bub.append(md_box)

            # 3. AUTO-EXPANDED Sensitive Permission & Safe Execution Approval Container
            approvals_container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            bub.append(approvals_container)

            # 4. Subtle Footer (engine/model + context compression telemetry + copy + regenerate)
            meta_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            meta_lbl = Gtk.Label(label="", xalign=0.0)
            meta_lbl.add_css_class("intentos-bubble-meta")
            meta_lbl.set_hexpand(True)
            meta_lbl.set_ellipsize(Pango.EllipsizeMode.END)
            meta_row.append(meta_lbl)

            def _update_footer_meta(b_used: str, m_used: str, cc_obj: Any) -> None:
                parts: list[str] = []
                em = f"{b_used}{' · ' + m_used if m_used else ''}".strip()
                if em:
                    parts.append(em)
                cc_tag = format_context_compression_tag(cc_obj)
                if cc_tag:
                    parts.append(cc_tag)
                meta_lbl.set_text(" · ".join(parts))

            _update_footer_meta(
                str(turn_data.get("backend_used") or ""),
                str(turn_data.get("model_used") or ""),
                turn_data.get("context_compression"),
            )

            cp_all = Gtk.Button(label="复制")
            cp_all.add_css_class("intentos-footer-btn")
            cp_all.connect("clicked", lambda _b: self._copy_text(reply_text_holder["text"]))
            retry_btn = Gtk.Button(label="↻")
            retry_btn.add_css_class("intentos-footer-btn")
            retry_btn.set_tooltip_text("重新生成此回复")
            retry_btn.connect("clicked", lambda _b, q=orig_prompt: self._send_prompt(q))
            meta_row.append(cp_all)
            meta_row.append(retry_btn)
            bub.append(meta_row)

            def _mount_approval_card(pa_item: dict[str, Any]) -> dict[str, Any]:
                self._set_status_dot("pending")
                app_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
                app_card.add_css_class("intentos-inline-approval")
                app_card.set_visible(True)  # ALWAYS auto-expanded immediately!

                hdr_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                a_title = Gtk.Label(label="🛡️ 敏感权限与安全执行审批", xalign=0.0)
                a_title.add_css_class("intentos-approval-header")
                a_title.set_hexpand(True)
                hdr_row.append(a_title)

                undo_txt = "可逆变更 · 支持撤销" if pa_item.get("reversible") else "敏感受控操作"
                badge = Gtk.Label(label=undo_txt)
                badge.add_css_class("intentos-approval-badge")
                hdr_row.append(badge)
                app_card.append(hdr_row)

                scope_kind, scope_val, human_target = extract_approval_scope(pa_item)
                cap_name = pa_item.get("capability_id") or pa_item.get("intent_action") or "受控系统操作"
                alive_pids = pa_item.get("alive_pids") or (pa_item.get("arguments") or {}).get("alive_pids")
                meta_parts = [f"能力: {cap_name}", f"目标({scope_kind}): {human_target}"]
                if alive_pids:
                    meta_parts.append(f"PID: {alive_pids}")
                meta_line = Gtk.Label(label=" · ".join(meta_parts), xalign=0.0)
                meta_line.add_css_class("intentos-trace-summary")
                meta_line.set_wrap(True)
                app_card.append(meta_line)

                a_desc: Gtk.Label | None = None
                desc = f"{pa_item.get('summary') or ''}\n{pa_item.get('diff_preview') or ''}".strip()
                if desc:
                    a_desc = Gtk.Label(label=desc[:700], xalign=0.0)
                    a_desc.add_css_class("intentos-approval-diff")
                    a_desc.set_wrap(True)
                    a_desc.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
                    a_desc.set_selectable(True)
                    app_card.append(a_desc)

                btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                b_once = Gtk.Button(label="✓ 批准本次")
                b_once.add_css_class("intentos-btn-approve")
                b_scope = Gtk.Button(label="⏱ 本会话放行此范围")
                b_scope.add_css_class("intentos-btn-scope")
                b_scope.set_tooltip_text(f"本会话 60 分钟内自动放行 {scope_kind}: {scope_val}")
                b_deny = Gtk.Button(label="✕ 拒绝")
                b_deny.add_css_class("intentos-btn-deny")

                res_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                res_lbl = Gtk.Label(label="", xalign=0.0)
                res_lbl.add_css_class("intentos-trace-summary")
                res_lbl.set_wrap(True)
                res_lbl.set_hexpand(True)
                res_row.append(res_lbl)

                ui_bundle: dict[str, Any] = {
                    "pa": pa_item,
                    "app_card": app_card,
                    "a_title": a_title,
                    "badge": badge,
                    "a_desc": a_desc,
                    "btn_row": btn_row,
                    "b_once": b_once,
                    "b_scope": b_scope,
                    "b_deny": b_deny,
                    "res_row": res_row,
                    "status_lbl": res_lbl,
                    "md_box": md_box,
                    "reply_text_holder": reply_text_holder,
                    "rebuild_trace_fn": _rebuild_trace_section,
                    "dots_holder": dots_holder,
                    "update_footer_fn": _update_footer_meta,
                    "mount_next_approval_fn": _mount_approval_card,
                    "default_backend": str(turn_data.get("backend_used") or ""),
                    "default_model": str(turn_data.get("model_used") or ""),
                }
                self._last_approval_ui_bundle = ui_bundle

                def _resolve_approval(mode: str, start_rpc: bool = True) -> None:
                    # 1. Instant unmistakable click feedback on UI thread!
                    b_once.set_sensitive(False)
                    b_scope.set_sensitive(False)
                    b_deny.set_sensitive(False)
                    btn_row.set_visible(False)
                    res_lbl.set_text(
                        "⏳ 正在取消受控操作…"
                        if mode == "deny"
                        else "⏳ 已确认授权，正在执行并继续会话推理…"
                    )
                    self._set_status_dot("busy")
                    if start_rpc:
                        self._handle_inline_approval(ui_bundle=ui_bundle, mode=mode)

                ui_bundle["trigger_click_fn"] = _resolve_approval
                b_once.connect("clicked", lambda _b: _resolve_approval("once"))
                b_scope.connect("clicked", lambda _b: _resolve_approval("session"))
                b_deny.connect("clicked", lambda _b: _resolve_approval("deny"))

                btn_row.append(b_once)
                btn_row.append(b_scope)
                btn_row.append(b_deny)
                app_card.append(btn_row)
                app_card.append(res_row)
                approvals_container.append(app_card)
                return ui_bundle

            pa = turn_data.get("pending_approval")
            cur_dots_init = dots_holder["dots"]
            if (not isinstance(pa, dict) or not pa) and any(d.get("kind") == "approval" for d in cur_dots_init):
                ap_dot = next(d for d in cur_dots_init if d.get("kind") == "approval")
                if isinstance(ap_dot.get("pending_approval"), dict) and ap_dot["pending_approval"]:
                    pa = ap_dot["pending_approval"]
                else:
                    pa = {
                        "capability_id": ap_dot.get("title", "受控操作"),
                        "summary": ap_dot.get("detail", "该敏感操作需人工确认后执行"),
                        "reversible": False,
                    }

            if isinstance(pa, dict) and pa:
                _mount_approval_card(pa)

            row.append(bub)
            self.chat_stream.append(row)
            GLib.idle_add(self._scroll_to_bottom)

        def _apply_resumed_approval_result(
            self,
            ui_bundle: dict[str, Any],
            mode: str,
            resumed_turn: dict[str, Any] | None,
            fallback_msg: str = "",
            fallback_md: str = "",
            fallback_cs_id: str | None = None,
            approved_ok: bool = True,
        ) -> bool:
            app_card: Gtk.Box = ui_bundle["app_card"]
            a_title: Gtk.Label = ui_bundle["a_title"]
            badge: Gtk.Label = ui_bundle["badge"]
            a_desc: Gtk.Label | None = ui_bundle["a_desc"]
            btn_row: Gtk.Box = ui_bundle["btn_row"]
            res_row: Gtk.Box = ui_bundle["res_row"]
            status_lbl: Gtk.Label = ui_bundle["status_lbl"]
            md_box: Gtk.Box = ui_bundle["md_box"]
            reply_text_holder: dict[str, str] = ui_bundle["reply_text_holder"]
            rebuild_trace_fn = ui_bundle["rebuild_trace_fn"]
            dots_holder: dict[str, Any] = ui_bundle["dots_holder"]
            update_footer_fn = ui_bundle["update_footer_fn"]
            mount_next_fn = ui_bundle["mount_next_approval_fn"]

            btn_row.set_visible(False)
            if a_desc is not None:
                a_desc.set_visible(False)

            app_card.remove_css_class("intentos-inline-approval")
            is_denied = mode == "deny" or (
                isinstance(resumed_turn, dict) and resumed_turn.get("approval_resolved") == "denied"
            )
            if is_denied or not approved_ok:
                app_card.add_css_class("intentos-inline-approval-denied")
            else:
                app_card.add_css_class("intentos-inline-approval-resolved")

            if is_denied:
                a_title.set_text("🛡️ 已拒绝执行该敏感操作")
                badge.set_text("已拒绝")
            elif not approved_ok:
                a_title.set_text("🛡️ 审批执行未完成")
                badge.set_text("失败")
            elif mode == "session":
                a_title.set_text("🛡️ 已放行本会话范围 · 已继续会话")
                badge.set_text("本会话已放行")
            else:
                a_title.set_text("🛡️ 敏感权限已批准 · 已继续会话")
                badge.set_text("已批准并继续")

            cs_id: str | None = fallback_cs_id
            next_pa: dict[str, Any] | None = None

            if isinstance(resumed_turn, dict):
                if resumed_turn.get("session_id"):
                    self.session_id = str(resumed_turn["session_id"])

                new_dots = normalize_trace_dots(resumed_turn)
                if new_dots:
                    rebuild_trace_fn(new_dots)

                new_md = str(
                    resumed_turn.get("reply_markdown")
                    or resumed_turn.get("reply")
                    or resumed_turn.get("assistant_message")
                    or fallback_md
                    or ""
                ).strip()
                if new_md:
                    reply_text_holder["text"] = new_md
                    self._render_markdown_into_box(md_box, new_md)

                csets = resumed_turn.get("changeset_ids") or []
                if isinstance(csets, list) and csets:
                    cs_id = str(csets[-1])

                update_footer_fn(
                    str(resumed_turn.get("backend_used") or ui_bundle["default_backend"] or ""),
                    str(resumed_turn.get("model_used") or ui_bundle["default_model"] or ""),
                    resumed_turn.get("context_compression"),
                )

                raw_next_pa = resumed_turn.get("pending_approval")
                if isinstance(raw_next_pa, dict) and raw_next_pa:
                    next_pa = raw_next_pa

                if is_denied:
                    status_lbl.set_text("✕ 已拒绝该敏感操作，未对系统产生任何修改")
                elif next_pa:
                    status_lbl.set_text("✓ 当前步骤已执行完成，后续步骤需继续确认授权")
                else:
                    status_lbl.set_text("✓ 已执行受控能力并将结果无缝衔接到当前会话")
            else:
                status_lbl.set_text(fallback_msg or ("✕ 已拒绝执行" if is_denied else "✓ 已确认执行"))
                if approved_ok and fallback_md:
                    reply_text_holder["text"] = fallback_md
                    self._render_markdown_into_box(md_box, fallback_md)
                ap_dot = dots_holder.get("approval_dot_btn")
                if ap_dot is not None:
                    ap_dot.remove_css_class("intentos-dot-amber")
                    ap_dot.add_css_class(
                        "intentos-dot-green" if (approved_ok and not is_denied) else "intentos-dot-red"
                    )

            if cs_id:
                self.last_changeset_id = cs_id
                undo_btn = Gtk.Button(label="↶ 撤销")
                undo_btn.add_css_class("intentos-btn-undo-mini")
                undo_btn.connect("clicked", lambda _ub, cid=cs_id: self._undo_changeset(cid))
                res_row.append(undo_btn)

            if next_pa:
                mount_next_fn(next_pa)
                self._set_status_dot("pending")
            else:
                self._set_status_dot("idle")

            if mode == "session":
                self._refresh_security_posture_async(re_render=True)
            self._refresh_memory_hints_async()
            GLib.idle_add(self._scroll_to_bottom)
            return False

        def _handle_inline_approval(
            self,
            ui_bundle: dict[str, Any],
            mode: str,
        ) -> None:
            pa = ui_bundle["pa"]
            scope_kind, scope_val, _ = extract_approval_scope(pa)

            def _worker() -> None:
                resumed_turn: dict[str, Any] | None = None
                msg = ""
                verified_md = ""
                cs_id: str | None = None
                approved_ok = False
                try:
                    if pa.get("approval_id"):
                        decision_val = "deny" if mode == "deny" else ("session" if mode == "session" else "once")
                        resume_payload: dict[str, Any] = {
                            "approval_id": str(pa.get("approval_id") or ""),
                            "nonce": str(pa.get("nonce") or ""),
                            "digest": str(pa.get("digest") or ""),
                            "decision": decision_val,
                            "scope_kind": scope_kind,
                            "scope_value": scope_val,
                            "ttl_minutes": 60,
                        }
                        res = call_module_rpc(
                            "backend_bridge",
                            "resume_approved_turn",
                            resume_payload,
                            timeout=45.0,
                        )
                        if res.get("ok") and isinstance(res.get("result"), dict):
                            resumed_turn = res["result"]
                            approved_ok = True
                        else:
                            err_str = str(res.get("error") or "")
                            if "unknown action" in err_str.lower():
                                # Graceful legacy fallback ONLY if backend lacks resume_approved_turn
                                if mode == "deny":
                                    call_ui_rpc("deny", {"approval_id": pa["approval_id"]}, timeout=10.0)
                                    approved_ok = True
                                    verified_md = "已拒绝执行该敏感操作。"
                                    msg = "✕ 已拒绝执行"
                                else:
                                    if mode == "session":
                                        try:
                                            call_module_rpc(
                                                "execution_hub",
                                                "grant_session_scope",
                                                {
                                                    "scope_kind": scope_kind,
                                                    "scope_value": scope_val,
                                                    "ttl_minutes": 60,
                                                },
                                                timeout=8.0,
                                            )
                                        except Exception:
                                            pass
                                    leg = call_ui_rpc(
                                        "approve",
                                        {
                                            "approval_id": pa["approval_id"],
                                            "nonce": pa.get("nonce", ""),
                                            "digest": pa.get("digest", ""),
                                        },
                                        timeout=25.0,
                                    )
                                    if leg.get("ok") and isinstance(leg.get("result"), dict):
                                        lr = leg["result"]
                                        approved_ok = True
                                        verified_md = str(lr.get("assistant_message") or "✓ 已批准并验证执行完成")
                                        msg = f"✓ {verified_md}"
                                        csets = lr.get("changeset_ids") or []
                                        if csets:
                                            cs_id = str(csets[-1])
                                    else:
                                        msg = f"✗ 审批失败: {leg.get('error')}"
                            else:
                                msg = f"✗ 审批续接失败: {err_str}"
                    elif pa.get("app_hint") or pa.get("intent_action"):
                        if mode == "deny":
                            approved_ok = True
                            verified_md = "已按您的指令取消该软件控制操作。"
                            msg = "✕ 已拒绝执行"
                        else:
                            res = call_module_rpc(
                                "app_adapter",
                                "translate_and_execute",
                                {
                                    "app_hint": pa.get("app_hint", ""),
                                    "intent_action": pa.get("intent_action", ""),
                                    "params": pa.get("params") or {},
                                    "approved": True,
                                },
                                timeout=20.0,
                            )
                            if res.get("ok") and isinstance(res.get("result"), dict):
                                approved_ok = True
                                verified_md = str(res["result"].get("summary") or "✓ 已批准执行")
                                msg = f"✓ {verified_md}"
                                cs_id = res["result"].get("changeset_id")
                            else:
                                msg = f"✗ 执行失败: {res.get('error') or '未知错误'}"
                    else:
                        approved_ok = True
                        msg = "✕ 已拒绝执行" if mode == "deny" else "✓ 已确认执行"
                except Exception as exc:
                    msg = f"✗ 错误: {exc}"

                GLib.idle_add(
                    self._apply_resumed_approval_result,
                    ui_bundle,
                    mode,
                    resumed_turn,
                    msg,
                    verified_md,
                    cs_id,
                    approved_ok,
                )

            threading.Thread(target=_worker, daemon=True).start()

        def _undo_changeset(self, target_id: str | None) -> None:
            def _worker() -> None:
                msg = ""
                try:
                    res = call_ui_rpc("undo", {"target_id": target_id}, timeout=12.0)
                    if res.get("ok") and isinstance(res.get("result"), dict):
                        msg = f"↶ 已撤销变更：{res['result'].get('message', target_id or '')}"
                    else:
                        msg = f"无法撤销：{res.get('error')}"
                except Exception as exc:
                    msg = f"撤销失败：{exc}"

                def _notify() -> bool:
                    self._append_assistant_turn(
                        {
                            "backend_used": "undo",
                            "model_used": "",
                            "reply_markdown": msg,
                            "trace_dots": [
                                {
                                    "kind": "tool_ok",
                                    "color": "green",
                                    "title": "变更回滚",
                                    "detail": msg,
                                    "changeset_id": None,
                                    "duration_ms": None,
                                }
                            ],
                        },
                        "撤销上一步",
                    )
                    return False

                GLib.idle_add(_notify)

            threading.Thread(target=_worker, daemon=True).start()

        def _copy_text(self, text: str) -> None:
            try:
                display = Gdk.Display.get_default()
                if display is not None:
                    display.get_clipboard().set(text)
            except Exception:
                pass

        # ------------------------------------------------------------------
        # Input Buffer, `@` Mentions, Prompt History & Turn Execution
        # ------------------------------------------------------------------
        def _get_input_text(self) -> str:
            start_it, end_it = self.input_buf.get_bounds()
            return self.input_buf.get_text(start_it, end_it, False)

        def _set_input_text(self, text: str) -> None:
            self.suppress_buffer_signal = True
            self.input_buf.set_text(text)
            self.placeholder_lbl.set_visible(len(text) == 0)
            self.suppress_buffer_signal = False

        def on_input_buffer_changed(self, _buf: Gtk.TextBuffer) -> None:
            txt = self._get_input_text()
            self.placeholder_lbl.set_visible(len(txt) == 0)
            if self.suppress_buffer_signal:
                return
            self.history_cursor = -1
            self._update_at_mention_bar(txt)

        def _update_at_mention_bar(self, txt: str) -> None:
            m = re.search(r"(?:^|\s)@([^\s@]*)$", txt)
            if not m:
                self.mention_bar.set_visible(False)
                return
            query = m.group(1).lower()
            matches = [
                c
                for c in self.mention_candidates
                if not query or query in c["label"].lower() or query in c["value"].lower()
            ][:5]
            if not matches:
                self.mention_bar.set_visible(False)
                return

            self._clear_box(self.mention_bar)
            tag_lbl = Gtk.Label(label="@引用:", xalign=0.0)
            tag_lbl.add_css_class("intentos-strip-label")
            self.mention_bar.append(tag_lbl)
            for item in matches:
                short_l = item["label"] if len(item["label"]) <= 16 else item["label"][:14] + "…"
                b = Gtk.Button(label=f"{item['kind']} {short_l}")
                b.add_css_class("intentos-mem-chip")
                b.set_tooltip_text(item["value"])
                b.connect("clicked", lambda _btn, v=item["value"]: self._complete_at_mention(v))
                self.mention_bar.append(b)
            self.mention_bar.set_visible(True)

        def _complete_at_mention(self, val: str) -> None:
            txt = self._get_input_text()
            new_txt = re.sub(r"@([^\s@]*)$", f"@{val} ", txt)
            self._set_input_text(new_txt)
            self.mention_bar.set_visible(False)
            self.input_view.grab_focus()

        def _insert_mention_value(self, val: str) -> None:
            cur = self._get_input_text()
            sep = "" if (not cur or cur.endswith(" ")) else " "
            self._set_input_text(f"{cur}{sep}@{val} ")
            self.mem_btn.set_active(False)
            self.input_view.grab_focus()

        def on_input_key_pressed(self, _ctrl: Any, keyval: int, _keycode: int, state: Any) -> bool:
            ctrl = bool(state & Gdk.ModifierType.CONTROL_MASK)
            shift = bool(state & Gdk.ModifierType.SHIFT_MASK)

            if keyval in (Gdk.KEY_Return, Gdk.KEY_KP_Enter):
                if shift:
                    return False
                self.on_send_or_stop_clicked(None)
                return True

            if keyval == Gdk.KEY_Tab and self.mention_bar.get_visible():
                first_btn = self.mention_bar.get_first_child()
                if first_btn is not None:
                    chip = first_btn.get_next_sibling()
                    if isinstance(chip, Gtk.Button):
                        chip.emit("clicked")
                        return True

            cur_txt = self._get_input_text()
            if keyval == Gdk.KEY_Up and (not cur_txt.strip() or self.history_cursor >= 0):
                if self.input_history:
                    self.history_cursor = min(self.history_cursor + 1, len(self.input_history) - 1)
                    recalled = self.input_history[len(self.input_history) - 1 - self.history_cursor]
                    self._set_input_text(recalled)
                    return True

            if keyval == Gdk.KEY_Down and self.history_cursor >= 0:
                self.history_cursor -= 1
                if self.history_cursor < 0:
                    self._set_input_text("")
                else:
                    recalled = self.input_history[len(self.input_history) - 1 - self.history_cursor]
                    self._set_input_text(recalled)
                return True

            if ctrl and keyval in (Gdk.KEY_z, Gdk.KEY_Z):
                self._undo_changeset(self.last_changeset_id)
                return True

            if ctrl and keyval in (Gdk.KEY_n, Gdk.KEY_N):
                self.start_new_session()
                return True

            return False

        def on_window_key_pressed(self, _ctrl: Any, keyval: int, _keycode: int, state: Any) -> bool:
            ctrl = bool(state & Gdk.ModifierType.CONTROL_MASK)
            if keyval == Gdk.KEY_Escape:
                if self.voice_recording:
                    self._cancel_voice_recording()
                    return True
                if self.mention_bar.get_visible():
                    self.mention_bar.set_visible(False)
                    return True
                if self.model_pill_btn.get_active():
                    self.model_pill_btn.set_active(False)
                    return True
                if self.shield_btn.get_active():
                    self.shield_btn.set_active(False)
                    return True
                if self.mem_btn.get_active():
                    self.mem_btn.set_active(False)
                    return True
                if self.turn_busy:
                    self._abort_active_turn()
                    return True
                self.win.close()
                return True

            if ctrl and keyval in (Gdk.KEY_n, Gdk.KEY_N):
                self.start_new_session()
                return True
            if ctrl and keyval in (Gdk.KEY_z, Gdk.KEY_Z):
                self._undo_changeset(self.last_changeset_id)
                return True
            return False

        def _set_status_dot(self, mode: str) -> None:
            for cls in ("intentos-status-dot-idle", "intentos-status-dot-busy", "intentos-status-dot-pending"):
                self.status_dot.remove_css_class(cls)
            if mode == "busy":
                self.status_dot.add_css_class("intentos-status-dot-busy")
            elif mode == "pending":
                self.status_dot.add_css_class("intentos-status-dot-pending")
            else:
                self.status_dot.add_css_class("intentos-status-dot-idle")

        def _set_busy_state(self, busy: bool) -> None:
            self.turn_busy = busy
            if busy:
                self.send_btn.set_label("■")
                self.send_btn.remove_css_class("intentos-send-btn")
                self.send_btn.add_css_class("intentos-stop-btn")
                self.send_btn.set_tooltip_text("中止当前回合 (Esc)")
                self._set_status_dot("busy")
            else:
                self.send_btn.set_label("➤")
                self.send_btn.remove_css_class("intentos-stop-btn")
                self.send_btn.add_css_class("intentos-send-btn")
                self.send_btn.set_tooltip_text("发送 (Enter)")
                self._set_status_dot("idle")

        def _abort_active_turn(self) -> None:
            self.active_turn_token += 1
            self._set_busy_state(False)
            sid = self.session_id

            def _cancel_worker() -> None:
                try:
                    call_module_rpc("backend_bridge", "cancel_turn", {"session_id": sid}, timeout=4.0)
                except Exception:
                    try:
                        call_ui_rpc("stop_all", None, timeout=4.0)
                    except Exception:
                        pass

            threading.Thread(target=_cancel_worker, daemon=True).start()

        def on_send_or_stop_clicked(self, _btn: Any) -> None:
            if self.turn_busy:
                self._abort_active_turn()
                return
            txt = self._get_input_text().strip()
            if not txt and self.clipboard_context:
                txt = "请帮我解释或处理这段剪贴板内容"
            if not txt:
                return
            self._send_prompt(txt)

        def _send_prompt(self, prompt_text: str) -> None:
            text = prompt_text.strip()
            if not text or self.turn_busy:
                return

            if not self.incognito:
                if not self.input_history or self.input_history[-1] != text:
                    self.input_history.append(text)

            clip_ctx = self.clipboard_context
            self._set_input_text("")
            self._set_clipboard_context("")
            self.mention_bar.set_visible(False)

            self._append_user_bubble(text, bool(clip_ctx))
            placeholder_row = self._append_thinking_placeholder()

            self.active_turn_token += 1
            token = self.active_turn_token
            self._set_busy_state(True)

            sid = self.session_id
            incog = self.incognito
            effort = self.selected_effort

            def _worker() -> None:
                try:
                    turn_res = execute_chat_turn_sync(
                        text=text,
                        session_id=sid,
                        clipboard_context=clip_ctx or None,
                        incognito=incog,
                        reasoning_effort=effort,
                    )
                except Exception as exc:
                    turn_res = {
                        "ok": False,
                        "session_id": sid,
                        "backend_used": "offline",
                        "model_used": "",
                        "reply_markdown": f"无法连接到 `intentosd` 守护进程：`{exc}`",
                        "trace_dots": [
                            {
                                "kind": "tool_err",
                                "color": "red",
                                "title": "守护进程未连接",
                                "detail": str(exc),
                                "changeset_id": None,
                                "duration_ms": None,
                            }
                        ],
                        "pending_approval": None,
                    }

                def _finish() -> bool:
                    if placeholder_row.get_parent() is not None:
                        self.chat_stream.remove(placeholder_row)
                    if token != self.active_turn_token:
                        return False
                    self._set_busy_state(False)
                    if turn_res.get("session_id"):
                        self.session_id = str(turn_res["session_id"])
                    self._append_assistant_turn(turn_res, text)
                    self._refresh_memory_hints_async()
                    return False

                GLib.idle_add(_finish)

            threading.Thread(target=_worker, daemon=True).start()

        # ------------------------------------------------------------------
        # Issue #4: Voice Input (`speech_hub` ASR Mic in Quick-Chat)
        # ------------------------------------------------------------------
        def _speech_state_flags(self, ov: dict[str, Any] | None = None) -> tuple[bool, bool, str, bool]:
            data = ov if isinstance(ov, dict) else self.speech_overview
            if not isinstance(data, dict):
                return False, False, "", False
            cfg = data.get("config") if isinstance(data.get("config"), dict) else {}
            enabled = bool(cfg.get("enabled") if "enabled" in cfg else data.get("enabled", False))
            auto_send = bool(
                cfg.get("auto_send_after_transcribe")
                if "auto_send_after_transcribe" in cfg
                else data.get("auto_send_after_transcribe", False)
            )
            models = data.get("models") if isinstance(data.get("models"), list) else []
            installed_models = [
                m
                for m in models
                if isinstance(m, dict) and (m.get("installed") is True or m.get("status") == "installed")
            ]
            has_installed = (
                bool(installed_models)
                or bool(data.get("has_installed_model"))
                or bool(data.get("ready"))
            )
            active_model = str(
                cfg.get("active_model_id")
                or data.get("active_model_id")
                or (installed_models[0].get("id", "") if installed_models else "")
            )
            return enabled, has_installed, active_model, auto_send

        def _apply_speech_overview(self, ov: dict[str, Any]) -> bool:
            if isinstance(ov, dict):
                self.speech_overview = ov
                enabled, has_installed, active_model, _ = self._speech_state_flags(ov)
                if not self.voice_recording and not self.voice_transcribing:
                    if enabled and has_installed:
                        self.mic_btn.set_tooltip_text(
                            f"本地语音输入就绪 ({active_model or 'ASR'}) · 点击开始说话，再次点击完成识别"
                        )
                    elif has_installed:
                        self.mic_btn.set_tooltip_text("语音识别模型已就绪 · 点击开启语音输入")
                    else:
                        self.mic_btn.set_tooltip_text("本地离线语音识别 · 点击前往设置中心下载 ASR 模型并开启")
            return False

        def _refresh_speech_overview_async(self) -> None:
            def _worker() -> None:
                try:
                    res = call_module_rpc("speech_hub", "get_speech_overview", {}, timeout=6.0)
                    if res.get("ok") and isinstance(res.get("result"), dict):
                        GLib.idle_add(self._apply_speech_overview, res["result"])
                except Exception:
                    pass

            threading.Thread(target=_worker, daemon=True).start()

        def _stop_voice_timer(self) -> None:
            if self.voice_timer_source_id:
                try:
                    GLib.source_remove(self.voice_timer_source_id)
                except Exception:
                    pass
                self.voice_timer_source_id = 0

        def _tick_voice_timer(self) -> bool:
            if not self.voice_recording:
                self.voice_timer_source_id = 0
                return False
            elapsed = max(0, int(time.time() - self.voice_started_ts))
            mm = elapsed // 60
            ss = elapsed % 60
            self.mic_btn.set_label(f"🔴 {mm:02d}:{ss:02d}")
            return True

        def _reset_mic_idle_ui(self) -> None:
            self._stop_voice_timer()
            self.voice_recording = False
            self.voice_transcribing = False
            self.mic_btn.remove_css_class("intentos-mic-recording")
            self.mic_btn.set_label("🎙")
            self.mic_btn.set_sensitive(True)
            self.placeholder_lbl.set_text(self.default_placeholder_text)

        def _enter_voice_recording_ui(self) -> None:
            self.voice_banner.set_visible(False)
            self._stop_voice_timer()
            self.voice_recording = True
            self.voice_transcribing = False
            self.voice_started_ts = time.time()
            self.mic_btn.add_css_class("intentos-mic-recording")
            self.mic_btn.set_label("🔴 00:00")
            self.mic_btn.set_sensitive(True)
            self.mic_btn.set_tooltip_text("正在录音 · 再次点击完成识别 (Esc 取消)")
            self.placeholder_lbl.set_text("正在聆听您的语音指令… 再次点击 🔴 完成识别")
            self.voice_timer_source_id = GLib.timeout_add(500, self._tick_voice_timer)

        def _show_voice_setup_banner(self, message: str, can_quick_enable: bool = False) -> None:
            self.voice_banner_lbl.set_text(message)
            self.voice_enable_btn.set_visible(can_quick_enable)
            self.voice_banner.set_visible(True)

        def _handle_mic_state_decision(self, ov: dict[str, Any] | None, start_rpc: bool = True) -> None:
            if isinstance(ov, dict) and ov:
                self._apply_speech_overview(ov)
            enabled, has_installed, active_model, _ = self._speech_state_flags(self.speech_overview)
            if not has_installed:
                self._show_voice_setup_banner(
                    "🎙 尚未下载本地离线语音识别模型（推荐 SenseVoice-Small ~228MB，中英高准度）：",
                    can_quick_enable=False,
                )
                return
            if not enabled:
                self._show_voice_setup_banner(
                    f"🎙 语音输入开关当前已关闭（已安装模型: {active_model or '本地 ASR'}）：",
                    can_quick_enable=True,
                )
                return
            self._start_voice_recording_flow(start_rpc=start_rpc)

        def on_mic_clicked(self, _btn: Any) -> None:
            if self.voice_transcribing:
                return
            if self.voice_recording:
                self._stop_and_transcribe_flow()
                return

            enabled, has_installed, _, _ = self._speech_state_flags(self.speech_overview)
            if enabled and has_installed:
                self._start_voice_recording_flow(start_rpc=True)
                return

            def _probe_worker() -> None:
                fresh_ov: dict[str, Any] | None = None
                try:
                    res = call_module_rpc("speech_hub", "get_speech_overview", {}, timeout=5.0)
                    if res.get("ok") and isinstance(res.get("result"), dict):
                        fresh_ov = res["result"]
                except Exception:
                    pass

                def _decide() -> bool:
                    self._handle_mic_state_decision(fresh_ov, start_rpc=True)
                    return False

                GLib.idle_add(_decide)

            threading.Thread(target=_probe_worker, daemon=True).start()

        def _quick_enable_speech_and_record(self) -> None:
            self.voice_banner.set_visible(False)

            def _worker() -> None:
                ok_enabled = False
                fresh_ov: dict[str, Any] | None = None
                try:
                    up = call_module_rpc("speech_hub", "update_speech_config", {"enabled": True}, timeout=6.0)
                    if up.get("ok"):
                        ok_enabled = True
                        if isinstance(up.get("result"), dict):
                            fresh_ov = up["result"]
                    ov_res = call_module_rpc("speech_hub", "get_speech_overview", {}, timeout=5.0)
                    if ov_res.get("ok") and isinstance(ov_res.get("result"), dict):
                        fresh_ov = ov_res["result"]
                except Exception:
                    pass

                def _after() -> bool:
                    if fresh_ov:
                        self._apply_speech_overview(fresh_ov)
                    elif ok_enabled:
                        cfg = self.speech_overview.setdefault("config", {})
                        if isinstance(cfg, dict):
                            cfg["enabled"] = True
                        self.speech_overview["enabled"] = True
                    self._start_voice_recording_flow(start_rpc=True)
                    return False

                GLib.idle_add(_after)

            threading.Thread(target=_worker, daemon=True).start()

        def _start_voice_recording_flow(self, start_rpc: bool = True) -> None:
            self._enter_voice_recording_ui()
            if not start_rpc:
                return

            def _worker() -> None:
                err_msg = ""
                try:
                    res = call_module_rpc("speech_hub", "start_recording", {}, timeout=8.0)
                    if not res.get("ok"):
                        err_msg = str(res.get("error") or "无法启动麦克风录音")
                    elif isinstance(res.get("result"), dict) and res["result"].get("ok") is False:
                        err_msg = str(res["result"].get("error") or res["result"].get("message") or "无法启动麦克风录音")
                except Exception as exc:
                    err_msg = str(exc)

                if err_msg:
                    def _on_fail() -> bool:
                        self._reset_mic_idle_ui()
                        self._show_voice_setup_banner(
                            f"🎙 语音录音未能启动：{err_msg}",
                            can_quick_enable=False,
                        )
                        return False

                    GLib.idle_add(_on_fail)

            threading.Thread(target=_worker, daemon=True).start()

        def _apply_transcribed_text(self, transcript: str, auto_send: bool = False) -> bool:
            self._reset_mic_idle_ui()
            clean = transcript.strip()
            if not clean:
                self._show_voice_setup_banner("🎙 未检测到清晰语音内容，请靠近麦克风重试。", can_quick_enable=False)
                return False
            self.voice_banner.set_visible(False)
            cur = self._get_input_text().strip()
            merged = f"{cur} {clean}".strip() if cur else clean
            self._set_input_text(merged)
            self.input_view.grab_focus()
            if auto_send and not self.turn_busy:
                self._send_prompt(merged)
            return False

        def _stop_and_transcribe_flow(self) -> None:
            self._stop_voice_timer()
            self.voice_recording = False
            self.voice_transcribing = True
            self.mic_btn.remove_css_class("intentos-mic-recording")
            self.mic_btn.set_label("⏳")
            self.mic_btn.set_sensitive(False)
            self.placeholder_lbl.set_text("⏳ 正在离线识别您的语音内容…")

            def _worker() -> None:
                transcript = ""
                err_msg = ""
                auto_send = self._speech_state_flags(self.speech_overview)[3]
                try:
                    res = call_module_rpc("speech_hub", "stop_and_transcribe", {}, timeout=30.0)
                    if res.get("ok") and isinstance(res.get("result"), dict):
                        r = res["result"]
                        if r.get("ok") is False and r.get("error"):
                            err_msg = str(r.get("error"))
                        else:
                            transcript = str(r.get("text") or r.get("transcript") or "")
                            if "auto_send_after_transcribe" in r:
                                auto_send = bool(r.get("auto_send_after_transcribe"))
                    else:
                        err_msg = str(res.get("error") or "语音识别失败")
                except Exception as exc:
                    err_msg = str(exc)

                def _done() -> bool:
                    if err_msg:
                        self._reset_mic_idle_ui()
                        self._show_voice_setup_banner(f"🎙 语音识别未完成：{err_msg}", can_quick_enable=False)
                        return False
                    return self._apply_transcribed_text(transcript, auto_send=auto_send)

                GLib.idle_add(_done)

            threading.Thread(target=_worker, daemon=True).start()

        def _cancel_voice_recording(self) -> None:
            self._reset_mic_idle_ui()

            def _worker() -> None:
                try:
                    call_module_rpc("speech_hub", "cancel_recording", {}, timeout=5.0)
                except Exception:
                    pass

            threading.Thread(target=_worker, daemon=True).start()

    if smoke_ui:
        app = FloatingQuickChatApp()
        app._load_css()
        if app.css_errors:
            print(f"[smoke-ui] CSS errors: {app.css_errors}", file=sys.stderr)
            return 1
        win = Gtk.Window()
        app.build_ui_onto_window(win, start_workers=False)

        # Verify 36 live `/v1/models` search & filtering without truncation
        mock_models = [("zcode-gw", f"gpt-6.{i}-luna") for i in range(36)]
        norm = normalize_backends_catalog(
            {
                "active": {"backend": "zcode", "provider": "zcode-gw", "model": "gpt-6.0-luna"},
                "backends": {
                    "zcode": {
                        "available": True,
                        "providers": [{"id": "zcode-gw", "models": [m for _, m in mock_models]}],
                    }
                },
            }
        )
        app._apply_catalog(norm)
        assert len(app.catalog["backends"]["zcode"]["models"]) == 36
        app.model_search_entry.set_text("gpt-6.3")

        # Verify Light & Dark theme toggle + Gtk.Settings sync
        app._apply_theme(True)
        assert "intentos-light-theme" in win.get_css_classes()
        app._apply_theme(False)
        assert "intentos-light-theme" not in win.get_css_classes()

        # Verify honest RequestedUnverified sky-blue dot (never misleading green!) + live tray console in 🧠 drawer
        unver_dots = normalize_trace_dots(
            {
                "trace_dots": [
                    {
                        "kind": "tool_ok",
                        "color": "green",
                        "title": "app.launch(汽水音乐)",
                        "detail": "verification=RequestedUnverified",
                        "verification": {"state": "RequestedUnverified"},
                    }
                ]
            }
        )
        assert unver_dots[0]["color"] == "blue", f"Expected blue for RequestedUnverified, got {unver_dots[0]}"
        assert unver_dots[0]["kind"] == "tool_unverified"
        assert "已发送请求（待桌面响应）" in unver_dots[0]["title"]

        # Issue #2 & #3: Verify Deep Scan 9-Category summary & Session Compression stats in 🧠 drawer
        app.deep_scan_summary = {
            "total_apps": 48,
            "running_apps": 11,
            "translatable_actions_total": 136,
            "categories": [{"id": f"cat_{i}", "count": 5} for i in range(9)],
        }
        app.session_compression_preview = {
            "enabled": True,
            "drop_tool_records": True,
            "included_qa_turns": 6,
            "compressed_estimated_tokens": 380,
            "saved_pct": 58.4,
        }
        app.live_tray_apps = normalize_live_tray_apps_py(
            {
                "apps": [
                    {
                        "app_id": "sodamusic",
                        "display_name": "汽水音乐 SodaM",
                        "live_title": "如果当时 · 许嵩",
                        "menu_items": ["暂停", "上一首", "下一首", "显示主窗口", "退出"],
                    }
                ]
            }
        )
        app.last_inspected_app = {
            "display_name": "FlClash",
            "desktop_id": "flclash.desktop",
            "pids": [4210],
            "channels": ["tray_menu", "atspi"],
            "tray_menu_items": ["显示主窗口", "规则模式", "退出"],
        }
        app._render_memory_panel()

        # Issue #4: Verify 🎙 Mic input banner when disabled/missing model + recording state + transcript insertion
        app._handle_mic_state_decision({"config": {"enabled": False}, "models": []}, start_rpc=False)
        assert app.voice_banner.get_visible() is True
        app._handle_mic_state_decision(
            {
                "config": {"enabled": True, "active_model_id": "sensevoice-small-int8"},
                "models": [{"id": "sensevoice-small-int8", "installed": True}],
            },
            start_rpc=False,
        )
        assert app.voice_recording is True
        assert "intentos-mic-recording" in app.mic_btn.get_css_classes()
        app._apply_transcribed_text("帮我查找文档里的年度报告", auto_send=False)
        assert app.voice_recording is False
        assert "年度报告" in app._get_input_text()
        app._set_input_text("")

        # Issue #1 & #3: Verify instant approval click feedback + seamless `resume_approved_turn` UI continuation
        eight_dots = [
            {"kind": "thinking", "color": "gray", "title": f"Step {i}", "detail": f"detail {i}"}
            for i in range(6)
        ] + [
            {"kind": "tool_unverified", "color": "blue", "title": "app.launch · 已发送请求（待桌面响应）", "detail": "RequestedUnverified"},
            {"kind": "approval", "color": "amber", "title": "待确认: file.search", "detail": "~/Documents"},
        ]
        app._append_assistant_turn(
            {
                "session_id": "ses_approve_test",
                "backend_used": "zcode",
                "model_used": "gpt-6.0-luna",
                "reply_markdown": "检索 `~/Documents` 需要确认授权：",
                "trace_dots": eight_dots,
                "pending_approval": {
                    "approval_id": "apr_smoke_1",
                    "capability_id": "file.search",
                    "arguments": {"path": "~/Documents", "query": "secret"},
                    "summary": "检索个人文档目录（~/Documents），需人工确认授权",
                    "diff_preview": "🛡️ 风险等级: R2 敏感目录检索",
                    "reversible": False,
                    "nonce": "n1",
                    "digest": "sha256:00",
                },
            },
            "查找 ~/Documents 下的报告",
        )
        bundle = app._last_approval_ui_bundle
        assert bundle is not None
        # Simulate user clicking `[⏱ 本会话放行此范围]`: buttons hide immediately & status shows ⏳!
        bundle["trigger_click_fn"]("session", start_rpc=False)
        assert bundle["btn_row"].get_visible() is False
        assert "⏳" in bundle["status_lbl"].get_text()
        # Simulate `resume_approved_turn` returning the full LLM follow-up answer + compression telemetry
        app._apply_resumed_approval_result(
            ui_bundle=bundle,
            mode="session",
            resumed_turn={
                "ok": True,
                "session_id": "ses_approve_test",
                "approval_resolved": "approved",
                "backend_used": "zcode",
                "model_used": "gpt-6.0-luna",
                "reply_markdown": "已在 `~/Documents` 找到匹配文件：\n- `secret_report_2026.md`（更新于今天 19:20）",
                "trace_dots": [
                    {
                        "kind": "tool_ok",
                        "color": "green",
                        "title": "✓ 已批准执行: file.search",
                        "detail": "命中 1 个文件: secret_report_2026.md",
                    }
                ],
                "context_compression": {
                    "enabled": True,
                    "included_qa_turns": 4,
                    "compressed_estimated_tokens": 380,
                    "saved_pct": 58.0,
                },
                "pending_approval": None,
            },
            approved_ok=True,
        )
        assert app.session_id == "ses_approve_test"
        assert "已放行本会话范围 · 已继续会话" in bundle["a_title"].get_text()
        assert bundle["a_desc"] is not None and bundle["a_desc"].get_visible() is False
        assert "secret_report_2026.md" in bundle["reply_text_holder"]["text"]

        ctx = GLib.MainContext.default()
        for _ in range(15):
            if not ctx.pending():
                break
            ctx.iteration(False)
        win.destroy()
        print(
            json.dumps(
                {
                    "ok": True,
                    "app": "org.intentos.Launcher",
                    "live_models_verified": 36,
                    "css_errors": 0,
                    "light_dark_theme_verified": True,
                    "approval_resume_turn_verified": True,
                    "context_compression_footer_verified": True,
                    "voice_mic_verified": True,
                },
                ensure_ascii=False,
            )
        )
        return 0

    app = FloatingQuickChatApp()
    return app.run(sys.argv[:1])


def run_smoke_rpc() -> int:
    """Verify `get_status` over `ui.sock` (auto-spawning an ephemeral `intentosd` if none is running)."""
    sock = resolve_ui_socket()
    if sock.exists():
        st = call_ui_rpc("get_status")
        print(json.dumps(st, ensure_ascii=False))
        return 0 if st.get("ok") else 1

    repo_root = Path(__file__).resolve().parent.parent.parent
    candidates = [
        repo_root / "target" / "debug" / "intentosd",
        repo_root / "target" / "release" / "intentosd",
    ]
    daemon_bin: str | None = next((str(p) for p in candidates if p.exists()), shutil.which("intentosd"))
    if not daemon_bin:
        print(json.dumps({"ok": False, "error": f"ui.sock not found ({sock}) and intentosd binary not built"}))
        return 1

    with tempfile.TemporaryDirectory(prefix="intentos-smoke-rpc-") as tmp_base:
        env = {**os.environ, "INTENTOS_BASE_DIR": tmp_base}
        local_conda_lib = Path.home() / "miniconda3" / "lib"
        if local_conda_lib.is_dir():
            prev_ld = env.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = f"{local_conda_lib}:{prev_ld}".rstrip(":")
        proc = subprocess.Popen(
            [daemon_bin, "--base-dir", tmp_base, "--repo-root", str(repo_root), "--no-web"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            os.environ["INTENTOS_BASE_DIR"] = tmp_base
            target_sock = Path(tmp_base) / "run" / "ui.sock"
            deadline = time.time() + 5.0
            while time.time() < deadline and not target_sock.exists():
                time.sleep(0.05)
            st = call_ui_rpc("get_status", timeout=5.0)
            print(json.dumps(st, ensure_ascii=False))
            return 0 if st.get("ok") else 1
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except Exception:
                proc.kill()


if __name__ == "__main__":
    if "--smoke-rpc" in sys.argv:
        sys.exit(run_smoke_rpc())
    if "--smoke-ui" in sys.argv:
        sys.exit(run_gtk_app(smoke_ui=True))

    is_clip_ask = "--clipboard-ask" in sys.argv
    extra_args = [a for a in sys.argv[1:] if not a.startswith("--")]
    sys.exit(run_gtk_app(clipboard_ask=is_clip_ask, initial_prompt=" ".join(extra_args)))
