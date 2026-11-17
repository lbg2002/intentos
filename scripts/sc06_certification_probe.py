#!/usr/bin/env python3
"""Read-only SC-06 evidence collector. Never certifies an app action by inference."""
from __future__ import annotations
import argparse
import json
import os
import pathlib
import platform
import shutil
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = 1
TARGETS = {
    "nautilus": ("org.gnome.Nautilus.desktop", "nautilus.desktop"),
    "browser": ("firefox.desktop", "org.mozilla.firefox.desktop", "chromium.desktop", "google-chrome.desktop"),
    "vscode": ("code.desktop", "code-oss.desktop", "codium.desktop"),
    "libreoffice": ("libreoffice-writer.desktop", "libreoffice-startcenter.desktop"),
    "wps": ("wps-office-wps.desktop", "wps-office.desktop", "wps.desktop"),
    "mpris": ("rhythmbox.desktop", "org.gnome.Rhythmbox3.desktop", "vlc.desktop", "spotify.desktop"),
    "sni": ("org.kde.StatusNotifierWatcher.desktop", "flclash.desktop", "nm-applet.desktop"),
}
ACTIONS = ("launch", "open_resource", "focus", "status", "quit")


def default_dirs() -> list[pathlib.Path]:
    home = pathlib.Path.home()
    xdg = pathlib.Path(os.environ.get("XDG_DATA_HOME", str(home / ".local/share")))
    return [xdg / "applications", pathlib.Path("/usr/share/applications"),
            pathlib.Path("/usr/local/share/applications"),
            pathlib.Path("/var/lib/snapd/desktop/applications"),
            pathlib.Path("/var/lib/flatpak/exports/share/applications")]


def classify_package(path: pathlib.Path) -> str:
    s = str(path)
    if "/snapd/" in s:
        return "snap"
    if "/flatpak/" in s:
        return "flatpak"
    if "/.local/" in s:
        return "user_local"
    return "system_apt_or_unknown"


def inventory(dirs: list[pathlib.Path], session: str) -> list[dict]:
    out = []
    for target, filenames in TARGETS.items():
        candidates = [(d / name) for d in dirs for name in filenames]
        match = next((p for p in candidates if p.is_file() and not p.is_symlink()), None)
        for action in ACTIONS:
            state = "blocked" if match else "not_installed_or_not_detected"
            out.append({
                "target_class": target,
                "action_id": action,
                "desktop_id": match.name if match else None,
                "desktop_path": str(match) if match else None,
                "package_format": classify_package(match) if match else None,
                "observed_version": None,
                "discovery_state": "desktop_entry_observed" if match else "unknown",
                "certification_state": "unverified",
                "test_result": state,
                "verification_reason": "No real action performed; presence is not certification",
                "desktop_session": session or None,
            })
    return out


def collect(dirs: list[pathlib.Path], session: str) -> dict:
    actions = inventory(dirs, session)
    return {
        "schema_version": SCHEMA_VERSION,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "probe_kind": "observation_only_no_actions_invoked",
        "machine": platform.machine(),
        "kernel": platform.release(),
        "os": platform.platform(),
        "session_type": session or None,
        "gnome_shell_detected": shutil.which("gnome-shell") is not None,
        "actions": actions,
        "summary": {"tested": 0, "passed": 0, "failed": 0, "blocked_or_unverified": len(actions)},
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--desktop-dir", action="append", type=pathlib.Path,
                   help="Test fixture directories; no arbitrary execution")
    p.add_argument("--output", type=pathlib.Path, help="JSON evidence path")
    args = p.parse_args(argv)
    evidence = collect(args.desktop_dir if args.desktop_dir is not None else default_dirs(),
                       os.environ.get("XDG_SESSION_TYPE", ""))
    body = json.dumps(evidence, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(body, encoding="utf-8")
    else:
        sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
