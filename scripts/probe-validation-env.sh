#!/usr/bin/env bash
set -euo pipefail
layer="${1:---l1}"
fail() { printf 'BLOCKED %s %s\n' "$layer" "$*" >&2; exit 2; }
pass() { printf 'READY %s %s (readiness only; behavioral tests not executed)\n' "$layer" "$*"; }
case "$layer" in
 --l1)
  for tool in cargo rustc git python3; do command -v "$tool" >/dev/null || fail "missing_tool=$tool"; done
  pass "rustc=$(rustc --version)"
  ;;
 --l2)
  command -v bwrap >/dev/null || fail missing_bwrap
  command -v unshare >/dev/null || fail missing_unshare
  unshare -Ur true >/dev/null 2>&1 || fail user_namespace_unavailable
  bwrap --unshare-user --unshare-pid --unshare-net --ro-bind / / --proc /proc --dev-bind /dev /dev -- /bin/true >/dev/null 2>&1 || fail bwrap_os_isolation_unavailable
  pass bwrap_with_user_pid_network_namespaces
  ;;
 --l3)
  [[ -n "${XDG_SESSION_TYPE:-}" && -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] || fail no_desktop_session
  /usr/bin/python3 -c 'import gi' || fail missing_gtk_python_gi
  pass "session=${XDG_SESSION_TYPE}"
  ;;
 --l4)
  [[ "${INTENTOS_PERF_EXCLUSIVE:-}" == "1" ]] || fail exclusive_runner_not_asserted
  command -v cargo >/dev/null || fail missing_cargo
  pass "kernel=$(uname -r)"
  ;;
 *) echo "usage: $0 --l1|--l2|--l3|--l4" >&2; exit 64 ;;
esac
