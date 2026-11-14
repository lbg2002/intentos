#!/usr/bin/env bash
set -euo pipefail

# IntentOS 本地免安装一键体验脚本（支持源码仓直接编译运行）
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! -d "${ROOT_DIR}/modules/builtin" && -d "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/modules/builtin" ]]; then
  ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

setup_build_env_if_needed() {
  if [[ ! -f /usr/include/openssl/ssl.h ]]; then
    local conda_lib=""
    if [[ -n "${CONDA_PREFIX:-}" && -d "${CONDA_PREFIX}/lib" ]]; then
      conda_lib="${CONDA_PREFIX}/lib"
    elif [[ -d "${HOME}/miniconda3/lib" ]]; then
      conda_lib="${HOME}/miniconda3/lib"
    elif [[ -d "${HOME}/anaconda3/lib" ]]; then
      conda_lib="${HOME}/anaconda3/lib"
    fi
    if [[ -n "${conda_lib}" ]]; then
      export RUSTFLAGS="${RUSTFLAGS:-} -L ${conda_lib} -C link-arg=-Wl,-rpath,${conda_lib}"
    fi
  fi
}

if [[ -x "${ROOT_DIR}/target/release/intentosd" && -x "${ROOT_DIR}/target/release/intentosctl" ]]; then
  DAEMON_BIN="${ROOT_DIR}/target/release/intentosd"
  CTL_BIN="${ROOT_DIR}/target/release/intentosctl"
elif [[ -x "${ROOT_DIR}/target/debug/intentosd" && -x "${ROOT_DIR}/target/debug/intentosctl" ]]; then
  DAEMON_BIN="${ROOT_DIR}/target/debug/intentosd"
  CTL_BIN="${ROOT_DIR}/target/debug/intentosctl"
elif [[ -x "${ROOT_DIR}/bin/intentosd" && -x "${ROOT_DIR}/bin/intentosctl" ]]; then
  DAEMON_BIN="${ROOT_DIR}/bin/intentosd"
  CTL_BIN="${ROOT_DIR}/bin/intentosctl"
elif command -v cargo >/dev/null 2>&1; then
  echo "==> 未检测到已编译二进制，正在使用 cargo 编译 Release 版本..."
  setup_build_env_if_needed
  cargo build --release --manifest-path "${ROOT_DIR}/Cargo.toml"
  DAEMON_BIN="${ROOT_DIR}/target/release/intentosd"
  CTL_BIN="${ROOT_DIR}/target/release/intentosctl"
else
  echo "错误：未找到已编译二进制，且本机未安装 cargo (Rust 工具链)。" >&2
  exit 1
fi

LISTEN_ADDR="${INTENTOS_WEB_LISTEN:-127.0.0.1:8787}"
echo "==> 启动 IntentOS 守护进程 (Web Shell: http://${LISTEN_ADDR}) ..."
"${DAEMON_BIN}" --repo-root "${ROOT_DIR}" --web-listen "${LISTEN_ADDR}" &
DAEMON_PID=$!

cleanup() {
  if kill -0 "${DAEMON_PID}" >/dev/null 2>&1; then
    kill "${DAEMON_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

sleep 0.6
echo ""
echo "================================================================"
echo "  ✦ IntentOS 守护进程已在本地启动！(PID: ${DAEMON_PID})"
echo "  • 桌面悬浮随问窗 : /usr/bin/python3 ${ROOT_DIR}/desktop/gtk-fallback/intentos-launcher.py"
echo "  • 11 页设置中心  : /usr/bin/python3 ${ROOT_DIR}/desktop/settings/intentos-settings.py"
echo "  • 浏览器交互界面 : http://${LISTEN_ADDR}"
echo "  • 命令行调用示例 : ${CTL_BIN} ask \"打开浏览器\""
echo "================================================================"

if [[ "${1:-}" == "--launcher" ]] && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
  /usr/bin/python3 "${ROOT_DIR}/desktop/gtk-fallback/intentos-launcher.py" &
elif [[ "${1:-}" == "--tui" ]]; then
  "${CTL_BIN}" --repo-root "${ROOT_DIR}" ui
  exit 0
fi

echo "按 Ctrl+C 停止守护进程..."
wait "${DAEMON_PID}"
