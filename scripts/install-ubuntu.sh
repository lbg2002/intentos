#!/usr/bin/env bash
set -euo pipefail

# IntentOS Ubuntu 24.04 / 26.04 LTS User-Space Installer
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${HOME}/.local/bin"
SHARE_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/intentos"
EXT_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/gnome-shell/extensions/intent-shell@intentos.org"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/systemd/user"
APPLICATIONS_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/applications"

mkdir -p "${BIN_DIR}" "${SHARE_DIR}" "${SHARE_DIR}/scripts" "${EXT_DIR}" "${SYSTEMD_USER_DIR}" "${APPLICATIONS_DIR}"

setup_build_env_if_needed() {
  # If system libssl-dev/libsqlite3-dev are absent but Conda is present, wire RPATH cleanly
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

if [[ "${1:-}" == "--prebuilt" ]] || { [[ -x "${REPO_ROOT}/bin/intentosd" && -x "${REPO_ROOT}/bin/intentosctl" ]] && ! command -v cargo >/dev/null 2>&1; }; then
  echo "==> [1/4] 使用发行包预编译 Release 二进制 (intentosd, intentosctl)..."
  install -m 0755 "${REPO_ROOT}/bin/intentosd" "${BIN_DIR}/intentosd"
  install -m 0755 "${REPO_ROOT}/bin/intentosctl" "${BIN_DIR}/intentosctl"
elif [[ -x "${REPO_ROOT}/bin/intentosd" && -x "${REPO_ROOT}/bin/intentosctl" && "${FORCE_BUILD:-0}" != "1" ]]; then
  echo "==> [1/4] 检测到预编译 Release 二进制，直接安装（如需重新编译可设 FORCE_BUILD=1）..."
  install -m 0755 "${REPO_ROOT}/bin/intentosd" "${BIN_DIR}/intentosd"
  install -m 0755 "${REPO_ROOT}/bin/intentosctl" "${BIN_DIR}/intentosctl"
else
  echo "==> [1/4] 编译 IntentOS Release 二进制 (intentosd, intentosctl)..."
  setup_build_env_if_needed
  cargo build --release --manifest-path "${REPO_ROOT}/Cargo.toml"
  install -m 0755 "${REPO_ROOT}/target/release/intentosd" "${BIN_DIR}/intentosd"
  install -m 0755 "${REPO_ROOT}/target/release/intentosctl" "${BIN_DIR}/intentosctl"
fi

echo "==> [2/4] 安装内置能力描述库、语音推理脚本、技能资产与沙箱 Agent Worker..."
rm -rf "${SHARE_DIR}/builtin-modules" "${SHARE_DIR}/pi-adapter" "${SHARE_DIR}/desktop"
cp -r "${REPO_ROOT}/modules/builtin" "${SHARE_DIR}/builtin-modules"
cp -r "${REPO_ROOT}/agent/pi-adapter" "${SHARE_DIR}/pi-adapter"
cp -r "${REPO_ROOT}/desktop" "${SHARE_DIR}/desktop"
if [[ -f "${REPO_ROOT}/scripts/intentos_asr_runner.py" ]]; then
  install -m 0755 "${REPO_ROOT}/scripts/intentos_asr_runner.py" "${SHARE_DIR}/scripts/intentos_asr_runner.py"
fi
if [[ -d "${REPO_ROOT}/skills/builtin" ]]; then
  mkdir -p "${SHARE_DIR}/skills"
  rm -rf "${SHARE_DIR}/skills/builtin"
  cp -r "${REPO_ROOT}/skills/builtin" "${SHARE_DIR}/skills/builtin"
fi

echo "==> [3/4] 安装 GNOME Shell 扩展 (intent-shell@intentos.org) 与桌面悬浮随问窗 / 11 页设置中心..."
cp "${REPO_ROOT}/desktop/gnome-extension/metadata.json" "${EXT_DIR}/"
cp "${REPO_ROOT}/desktop/gnome-extension/extension.js" "${EXT_DIR}/"
cp "${REPO_ROOT}/desktop/gnome-extension/stylesheet.css" "${EXT_DIR}/"
if [[ -f "${REPO_ROOT}/desktop/gtk-fallback/intentos-launcher.py" ]]; then
  cat > "${BIN_DIR}/intentos-launcher" <<EOF
#!/usr/bin/env bash
exec /usr/bin/python3 "${SHARE_DIR}/desktop/gtk-fallback/intentos-launcher.py" "\$@"
EOF
  chmod 0755 "${BIN_DIR}/intentos-launcher"
fi
if [[ -f "${REPO_ROOT}/desktop/gtk-fallback/org.intentos.Launcher.desktop" ]]; then
  cp "${REPO_ROOT}/desktop/gtk-fallback/org.intentos.Launcher.desktop" "${APPLICATIONS_DIR}/"
fi
if [[ -f "${REPO_ROOT}/desktop/settings/intentos-settings.py" ]]; then
  cat > "${BIN_DIR}/intentos-settings" <<EOF
#!/usr/bin/env bash
exec /usr/bin/python3 "${SHARE_DIR}/desktop/settings/intentos-settings.py" "\$@"
EOF
  chmod 0755 "${BIN_DIR}/intentos-settings"
fi
if [[ -f "${REPO_ROOT}/desktop/settings/org.intentos.Settings.desktop" ]]; then
  cp "${REPO_ROOT}/desktop/settings/org.intentos.Settings.desktop" "${APPLICATIONS_DIR}/"
fi

echo "==> [4/4] 安装 systemd --user 服务单元..."
sed "s@%h/.local/bin/intentosd@${BIN_DIR}/intentosd@g" "${REPO_ROOT}/packaging/systemd/intentosd.service" > "${SYSTEMD_USER_DIR}/intentosd.service"
if command -v systemctl >/dev/null 2>&1 && systemctl --user status >/dev/null 2>&1; then
  systemctl --user daemon-reload
  systemctl --user enable --now intentosd.service
  systemctl --user is-active --quiet intentosd.service || { echo "intentosd.service did not start" >&2; exit 1; }
  echo "✓ intentosd user service active"
else
  echo "systemd user manager unavailable; service not started" >&2
  exit 2
fi

echo ""
echo "安装完成！请确保 ~/.local/bin 在 PATH 中，快速体验："
echo "  • 启动桌面悬浮随问窗 : ~/.local/bin/intentos-launcher"
echo "  • 打开 11 页设置中心 : ~/.local/bin/intentos-settings"
echo "  • 命令行执行意图     : ~/.local/bin/intentosctl ask \"打开浏览器\""
echo "  • 一键撤销变更       : ~/.local/bin/intentosctl undo"
