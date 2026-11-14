#!/usr/bin/env bash
# Build native Ubuntu/Debian package `intentos_0.1.0_amd64.deb` (`WP15`, §16.2).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${1:-0.1.0}"
ARCH="amd64"
OUT_DIR="${2:-${REPO_ROOT}/target/deb}"
PKG_DIR="${OUT_DIR}/intentos_${VERSION}_${ARCH}"

rm -rf "${PKG_DIR}"
mkdir -p \
  "${PKG_DIR}/DEBIAN" \
  "${PKG_DIR}/usr/bin" \
  "${PKG_DIR}/usr/lib/intentos/intentos-agent/dist" \
  "${PKG_DIR}/usr/lib/systemd/user" \
  "${PKG_DIR}/usr/share/intentos/builtin-modules" \
  "${PKG_DIR}/usr/share/intentos/skills" \
  "${PKG_DIR}/usr/share/intentos/gnome-extension" \
  "${PKG_DIR}/usr/share/dbus-1/interfaces" \
  "${PKG_DIR}/usr/share/applications" \
  "${PKG_DIR}/etc/apparmor.d"
chmod 0755 "${PKG_DIR}" "${PKG_DIR}/DEBIAN"

cp "${REPO_ROOT}/target/release/intentosd" "${PKG_DIR}/usr/bin/intentosd"
cp "${REPO_ROOT}/target/release/intentosctl" "${PKG_DIR}/usr/bin/intentosctl"
cp "${REPO_ROOT}/desktop/gtk-fallback/intentos-launcher.py" "${PKG_DIR}/usr/bin/intentos-launcher"
cp "${REPO_ROOT}/desktop/settings/intentos-settings.py" "${PKG_DIR}/usr/bin/intentos-settings"
chmod 0755 \
  "${PKG_DIR}/usr/bin/intentosd" \
  "${PKG_DIR}/usr/bin/intentosctl" \
  "${PKG_DIR}/usr/bin/intentos-launcher" \
  "${PKG_DIR}/usr/bin/intentos-settings"

cp -r "${REPO_ROOT}/modules/builtin/"* "${PKG_DIR}/usr/share/intentos/builtin-modules/"
cp -r "${REPO_ROOT}/skills/builtin/"* "${PKG_DIR}/usr/share/intentos/skills/"
cp "${REPO_ROOT}/agent/pi-adapter/dist/worker.js" "${PKG_DIR}/usr/lib/intentos/intentos-agent/dist/worker.js"
cp -r "${REPO_ROOT}/desktop/gnome-extension/"* "${PKG_DIR}/usr/share/intentos/gnome-extension/"
cp "${REPO_ROOT}/desktop/dbus/org.intentos.Core1.xml" "${PKG_DIR}/usr/share/dbus-1/interfaces/org.intentos.Core1.xml"
cp "${REPO_ROOT}/desktop/gtk-fallback/org.intentos.Launcher.desktop" "${PKG_DIR}/usr/share/applications/"
cp "${REPO_ROOT}/desktop/settings/org.intentos.Settings.desktop" "${PKG_DIR}/usr/share/applications/"
cp "${REPO_ROOT}/packaging/systemd/intentosd.service" "${PKG_DIR}/usr/lib/systemd/user/intentosd.service"
cp "${REPO_ROOT}/packaging/apparmor/intentos-sandbox" "${PKG_DIR}/etc/apparmor.d/intentos-sandbox"

cat > "${PKG_DIR}/DEBIAN/control" <<EOF
Package: intentos
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: IntentOS Contributors <maintainers@intentos.org>
Recommends: bubblewrap, pipewire-bin | wireplumber, xdg-utils, python3-gi, gir1.2-gtk-4.0, nodejs
Description: Intent-driven intelligent desktop shell and capability runtime for Ubuntu
 IntentOS provides a <30ms L0/L1/L2 hybrid intent router, 87 structured desktop
 and developer capabilities, openat2 symlink-safe reversible filesystem ChangeSets,
 composite scene undo, privacy sessions, and a sandboxed zero-TCP agent worker.
EOF

cat > "${PKG_DIR}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ -x /sbin/apparmor_parser ] && [ -f /etc/apparmor.d/intentos-sandbox ]; then
    /sbin/apparmor_parser -r /etc/apparmor.d/intentos-sandbox >/dev/null 2>&1 || true
fi
echo "IntentOS installed. Enable user service with: systemctl --user enable --now intentosd.service"
exit 0
EOF
chmod 0755 "${PKG_DIR}/DEBIAN/postinst"

mkdir -p "${OUT_DIR}"
DEB_PATH="${OUT_DIR}/intentos_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "${PKG_DIR}" "${DEB_PATH}"
echo "Built Debian package: ${DEB_PATH}"
