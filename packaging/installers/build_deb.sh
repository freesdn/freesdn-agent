#!/usr/bin/env bash
# =============================================================================
# FreeSDN Agent — Debian/Ubuntu Package Builder
#
# Usage:
#   ./build_deb.sh <version> <binary_path>
#   ./build_deb.sh 0.4.0 dist/freesdn-agent
#
# Output: freesdn-agent_<version>_amd64.deb
# =============================================================================
set -euo pipefail

VERSION="${1:?Usage: build_deb.sh <version> <binary_path>}"
BINARY="${2:?Usage: build_deb.sh <version> <binary_path>}"

# Validate version format
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$'; then
    echo "ERROR: Invalid version format: $VERSION"
    exit 1
fi
PKG_NAME="freesdn-agent"
ARCH="amd64"
INSTALL_DIR="/opt/freesdn-agent"
OUTPUT="${PKG_NAME}_${VERSION}_${ARCH}.deb"

# Validate binary exists
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found: $BINARY"
    exit 1
fi

# Create temporary build directory
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "Building ${OUTPUT} ..."

# -- Directory structure --
mkdir -p "${BUILD_DIR}${INSTALL_DIR}/bin"
mkdir -p "${BUILD_DIR}/usr/local/bin"
mkdir -p "${BUILD_DIR}/etc/systemd/system"
mkdir -p "${BUILD_DIR}/var/log/freesdn-agent"
mkdir -p "${BUILD_DIR}/DEBIAN"

# -- Install binary --
cp "$BINARY" "${BUILD_DIR}${INSTALL_DIR}/bin/freesdn-agent"
chmod 755 "${BUILD_DIR}${INSTALL_DIR}/bin/freesdn-agent"

# -- Symlink in PATH --
ln -sf "${INSTALL_DIR}/bin/freesdn-agent" "${BUILD_DIR}/usr/local/bin/freesdn-agent"

# -- systemd unit --
cat > "${BUILD_DIR}/etc/systemd/system/freesdn-agent.service" << 'UNIT'
[Unit]
Description=FreeSDN Agent - Network Discovery Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/freesdn-agent/bin/freesdn-agent daemon
Restart=always
RestartSec=10
User=freesdn-agent
Group=freesdn-agent
AmbientCapabilities=CAP_NET_RAW

StandardOutput=journal
StandardError=journal
SyslogIdentifier=freesdn-agent

ProtectSystem=strict
ReadWritePaths=/opt/freesdn-agent /var/log/freesdn-agent
PrivateTmp=true
NoNewPrivileges=true
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
UNIT

# -- DEBIAN/control --
INSTALLED_SIZE=$(du -sk "${BUILD_DIR}" | awk '{print $1}')
cat > "${BUILD_DIR}/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_SIZE}
Maintainer: FreeSDN Team <contact@freesdn.org>
Description: FreeSDN Agent - Network Discovery Daemon
 Headless network discovery agent that connects to the FreeSDN
 control plane via WebSocket for remote site scanning, L2/L3
 discovery (ARP, LLDP, CDP, SNMP), and device management.
 .
 Supports 14 discovery protocols, passive listeners (LLDP, CDP,
 SNMP traps, syslog), scheduled scans, and auto-updates.
Homepage: https://github.com/freesdn/freesdn-agent
EOF

# -- DEBIAN/postinst --
cat > "${BUILD_DIR}/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e

# Create dedicated service user
if ! id -u freesdn-agent >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin freesdn-agent
fi

# Ensure directories are owned by service user
chown -R freesdn-agent:freesdn-agent /opt/freesdn-agent /var/log/freesdn-agent 2>/dev/null || true

# Set CAP_NET_RAW on the binary so it works without root
setcap cap_net_raw+ep /opt/freesdn-agent/bin/freesdn-agent 2>/dev/null || true

systemctl daemon-reload
echo ""
echo "FreeSDN Agent installed."
echo ""
echo "Next steps:"
echo "  1. Register:  sudo freesdn-agent register --server https://your-freesdn.com"
echo "  2. Approve the agent in FreeSDN UI → Agents"
echo "  3. Start:     sudo systemctl enable --now freesdn-agent"
echo ""
EOF
chmod 755 "${BUILD_DIR}/DEBIAN/postinst"

# -- DEBIAN/prerm --
cat > "${BUILD_DIR}/DEBIAN/prerm" << 'EOF'
#!/bin/sh
set -e
if systemctl is-active --quiet freesdn-agent 2>/dev/null; then
    systemctl stop freesdn-agent || true
fi
if systemctl is-enabled --quiet freesdn-agent 2>/dev/null; then
    systemctl disable freesdn-agent || true
fi
EOF
chmod 755 "${BUILD_DIR}/DEBIAN/prerm"

# -- DEBIAN/postrm --
cat > "${BUILD_DIR}/DEBIAN/postrm" << 'EOF'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
    rm -rf /opt/freesdn-agent
    rm -rf /var/log/freesdn-agent
fi
systemctl daemon-reload || true
EOF
chmod 755 "${BUILD_DIR}/DEBIAN/postrm"

# -- Build .deb --
dpkg-deb --build --root-owner-group "$BUILD_DIR" "$OUTPUT"

echo "Built: $OUTPUT ($(du -h "$OUTPUT" | awk '{print $1}'))"
sha256sum "$OUTPUT"
