#!/usr/bin/env bash
# =============================================================================
# FreeSDN Agent — macOS Package Builder
#
# Usage:
#   ./build_pkg.sh <version> <binary_path>
#   ./build_pkg.sh 0.4.0 dist/freesdn-agent
#
# Output: freesdn-agent-<version>-macos.pkg
# =============================================================================
set -euo pipefail

VERSION="${1:?Usage: build_pkg.sh <version> <binary_path>}"
BINARY="${2:?Usage: build_pkg.sh <version> <binary_path>}"
PKG_ID="com.freesdn.agent"
INSTALL_DIR="/Applications/FreeSDN Agent"
OUTPUT="freesdn-agent-${VERSION}-macos.pkg"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found: $BINARY"
    exit 1
fi

BUILD_DIR=$(mktemp -d)
SCRIPTS_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR" "$SCRIPTS_DIR"' EXIT

echo "Building ${OUTPUT} ..."

# -- Install payload --
mkdir -p "${BUILD_DIR}${INSTALL_DIR}"
cp "$BINARY" "${BUILD_DIR}${INSTALL_DIR}/freesdn-agent"
chmod 755 "${BUILD_DIR}${INSTALL_DIR}/freesdn-agent"

# -- LaunchDaemon plist --
mkdir -p "${BUILD_DIR}/Library/LaunchDaemons"
cat > "${BUILD_DIR}/Library/LaunchDaemons/com.freesdn.agent.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.freesdn.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/FreeSDN Agent/freesdn-agent</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>_freesdn</string>
    <key>GroupName</key>
    <string>_freesdn</string>
    <key>StandardOutPath</key>
    <string>/var/log/freesdn-agent/agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/freesdn-agent/agent.err</string>
</dict>
</plist>
PLIST

# -- Symlink in PATH --
mkdir -p "${BUILD_DIR}/usr/local/bin"
ln -sf "/Applications/FreeSDN Agent/freesdn-agent" "${BUILD_DIR}/usr/local/bin/freesdn-agent"

# -- Post-install script --
cat > "${SCRIPTS_DIR}/postinstall" << 'EOF'
#!/bin/sh
set -e
mkdir -p /var/log/freesdn-agent
echo ""
echo "FreeSDN Agent installed."
echo ""
echo "Next steps:"
echo "  1. Register:  sudo freesdn-agent register --server https://your-freesdn.com"
echo "  2. Approve the agent in FreeSDN UI → Agents"
echo "  3. Start:     sudo launchctl load -w /Library/LaunchDaemons/com.freesdn.agent.plist"
echo ""
EOF
chmod 755 "${SCRIPTS_DIR}/postinstall"

# -- Build component package --
pkgbuild \
    --root "$BUILD_DIR" \
    --identifier "$PKG_ID" \
    --version "$VERSION" \
    --scripts "$SCRIPTS_DIR" \
    --install-location "/" \
    "${OUTPUT}"

echo "Built: $OUTPUT ($(du -h "$OUTPUT" | awk '{print $1}'))"
shasum -a 256 "$OUTPUT"
