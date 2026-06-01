# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for FreeSDN Agent — Daemon (headless, no Qt).

Produces a single ~30MB console binary suitable for running as a system service.

Build:
    cd agent/
    pyinstaller packaging/daemon.spec
"""
import sys
from pathlib import Path

block_cipher = None
agent_root = Path(SPECPATH).parent / "src"

# All scanner modules need to be collected since they're loaded dynamically
# via SCANNER_REGISTRY at runtime.
scanner_hiddenimports = [
    "freesdn_agent.scanners.ping",
    "freesdn_agent.scanners.arp",
    "freesdn_agent.scanners.tcp_port",
    "freesdn_agent.scanners.http_service",
    "freesdn_agent.scanners.banner",
    "freesdn_agent.scanners.snmp",
    "freesdn_agent.scanners.netbios",
    "freesdn_agent.scanners.mdns",
    "freesdn_agent.scanners.ssdp",
    "freesdn_agent.scanners.sip",
    "freesdn_agent.scanners.dns",
    "freesdn_agent.scanners.rtsp",
    "freesdn_agent.scanners.onvif",
    "freesdn_agent.scanners.sadp",
]

# Listener modules (Phase 6)
listener_hiddenimports = [
    "freesdn_agent.listeners.lldp",
    "freesdn_agent.listeners.cdp",
    "freesdn_agent.listeners.snmp_trap",
    "freesdn_agent.listeners.syslog",
    "freesdn_agent.listeners.dhcp_watcher",
]

# Dependency hidden imports that PyInstaller may miss
dep_hiddenimports = [
    "keyring.backends",
    "keyring.backends.Windows",
    "keyring.backends.macOS",
    "keyring.backends.SecretService",
    "pydantic",
    "pydantic.deprecated",
    "pydantic._internal",
    "netifaces",
    "psutil",
    "scapy.all",
    "scapy.layers.l2",
    "scapy.layers.inet",
    "scapy.layers.dhcp",
    "pysnmp",
    "pysnmp.hlapi",
    "zeroconf",
    "wsdiscovery",
    "httpx",
    "websockets",
]

a = Analysis(
    [str(agent_root / "freesdn_agent" / "daemon" / "cli.py")],
    pathex=[str(agent_root)],
    binaries=[],
    datas=[],
    hiddenimports=(
        scanner_hiddenimports
        + listener_hiddenimports
        + dep_hiddenimports
    ),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude Qt/PySide6 entirely — daemon is headless
        "PySide6",
        "shiboken6",
        "PyQt5",
        "PyQt6",
        "tkinter",
        "_tkinter",
        "matplotlib",
        "numpy",
        "PIL",
        "cv2",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="freesdn-agent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
