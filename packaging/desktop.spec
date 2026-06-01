# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for FreeSDN Agent — Desktop App (PySide6 GUI).

Produces a ~150MB windowed application with full Qt GUI for interactive
network scanning and device discovery.

Build:
    cd agent/
    pyinstaller packaging/desktop.spec
"""
import sys
from pathlib import Path

block_cipher = None
agent_root = Path(SPECPATH).parent / "src"
resource_dir = agent_root / "freesdn_agent" / "ui"

# Scanner modules — dynamically loaded via SCANNER_REGISTRY
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
    "pysnmp",
    "pysnmp.hlapi",
    "zeroconf",
    "wsdiscovery",
    "httpx",
    "websockets",
    "PySide6.QtWidgets",
    "PySide6.QtCore",
    "PySide6.QtGui",
]

# Collect Qt resources (stylesheets, icons)
datas = []
styles_dir = resource_dir / "styles"
icons_dir = resource_dir / "resources" / "icons"
if styles_dir.exists():
    datas.append((str(styles_dir), "freesdn_agent/ui/styles"))
if icons_dir.exists():
    datas.append((str(icons_dir), "freesdn_agent/ui/resources/icons"))

a = Analysis(
    [str(agent_root / "freesdn_agent" / "main.py")],
    pathex=[str(agent_root)],
    binaries=[],
    datas=datas,
    hiddenimports=scanner_hiddenimports + dep_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "_tkinter",
        "matplotlib",
        "numpy",
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
    name="freesdn-agent-gui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Windowed mode — no console
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(icons_dir / "app.ico") if (icons_dir / "app.ico").exists() else None,
)
