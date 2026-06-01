"""
OS service integration for FreeSDN Agent.

Provides helpers for installing/uninstalling the daemon as a system service
on Windows (NSSM), Linux (systemd), and macOS (launchd).
"""

import platform
import shutil
import sys
import textwrap
from pathlib import Path

AGENT_BIN = "freesdn-agent"


# -----------------------------------------------------------------
# systemd (Linux)
# -----------------------------------------------------------------

_SYSTEMD_UNIT = textwrap.dedent("""\
    [Unit]
    Description=FreeSDN Agent - Network Discovery Daemon
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    ExecStart={exe_path} daemon
    Restart=always
    RestartSec=10
    User=root
    AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE

    # Logging
    StandardOutput=journal
    StandardError=journal
    SyslogIdentifier=freesdn-agent

    # Security hardening
    ProtectSystem=strict
    ReadWritePaths=/opt/freesdn-agent /var/log/freesdn-agent
    PrivateTmp=true
    NoNewPrivileges=false

    [Install]
    WantedBy=multi-user.target
""")

SYSTEMD_PATH = Path("/etc/systemd/system/freesdn-agent.service")


def install_systemd() -> str:
    """Install systemd unit file."""
    exe = shutil.which(AGENT_BIN) or sys.executable
    unit = _SYSTEMD_UNIT.format(exe_path=exe)
    SYSTEMD_PATH.write_text(unit)
    return (
        f"Systemd unit installed at {SYSTEMD_PATH}\n"
        "Run:\n"
        "  sudo systemctl daemon-reload\n"
        "  sudo systemctl enable --now freesdn-agent"
    )


def uninstall_systemd() -> str:
    """Remove systemd unit file."""
    if SYSTEMD_PATH.exists():
        SYSTEMD_PATH.unlink()
    return "Systemd unit removed. Run: sudo systemctl daemon-reload"


# -----------------------------------------------------------------
# launchd (macOS)
# -----------------------------------------------------------------

_LAUNCHD_PLIST = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
      "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.freesdn.agent</string>
        <key>ProgramArguments</key>
        <array>
            <string>{exe_path}</string>
            <string>daemon</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <true/>
        <key>StandardOutPath</key>
        <string>/var/log/freesdn-agent/agent.log</string>
        <key>StandardErrorPath</key>
        <string>/var/log/freesdn-agent/agent.err</string>
    </dict>
    </plist>
""")

LAUNCHD_PATH = Path("/Library/LaunchDaemons/com.freesdn.agent.plist")


def install_launchd() -> str:
    """Install launchd plist."""
    exe = shutil.which(AGENT_BIN) or sys.executable
    plist = _LAUNCHD_PLIST.format(exe_path=exe)
    LAUNCHD_PATH.write_text(plist)
    return (
        f"LaunchDaemon installed at {LAUNCHD_PATH}\n"
        "Run:\n"
        "  sudo launchctl load -w /Library/LaunchDaemons/com.freesdn.agent.plist"
    )


def uninstall_launchd() -> str:
    """Remove launchd plist."""
    if LAUNCHD_PATH.exists():
        LAUNCHD_PATH.unlink()
    return "LaunchDaemon removed."


# -----------------------------------------------------------------
# Windows Service (via NSSM or native)
# -----------------------------------------------------------------

def install_windows_service() -> str:
    """
    Generate instructions / scripts for Windows service installation.

    Uses NSSM (Non-Sucking Service Manager) when available,
    otherwise provides sc.exe instructions.
    """
    exe = shutil.which(AGENT_BIN)
    if not exe:
        exe = f"{sys.executable} -m freesdn_agent.daemon.cli daemon"

    nssm = shutil.which("nssm")
    if nssm:
        return (
            "NSSM detected. Run as Administrator:\n"
            f'  nssm install FreeSDNAgent "{exe}" daemon\n'
            "  nssm set FreeSDNAgent DisplayName \"FreeSDN Agent\"\n"
            "  nssm set FreeSDNAgent Description \"FreeSDN Network Discovery Agent\"\n"
            "  nssm set FreeSDNAgent Start SERVICE_AUTO_START\n"
            "  nssm start FreeSDNAgent"
        )

    return (
        "Install as Windows service (run as Administrator):\n"
        f'  sc create FreeSDNAgent binPath= "{exe} daemon" start= auto\n'
        "  sc description FreeSDNAgent \"FreeSDN Network Discovery Agent\"\n"
        "  sc start FreeSDNAgent\n"
        "\n"
        "For more robust service management, install NSSM:\n"
        "  https://nssm.cc/download"
    )


def uninstall_windows_service() -> str:
    """Instructions to remove Windows service."""
    return (
        "Run as Administrator:\n"
        "  sc stop FreeSDNAgent\n"
        "  sc delete FreeSDNAgent"
    )


# -----------------------------------------------------------------
# Dispatcher
# -----------------------------------------------------------------

def install_service() -> str:
    """Install the agent as a system service for the current platform."""
    system = platform.system()
    if system == "Linux":
        return install_systemd()
    elif system == "Darwin":
        return install_launchd()
    elif system == "Windows":
        return install_windows_service()
    else:
        return f"Unsupported platform: {system}"


def uninstall_service() -> str:
    """Remove the agent system service."""
    system = platform.system()
    if system == "Linux":
        return uninstall_systemd()
    elif system == "Darwin":
        return uninstall_launchd()
    elif system == "Windows":
        return uninstall_windows_service()
    else:
        return f"Unsupported platform: {system}"
