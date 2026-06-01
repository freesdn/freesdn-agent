"""Compute the agent's capability advertisement.

The backend uses this to:
- Filter scan_type choices in the schedule-create UI to what THIS
  agent can actually run (no more "scheduled Camera Scan fails
  forever because the agent lacks scapy" failure mode)
- Surface platform / privilege info on the per-agent detail page
- Validate scan_type on schedule create against the targeted agent's
  capabilities

Computed lazily at agent startup + refreshed on heartbeat. Cheap
(no I/O beyond a couple of platform-detection calls).
"""

from __future__ import annotations

import logging
import os
import platform
import sys

logger = logging.getLogger(__name__)


def _has_scapy() -> bool:
    try:
        import scapy  # noqa: F401
        return True
    except ImportError:
        return False


def _has_raw_socket_privilege() -> bool:
    """Crude probe for whether the process can open a raw socket.

    On Unix, check effective UID. On Windows, query the
    administrator group. Doesn't actually open a socket (that's
    intrusive); just checks the prerequisites.
    """
    if platform.system() == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


def _resolve_windows_friendly_name(guid: str) -> str | None:
    """Map a Windows interface GUID to its friendly name via the registry.

    netifaces returns adapter GUIDs on Windows (e.g.
    ``{37217669-42DA-4657-A55B-0D995D328250}``) which are useless to a
    human reading the agent capability advertisement. The friendly
    name (``Ethernet``, ``Wi-Fi``) lives in the registry at
    ``HKLM\\SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-...}\\<GUID>\\Connection``.
    """
    if platform.system() != "Windows":
        return None
    try:
        import winreg
        key_path = (
            r"SYSTEM\CurrentControlSet\Control\Network"
            r"\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            f"\\{guid}\\Connection"
        )
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            name, _ = winreg.QueryValueEx(key, "Name")
            return str(name) if name else None
    except Exception:
        return None


def _list_interfaces() -> list[str]:
    """Return active network interfaces with friendly names.

    Filters:
    - loopback adapters (``lo``, ``Loopback Pseudo-Interface 1``)
    - adapters with no IPv4 address bound (disconnected/disabled)
    - link-local-only adapters (169.254.x.x, IPv6 fe80::)

    On Windows, GUIDs are resolved to friendly names so the operator
    sees ``Ethernet`` / ``Wi-Fi`` instead of opaque braces. If the
    registry lookup fails we keep the GUID (better than nothing).
    """
    try:
        import netifaces
    except ImportError:
        return []

    result: list[str] = []
    try:
        for iface in netifaces.interfaces():
            if iface.startswith("lo"):
                continue
            addrs = netifaces.ifaddresses(iface)
            v4 = addrs.get(netifaces.AF_INET, [])
            usable_v4 = [
                a for a in v4
                if a.get("addr")
                and not a["addr"].startswith("127.")
                and not a["addr"].startswith("169.254.")
            ]
            if not usable_v4:
                continue

            friendly = _resolve_windows_friendly_name(iface) or iface
            if (
                platform.system() == "Windows"
                and friendly.lower().startswith("loopback")
            ):
                continue
            result.append(friendly)
    except Exception:
        logger.exception("Interface enumeration failed")
        return []
    return result


def compute_capabilities(agent_version: str) -> dict:
    """Return the capabilities advertisement dict.

    Shape is stable; the backend uses these keys directly:
    - ``scanners``: scanner module names that work in this env
    - ``listeners``: passive listener names that work in this env
    - ``scan_types``: composite scan types the agent can fully run
    - ``platform`` / ``python_version`` / ``agent_version``: env info
    - ``has_scapy`` / ``has_root``: privilege/library probes
    - ``interfaces``: detected non-loopback NICs
    """
    has_scapy = _has_scapy()
    has_root = _has_raw_socket_privilege()

    # Scanners that work without raw sockets
    scanners: list[str] = [
        "icmp",        # ping uses scapy when available, falls back to socket
        "ports",       # plain TCP connect
        "http",        # plain TCP+HTTP
        "banner",
        "netbios",
        "sip",
        "mdns",        # multicast — needs UDP socket bind
        "ssdp",
        "snmp",
    ]
    # Scanners that need raw sockets (scapy + privilege)
    if has_scapy:
        scanners.append("onvif")
        scanners.append("sadp")
    if has_scapy and has_root:
        scanners.insert(0, "arp")  # raw L2 frames

    listeners: list[str] = []
    if has_scapy and has_root:
        listeners.extend(["lldp", "cdp"])

    # Composite scan_types map to scanner sets. If any required scanner
    # is missing we drop the composite — keeps the backend's filter
    # tight.
    scan_types: list[str] = []
    composites = {
        "quick": ["icmp"],  # arp optional
        "camera": ["onvif", "sadp"],  # both scapy
        "voip": ["sip", "mdns"],
        "iot": ["mdns", "ssdp"],
        "port": ["ports"],
        "windows": ["netbios"],
        "full": ["icmp", "ports", "mdns"],
    }
    for name, required in composites.items():
        if all(s in scanners for s in required):
            scan_types.append(name)

    return {
        "scanners": scanners,
        "listeners": listeners,
        "scan_types": scan_types,
        "platform": platform.system().lower(),  # "linux"|"windows"|"darwin"
        "python_version": sys.version.split()[0],
        "agent_version": agent_version,
        "has_scapy": has_scapy,
        "has_root": has_root,
        "interfaces": _list_interfaces(),
    }
