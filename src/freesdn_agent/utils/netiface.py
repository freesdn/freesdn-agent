"""What a network interface name means, in one place.

An interface name gets used for three different jobs in this agent, and each
one had its own private implementation:

* as a LABEL an operator reads in the GUI,
* as a HINT for whether the adapter is virtual and should be left out of a scan,
* as a stand-in for the SUBNET to scan when no explicit targets were given.

Only the first had a Windows-aware implementation, and it lived inside the
daemon's capability advertiser where the GUI could not reach it. The other two
took the raw string from ``netifaces``, which on Windows is an adapter GUID like
``{37217669-42DA-4657-A55B-0D995D328250}``. So the GUI listed braces, the
"don't scan the virtual switch" filter never matched anything, and naming an
interface as a scan target produced zero addresses.

Qt-free and outside ``ui/`` on purpose: PySide6 is an optional extra that CI
does not install, so anything reachable only through ``ui/`` cannot be tested.
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import re

logger = logging.getLogger(__name__)

__all__ = [
    "OVERLAY_HINTS",
    "friendly_name",
    "interface_networks",
    "is_overlay",
    "local_networks",
    "usable_ipv4",
]

#: Adapters that carry no scannable LAN: tunnels, container bridges and
#: hypervisor switches. Matched against the FRIENDLY name -- matching the raw
#: netifaces identifier is what made this inert on Windows. ``vethernet``
#: covers Hyper-V's ``vEthernet (Default Switch)`` and ``vEthernet (WSL ...)``,
#: which present a /20 each and would otherwise dominate a scan.
OVERLAY_HINTS = re.compile(
    r"(tailscale|wireguard|zerotier|openvpn|tap|tun\d|vethernet|docker|veth|br-"
    r"|hyper-v|wsl|vmnet|vmware|virtualbox|loopback|vpn)",
    re.IGNORECASE,
)

_WINDOWS_ADAPTER_KEY = (
    r"SYSTEM\CurrentControlSet\Control\Network"
    r"\{4D36E972-E325-11CE-BFC1-08002BE10318}"
)


def friendly_name(iface: str) -> str:
    """The name an operator would recognise for ``iface``.

    On Windows ``netifaces`` yields the adapter GUID; the name shown in
    Network Connections lives in the registry under the adapter's
    ``Connection`` subkey. Everywhere else the identifier already IS the name.

    Never raises and never returns empty: an unresolvable GUID comes back
    unchanged, which is worse to read but still correctly identifies the
    adapter.
    """
    if not iface or platform.system() != "Windows":
        return iface
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, f"{_WINDOWS_ADAPTER_KEY}\\{iface}\\Connection"
        ) as key:
            name, _ = winreg.QueryValueEx(key, "Name")
        return str(name) if name else iface
    except Exception:
        return iface


def is_overlay(label: str) -> bool:
    """Whether ``label`` names a virtual adapter rather than a real LAN.

    Pass the FRIENDLY name. Passing a raw Windows GUID here is the original
    bug: it matches nothing, so every hypervisor switch is treated as a LAN
    worth scanning.
    """
    return bool(label) and bool(OVERLAY_HINTS.search(label))


def usable_ipv4(iface: str) -> list[tuple[str, str]]:
    """``(address, netmask)`` pairs bound to ``iface``, loopback/APIPA removed.

    A link-local 169.254.x.x address means DHCP failed, so the adapter has no
    real network behind it and is not worth scanning.
    """
    try:
        import netifaces
    except ImportError:
        return []

    pairs: list[tuple[str, str]] = []
    try:
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
    except Exception:
        return []
    for addr in addrs:
        ip = addr.get("addr", "")
        mask = addr.get("netmask", "") or "255.255.255.255"
        if not ip or ip.startswith("127.") or ip.startswith("169.254."):
            continue
        pairs.append((ip, mask))
    return pairs


def interface_networks(iface: str | None) -> list[str]:
    """The CIDRs reachable on ``iface`` -- what "scan this interface" means.

    Returns the SUBNET, not the address: ``192.168.1.157/24`` becomes
    ``192.168.1.0/24``. This is the substitution that was missing, and without
    it the interface name itself was handed to the scanner as a target, where
    it parsed to zero addresses and the scan reported success having looked at
    nothing.

    A blank or absent name means "auto-detect", the sense in which callers
    already pass ``[""]``, and yields every usable local network.

    A /32 is dropped. It is a single-host route -- a Tailscale address, a
    point-to-point link -- and expanding it produces one address, the agent's
    own, which no scan wants.
    """
    if not iface:
        return local_networks()

    nets: list[str] = []
    for ip, mask in usable_ipv4(iface):
        try:
            prefix = sum(bin(int(octet)).count("1") for octet in mask.split("."))
            if prefix >= 32:
                continue
            network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        except Exception:
            logger.debug("Cannot derive a network from %s/%s on %s", ip, mask, iface)
            continue
        if str(network) not in nets:
            nets.append(str(network))
    return nets


def local_networks() -> list[str]:
    """Every usable local IPv4 network, virtual adapters excluded.

    The exclusion matters more here than in the GUI: nothing prompts the
    operator, so a Hyper-V switch's /20 would silently become 4,094 addresses
    of an unattended scan.
    """
    try:
        import netifaces
    except ImportError:
        return []

    nets: list[str] = []
    try:
        ifaces = netifaces.interfaces()
    except Exception:
        return []
    for iface in ifaces:
        if iface.startswith("lo"):
            continue
        if is_overlay(friendly_name(iface)):
            continue
        for network in interface_networks(iface):
            if network not in nets:
                nets.append(network)
    return nets
