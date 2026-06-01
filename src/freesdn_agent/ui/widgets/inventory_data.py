"""Pure data helpers for the Inventory panel.

Split out of ``inventory_panel`` so the merge logic (which has no Qt
dependency) can be unit-tested in environments that don't ship
PySide6 — namely the daemon-mode CI runs.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Set


class InventoryRow:
    """One row in the unified view, derived from either source."""

    __slots__ = (
        "status",         # "Managed" | "Known" | "Discovered" | "Ignored"
        "name",
        "ip",
        "mac",
        "vendor",
        "device_type",
        "last_seen",
        "source_id",      # Device.id or DiscoveredHost.id
        "known_detail",   # e.g. "mikrotik controller" / "managed via omada"
        "raw",            # the underlying dict for the action handlers
    )

    def __init__(
        self,
        *,
        status: str,
        name: str,
        ip: str,
        mac: str,
        vendor: str,
        device_type: str,
        last_seen: str,
        source_id: str,
        raw: dict,
        known_detail: str = "",
    ):
        self.status = status
        self.name = name
        self.ip = ip
        self.mac = mac
        self.vendor = vendor
        self.device_type = device_type
        self.last_seen = last_seen
        self.source_id = source_id
        self.known_detail = known_detail
        self.raw = raw


def normalize_mac(mac: Optional[str]) -> str:
    if not mac:
        return ""
    return mac.replace(":", "").replace("-", "").replace(".", "").upper()


def format_last_seen(raw: Optional[str]) -> str:
    if not raw:
        return "—"
    try:
        if isinstance(raw, str):
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        else:
            dt = raw
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(raw)[:16]


def merge_into_inventory(
    managed_devices: List[dict],
    discovered_hosts: List[dict],
) -> List[InventoryRow]:
    """Collapse the two lists by MAC, then by IP.

    When the same MAC appears in both lists the Managed row wins and
    the discovered row is dropped — that's the whole point of the
    unified view (no more "why is this in both tabs?").

    IP is an authoritative fallback **even when the discovered host
    has a MAC**: some managed device rows carry an IP but no MAC (a
    Proxmox hypervisor onboarded as a controller syncs to a Device
    with ip_address but no mac_address). Without the IP fallback those
    would show twice — once Managed (the hypervisor, no MAC) and once
    Discovered (the agent's scan row, which DID capture a MAC). IP is
    unique per site/subnet so collapsing on it is safe.
    """
    rows: List[InventoryRow] = []
    managed_macs: Set[str] = set()
    managed_ips: Set[str] = set()

    for dev in managed_devices:
        mac = normalize_mac(dev.get("mac_address") or dev.get("mac"))
        ip = (dev.get("ip_address") or dev.get("ip") or "").strip()
        if mac:
            managed_macs.add(mac)
        if ip:
            managed_ips.add(ip)
        rows.append(InventoryRow(
            status="Managed",
            name=dev.get("name") or dev.get("hostname") or "Unnamed",
            ip=ip,
            mac=(dev.get("mac_address") or dev.get("mac") or "").upper(),
            vendor=dev.get("vendor") or dev.get("manufacturer") or "Unknown",
            device_type=dev.get("device_type") or "unknown",
            last_seen=format_last_seen(
                dev.get("last_seen") or dev.get("updated_at"),
            ),
            source_id=str(dev.get("id") or ""),
            raw=dev,
        ))

    for host in discovered_hosts:
        mac_norm = normalize_mac(host.get("mac_address") or host.get("mac"))
        ip = (host.get("ip_address") or host.get("ip") or "").strip()

        if mac_norm and mac_norm in managed_macs:
            continue
        # IP fallback applies regardless of whether the host has a MAC —
        # a managed row may have the IP but no MAC (hypervisor case).
        if ip and ip in managed_ips:
            continue

        # known_as is stamped by the backend: FreeSDN already knows this
        # IP/MAC (a controller appliance like the MikroTik gateway, or a
        # controller-synced device). Such a host isn't "brand new" — it's
        # Known. Genuinely-new hosts have known_as=None → Discovered.
        known = host.get("known_as") or None
        known_detail = ""
        if bool(host.get("ignored")):
            status = "Ignored"
        elif known:
            status = "Known"
            name_part = known.get("name") or ""
            detail_part = known.get("detail") or ""
            known_detail = (
                f"{name_part} · {detail_part}".strip(" ·")
                if name_part or detail_part
                else "known to FreeSDN"
            )
        else:
            status = "Discovered"

        rows.append(InventoryRow(
            status=status,
            name=host.get("hostname") or f"discovered-{ip}",
            ip=ip,
            mac=(host.get("mac_address") or host.get("mac") or "").upper(),
            vendor=host.get("vendor") or "Unknown",
            device_type=host.get("device_type") or "unknown",
            last_seen=format_last_seen(host.get("last_seen")),
            source_id=str(host.get("id") or ""),
            known_detail=known_detail,
            raw=host,
        ))

    return rows
