"""Brief-window LLDP capture for GUI-mode scans.

The daemon ListenerManager runs LLDP indefinitely via the
``LLDPListener`` in ``listeners/lldp.py``. GUI users don't keep a
long-lived daemon connection, so we instead run a bounded sniff
during Full Scan — typically 30 seconds, which covers one or two
LLDP TX intervals (the standard interval is 30s).

Captures are pushed to the backend via REST
(``POST /api/v1/discovery/topology-edges/batch``) since the GUI
doesn't maintain a WS connection. The collected list is in-memory
only; callers stream + then push, no on-disk state.

Privileges:
- Linux: needs CAP_NET_RAW or root.
- Windows: needs Administrator (raw socket is privileged).
- macOS: needs root.

If scapy isn't available or the socket open fails we return an
empty list + log a warning — the surrounding Full Scan continues.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from freesdn_agent.listeners.lldp import parse_lldp_tlvs

logger = logging.getLogger(__name__)


async def capture_lldp_edges(
    duration_seconds: int = 30,
    interfaces: list[str] | None = None,
) -> list[dict]:
    """Sniff LLDP frames for ``duration_seconds`` + return a deduped edge list.

    Each result row has the same shape as the WS ``topology_update``
    payload's ``neighbor`` dict, plus ``local_interface``. Caller
    converts to the REST payload format before pushing.

    Returns an empty list if scapy isn't installed or the sniff
    couldn't open a raw socket (no privileges).
    """
    try:
        from scapy.all import sniff, Ether  # noqa: F401
    except ImportError:
        logger.warning("scapy not available — LLDP capture skipped")
        return []

    seen: dict[tuple, dict] = {}  # (local_iface, chassis, port) -> edge

    def _on_pkt(pkt):
        try:
            if Ether in pkt:
                raw_payload = bytes(pkt[Ether].payload)
                iface = str(getattr(pkt, "sniffed_on", None) or "unknown")
                neighbor = parse_lldp_tlvs(raw_payload)
                chassis = neighbor.get("chassis_id")
                port = neighbor.get("port_id")
                if not chassis or not port:
                    return
                key = (iface, chassis, port)
                # First sighting wins; later TLVs overwrite if richer
                edge = {
                    "local_interface": iface,
                    "neighbor_chassis_id": chassis,
                    "neighbor_chassis_subtype": neighbor.get("chassis_id_subtype"),
                    "neighbor_port_id": port,
                    "neighbor_port_description": neighbor.get("port_description"),
                    "neighbor_system_name": neighbor.get("system_name"),
                    "neighbor_system_description": neighbor.get("system_description"),
                    "neighbor_capabilities": neighbor.get("capabilities"),
                    "neighbor_mgmt_address": neighbor.get("management_address"),
                    "vlan_id": neighbor.get("vlan_id"),
                    "protocol": "lldp",
                    "_seen_at": datetime.now(timezone.utc).isoformat(),
                }
                # Merge with prior, preferring non-None values
                prior = seen.get(key)
                if prior:
                    for k, v in edge.items():
                        if v is not None and v != "":
                            prior[k] = v
                else:
                    seen[key] = edge
        except Exception:
            logger.debug("LLDP frame parse error", exc_info=True)

    def _blocking_sniff():
        from scapy.all import sniff
        kwargs = {
            "filter": "ether proto 0x88cc",
            "prn": _on_pkt,
            "store": 0,
            "timeout": duration_seconds,
        }
        if interfaces:
            kwargs["iface"] = interfaces
        try:
            sniff(**kwargs)
        except PermissionError:
            logger.warning(
                "LLDP capture requires root/Administrator — skipping",
            )
        except Exception:
            logger.warning("LLDP sniff failed", exc_info=True)

    logger.info(
        "Starting LLDP capture for %ds on %s",
        duration_seconds,
        ",".join(interfaces) if interfaces else "all interfaces",
    )

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _blocking_sniff)

    edges = list(seen.values())
    logger.info("LLDP capture complete — %d unique edge(s) found", len(edges))
    return edges
