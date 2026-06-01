"""
LLDP (Link Layer Discovery Protocol) passive listener.

Captures LLDP frames (ethertype 0x88CC) via scapy raw L2 socket,
parses TLV fields, and reports topology discoveries to the control plane.

Requires root/admin for raw socket access.
"""

import asyncio
import logging
import struct
from datetime import datetime, timezone
from typing import Any

from freesdn_agent.listeners.base import BaseListener

logger = logging.getLogger(__name__)


def _log_future_error(fut):
    """Done callback for run_coroutine_threadsafe futures — log exceptions."""
    try:
        fut.result()
    except Exception:
        logger.debug("Async report delivery failed", exc_info=True)


# LLDP TLV type constants
LLDP_TLV_END = 0
LLDP_TLV_CHASSIS_ID = 1
LLDP_TLV_PORT_ID = 2
LLDP_TLV_TTL = 3
LLDP_TLV_PORT_DESC = 4
LLDP_TLV_SYSTEM_NAME = 5
LLDP_TLV_SYSTEM_DESC = 6
LLDP_TLV_SYSTEM_CAP = 7
LLDP_TLV_MGMT_ADDR = 8

# Chassis ID subtypes
CHASSIS_SUBTYPE_MAC = 4
CHASSIS_SUBTYPE_NET = 5
CHASSIS_SUBTYPE_LOCAL = 7

# Port ID subtypes
PORT_SUBTYPE_MAC = 3
PORT_SUBTYPE_NET = 4
PORT_SUBTYPE_LOCAL = 7
PORT_SUBTYPE_IFACE = 5


def _parse_mac(data: bytes) -> str:
    """Format raw bytes as MAC address string."""
    return ":".join(f"{b:02x}" for b in data)


def _parse_ip(data: bytes) -> str:
    """Parse IPv4 address from bytes."""
    if len(data) >= 4:
        return ".".join(str(b) for b in data[:4])
    return data.hex()


def parse_lldp_tlvs(raw: bytes) -> dict[str, Any]:
    """
    Parse LLDP TLV chain from raw Ethernet payload.

    Returns dict with keys: chassis_id, port_id, ttl, port_description,
    system_name, system_description, system_capabilities, management_address.
    """
    result: dict[str, Any] = {}
    offset = 0
    max_tlvs = 256  # safety cap on iterations

    # Reject oversized payloads (max jumbo frame ~9000 bytes)
    if len(raw) > 9000:
        return result

    while offset + 2 <= len(raw) and max_tlvs > 0:
        max_tlvs -= 1

        # TLV header: 7 bits type + 9 bits length
        header = struct.unpack("!H", raw[offset:offset + 2])[0]
        tlv_type = (header >> 9) & 0x7F
        tlv_len = header & 0x01FF
        offset += 2

        if tlv_type == LLDP_TLV_END:
            break

        # Reject zero-length non-End TLVs (would cause infinite loop)
        if tlv_len == 0 or offset + tlv_len > len(raw):
            break

        data = raw[offset:offset + tlv_len]
        offset += tlv_len

        if tlv_type == LLDP_TLV_CHASSIS_ID and len(data) >= 2:
            subtype = data[0]
            if subtype == CHASSIS_SUBTYPE_MAC and len(data) >= 7:
                result["chassis_id"] = _parse_mac(data[1:7])
                result["chassis_id_subtype"] = "mac"
            elif subtype == CHASSIS_SUBTYPE_NET:
                result["chassis_id"] = _parse_ip(data[2:])
                result["chassis_id_subtype"] = "ip"
            else:
                result["chassis_id"] = data[1:].decode("utf-8", errors="replace").strip("\x00")
                result["chassis_id_subtype"] = "local"

        elif tlv_type == LLDP_TLV_PORT_ID and len(data) >= 2:
            subtype = data[0]
            if subtype == PORT_SUBTYPE_MAC and len(data) >= 7:
                result["port_id"] = _parse_mac(data[1:7])
            elif subtype in (PORT_SUBTYPE_LOCAL, PORT_SUBTYPE_IFACE):
                result["port_id"] = data[1:].decode("utf-8", errors="replace").strip("\x00")
            else:
                result["port_id"] = data[1:].decode("utf-8", errors="replace").strip("\x00")

        elif tlv_type == LLDP_TLV_TTL and len(data) >= 2:
            result["ttl"] = struct.unpack("!H", data[:2])[0]

        elif tlv_type == LLDP_TLV_PORT_DESC:
            result["port_description"] = data.decode("utf-8", errors="replace").strip("\x00")

        elif tlv_type == LLDP_TLV_SYSTEM_NAME:
            result["system_name"] = data.decode("utf-8", errors="replace").strip("\x00")

        elif tlv_type == LLDP_TLV_SYSTEM_DESC:
            result["system_description"] = data.decode("utf-8", errors="replace").strip("\x00")

        elif tlv_type == LLDP_TLV_SYSTEM_CAP and len(data) >= 4:
            caps_available = struct.unpack("!H", data[0:2])[0]
            caps_enabled = struct.unpack("!H", data[2:4])[0]
            result["system_capabilities"] = {
                "available": caps_available,
                "enabled": caps_enabled,
            }

        elif tlv_type == LLDP_TLV_MGMT_ADDR and len(data) >= 4:
            addr_len = data[0]
            addr_subtype = data[1]
            if addr_subtype == 1 and addr_len >= 5 and len(data) >= 6:  # IPv4
                result["management_address"] = _parse_ip(data[2:6])
            elif addr_subtype == 2 and addr_len >= 17 and len(data) >= 18:  # IPv6
                result["management_address"] = data[2:18].hex(":")
            elif addr_len > 1 and len(data) >= 2 + addr_len - 1:
                result["management_address"] = data[2:2 + addr_len - 1].hex()

    return result


class LLDPListener(BaseListener):
    """Passive LLDP frame listener using scapy raw sockets."""

    LISTENER_NAME = "LLDP"
    REQUIRES_ROOT = True

    async def run(self) -> None:
        """Sniff LLDP frames in a background thread."""
        try:
            from scapy.all import sniff, Ether
        except ImportError:
            logger.warning("scapy not available — LLDP listener disabled")
            return

        loop = asyncio.get_running_loop()

        def _sniff_callback(pkt):
            """Called by scapy in the executor thread for each LLDP frame."""
            if not self._running:
                return

            try:
                if Ether in pkt:
                    raw_payload = bytes(pkt[Ether].payload)
                    iface = str(getattr(pkt, "sniffed_on", None) or "unknown")
                    neighbor = parse_lldp_tlvs(raw_payload)

                    if neighbor.get("chassis_id"):
                        payload = {
                            "discovered_via": "LLDP",
                            "neighbor": neighbor,
                            "local_interface": iface,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                        fut = asyncio.run_coroutine_threadsafe(
                            self._report("topology_update", payload),
                            loop,
                        )
                        fut.add_done_callback(_log_future_error)
            except Exception:
                self._stats["errors"] += 1
                logger.debug("Error parsing LLDP frame", exc_info=True)

        def _blocking_sniff():
            """Run scapy sniff in executor with periodic timeout for stop checks."""
            try:
                while self._running:
                    sniff(
                        filter="ether proto 0x88cc",
                        prn=_sniff_callback,
                        store=0,
                        timeout=5,
                        stop_filter=lambda _: not self._running,
                    )
            except PermissionError:
                raise
            except Exception:
                if self._running:
                    logger.warning("LLDP sniff error", exc_info=True)
                    raise

        logger.info("LLDP listener active — sniffing for 802.1AB frames")
        await loop.run_in_executor(None, _blocking_sniff)
