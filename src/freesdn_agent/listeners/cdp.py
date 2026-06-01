"""
CDP (Cisco Discovery Protocol) passive listener.

Captures CDP frames (multicast 01:00:0c:cc:cc:cc, SNAP 0x2000) via scapy,
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


# CDP TLV type constants
CDP_TLV_DEVICE_ID = 0x0001
CDP_TLV_ADDRESSES = 0x0002
CDP_TLV_PORT_ID = 0x0003
CDP_TLV_CAPABILITIES = 0x0004
CDP_TLV_SOFTWARE_VERSION = 0x0005
CDP_TLV_PLATFORM = 0x0006
CDP_TLV_NATIVE_VLAN = 0x000A
CDP_TLV_DUPLEX = 0x000B
CDP_TLV_MGMT_ADDRESS = 0x0016


def _parse_cdp_address(data: bytes) -> str | None:
    """Parse a single CDP address entry."""
    if len(data) < 8:
        return None
    proto_type = data[0]
    proto_len = data[1]
    addr_len_offset = 2 + proto_len
    if len(data) < addr_len_offset + 2:
        return None
    addr_len = struct.unpack("!H", data[addr_len_offset:addr_len_offset + 2])[0]
    addr_start = addr_len_offset + 2
    if proto_type == 1 and addr_len == 4 and len(data) >= addr_start + 4:
        return ".".join(str(b) for b in data[addr_start:addr_start + 4])
    return None


def parse_cdp_tlvs(raw: bytes) -> dict[str, Any]:
    """
    Parse CDP TLV chain from raw CDP payload (after version + TTL + checksum).

    CDP frame layout: version(1) + TTL(1) + checksum(2) + TLVs
    """
    result: dict[str, Any] = {}

    if len(raw) < 4 or len(raw) > 9000:
        return result

    result["cdp_version"] = raw[0]
    result["ttl"] = raw[1]

    offset = 4  # skip version + TTL + checksum
    max_tlvs = 256  # safety cap

    while offset + 4 <= len(raw) and max_tlvs > 0:
        max_tlvs -= 1
        tlv_type = struct.unpack("!H", raw[offset:offset + 2])[0]
        tlv_len = struct.unpack("!H", raw[offset + 2:offset + 4])[0]

        if tlv_len < 4 or offset + tlv_len > len(raw):
            break

        data = raw[offset + 4:offset + tlv_len]
        offset += tlv_len

        if tlv_type == CDP_TLV_DEVICE_ID:
            result["device_id"] = data.decode("utf-8", errors="replace").strip("\x00")

        elif tlv_type == CDP_TLV_ADDRESSES and len(data) >= 4:
            num_addrs = struct.unpack("!I", data[:4])[0]
            addrs = []
            addr_offset = 4
            for _ in range(min(num_addrs, 10)):
                if addr_offset + 2 > len(data):
                    break
                addr = _parse_cdp_address(data[addr_offset:])
                if addr:
                    addrs.append(addr)
                # Move past this address entry (variable length)
                if addr_offset + 1 >= len(data):
                    break
                proto_len = data[addr_offset + 1]
                addr_len_off = addr_offset + 2 + proto_len
                if addr_len_off + 2 > len(data):
                    break
                a_len = struct.unpack("!H", data[addr_len_off:addr_len_off + 2])[0]
                if a_len > len(data) - (addr_len_off + 2):
                    break
                addr_offset = addr_len_off + 2 + a_len
            result["addresses"] = addrs

        elif tlv_type == CDP_TLV_PORT_ID:
            result["port_id"] = data.decode("utf-8", errors="replace").strip("\x00")

        elif tlv_type == CDP_TLV_CAPABILITIES and len(data) >= 4:
            caps = struct.unpack("!I", data[:4])[0]
            result["capabilities"] = {
                "router": bool(caps & 0x01),
                "bridge": bool(caps & 0x02),
                "switch": bool(caps & 0x08),
                "host": bool(caps & 0x10),
                "raw": caps,
            }

        elif tlv_type == CDP_TLV_SOFTWARE_VERSION:
            result["software_version"] = data.decode("utf-8", errors="replace").strip("\x00")

        elif tlv_type == CDP_TLV_PLATFORM:
            result["platform"] = data.decode("utf-8", errors="replace").strip("\x00")

        elif tlv_type == CDP_TLV_NATIVE_VLAN and len(data) >= 2:
            result["native_vlan"] = struct.unpack("!H", data[:2])[0]

        elif tlv_type == CDP_TLV_DUPLEX and len(data) >= 1:
            result["duplex"] = "full" if data[0] else "half"

    return result


class CDPListener(BaseListener):
    """Passive CDP frame listener using scapy raw sockets."""

    LISTENER_NAME = "CDP"
    REQUIRES_ROOT = True

    async def run(self) -> None:
        """Sniff CDP frames in a background thread."""
        try:
            from scapy.all import sniff, Ether
        except ImportError:
            logger.warning("scapy not available — CDP listener disabled")
            return

        loop = asyncio.get_running_loop()

        # LLC/SNAP header: AA:AA:03:00:00:0C:20:00
        SNAP_HEADER = b'\xaa\xaa\x03\x00\x00\x0c\x20\x00'

        def _sniff_callback(pkt):
            if not self._running:
                return
            try:
                if Ether in pkt:
                    raw_payload = bytes(pkt[Ether].payload)
                    if len(raw_payload) >= 12:
                        # Robust LLC/SNAP detection
                        if raw_payload[:8] == SNAP_HEADER:
                            cdp_data = raw_payload[8:]
                        else:
                            cdp_data = raw_payload
                        iface = str(getattr(pkt, "sniffed_on", None) or "unknown")
                        neighbor = parse_cdp_tlvs(cdp_data)

                        if neighbor.get("device_id"):
                            payload = {
                                "discovered_via": "CDP",
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
                logger.debug("Error parsing CDP frame", exc_info=True)

        def _blocking_sniff():
            try:
                while self._running:
                    sniff(
                        filter="ether dst 01:00:0c:cc:cc:cc",
                        prn=_sniff_callback,
                        store=0,
                        timeout=5,
                        stop_filter=lambda _: not self._running,
                    )
            except PermissionError:
                raise
            except Exception:
                if self._running:
                    logger.warning("CDP sniff error", exc_info=True)
                    raise

        logger.info("CDP listener active — sniffing for Cisco Discovery Protocol frames")
        await loop.run_in_executor(None, _blocking_sniff)
