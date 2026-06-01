"""
DHCP watcher for FreeSDN Agent.

Passively monitors DHCP traffic (UDP 67/68) via scapy to detect
new devices joining the network. Reports device discoveries to the
control plane as device_event reports.

Requires root/admin for raw socket access.
"""

import asyncio
import logging
import threading
import time
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

# DHCP message types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5

DHCP_MSG_NAMES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}

# Dedup window: ignore same MAC within this many seconds
DEDUP_WINDOW = 300  # 5 minutes


def _parse_dhcp_packet(pkt) -> dict[str, Any] | None:
    """Extract DHCP fields from a scapy packet."""
    try:
        from scapy.layers.dhcp import DHCP, BOOTP
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, UDP

        if BOOTP not in pkt:
            return None

        bootp = pkt[BOOTP]
        chaddr = bootp.chaddr if bootp.chaddr else b""
        result: dict[str, Any] = {
            "mac_address": chaddr[:6].hex(":") if len(chaddr) >= 6 else None,
            "client_ip": bootp.ciaddr if bootp.ciaddr != "0.0.0.0" else None,
            "your_ip": bootp.yiaddr if bootp.yiaddr != "0.0.0.0" else None,
            "server_ip": bootp.siaddr if bootp.siaddr != "0.0.0.0" else None,
        }

        # Parse DHCP options
        if DHCP in pkt:
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple):
                    name, value = opt[0], opt[1] if len(opt) > 1 else None
                    if name == "message-type":
                        result["message_type"] = int(value)
                        result["message_type_name"] = DHCP_MSG_NAMES.get(int(value), str(value))
                    elif name == "requested_addr":
                        result["requested_ip"] = str(value)
                    elif name == "hostname":
                        result["hostname"] = (
                            value.decode("utf-8", errors="replace")
                            if isinstance(value, bytes) else str(value)
                        )
                    elif name == "vendor_class_id":
                        result["vendor_class"] = (
                            value.decode("utf-8", errors="replace")
                            if isinstance(value, bytes) else str(value)
                        )
                    elif name == "param_req_list":
                        result["param_request_list"] = (
                            list(value) if isinstance(value, (bytes, list)) else str(value)
                        )

        # Get source MAC from Ethernet header if available
        if Ether in pkt and not result.get("mac_address"):
            result["mac_address"] = pkt[Ether].src

        return result if result.get("mac_address") else None

    except Exception:
        logger.debug("Error parsing DHCP packet", exc_info=True)
        return None


class DHCPWatcher(BaseListener):
    """Passive DHCP traffic monitor using scapy raw sockets."""

    LISTENER_NAME = "DHCP"
    REQUIRES_ROOT = True

    def __init__(self, ws_client, config):
        super().__init__(ws_client, config)
        self._seen_macs: dict[str, float] = {}  # mac -> last_seen timestamp
        self._dedup_lock = threading.Lock()

    def _is_new_device(self, mac: str) -> bool:
        """Check if this MAC was seen recently (dedup window). Thread-safe."""
        now = time.monotonic()
        with self._dedup_lock:
            last_seen = self._seen_macs.get(mac)
            if last_seen and (now - last_seen) < DEDUP_WINDOW:
                return False
            self._seen_macs[mac] = now

            # Prune old entries to prevent memory growth
            if len(self._seen_macs) > 5000:
                cutoff = now - DEDUP_WINDOW
                self._seen_macs = {
                    m: t for m, t in self._seen_macs.items() if t > cutoff
                }

        return True

    async def run(self) -> None:
        """Sniff DHCP traffic in a background thread."""
        try:
            from scapy.all import sniff
        except ImportError:
            logger.warning("scapy not available — DHCP watcher disabled")
            return

        loop = asyncio.get_running_loop()

        def _sniff_callback(pkt):
            if not self._running:
                return

            parsed = _parse_dhcp_packet(pkt)
            if not parsed:
                self._stats["errors"] += 1
                return

            mac = parsed.get("mac_address", "")
            msg_type = parsed.get("message_type", 0)

            # Only report DISCOVER, REQUEST, and ACK — these indicate new/renewing clients
            if msg_type not in (DHCP_DISCOVER, DHCP_REQUEST, DHCP_ACK):
                return

            if not self._is_new_device(mac):
                return

            payload = {
                "event_type": "dhcp_discovery",
                "mac_address": mac,
                "requested_ip": parsed.get("requested_ip") or parsed.get("your_ip", ""),
                "hostname": parsed.get("hostname", ""),
                "vendor_class": parsed.get("vendor_class", ""),
                "dhcp_message": parsed.get("message_type_name", ""),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            fut = asyncio.run_coroutine_threadsafe(
                self._report("device_event", payload),
                loop,
            )
            fut.add_done_callback(_log_future_error)

        def _blocking_sniff():
            try:
                while self._running:
                    sniff(
                        filter="udp and (port 67 or port 68)",
                        prn=_sniff_callback,
                        store=0,
                        timeout=5,
                        stop_filter=lambda _: not self._running,
                    )
            except PermissionError:
                raise
            except Exception:
                if self._running:
                    logger.warning("DHCP sniff error", exc_info=True)
                    raise

        logger.info("DHCP watcher active — monitoring BOOTP/DHCP traffic")
        await loop.run_in_executor(None, _blocking_sniff)
