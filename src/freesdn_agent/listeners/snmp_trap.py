"""
SNMP Trap receiver for FreeSDN Agent.

Listens on a configurable UDP port (default 162) for SNMPv1/v2c trap PDUs.
Parses trap metadata and variable bindings, then reports to the control plane
as device_event reports.

Requires root on Linux (port < 1024).
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from freesdn_agent.listeners.base import BaseListener

logger = logging.getLogger(__name__)

# Maximum datagram size and backlog
MAX_DATAGRAM = 65535
MAX_BACKLOG = 1000


def _try_parse_snmp_trap(data: bytes, source_ip: str) -> dict[str, Any] | None:
    """
    Attempt to parse an SNMP trap PDU.

    Uses pysnmp's BER decoder if available, falls back to basic extraction.
    """
    try:
        from pysnmp.proto import api as snmp_api
        from pyasn1.codec.ber import decoder as ber_decoder

        # Decode with the proper SNMP Message schema for this version. A
        # generic pyasn1 decode cannot read the context-tagged trap PDU
        # (pyasn1 >= 0.6 rejects it), so sniff the version and use the
        # matching protocol module's ASN.1 spec.
        version = snmp_api.decodeMessageVersion(data)
        p_mod = snmp_api.PROTOCOL_MODULES[version]
        msg, _ = ber_decoder.decode(data, asn1Spec=p_mod.Message())

        # Community is sensitive — record only its length, never the value.
        community_len = len(bytes(p_mod.apiMessage.get_community(msg)))
        pdu = p_mod.apiMessage.get_pdu(msg)

        result: dict[str, Any] = {
            "event_type": "snmp_trap",
            "source_ip": source_ip,
            "snmp_version": "v1" if version == snmp_api.SNMP_VERSION_1 else "v2",
            "community_length": community_len,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if version == snmp_api.SNMP_VERSION_1:  # SNMPv1 trap PDU
            trap = p_mod.apiTrapPDU
            result["enterprise"] = str(trap.get_enterprise(pdu))
            agent_bytes = bytes(trap.get_agent_address(pdu))
            if len(agent_bytes) >= 4:
                result["agent_address"] = ".".join(str(b) for b in agent_bytes[:4])
            result["generic_trap"] = int(trap.get_generic_trap(pdu))
            result["specific_trap"] = int(trap.get_specific_trap(pdu))
            result["uptime"] = int(trap.get_timestamp(pdu))
            varbinds = {str(oid): str(val) for oid, val in trap.get_varbinds(pdu)}
            result["variables"] = varbinds
        else:  # SNMPv2c trap PDU
            varbinds = {str(oid): str(val) for oid, val in p_mod.apiPDU.get_varbinds(pdu)}
            result["variables"] = varbinds
            # The trap OID rides in the snmpTrapOID.0 varbind.
            result["trap_oid"] = varbinds.get("1.3.6.1.6.3.1.1.4.1.0", "")

        return result

    except ImportError:
        logger.debug("pysnmp/pyasn1 not available — basic SNMP trap parsing")
        return {
            "event_type": "snmp_trap",
            "source_ip": source_ip,
            "raw_length": len(data),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except (RecursionError, MemoryError):
        logger.warning("SNMP trap from %s: resource limit during BER decoding", source_ip)
        return None
    except Exception:
        logger.debug("Failed to parse SNMP trap from %s", source_ip, exc_info=True)
        return None


class _TrapProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol for receiving SNMP traps."""

    def __init__(self, listener: "SNMPTrapListener"):
        self._listener = listener
        self.queue: asyncio.Queue[tuple[bytes, str]] = asyncio.Queue(maxsize=MAX_BACKLOG)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        source_ip = addr[0]
        try:
            self.queue.put_nowait((data, source_ip))
        except asyncio.QueueFull:
            self._listener._stats["dropped"] += 1

    def error_received(self, exc: Exception) -> None:
        logger.debug("SNMP trap socket error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.warning("SNMP trap socket lost: %s", exc)


class SNMPTrapListener(BaseListener):
    """SNMP trap receiver using asyncio DatagramProtocol."""

    LISTENER_NAME = "SNMP-Trap"
    REQUIRES_ROOT = True  # Port 162

    async def run(self) -> None:
        port = self._config.snmp_trap_port
        loop = asyncio.get_running_loop()

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _TrapProtocol(self),
            local_addr=("0.0.0.0", port),
        )

        logger.info("SNMP trap receiver listening on UDP :%d", port)

        try:
            while self._running:
                try:
                    data, source_ip = await asyncio.wait_for(
                        protocol.queue.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue

                parsed = _try_parse_snmp_trap(data, source_ip)
                if parsed:
                    await self._report("device_event", parsed)
        finally:
            transport.close()
