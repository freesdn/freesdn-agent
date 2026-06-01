"""
Syslog receiver for FreeSDN Agent.

Listens on a configurable UDP port (default 514) for syslog messages.
Supports RFC 5424 (structured) and RFC 3164 (BSD) formats.
Reports parsed messages to the control plane as log reports.

Requires root on Linux (port < 1024).
"""

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any

from freesdn_agent.listeners.base import BaseListener, RateLimiter

logger = logging.getLogger(__name__)

MAX_BACKLOG = 2000
MAX_MESSAGE_LENGTH = 8192  # RFC 5424 recommendation

# Control character stripping pattern (keep printable + whitespace)
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]')

# Syslog facility names
FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]

# Syslog severity names
SEVERITIES = [
    "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug",
]

# RFC 5424 pattern: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
_RFC5424_RE = re.compile(
    r"<(\d{1,3})>(\d+)\s+"
    r"(\S+)\s+"      # timestamp
    r"(\S+)\s+"      # hostname
    r"(\S+)\s+"      # app-name
    r"(\S+)\s+"      # procid
    r"(\S+)\s*"      # msgid
    r"(.*)",          # message
    re.DOTALL,
)

# RFC 3164 pattern: <PRI>TIMESTAMP HOSTNAME MSG
_RFC3164_RE = re.compile(
    r"<(\d{1,3})>"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(\S+)\s+"                                      # hostname
    r"(.*)",                                          # message
    re.DOTALL,
)


def _sanitize_message(msg: str) -> str:
    """Strip control characters and enforce max length."""
    msg = _CONTROL_CHARS_RE.sub("", msg)
    if len(msg) > MAX_MESSAGE_LENGTH:
        msg = msg[:MAX_MESSAGE_LENGTH] + "…[truncated]"
    return msg


def parse_syslog(raw: str, source_ip: str) -> dict[str, Any] | None:
    """Parse a syslog message (RFC 5424 or RFC 3164)."""
    raw = raw.strip()
    if not raw:
        return None

    result: dict[str, Any] = {
        "source": "syslog",
        "source_ip": source_ip,
    }

    # Try RFC 5424 first
    m = _RFC5424_RE.match(raw)
    if m:
        pri = int(m.group(1))
        result["facility"] = FACILITIES[pri >> 3] if (pri >> 3) < len(FACILITIES) else str(pri >> 3)
        result["severity"] = SEVERITIES[pri & 0x07]
        result["syslog_version"] = int(m.group(2))
        result["syslog_timestamp"] = m.group(3)
        result["hostname"] = m.group(4) if m.group(4) != "-" else ""
        result["app_name"] = m.group(5) if m.group(5) != "-" else ""
        result["proc_id"] = m.group(6) if m.group(6) != "-" else ""
        result["msg_id"] = m.group(7) if m.group(7) != "-" else ""
        result["message"] = _sanitize_message(m.group(8).strip())
        result["timestamp"] = datetime.now(timezone.utc).isoformat()
        return result

    # Try RFC 3164
    m = _RFC3164_RE.match(raw)
    if m:
        pri = int(m.group(1))
        result["facility"] = FACILITIES[pri >> 3] if (pri >> 3) < len(FACILITIES) else str(pri >> 3)
        result["severity"] = SEVERITIES[pri & 0x07]
        result["syslog_timestamp"] = m.group(2)
        result["hostname"] = m.group(3)
        result["message"] = _sanitize_message(m.group(4).strip())
        result["timestamp"] = datetime.now(timezone.utc).isoformat()
        return result

    # Fallback: just extract priority if present
    if raw.startswith("<"):
        try:
            end = raw.index(">", 0, 6)  # PRI is at most 3 digits + angle brackets
            pri = int(raw[1:end])
            result["facility"] = FACILITIES[pri >> 3] if (pri >> 3) < len(FACILITIES) else str(pri >> 3)
            result["severity"] = SEVERITIES[pri & 0x07]
            result["message"] = _sanitize_message(raw[end + 1:].strip())
            result["timestamp"] = datetime.now(timezone.utc).isoformat()
            return result
        except (ValueError, IndexError):
            pass

    return None


class _SyslogProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol for syslog reception."""

    def __init__(self, listener: "SyslogListener"):
        self._listener = listener
        self.queue: asyncio.Queue[tuple[str, str]] = asyncio.Queue(maxsize=MAX_BACKLOG)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        # Drop oversized messages to prevent memory abuse
        if len(data) > MAX_MESSAGE_LENGTH:
            self._listener._stats["dropped"] += 1
            return
        try:
            message = data.decode("utf-8", errors="replace")
            self.queue.put_nowait((message, addr[0]))
        except asyncio.QueueFull:
            self._listener._stats["dropped"] += 1

    def error_received(self, exc: Exception) -> None:
        logger.debug("Syslog socket error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.warning("Syslog socket lost: %s", exc)


class SyslogListener(BaseListener):
    """Syslog receiver using asyncio DatagramProtocol."""

    LISTENER_NAME = "Syslog"
    REQUIRES_ROOT = True  # Port 514

    def __init__(self, ws_client, config):
        super().__init__(ws_client, config)
        # Higher rate limit for syslog — can be very chatty
        self._rate_limiter = RateLimiter(max_per_second=100.0)

    async def run(self) -> None:
        port = self._config.syslog_port
        loop = asyncio.get_running_loop()

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _SyslogProtocol(self),
            local_addr=("0.0.0.0", port),
        )

        logger.info("Syslog receiver listening on UDP :%d", port)

        try:
            while self._running:
                try:
                    message, source_ip = await asyncio.wait_for(
                        protocol.queue.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue

                parsed = parse_syslog(message, source_ip)
                if parsed:
                    await self._report("log", parsed)
        finally:
            transport.close()
