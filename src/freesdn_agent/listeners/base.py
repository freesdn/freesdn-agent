"""
Base listener for FreeSDN Agent passive discovery.

All passive listeners (LLDP, CDP, SNMP traps, syslog, DHCP)
inherit from BaseListener which provides:
  - Rate limiting (token bucket)
  - Graceful degradation (bind failures log and skip)
  - Unified stats tracking
  - Report delivery via WebSocket client
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class RateLimiter:
    """Token-bucket rate limiter for controlling report volume."""

    def __init__(self, max_per_second: float = 10.0):
        self._rate = max_per_second
        self._tokens = max_per_second
        self._max_tokens = max_per_second
        self._last_refill = time.monotonic()

    def allow(self) -> bool:
        """Return True if a token is available, consuming it."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._max_tokens, self._tokens + elapsed * self._rate)
        self._last_refill = now

        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class BaseListener(ABC):
    """Abstract base for all passive network listeners."""

    LISTENER_NAME: str = "unknown"
    REQUIRES_ROOT: bool = False

    def __init__(self, ws_client, config):
        """
        Args:
            ws_client: AgentWSClient for reporting discoveries.
            config: PassiveConfig with listener-specific settings.
        """
        self._ws = ws_client
        self._config = config
        self._running = False
        self._rate_limiter = RateLimiter(max_per_second=10.0)
        self._stats = {"received": 0, "reported": 0, "dropped": 0, "errors": 0}

    @abstractmethod
    async def run(self) -> None:
        """Main listener loop. Must respect self._running flag."""
        ...

    def stop(self) -> None:
        """Signal the listener to stop."""
        self._running = False

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    async def _report(self, report_type: str, payload: dict[str, Any]) -> None:
        """Send a rate-limited report to the control plane."""
        self._stats["received"] += 1
        if self._rate_limiter.allow():
            try:
                await self._ws.send_report(report_type, payload)
                self._stats["reported"] += 1
            except Exception:
                self._stats["errors"] += 1
                logger.debug("Failed to send %s report", report_type, exc_info=True)
        else:
            self._stats["dropped"] += 1

    def _check_privileges(self) -> bool:
        """Check if we have the required privileges to run."""
        if not self.REQUIRES_ROOT:
            return True

        import sys
        if sys.platform == "win32":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            import os
            return os.geteuid() == 0

    async def safe_run(self) -> None:
        """
        Wrapper around run() with privilege checks and error handling.

        If the listener can't start (no root, port in use), it logs
        a warning and returns instead of crashing the daemon.
        """
        if self.REQUIRES_ROOT and not self._check_privileges():
            logger.warning(
                "%s listener requires root/admin — skipping",
                self.LISTENER_NAME,
            )
            return

        self._running = True
        try:
            logger.info("%s listener starting", self.LISTENER_NAME)
            await self.run()
        except PermissionError:
            logger.warning(
                "%s listener: permission denied (need root/admin) — skipping",
                self.LISTENER_NAME,
            )
        except OSError as e:
            if e.errno in (98, 48, 10048):  # EADDRINUSE on Linux/macOS/Windows
                logger.warning(
                    "%s listener: port already in use — skipping",
                    self.LISTENER_NAME,
                )
            else:
                logger.warning(
                    "%s listener failed: %s — skipping",
                    self.LISTENER_NAME, e,
                )
        except asyncio.CancelledError:
            logger.info("%s listener cancelled", self.LISTENER_NAME)
            raise
        except Exception:
            logger.exception("%s listener crashed", self.LISTENER_NAME)
        finally:
            self._running = False
            logger.info(
                "%s listener stopped (received=%d, reported=%d, dropped=%d, errors=%d)",
                self.LISTENER_NAME,
                self._stats["received"],
                self._stats["reported"],
                self._stats["dropped"],
                self._stats["errors"],
            )
