"""
FreeSDN Agent passive listeners.

Manages LLDP, CDP, SNMP trap, syslog, and DHCP listeners.
Each listener runs as a concurrent asyncio task and reports
discoveries to the control plane via WebSocket.
"""

import asyncio
import logging
from typing import Any

from freesdn_agent.listeners.base import BaseListener

logger = logging.getLogger(__name__)

# Lazy registry — imports deferred to avoid pulling scapy/pysnmp at module load
LISTENER_REGISTRY: dict[str, tuple[str, str]] = {
    "lldp": ("freesdn_agent.listeners.lldp", "LLDPListener"),
    "cdp": ("freesdn_agent.listeners.cdp", "CDPListener"),
    "snmp_trap": ("freesdn_agent.listeners.snmp_trap", "SNMPTrapListener"),
    "syslog": ("freesdn_agent.listeners.syslog", "SyslogListener"),
    "dhcp": ("freesdn_agent.listeners.dhcp_watcher", "DHCPWatcher"),
}

# Config flag names corresponding to each listener key
_ENABLE_FLAGS: dict[str, str] = {
    "lldp": "enable_lldp",
    "cdp": "enable_cdp",
    "snmp_trap": "enable_snmp_traps",
    "syslog": "enable_syslog",
    "dhcp": "enable_dhcp_watcher",
}


def _load_listener_class(key: str) -> type[BaseListener] | None:
    """Dynamically import a listener class by registry key."""
    module_path, class_name = LISTENER_REGISTRY[key]
    try:
        import importlib
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)
    except Exception:
        logger.warning("Failed to load %s listener", key, exc_info=True)
        return None


class ListenerManager:
    """
    Manages lifecycle of all passive network listeners.

    Reads PassiveConfig to decide which listeners to start,
    launches each as a concurrent asyncio task via safe_run(),
    and provides a unified stop/stats interface.
    """

    def __init__(self, ws_client, config):
        """
        Args:
            ws_client: AgentWSClient for forwarding reports.
            config: PassiveConfig instance.
        """
        self._ws_client = ws_client
        self._config = config
        self._listeners: list[BaseListener] = []
        self._tasks: list[asyncio.Task] = []
        self._running = False

    def _build_listeners(self) -> list[BaseListener]:
        """Instantiate only the listeners enabled in config."""
        listeners: list[BaseListener] = []

        for key, flag_name in _ENABLE_FLAGS.items():
            if not getattr(self._config, flag_name, False):
                logger.debug("Listener %s disabled in config", key)
                continue

            cls = _load_listener_class(key)
            if cls is None:
                continue

            try:
                listener = cls(self._ws_client, self._config)
                listeners.append(listener)
                logger.info("Registered %s listener", listener.LISTENER_NAME)
            except Exception:
                logger.warning("Failed to instantiate %s listener", key, exc_info=True)

        return listeners

    async def run(self) -> None:
        """Start all enabled listeners as concurrent tasks."""
        self._running = True
        self._listeners = self._build_listeners()

        if not self._listeners:
            logger.info("No passive listeners enabled")
            return

        logger.info(
            "Starting %d passive listener(s): %s",
            len(self._listeners),
            ", ".join(l.LISTENER_NAME for l in self._listeners),
        )

        self._tasks = [
            asyncio.create_task(
                listener.safe_run(),
                name=f"listener-{listener.LISTENER_NAME}",
            )
            for listener in self._listeners
        ]

        # Wait for all to complete (they run until stopped or error)
        try:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        except asyncio.CancelledError:
            pass

    def stop(self) -> None:
        """Signal all listeners to stop."""
        self._running = False
        for listener in self._listeners:
            listener.stop()
        for task in self._tasks:
            if not task.done():
                task.cancel()

    def get_stats(self) -> dict[str, dict[str, int]]:
        """Return per-listener stats."""
        return {
            listener.LISTENER_NAME: listener.stats
            for listener in self._listeners
        }
