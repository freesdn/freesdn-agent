"""
Heartbeat service for FreeSDN Agent Daemon.

Periodically collects system metrics via psutil and sends
them to the control plane over the WebSocket connection.
"""

import asyncio
import logging
import platform
import socket
import sys

logger = logging.getLogger(__name__)

# psutil is not in the current dependency list but is
# widely available.  Fall back to dummy metrics if missing.
try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False


def _get_subnets() -> list[str]:
    """Return list of local subnet CIDRs from all active interfaces."""
    subnets: list[str] = []
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            ipv4 = addrs.get(netifaces.AF_INET, [])
            for addr_info in ipv4:
                ip = addr_info.get("addr", "")
                mask = addr_info.get("netmask", "")
                if ip and not ip.startswith("127."):
                    # Convert netmask to CIDR prefix length
                    try:
                        bits = sum(bin(int(x)).count("1") for x in mask.split("."))
                        subnets.append(f"{ip}/{bits}")
                    except ValueError:
                        subnets.append(ip)
    except ImportError:
        pass
    return subnets


class HeartbeatService:
    """Sends periodic heartbeat reports."""

    def __init__(
        self,
        ws_client,  # AgentWSClient
        interval: int = 30,
        agent_version: str = "0.0.0",
        daemon=None,  # AgentDaemon — provides uptime + active_tasks
    ):
        self._ws = ws_client
        self._interval = interval
        self._version = agent_version
        self._daemon = daemon
        self._running = False
        self._first_sent = False
        self.on_first_heartbeat = None  # Callable[[], None] | None

    def stop(self) -> None:
        self._running = False

    async def run(self) -> None:
        """Main loop — runs until stop() or CancelledError."""
        self._running = True
        logger.info("Heartbeat service started (every %ds)", self._interval)

        while self._running:
            try:
                if self._ws.connected:
                    payload = self._collect_metrics()
                    await self._ws.send_report("heartbeat", payload)

                    # Fire on_first_heartbeat callback once
                    if not self._first_sent and self.on_first_heartbeat:
                        self._first_sent = True
                        try:
                            self.on_first_heartbeat()
                        except Exception:
                            logger.debug("on_first_heartbeat callback failed", exc_info=True)
            except Exception:
                logger.exception("Heartbeat send failed")

            await asyncio.sleep(self._interval)

    def _collect_metrics(self) -> dict:
        """Gather system health metrics."""
        if _HAS_PSUTIL:
            cpu = psutil.cpu_percent(interval=0)
            mem = psutil.virtual_memory().percent
            disk_path = "C:\\" if sys.platform == "win32" else "/"
            disk = psutil.disk_usage(disk_path).percent
        else:
            cpu = mem = disk = 0.0

        uptime = self._daemon.uptime_seconds if self._daemon else 0.0
        active = (
            self._daemon._task_executor.active_tasks
            if self._daemon and self._daemon._task_executor
            else 0
        )

        # Compute capabilities once per heartbeat — cheap (just probes
        # imports + euid). Backend uses these to filter scan_type
        # choices in the schedule-create UI.
        try:
            from freesdn_agent.services.capabilities import compute_capabilities
            capabilities = compute_capabilities(self._version)
        except Exception:
            capabilities = {}

        return {
            "cpu_percent": cpu,
            "memory_percent": mem,
            "disk_percent": disk,
            "status": "online",
            "managed_devices": 0,
            "active_tasks": active,
            "version": self._version,
            "uptime_seconds": int(uptime),
            "platform": platform.system().lower(),
            "hostname": socket.gethostname(),
            "subnets": _get_subnets(),
            "capabilities": capabilities,
        }
