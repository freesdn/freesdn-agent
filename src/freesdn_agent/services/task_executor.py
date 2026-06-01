"""
Task executor for FreeSDN Agent Daemon.

Dispatches incoming commands from the control plane to the
appropriate local handler (scanner engine, device actions, etc.).
"""

import asyncio
import logging
from typing import Any

import aiohttp

from freesdn_agent.services.async_scan_manager import AsyncScanManager, ScanJob, ScanType

logger = logging.getLogger(__name__)


class TaskExecutor:
    """
    Receives AgentCommandType messages from the WebSocket client
    and executes them locally, reporting results back.
    """

    def __init__(self, ws_client, scan_manager: AsyncScanManager, daemon=None):
        self._ws = ws_client  # AgentWSClient
        self._scan_manager = scan_manager
        self._daemon = daemon  # AgentDaemon (for restart / scheduler access)
        self._active_tasks: int = 0

    @property
    def active_tasks(self) -> int:
        return self._active_tasks

    async def handle_command(self, message: dict[str, Any]) -> None:
        """
        Dispatch a server command.

        message format (from remote_agent.py AgentCommand):
            {
                "id": "...",
                "type": "scan_network | fingerprint_device | ...",
                "payload": { ... },
                "priority": 5,
                "timeout_seconds": 30
            }
        """
        cmd_id = message.get("id", "")
        cmd_type = message.get("type", "")
        payload = message.get("payload", {})
        timeout = message.get("timeout_seconds", 60)

        handler = self._HANDLERS.get(cmd_type)
        if not handler:
            logger.warning("Unknown command type: %s", cmd_type)
            await self._ws.send_report(
                "error",
                {"message": f"Unknown command type: {cmd_type}"},
                command_id=cmd_id,
            )
            return

        self._active_tasks += 1
        try:
            result = await asyncio.wait_for(
                handler(self, payload, cmd_id),
                timeout=timeout,
            )
            await self._ws.send_report(
                "action_result",
                {"status": "completed", "result": result},
                command_id=cmd_id,
            )
        except asyncio.TimeoutError:
            logger.error("Command %s timed out after %ds", cmd_type, timeout)
            await self._ws.send_report(
                "error",
                {"message": f"Command timed out after {timeout}s"},
                command_id=cmd_id,
            )
        except Exception as e:
            logger.exception("Command %s failed", cmd_type)
            await self._ws.send_report(
                "error",
                {"message": str(e)},
                command_id=cmd_id,
            )
        finally:
            self._active_tasks -= 1

    # -----------------------------------------------------------------
    # Command handlers
    # -----------------------------------------------------------------

    async def _handle_scan_network(
        self, payload: dict, cmd_id: str
    ) -> dict:
        """Execute a network scan."""
        scan_type_str = payload.get("scan_type", "quick")
        try:
            scan_type = ScanType(scan_type_str)
        except ValueError:
            scan_type = ScanType.QUICK

        targets = payload.get("targets", [])
        interfaces = payload.get("interfaces", [])

        if not interfaces:
            # Auto-detect
            try:
                import netifaces
                interfaces = [
                    iface for iface in netifaces.interfaces()
                    if any(
                        not addr.get("addr", "").startswith("127.")
                        for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                    )
                ]
            except ImportError:
                interfaces = ["eth0"]

        job = ScanJob(
            scan_type=scan_type,
            interfaces=interfaces,
            targets=targets or None,
        )

        # Progress callback runs in ThreadPoolExecutor (sync context),
        # so we use a sync callback that schedules the async send.
        loop = asyncio.get_running_loop()

        def on_progress(progress):
            asyncio.run_coroutine_threadsafe(
                self._ws.send_report(
                    "scan_progress",
                    {
                        "scanner": progress.scanner_name,
                        "status": progress.status,
                        "progress": progress.progress,
                        "devices_found": progress.devices_found,
                    },
                    command_id=cmd_id,
                ),
                loop,
            )

        results = await self._scan_manager.run_scan(
            job,
            on_progress=on_progress,
        )

        # Send scan_result report with all devices
        devices = [r.to_dict() for r in results]
        await self._ws.send_report(
            "scan_result",
            {"devices": devices, "total": len(devices)},
            command_id=cmd_id,
        )

        return {"total_devices": len(devices)}

    async def _handle_fingerprint_device(
        self, payload: dict, cmd_id: str
    ) -> dict:
        """Deep-probe a single device with all scanners."""
        ip = payload.get("ip_address", "")
        if not ip:
            return {"error": "No ip_address in payload"}

        job = ScanJob(
            scan_type=ScanType.FULL,
            interfaces=[""],
            targets=[ip],
        )
        results = await self._scan_manager.run_scan(job)
        return {
            "devices": [r.to_dict() for r in results],
            "total": len(results),
        }

    async def _handle_report_status(
        self, payload: dict, cmd_id: str
    ) -> dict:
        """Return current agent status."""
        import platform as plat
        import socket

        return {
            "status": "online",
            "platform": plat.system().lower(),
            "hostname": socket.gethostname(),
            "active_tasks": self._active_tasks,
            "scanning": self._scan_manager.is_scanning,
        }

    async def _handle_get_health(
        self, payload: dict, cmd_id: str
    ) -> dict:
        """Return health metrics."""
        try:
            import psutil
            import sys as _sys
            disk_path = "C:\\" if _sys.platform == "win32" else "/"
            return {
                "cpu_percent": psutil.cpu_percent(interval=0),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage(disk_path).percent,
            }
        except ImportError:
            return {"cpu_percent": 0, "memory_percent": 0, "disk_percent": 0}

    async def _handle_get_device_status(
        self, payload: dict, cmd_id: str
    ) -> dict:
        """Check if a device is reachable."""
        ip = payload.get("ip_address", "")
        if not ip:
            return {"error": "No ip_address in payload"}

        job = ScanJob(
            scan_type=ScanType.QUICK,
            interfaces=[""],
            targets=[ip],
        )
        results = await self._scan_manager.run_scan(job)
        reachable = len(results) > 0
        return {"ip_address": ip, "reachable": reachable}

    async def _handle_collect_metrics(
        self, payload: dict, cmd_id: str
    ) -> dict:
        """SNMP polling of a device."""
        ip = payload.get("ip_address", "")
        community = payload.get("community", "public")
        if not ip:
            return {"error": "No ip_address in payload"}

        job = ScanJob(
            scan_type=ScanType.QUICK,
            interfaces=[""],
            targets=[ip],
            scanners=["snmp"],
        )
        results = await self._scan_manager.run_scan(job)
        return {
            "devices": [r.to_dict() for r in results],
            "total": len(results),
        }

    async def _handle_update_agent(
        self, payload: dict, cmd_id: str
    ) -> dict:
        """Trigger an immediate update check."""
        if not self._daemon or not hasattr(self._daemon, "_updater"):
            return {"error": "Updater service not available"}

        updater = self._daemon._updater
        if updater is None:
            return {"error": "Updater service not initialized"}

        updated = await updater.check_and_apply()
        return {"update_applied": updated}

    async def _handle_update_schedule(
        self, payload: dict, cmd_id: str
    ) -> dict:
        """Hot-reload scheduled scans from server-pushed config."""
        if not self._daemon or not hasattr(self._daemon, "_scheduler"):
            return {"error": "Scheduler service not available"}

        scheduler = self._daemon._scheduler
        if scheduler is None:
            return {"error": "Scheduler service not initialized"}

        schedules_raw = payload.get("schedules", [])

        # Parse raw dicts into ScheduleEntry objects
        from freesdn_agent.core.config import ScheduleEntry
        entries = [ScheduleEntry.model_validate(s) for s in schedules_raw]

        scheduler.update_schedules(entries)
        return {"schedules_loaded": len(entries)}

    async def _handle_restart(
        self, payload: dict, cmd_id: str
    ) -> dict:
        """Graceful restart — stop daemon, let service manager restart."""
        logger.info("Restart command received from server")

        if self._daemon:
            # Schedule stop after a short delay so the result can be sent first
            async def _delayed_stop():
                await asyncio.sleep(1.0)
                await self._daemon.stop()
            asyncio.create_task(_delayed_stop(), name="daemon-restart")

        return {"status": "restarting"}

    async def _handle_proxy_http(
        self, payload: dict, cmd_id: str
    ) -> dict:
        """Edge bridge: proxy an HTTP request to a device on the agent's LAN.

        The controller often can't reach an appliance LAN (it may run on AWS, or
        the device — a camera / PBX — can't join the overlay). The agent sits on
        that LAN, so the controller sends the request spec and the agent executes
        it and returns the response. This is the device-reach half of P4 (see
        CONNECTIVITY-FABRIC-DESIGN.md section 5).

        payload: {url, method?, headers?, body?, username?, password?, verify_ssl?,
        timeout?, max_bytes?}. Bounded (body cap + timeout). Commands arrive ONLY
        over the authenticated controller WebSocket.
        """
        url = payload.get("url")
        if not url:
            return {"error": "proxy_http requires a 'url'"}
        method = str(payload.get("method") or "GET").upper()
        headers = payload.get("headers") or {}
        body = payload.get("body")
        verify_ssl = bool(payload.get("verify_ssl", False))
        req_timeout = float(payload.get("timeout", 15))
        max_bytes = int(payload.get("max_bytes", 5_000_000))
        auth = None
        if payload.get("username") is not None:
            auth = aiohttp.BasicAuth(
                payload["username"], payload.get("password", "") or ""
            )
        try:
            connector = aiohttp.TCPConnector(ssl=None if verify_ssl else False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    data=body,
                    auth=auth,
                    timeout=aiohttp.ClientTimeout(total=req_timeout),
                    allow_redirects=True,
                ) as resp:
                    raw = await resp.content.read(max_bytes + 1)
                    return {
                        "status_code": resp.status,
                        "headers": dict(resp.headers),
                        "body": raw[:max_bytes].decode("utf-8", errors="replace"),
                        "truncated": len(raw) > max_bytes,
                    }
        except TimeoutError:
            return {"error": f"proxy_http timed out after {req_timeout}s", "target": url}
        except Exception as e:  # noqa: BLE001 - report any reach failure to the controller
            return {"error": str(e), "target": url}

    # Handler registry — keys match AgentCommandType values
    _HANDLERS = {
        "scan_network": _handle_scan_network,
        "fingerprint_device": _handle_fingerprint_device,
        "report_status": _handle_report_status,
        "get_health": _handle_get_health,
        "get_device_status": _handle_get_device_status,
        "collect_metrics": _handle_collect_metrics,
        "update_agent": _handle_update_agent,
        "update_schedule": _handle_update_schedule,
        "restart": _handle_restart,
        "proxy_http": _handle_proxy_http,
    }
