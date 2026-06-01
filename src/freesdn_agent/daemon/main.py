"""
FreeSDN Agent Daemon — main entry point.

Runs an asyncio event loop with:
  - WebSocket connection to the FreeSDN control plane
  - Periodic heartbeat reporting
  - Task executor for server-issued commands
  - Passive network listeners (LLDP, CDP, SNMP, syslog, DHCP)
  - Scheduled scan execution (cron-based)
  - Auto-update with rollback protection
"""

import asyncio
import logging
import signal
import sys
from datetime import datetime, timezone

from freesdn_agent import __version__
from freesdn_agent.core.config import Config, get_config

logger = logging.getLogger("freesdn_agent.daemon")


class AgentDaemon:
    """Headless FreeSDN agent that runs as a system service."""

    def __init__(self, config: Config | None = None):
        self.config = config or get_config()
        self._running = False
        self._started_at: datetime | None = None

        # Components (lazily wired in start())
        self._ws_client = None
        self._heartbeat = None
        self._task_executor = None
        self._scan_manager = None
        self._listener_manager = None
        self._updater = None
        self._scheduler = None

    async def start(self) -> None:
        """Start the daemon and all subsystems."""
        from freesdn_agent.api.ws_client import AgentWSClient
        from freesdn_agent.services.heartbeat import HeartbeatService
        from freesdn_agent.services.task_executor import TaskExecutor
        from freesdn_agent.services.async_scan_manager import AsyncScanManager
        from freesdn_agent.services.updater import UpdaterService
        from freesdn_agent.services.scheduler import SchedulerService
        from freesdn_agent.services.rollback import check_rollback_needed, clear_rollback_marker
        from freesdn_agent.listeners import ListenerManager

        daemon_cfg = self.config.daemon
        if not daemon_cfg.agent_id or not daemon_cfg.server_url:
            logger.error("Agent not registered. Run 'freesdn-agent register' first.")
            return

        # Check for rollback before starting subsystems
        if check_rollback_needed():
            logger.warning("Rollback was performed — starting with restored binary")

        self._running = True
        self._started_at = datetime.now(timezone.utc)

        logger.info(
            "FreeSDN Agent Daemon v%s starting (agent_id=%s, server=%s)",
            __version__,
            daemon_cfg.agent_id,
            daemon_cfg.server_url,
        )

        # Build components
        self._scan_manager = AsyncScanManager(config=self.config)

        self._ws_client = AgentWSClient(
            agent_id=daemon_cfg.agent_id,
            server_url=daemon_cfg.server_url,
            site_id=daemon_cfg.site_id,
            reconnect_delay=daemon_cfg.reconnect_delay,
            reconnect_max_delay=daemon_cfg.reconnect_max_delay,
        )

        self._heartbeat = HeartbeatService(
            ws_client=self._ws_client,
            interval=daemon_cfg.heartbeat_interval,
            agent_version=__version__,
            daemon=self,
        )

        self._task_executor = TaskExecutor(
            ws_client=self._ws_client,
            scan_manager=self._scan_manager,
            daemon=self,
        )

        self._updater = UpdaterService(
            ws_client=self._ws_client,
            config=daemon_cfg,
            agent_version=__version__,
        )

        self._scheduler = SchedulerService(
            ws_client=self._ws_client,
            scan_manager=self._scan_manager,
            schedules=self.config.schedules,
        )

        self._listener_manager = ListenerManager(
            ws_client=self._ws_client,
            config=self.config.passive,
        )

        # Register incoming-message handler
        self._ws_client.on_command = self._task_executor.handle_command

        # Clear rollback marker once heartbeat succeeds
        self._heartbeat.on_first_heartbeat = clear_rollback_marker

        # Run all subsystems concurrently
        try:
            await asyncio.gather(
                self._ws_client.run(),
                self._heartbeat.run(),
                self._listener_manager.run(),
                self._updater.run(),
                self._scheduler.run(),
            )
        except asyncio.CancelledError:
            logger.info("Daemon tasks cancelled — shutting down")
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Graceful shutdown."""
        if not self._running:
            return
        self._running = False
        logger.info("Shutting down daemon …")

        if self._updater:
            self._updater.stop()
        if self._scheduler:
            self._scheduler.stop()
        if self._listener_manager:
            self._listener_manager.stop()
        if self._heartbeat:
            self._heartbeat.stop()
        if self._ws_client:
            await self._ws_client.close()
        if self._scan_manager:
            self._scan_manager.shutdown()

        logger.info("Daemon stopped")

    @property
    def uptime_seconds(self) -> float:
        if self._started_at is None:
            return 0.0
        return (datetime.now(timezone.utc) - self._started_at).total_seconds()


def _setup_logging(config: Config) -> None:
    """Configure daemon logging."""
    level = getattr(logging, config.daemon.log_level.upper(), logging.INFO)

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]

    if config.daemon.log_file:
        from logging.handlers import RotatingFileHandler

        handlers.append(
            RotatingFileHandler(
                config.daemon.log_file,
                maxBytes=config.daemon.log_max_size_mb * 1024 * 1024,
                backupCount=config.daemon.log_backup_count,
            )
        )

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def run_daemon(config: Config | None = None) -> None:
    """Entry point called by the CLI."""
    config = config or get_config()
    _setup_logging(config)

    daemon = AgentDaemon(config)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Graceful shutdown on SIGINT / SIGTERM
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: loop.create_task(daemon.stop()))
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    try:
        loop.run_until_complete(daemon.start())
    except KeyboardInterrupt:
        loop.run_until_complete(daemon.stop())
    finally:
        loop.close()
