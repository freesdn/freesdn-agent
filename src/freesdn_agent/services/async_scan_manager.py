"""
Async Scan Manager for FreeSDN Agent Daemon.

Asyncio-based scan orchestration using ThreadPoolExecutor for blocking scanners.
Mirrors ScanManager logic without any Qt dependency.
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from freesdn_agent.scanners.base import BaseScanner, ScanResult, ScanProgress
from freesdn_agent.core.config import Config, get_config

logger = logging.getLogger(__name__)


class ScanType(str, Enum):
    """Types of scans available."""
    QUICK = "quick"
    CAMERA = "camera"
    VOIP = "voip"
    IOT = "iot"
    PORT = "port"
    WINDOWS = "windows"
    FULL = "full"


@dataclass
class ScanJob:
    """Represents a scan job configuration."""
    scan_type: ScanType
    interfaces: list[str]
    targets: list[str] | None = None
    scanners: list[str] = field(default_factory=list)


class AsyncScanManager:
    """
    Asyncio-based scan manager for daemon mode.

    Runs blocking scanner.scan() calls in a ThreadPoolExecutor
    and delivers results via async callbacks.
    """

    def __init__(
        self,
        config: Config | None = None,
        max_workers: int = 4,
    ):
        self.config = config or get_config()
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._is_scanning = False
        self._cancelled = False

    @property
    def is_scanning(self) -> bool:
        return self._is_scanning

    async def run_scan(
        self,
        job: ScanJob,
        on_device: Callable[[ScanResult], None] | None = None,
        on_progress: Callable[[ScanProgress], None] | None = None,
    ) -> list[ScanResult]:
        """
        Execute a scan job asynchronously.

        Args:
            job: Scan configuration.
            on_device: Called for each discovered device.
            on_progress: Called with progress updates.

        Returns:
            List of all discovered devices.
        """
        if self._is_scanning:
            logger.warning("Scan already in progress")
            return []

        self._is_scanning = True
        self._cancelled = False
        results: list[ScanResult] = []
        seen_macs: set[str] = set()

        try:
            scanners = self._get_scanners_for_job(job)
            if not scanners:
                logger.warning("No scanners available for scan type %s", job.scan_type.value)
                return []

            logger.info("Starting %s scan with %d scanners", job.scan_type.value, len(scanners))

            for scanner in scanners:
                if self._cancelled:
                    logger.info("Scan cancelled")
                    break

                scanner_name = scanner.__class__.__name__
                scanner.timeout = self.config.scan.timeout
                scanner.concurrency = self.config.scan.concurrency

                for interface in job.interfaces:
                    if self._cancelled:
                        break

                    targets = job.targets or [interface]
                    logger.info("Running %s on %s (targets: %s)", scanner_name, interface, targets)

                    # Run the blocking generator in the executor
                    loop = asyncio.get_running_loop()
                    scan_results = await loop.run_in_executor(
                        self._executor,
                        lambda s=scanner, t=targets, i=interface: list(
                            s.scan(
                                targets=t,
                                interface=i,
                                progress_callback=on_progress,
                            )
                        ),
                    )

                    for result in scan_results:
                        if self._cancelled:
                            break

                        # Deduplicate by MAC
                        if result.mac_address and result.mac_address in seen_macs:
                            continue
                        if result.mac_address:
                            seen_macs.add(result.mac_address)

                        results.append(result)
                        if on_device:
                            on_device(result)

            logger.info("Scan completed: %d devices found", len(results))
            return results

        except Exception:
            logger.exception("Scan failed")
            return results
        finally:
            self._is_scanning = False

    def cancel(self) -> None:
        """Cancel the running scan."""
        self._cancelled = True
        logger.info("Scan cancellation requested")

    def shutdown(self) -> None:
        """Shutdown the executor."""
        self._executor.shutdown(wait=False)

    # -----------------------------------------------------------------
    # Scanner selection (mirrors ScanManager._get_scanners_for_job)
    # -----------------------------------------------------------------

    def _get_scanners_for_job(self, job: ScanJob) -> list[BaseScanner]:
        """Build scanner list from SCANNER_REGISTRY based on job config."""
        from freesdn_agent.scanners import SCANNER_REGISTRY

        if job.scanners:
            # Explicit list requested
            instances = []
            for name in job.scanners:
                cls = SCANNER_REGISTRY.get(name)
                if cls:
                    instances.append(cls())
                else:
                    logger.warning("Unknown scanner: %s", name)
            return instances

        cfg = self.config.scan
        scanners: list[BaseScanner] = []

        def add(name: str) -> None:
            cls = SCANNER_REGISTRY.get(name)
            if cls:
                scanners.append(cls())

        if job.scan_type == ScanType.QUICK:
            add("ping")

        elif job.scan_type == ScanType.CAMERA:
            add("ping")
            if cfg.enable_onvif:
                add("onvif")
            if cfg.enable_sadp:
                add("sadp")
            add("rtsp")

        elif job.scan_type == ScanType.VOIP:
            add("ping")
            add("sip")
            add("mdns")

        elif job.scan_type == ScanType.IOT:
            add("ping")
            add("mdns")
            add("ssdp")

        elif job.scan_type == ScanType.PORT:
            add("ping")
            add("tcp_port")
            add("http_service")
            add("banner")

        elif job.scan_type == ScanType.WINDOWS:
            add("ping")
            add("netbios")

        elif job.scan_type == ScanType.FULL:
            add("ping")
            if cfg.enable_onvif:
                add("onvif")
            if cfg.enable_sadp:
                add("sadp")
            add("tcp_port")
            add("http_service")
            add("banner")
            if cfg.enable_snmp:
                add("snmp")
            add("netbios")
            add("mdns")
            add("ssdp")
            add("sip")
            add("rtsp")
            add("dns")

        return scanners
