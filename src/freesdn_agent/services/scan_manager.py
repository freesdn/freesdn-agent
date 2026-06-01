"""
Scan Manager for FreeSDN Agent.

Orchestrates scan execution using QThread for background processing.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any, Type
from queue import Queue

from PySide6.QtCore import QObject, QThread, Signal, Slot, QMutex, QMutexLocker

from freesdn_agent.scanners.base import BaseScanner, ScanResult, ScanProgress, DeviceType
from freesdn_agent.core.config import Config, get_config

logger = logging.getLogger(__name__)


class ScanType(str, Enum):
    """Types of scans available."""
    QUICK = "quick"  # Ping only (fast)
    CAMERA = "camera"  # Ping + ONVIF + SADP
    VOIP = "voip"  # Ping + SIP + mDNS
    IOT = "iot"  # Ping + mDNS + SSDP (smart home, IoT)
    PORT = "port"  # Ping + TCP port scan + HTTP detection
    WINDOWS = "windows"  # Ping + NetBIOS + SMB
    FULL = "full"  # All scanners


@dataclass
class ScanJob:
    """Represents a scan job configuration."""
    scan_type: ScanType
    interfaces: List[str]
    targets: Optional[List[str]] = None  # Optional target IPs/ranges
    scanners: List[str] = field(default_factory=list)  # Scanner names to use


class ScanWorker(QObject):
    """
    Worker thread for running scans in the background.
    
    Runs in a separate QThread to avoid blocking the UI.
    """
    
    # Signals
    progress = Signal(ScanProgress)
    device_found = Signal(ScanResult)
    finished = Signal(list)  # List[ScanResult]
    error = Signal(str)
    scanner_started = Signal(str)  # Scanner name
    scanner_finished = Signal(str)  # Scanner name
    
    def __init__(self, job: ScanJob, config: Config):
        super().__init__()
        self.job = job
        self.config = config
        self._is_cancelled = False
        self._mutex = QMutex()
        self._results: List[ScanResult] = []
        self._seen_macs: set = set()
    
    @property
    def is_cancelled(self) -> bool:
        """Check if scan has been cancelled."""
        with QMutexLocker(self._mutex):
            return self._is_cancelled
    
    def cancel(self) -> None:
        """Cancel the running scan."""
        with QMutexLocker(self._mutex):
            self._is_cancelled = True
            logger.info("Scan cancellation requested")
    
    @Slot()
    def run(self) -> None:
        """Execute the scan job."""
        logger.info(f"Starting {self.job.scan_type.value} scan")
        
        try:
            # Get scanner instances based on scan type
            scanners = self._get_scanners_for_job()
            
            if not scanners:
                self.error.emit("No scanners available for this scan type")
                self.finished.emit([])
                return
            
            total_scanners = len(scanners)
            
            for idx, scanner in enumerate(scanners):
                if self.is_cancelled:
                    logger.info("Scan cancelled")
                    break
                
                scanner_name = scanner.__class__.__name__
                self.scanner_started.emit(scanner_name)
                
                try:
                    # Configure scanner
                    scanner.timeout = self.config.scan.timeout
                    scanner.concurrency = self.config.scan.concurrency
                    
                    # Run scan for each interface
                    for interface in self.job.interfaces:
                        if self.is_cancelled:
                            break
                        
                        logger.info(f"Running {scanner_name} on {interface}")
                        
                        # Get targets (use job targets or default to interface subnet)
                        targets = self.job.targets or [interface]
                        logger.info(f"Scan targets: {targets}")
                        
                        # Execute scan with progress callback
                        for result in scanner.scan(
                            targets=targets,
                            interface=interface,
                            progress_callback=self._on_progress,
                        ):
                            if self.is_cancelled:
                                break
                            
                            # Deduplicate by MAC address
                            if result.mac_address and result.mac_address in self._seen_macs:
                                continue
                            
                            if result.mac_address:
                                self._seen_macs.add(result.mac_address)
                            
                            self._results.append(result)
                            self.device_found.emit(result)
                
                except Exception as e:
                    logger.error(f"Scanner {scanner_name} failed: {e}")
                    self.error.emit(f"{scanner_name}: {str(e)}")
                
                finally:
                    self.scanner_finished.emit(scanner_name)
            
            logger.info(f"Scan completed: {len(self._results)} devices found")
            self.finished.emit(self._results)
            
        except Exception as e:
            logger.exception(f"Scan failed: {e}")
            self.error.emit(str(e))
            self.finished.emit([])
    
    def _on_progress(self, progress: ScanProgress) -> None:
        """Handle scanner progress update."""
        self.progress.emit(progress)
    
    def _get_scanners_for_job(self) -> List[BaseScanner]:
        """Get scanner instances based on job configuration."""
        from freesdn_agent.scanners.arp import ARPScanner
        from freesdn_agent.scanners.ping import PingScanner
        
        scanners: List[BaseScanner] = []
        
        # Import additional scanners as they become available
        scanner_classes: Dict[str, Type[BaseScanner]] = {
            "arp": ARPScanner,
            "ping": PingScanner,
        }
        
        # Try to import optional scanners
        try:
            from freesdn_agent.scanners.onvif import ONVIFScanner
            scanner_classes["onvif"] = ONVIFScanner
        except ImportError:
            logger.debug("ONVIF scanner not available")
        
        try:
            from freesdn_agent.scanners.sadp import SADPScanner
            scanner_classes["sadp"] = SADPScanner
        except ImportError:
            logger.debug("SADP scanner not available")
        
        try:
            from freesdn_agent.scanners.tcp_port import TCPPortScanner
            scanner_classes["tcp_port"] = TCPPortScanner
        except ImportError:
            logger.debug("TCP port scanner not available")
        
        try:
            from freesdn_agent.scanners.http_service import HTTPServiceScanner
            scanner_classes["http_service"] = HTTPServiceScanner
        except ImportError:
            logger.debug("HTTP service scanner not available")
        
        try:
            from freesdn_agent.scanners.banner import BannerScanner
            scanner_classes["banner"] = BannerScanner
        except ImportError:
            logger.debug("Banner scanner not available")
        
        try:
            from freesdn_agent.scanners.snmp import SNMPScanner
            scanner_classes["snmp"] = SNMPScanner
        except ImportError:
            logger.debug("SNMP scanner not available")
        
        try:
            from freesdn_agent.scanners.netbios import NetBIOSScanner
            scanner_classes["netbios"] = NetBIOSScanner
        except ImportError:
            logger.debug("NetBIOS scanner not available")
        
        try:
            from freesdn_agent.scanners.mdns import MDNSScanner
            scanner_classes["mdns"] = MDNSScanner
        except ImportError:
            logger.debug("mDNS scanner not available")
        
        try:
            from freesdn_agent.scanners.ssdp import SSDPScanner
            scanner_classes["ssdp"] = SSDPScanner
        except ImportError:
            logger.debug("SSDP scanner not available")
        
        try:
            from freesdn_agent.scanners.sip import SIPScanner
            scanner_classes["sip"] = SIPScanner
        except ImportError:
            logger.debug("SIP scanner not available")
        
        try:
            from freesdn_agent.scanners.dns import DNSScanner
            scanner_classes["dns"] = DNSScanner
        except ImportError:
            logger.debug("DNS scanner not available")
        
        try:
            from freesdn_agent.scanners.rtsp import RTSPScanner
            scanner_classes["rtsp"] = RTSPScanner
        except ImportError:
            logger.debug("RTSP scanner not available")
        
        # Determine which scanners to use
        if self.job.scanners:
            # Use specified scanners
            for name in self.job.scanners:
                if name in scanner_classes:
                    scanners.append(scanner_classes[name]())
        else:
            # Use defaults based on scan type
            # Ping scanner is always added as base discovery method
            if self.job.scan_type == ScanType.QUICK:
                # Quick scan: just ping
                scanners.append(scanner_classes["ping"]())
            
            elif self.job.scan_type == ScanType.CAMERA:
                # Camera scan: ping + camera protocols
                scanners.append(scanner_classes["ping"]())
                if self.config.scan.enable_onvif and "onvif" in scanner_classes:
                    scanners.append(scanner_classes["onvif"]())
                if self.config.scan.enable_sadp and "sadp" in scanner_classes:
                    scanners.append(scanner_classes["sadp"]())
                if "rtsp" in scanner_classes:
                    scanners.append(scanner_classes["rtsp"]())
            
            elif self.job.scan_type == ScanType.VOIP:
                # VoIP scan: ping + SIP + mDNS
                scanners.append(scanner_classes["ping"]())
                if "sip" in scanner_classes:
                    scanners.append(scanner_classes["sip"]())
                if "mdns" in scanner_classes:
                    scanners.append(scanner_classes["mdns"]())
            
            elif self.job.scan_type == ScanType.IOT:
                # IoT scan: ping + mDNS + SSDP (smart home devices)
                scanners.append(scanner_classes["ping"]())
                if "mdns" in scanner_classes:
                    scanners.append(scanner_classes["mdns"]())
                if "ssdp" in scanner_classes:
                    scanners.append(scanner_classes["ssdp"]())
            
            elif self.job.scan_type == ScanType.PORT:
                # Port scan: ping + TCP port scan + HTTP detection + banner
                scanners.append(scanner_classes["ping"]())
                if "tcp_port" in scanner_classes:
                    scanners.append(scanner_classes["tcp_port"]())
                if "http_service" in scanner_classes:
                    scanners.append(scanner_classes["http_service"]())
                if "banner" in scanner_classes:
                    scanners.append(scanner_classes["banner"]())
            
            elif self.job.scan_type == ScanType.WINDOWS:
                # Windows scan: ping + NetBIOS/SMB
                scanners.append(scanner_classes["ping"]())
                if "netbios" in scanner_classes:
                    scanners.append(scanner_classes["netbios"]())
            
            elif self.job.scan_type == ScanType.FULL:
                # Full scan: all available scanners
                scanners.append(scanner_classes["ping"]())
                
                # Camera protocols
                if self.config.scan.enable_onvif and "onvif" in scanner_classes:
                    scanners.append(scanner_classes["onvif"]())
                if self.config.scan.enable_sadp and "sadp" in scanner_classes:
                    scanners.append(scanner_classes["sadp"]())
                
                # Port/service detection
                if "tcp_port" in scanner_classes:
                    scanners.append(scanner_classes["tcp_port"]())
                if "http_service" in scanner_classes:
                    scanners.append(scanner_classes["http_service"]())
                if "banner" in scanner_classes:
                    scanners.append(scanner_classes["banner"]())
                
                # Network protocols
                if self.config.scan.enable_snmp and "snmp" in scanner_classes:
                    scanners.append(scanner_classes["snmp"]())
                if "netbios" in scanner_classes:
                    scanners.append(scanner_classes["netbios"]())
                
                # Discovery protocols
                if "mdns" in scanner_classes:
                    scanners.append(scanner_classes["mdns"]())
                if "ssdp" in scanner_classes:
                    scanners.append(scanner_classes["ssdp"]())
                
                # VoIP protocols
                if "sip" in scanner_classes:
                    scanners.append(scanner_classes["sip"]())
                
                # Streaming/DNS
                if "rtsp" in scanner_classes:
                    scanners.append(scanner_classes["rtsp"]())
                if "dns" in scanner_classes:
                    scanners.append(scanner_classes["dns"]())
        
        return scanners


class ScanManager(QObject):
    """
    Manages scan execution and thread lifecycle.
    
    Provides a high-level API for starting/stopping scans
    and connecting to UI components.
    """
    
    # Signals forwarded from worker
    scan_started = Signal(str)  # Scan type
    scan_finished = Signal(list)  # Results
    scan_cancelled = Signal()
    scan_error = Signal(str)
    scan_progress = Signal(ScanProgress)
    device_found = Signal(ScanResult)
    scanner_started = Signal(str)
    scanner_finished = Signal(str)
    
    def __init__(self, config: Optional[Config] = None):
        super().__init__()
        self.config = config or get_config()
        
        self._thread: Optional[QThread] = None
        self._worker: Optional[ScanWorker] = None
        self._is_scanning = False
    
    @property
    def is_scanning(self) -> bool:
        """Check if a scan is currently running."""
        return self._is_scanning
    
    def start_scan(
        self,
        scan_type: ScanType,
        interfaces: List[str],
        targets: Optional[List[str]] = None,
    ) -> bool:
        """
        Start a new scan.
        
        Args:
            scan_type: Type of scan to perform
            interfaces: Network interfaces to scan on
            targets: Optional specific targets (IPs/CIDRs)
        
        Returns:
            True if scan started successfully
        """
        if self._is_scanning:
            logger.warning("Scan already in progress")
            return False
        
        if not interfaces:
            logger.error("No interfaces specified for scan")
            return False
        
        # Create job
        job = ScanJob(
            scan_type=scan_type,
            interfaces=interfaces,
            targets=targets,
        )
        
        # Create thread and worker
        self._thread = QThread()
        self._worker = ScanWorker(job, self.config)
        self._worker.moveToThread(self._thread)
        
        # Connect signals
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_scan_finished)
        self._worker.error.connect(self._on_scan_error)
        self._worker.progress.connect(self.scan_progress.emit)
        self._worker.device_found.connect(self.device_found.emit)
        self._worker.scanner_started.connect(self.scanner_started.emit)
        self._worker.scanner_finished.connect(self.scanner_finished.emit)
        
        # Start
        self._is_scanning = True
        self._thread.start()
        self.scan_started.emit(scan_type.value)
        
        logger.info(f"Started {scan_type.value} scan on interfaces: {interfaces}")
        return True
    
    def stop_scan(self) -> None:
        """Stop the current scan."""
        if not self._is_scanning or not self._worker:
            return
        
        logger.info("Stopping scan...")
        self._worker.cancel()
    
    def _on_scan_finished(self, results: List[ScanResult]) -> None:
        """Handle scan completion."""
        self._cleanup()
        self.scan_finished.emit(results)
        logger.info(f"Scan finished: {len(results)} devices found")
    
    def _on_scan_error(self, error: str) -> None:
        """Handle scan error."""
        self.scan_error.emit(error)
        logger.error(f"Scan error: {error}")
    
    def _cleanup(self) -> None:
        """Clean up thread and worker."""
        self._is_scanning = False
        
        if self._thread:
            self._thread.quit()
            self._thread.wait()
            self._thread.deleteLater()
            self._thread = None
        
        if self._worker:
            self._worker.deleteLater()
            self._worker = None


# Global instance
_scan_manager: Optional[ScanManager] = None


def get_scan_manager() -> ScanManager:
    """Get the global scan manager instance."""
    global _scan_manager
    if _scan_manager is None:
        _scan_manager = ScanManager()
    return _scan_manager
