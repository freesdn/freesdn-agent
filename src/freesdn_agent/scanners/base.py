"""
Base Scanner Interface.

Defines the common interface for all network scanners.
"""

import logging
from abc import ABC, abstractmethod
from typing import Optional, Generator, Callable, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class DeviceType(str, Enum):
    """Device type classification."""
    UNKNOWN = "unknown"
    CAMERA = "camera"
    SWITCH = "switch"
    ROUTER = "router"
    ACCESS_POINT = "access_point"
    VOIP_PHONE = "voip_phone"
    NVR = "nvr"
    DVR = "dvr"
    PRINTER = "printer"
    SERVER = "server"
    WORKSTATION = "workstation"
    IOT_DEVICE = "iot_device"
    FIREWALL = "firewall"


@dataclass
class ScanResult:
    """Result from a network scan."""
    
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: DeviceType = DeviceType.UNKNOWN
    
    # Discovery metadata
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    discovered_by: str = ""  # Scanner name
    response_time_ms: Optional[float] = None
    
    # Protocol-specific data
    onvif_url: Optional[str] = None
    http_port: Optional[int] = None
    https_port: Optional[int] = None
    serial_number: Optional[str] = None
    firmware_version: Optional[str] = None
    model: Optional[str] = None
    manufacturer: Optional[str] = None
    
    # Extra data (protocol-specific)
    extra: dict = field(default_factory=dict)
    
    # Status
    is_new: bool = True
    confidence: float = 0.0  # Classification confidence 0-1
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "device_type": self.device_type.value,
            "discovered_at": self.discovered_at.isoformat(),
            "discovered_by": self.discovered_by,
            "response_time_ms": self.response_time_ms,
            "onvif_url": self.onvif_url,
            "http_port": self.http_port,
            "https_port": self.https_port,
            "serial_number": self.serial_number,
            "firmware_version": self.firmware_version,
            "model": self.model,
            "manufacturer": self.manufacturer,
            "extra": self.extra,
            "is_new": self.is_new,
            "confidence": self.confidence,
        }


@dataclass
class ScanProgress:
    """Progress information for a scan."""
    
    scanner_name: str
    status: str  # "starting", "running", "completed", "failed", "cancelled"
    progress: float  # 0-100
    current_target: Optional[str] = None
    devices_found: int = 0
    errors: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0


class BaseScanner(ABC):
    """
    Base class for all network scanners.
    
    Subclasses must implement the scan() method.
    """
    
    SCANNER_NAME: str = "base"
    DISPLAY_NAME: str = "Base Scanner"
    REQUIRES_ROOT: bool = False
    
    def __init__(
        self,
        timeout: float = 3.0,
        concurrency: int = 50,
    ):
        """
        Initialize scanner.
        
        Args:
            timeout: Timeout for each scan operation in seconds
            concurrency: Maximum concurrent operations
        """
        self.timeout = timeout
        self.concurrency = concurrency
        self._cancelled = False
    
    @abstractmethod
    def scan(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        progress_callback: Optional[Callable[["ScanProgress"], None]] = None,
    ) -> Generator[ScanResult, None, None]:
        """
        Perform network scan.
        
        Args:
            targets: Targets to scan (IP ranges, subnets, etc.)
            interface: Network interface to use
            progress_callback: Called with progress updates
            
        Yields:
            ScanResult for each discovered device
        """
        pass
    
    def cancel(self) -> None:
        """Cancel the current scan."""
        self._cancelled = True
        logger.info(f"{self.SCANNER_NAME} scanner cancelled")
    
    def reset(self) -> None:
        """Reset scanner state."""
        self._cancelled = False
    
    @property
    def is_cancelled(self) -> bool:
        """Check if scan was cancelled."""
        return self._cancelled
