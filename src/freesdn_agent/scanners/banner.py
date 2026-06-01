"""
SSH/Telnet Banner Scanner Module.

Connects to SSH and Telnet services to grab identification banners.
"""

import logging
import socket
import re
from typing import Optional, Generator, Callable, List, Dict
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from freesdn_agent.scanners.base import BaseScanner, ScanResult, ScanProgress, DeviceType

logger = logging.getLogger(__name__)


# SSH version patterns for device identification
SSH_SIGNATURES = [
    # Network devices
    {"pattern": r"cisco", "vendor": "Cisco", "type": DeviceType.SWITCH},
    {"pattern": r"mikrotik|routeros", "vendor": "MikroTik", "type": DeviceType.ROUTER},
    {"pattern": r"ubnt|ubiquiti", "vendor": "Ubiquiti", "type": DeviceType.ACCESS_POINT},
    {"pattern": r"juniper|junos", "vendor": "Juniper", "type": DeviceType.ROUTER},
    {"pattern": r"fortigate|fortios", "vendor": "Fortinet", "type": DeviceType.FIREWALL},
    {"pattern": r"pfsense", "vendor": "pfSense", "type": DeviceType.FIREWALL},
    {"pattern": r"opnsense", "vendor": "OPNsense", "type": DeviceType.FIREWALL},
    {"pattern": r"aruba", "vendor": "Aruba", "type": DeviceType.SWITCH},
    {"pattern": r"hp.*procurve|procurve", "vendor": "HP", "type": DeviceType.SWITCH},
    {"pattern": r"dell.*emc|powerswitch", "vendor": "Dell", "type": DeviceType.SWITCH},
    {"pattern": r"edgeos|vyatta|vyos", "vendor": "Ubiquiti/VyOS", "type": DeviceType.ROUTER},
    {"pattern": r"brocade", "vendor": "Brocade", "type": DeviceType.SWITCH},
    {"pattern": r"extreme", "vendor": "Extreme", "type": DeviceType.SWITCH},
    
    # NAS devices
    {"pattern": r"synology", "vendor": "Synology", "type": DeviceType.SERVER},
    {"pattern": r"qnap", "vendor": "QNAP", "type": DeviceType.SERVER},
    {"pattern": r"freenas|truenas", "vendor": "TrueNAS", "type": DeviceType.SERVER},
    
    # Linux distributions (servers)
    {"pattern": r"ubuntu", "vendor": "Ubuntu", "type": DeviceType.SERVER},
    {"pattern": r"debian", "vendor": "Debian", "type": DeviceType.SERVER},
    {"pattern": r"centos|rhel|red\s*hat", "vendor": "RedHat", "type": DeviceType.SERVER},
    {"pattern": r"openssh", "vendor": None, "type": DeviceType.SERVER},
    
    # Cameras
    {"pattern": r"hikvision", "vendor": "Hikvision", "type": DeviceType.CAMERA},
    {"pattern": r"dahua", "vendor": "Dahua", "type": DeviceType.CAMERA},
    {"pattern": r"axis", "vendor": "Axis", "type": DeviceType.CAMERA},
    
    # IoT
    {"pattern": r"dropbear", "vendor": None, "type": DeviceType.IOT_DEVICE},
    
    # VoIP
    {"pattern": r"sangoma|digium", "vendor": "Sangoma", "type": DeviceType.VOIP_PHONE},
    {"pattern": r"polycom", "vendor": "Polycom", "type": DeviceType.VOIP_PHONE},
    {"pattern": r"yealink", "vendor": "Yealink", "type": DeviceType.VOIP_PHONE},
]

# Telnet banner patterns
TELNET_SIGNATURES = [
    {"pattern": r"cisco", "vendor": "Cisco", "type": DeviceType.SWITCH},
    {"pattern": r"mikrotik|routeros", "vendor": "MikroTik", "type": DeviceType.ROUTER},
    {"pattern": r"hp.*procurve|procurve", "vendor": "HP", "type": DeviceType.SWITCH},
    {"pattern": r"juniper", "vendor": "Juniper", "type": DeviceType.ROUTER},
    {"pattern": r"zyxel", "vendor": "ZyXEL", "type": DeviceType.SWITCH},
    {"pattern": r"dlink|d-link", "vendor": "D-Link", "type": DeviceType.SWITCH},
    {"pattern": r"netgear", "vendor": "Netgear", "type": DeviceType.ROUTER},
    {"pattern": r"tp-link|tplink", "vendor": "TP-Link", "type": DeviceType.ROUTER},
    {"pattern": r"busybox", "vendor": None, "type": DeviceType.IOT_DEVICE},
    {"pattern": r"linux", "vendor": None, "type": DeviceType.SERVER},
]


@dataclass
class BannerResult:
    """Result of a banner grab."""
    ip_address: str
    port: int
    service: str  # "ssh" or "telnet"
    banner: Optional[str] = None
    version: Optional[str] = None
    os_info: Optional[str] = None
    response_time_ms: Optional[float] = None


class BannerScanner(BaseScanner):
    """
    SSH/Telnet Banner Scanner.
    
    Connects to SSH (22) and Telnet (23) services to grab
    identification banners for device classification.
    """
    
    SCANNER_NAME = "banner"
    DISPLAY_NAME = "SSH/Telnet Banner Scanner"
    REQUIRES_ROOT = False
    
    def __init__(
        self,
        timeout: float = 5.0,
        concurrency: int = 50,
        scan_ssh: bool = True,
        scan_telnet: bool = True,
        ssh_port: int = 22,
        telnet_port: int = 23,
    ):
        """
        Initialize banner scanner.
        
        Args:
            timeout: Connection timeout
            concurrency: Max concurrent connections
            scan_ssh: Whether to scan SSH
            scan_telnet: Whether to scan Telnet
            ssh_port: SSH port number
            telnet_port: Telnet port number
        """
        super().__init__(timeout=timeout, concurrency=concurrency)
        self.scan_ssh = scan_ssh
        self.scan_telnet = scan_telnet
        self.ssh_port = ssh_port
        self.telnet_port = telnet_port
    
    def scan(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
    ) -> Generator[ScanResult, None, None]:
        """
        Scan targets for SSH/Telnet banners.
        
        Args:
            targets: IP addresses to scan
            interface: Not used
            progress_callback: Progress callback
            
        Yields:
            ScanResult for each host with banners
        """
        self.reset()
        
        # Build endpoint list
        endpoints = []
        for ip in targets:
            if self.scan_ssh:
                endpoints.append((ip, self.ssh_port, "ssh"))
            if self.scan_telnet:
                endpoints.append((ip, self.telnet_port, "telnet"))
        
        total = len(endpoints)
        completed = 0
        devices_found = 0
        
        # Group results by IP
        results_by_ip: Dict[str, List[BannerResult]] = {}
        
        logger.info(f"Starting banner scan of {len(targets)} hosts")
        
        start_time = datetime.now()
        
        if progress_callback:
            progress_callback(ScanProgress(
                scanner_name=self.SCANNER_NAME,
                status="starting",
                progress=0,
            ))
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {
                executor.submit(self._grab_banner, ip, port, service): (ip, port, service)
                for ip, port, service in endpoints
            }
            
            for future in as_completed(futures):
                if self._cancelled:
                    break
                
                completed += 1
                ip, port, service = futures[future]
                
                try:
                    result = future.result()
                    if result and result.banner:
                        if ip not in results_by_ip:
                            results_by_ip[ip] = []
                        results_by_ip[ip].append(result)
                except Exception as e:
                    logger.debug(f"Error grabbing banner from {ip}:{port}: {e}")
                
                if progress_callback and completed % 20 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    progress_callback(ScanProgress(
                        scanner_name=self.SCANNER_NAME,
                        status="running",
                        progress=(completed / total) * 100,
                        current_target=ip,
                        devices_found=len(results_by_ip),
                        elapsed_seconds=elapsed,
                    ))
        
        # Convert to ScanResults
        for ip, banner_results in results_by_ip.items():
            if self._cancelled:
                break
            
            device_info = self._analyze_banners(banner_results)
            devices_found += 1
            
            yield ScanResult(
                ip_address=ip,
                device_type=device_info.get("type", DeviceType.UNKNOWN),
                vendor=device_info.get("vendor"),
                discovered_by=self.SCANNER_NAME,
                discovered_at=datetime.utcnow(),
                extra={
                    "banners": [
                        {
                            "service": r.service,
                            "port": r.port,
                            "banner": r.banner,
                            "version": r.version,
                        }
                        for r in banner_results
                    ],
                    "ssh_available": any(r.service == "ssh" for r in banner_results),
                    "telnet_available": any(r.service == "telnet" for r in banner_results),
                },
            )
        
        if progress_callback:
            elapsed = (datetime.now() - start_time).total_seconds()
            progress_callback(ScanProgress(
                scanner_name=self.SCANNER_NAME,
                status="completed" if not self._cancelled else "cancelled",
                progress=100,
                devices_found=devices_found,
                elapsed_seconds=elapsed,
            ))
        
        logger.info(f"Banner scan completed: {devices_found} hosts with banners")
    
    def _grab_banner(self, ip: str, port: int, service: str) -> Optional[BannerResult]:
        """
        Grab banner from a single service.
        
        Args:
            ip: Target IP
            port: Target port
            service: "ssh" or "telnet"
            
        Returns:
            BannerResult or None
        """
        start_time = datetime.now()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            if service == "ssh":
                banner = self._grab_ssh_banner(sock)
            else:
                banner = self._grab_telnet_banner(sock)
            
            sock.close()
            
            if banner:
                result = BannerResult(
                    ip_address=ip,
                    port=port,
                    service=service,
                    banner=banner,
                    response_time_ms=response_time,
                )
                
                # Extract version info
                if service == "ssh":
                    result.version = self._extract_ssh_version(banner)
                
                return result
            
            return None
            
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception as e:
            logger.debug(f"Banner grab error for {ip}:{port}: {e}")
            return None
    
    def _grab_ssh_banner(self, sock: socket.socket) -> Optional[str]:
        """Grab SSH identification banner."""
        try:
            # SSH sends banner immediately on connect
            banner = sock.recv(256)
            if banner:
                banner_str = banner.decode('utf-8', errors='ignore').strip()
                # SSH banners start with "SSH-"
                if banner_str.startswith('SSH-'):
                    return banner_str
            return None
        except Exception as e:
            logger.debug(f"SSH banner error: {e}")
            return None
    
    def _grab_telnet_banner(self, sock: socket.socket) -> Optional[str]:
        """Grab Telnet login banner."""
        try:
            # Telnet may send negotiation bytes first
            # Try to read until we get something text-like
            
            all_data = b""
            for _ in range(5):  # Multiple reads for negotiation
                try:
                    data = sock.recv(512)
                    if not data:
                        break
                    all_data += data
                except socket.timeout:
                    break
            
            if all_data:
                # Strip telnet negotiation bytes (IAC = 0xFF)
                text = b""
                i = 0
                while i < len(all_data):
                    if all_data[i] == 0xFF:
                        # Skip IAC command (3 bytes usually)
                        i += 3
                    else:
                        text += bytes([all_data[i]])
                        i += 1
                
                banner_str = text.decode('utf-8', errors='ignore').strip()
                
                # Clean up and limit length
                banner_str = re.sub(r'\s+', ' ', banner_str)[:500]
                
                if len(banner_str) > 5:  # Must have some content
                    return banner_str
            
            return None
            
        except Exception as e:
            logger.debug(f"Telnet banner error: {e}")
            return None
    
    def _extract_ssh_version(self, banner: str) -> Optional[str]:
        """Extract SSH version from banner."""
        # Format: SSH-2.0-OpenSSH_8.4
        match = re.match(r'SSH-(\d\.\d)-(.+)', banner)
        if match:
            return match.group(2)
        return None
    
    def _analyze_banners(self, results: List[BannerResult]) -> Dict:
        """
        Analyze banners to identify device.
        
        Args:
            results: Banner results for one host
            
        Returns:
            Dict with device info
        """
        info = {
            "type": DeviceType.UNKNOWN,
            "vendor": None,
        }
        
        for result in results:
            if not result.banner:
                continue
            
            banner_lower = result.banner.lower()
            signatures = SSH_SIGNATURES if result.service == "ssh" else TELNET_SIGNATURES
            
            for sig in signatures:
                if re.search(sig["pattern"], banner_lower, re.I):
                    info["type"] = sig["type"]
                    if sig["vendor"]:
                        info["vendor"] = sig["vendor"]
                    return info  # First match wins
        
        return info
