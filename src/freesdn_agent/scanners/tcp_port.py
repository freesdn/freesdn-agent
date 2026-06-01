"""
TCP Port Scanner Module.

Provides TCP port scanning with service detection.
"""

import logging
import socket
import asyncio
import struct
from typing import Optional, Generator, Callable, List, Dict, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from freesdn_agent.scanners.base import BaseScanner, ScanResult, ScanProgress, DeviceType

logger = logging.getLogger(__name__)


# Common ports and their typical services
COMMON_PORTS = {
    # Management
    22: ("ssh", "SSH"),
    23: ("telnet", "Telnet"),
    80: ("http", "HTTP"),
    443: ("https", "HTTPS"),
    8080: ("http-alt", "HTTP Alternate"),
    8443: ("https-alt", "HTTPS Alternate"),
    
    # Network devices
    161: ("snmp", "SNMP"),
    162: ("snmptrap", "SNMP Trap"),
    
    # Cameras/Video
    554: ("rtsp", "RTSP"),
    8000: ("hikvision", "Hikvision SDK"),
    8554: ("rtsp-alt", "RTSP Alternate"),
    37777: ("dahua", "Dahua SDK"),
    
    # VoIP
    5060: ("sip", "SIP"),
    5061: ("sips", "SIP-TLS"),
    5080: ("sip-alt", "SIP Alternate"),
    4569: ("iax2", "IAX2"),
    2000: ("skinny", "Cisco Skinny"),
    2001: ("skinny-alt", "Cisco Skinny Alt"),
    
    # Databases (for servers)
    3306: ("mysql", "MySQL"),
    5432: ("postgresql", "PostgreSQL"),
    1433: ("mssql", "MS SQL"),
    27017: ("mongodb", "MongoDB"),
    6379: ("redis", "Redis"),
    
    # Remote access
    3389: ("rdp", "RDP"),
    5900: ("vnc", "VNC"),
    
    # File sharing
    21: ("ftp", "FTP"),
    139: ("netbios", "NetBIOS"),
    445: ("smb", "SMB"),
    
    # Printers
    9100: ("jetdirect", "JetDirect"),
    631: ("ipp", "IPP"),
    
    # IoT/Industrial
    1883: ("mqtt", "MQTT"),
    8883: ("mqtt-tls", "MQTT TLS"),
    502: ("modbus", "Modbus"),
    47808: ("bacnet", "BACnet"),
    
    # Other services
    25: ("smtp", "SMTP"),
    53: ("dns", "DNS"),
    110: ("pop3", "POP3"),
    143: ("imap", "IMAP"),
    389: ("ldap", "LDAP"),
    636: ("ldaps", "LDAPS"),
}

# Preset port lists
PORT_PRESETS = {
    "quick": [22, 23, 80, 443, 161, 554, 8080],
    "common": list(COMMON_PORTS.keys()),
    "top100": [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
        139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
        554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
        1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
        4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
        6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
        49152, 49153, 49154, 49155, 49156, 49157
    ],
    "camera": [80, 443, 554, 8000, 8080, 8443, 8554, 37777, 34567],
    "network": [22, 23, 80, 161, 443, 830],
}


@dataclass
class PortScanResult:
    """Result of scanning a single port."""
    port: int
    state: str  # "open", "closed", "filtered"
    service: Optional[str] = None
    service_name: Optional[str] = None
    banner: Optional[str] = None
    response_time_ms: Optional[float] = None


@dataclass
class HostPortScanResult:
    """Complete port scan result for a host."""
    ip_address: str
    open_ports: List[PortScanResult] = field(default_factory=list)
    closed_count: int = 0
    filtered_count: int = 0
    scan_time_ms: float = 0
    
    @property
    def has_web(self) -> bool:
        """Check if host has web services."""
        web_ports = {80, 443, 8080, 8443}
        return any(p.port in web_ports for p in self.open_ports)
    
    @property
    def has_ssh(self) -> bool:
        """Check if host has SSH."""
        return any(p.port == 22 for p in self.open_ports)
    
    @property
    def has_telnet(self) -> bool:
        """Check if host has Telnet."""
        return any(p.port == 23 for p in self.open_ports)
    
    @property
    def has_snmp(self) -> bool:
        """Check if host has SNMP."""
        return any(p.port == 161 for p in self.open_ports)


class TCPPortScanner(BaseScanner):
    """
    TCP Port Scanner using socket connections.
    
    Performs TCP connect scans to detect open ports and optionally
    grabs service banners for identification.
    """
    
    SCANNER_NAME = "tcp_port"
    DISPLAY_NAME = "TCP Port Scanner"
    REQUIRES_ROOT = False
    
    def __init__(
        self,
        timeout: float = 1.0,
        concurrency: int = 100,
        ports: Optional[List[int]] = None,
        port_preset: str = "quick",
        grab_banners: bool = True,
        banner_timeout: float = 2.0,
    ):
        """
        Initialize TCP port scanner.
        
        Args:
            timeout: Connection timeout per port
            concurrency: Max concurrent port checks
            ports: Specific ports to scan (overrides preset)
            port_preset: Preset port list name
            grab_banners: Whether to grab service banners
            banner_timeout: Timeout for banner grabbing
        """
        super().__init__(timeout=timeout, concurrency=concurrency)
        self.ports = ports or PORT_PRESETS.get(port_preset, PORT_PRESETS["quick"])
        self.grab_banners = grab_banners
        self.banner_timeout = banner_timeout
    
    def scan(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
    ) -> Generator[ScanResult, None, None]:
        """
        Scan targets for open TCP ports.
        
        Args:
            targets: List of IP addresses to scan
            interface: Not used for TCP scans
            progress_callback: Progress update callback
            
        Yields:
            ScanResult for each host with open ports
        """
        self.reset()
        
        total_targets = len(targets)
        total_ports = len(self.ports)
        total_checks = total_targets * total_ports
        completed_checks = 0
        devices_found = 0
        
        logger.info(
            f"Starting TCP port scan of {total_targets} hosts, "
            f"{total_ports} ports each ({total_checks} total checks)"
        )
        
        start_time = datetime.now()
        
        if progress_callback:
            progress_callback(ScanProgress(
                scanner_name=self.SCANNER_NAME,
                status="starting",
                progress=0,
                current_target=None,
                devices_found=0,
            ))
        
        for idx, target in enumerate(targets):
            if self._cancelled:
                logger.info("Port scan cancelled")
                break
            
            # Scan all ports for this host
            host_result = self._scan_host(target)
            completed_checks += total_ports
            
            if progress_callback:
                elapsed = (datetime.now() - start_time).total_seconds()
                progress_callback(ScanProgress(
                    scanner_name=self.SCANNER_NAME,
                    status="running",
                    progress=(completed_checks / total_checks) * 100,
                    current_target=target,
                    devices_found=devices_found,
                    elapsed_seconds=elapsed,
                ))
            
            # Only yield results for hosts with open ports
            if host_result.open_ports:
                devices_found += 1
                
                # Convert to ScanResult
                device_type = self._classify_device(host_result)
                
                yield ScanResult(
                    ip_address=target,
                    device_type=device_type,
                    discovered_by=self.SCANNER_NAME,
                    discovered_at=datetime.utcnow(),
                    http_port=self._get_http_port(host_result),
                    https_port=self._get_https_port(host_result),
                    extra={
                        "open_ports": [
                            {
                                "port": p.port,
                                "service": p.service,
                                "service_name": p.service_name,
                                "banner": p.banner,
                            }
                            for p in host_result.open_ports
                        ],
                        "scan_time_ms": host_result.scan_time_ms,
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
        
        logger.info(f"Port scan completed: {devices_found} hosts with open ports")
    
    def _scan_host(self, ip: str) -> HostPortScanResult:
        """
        Scan all ports for a single host.
        
        Args:
            ip: IP address to scan
            
        Returns:
            HostPortScanResult with all findings
        """
        start_time = datetime.now()
        result = HostPortScanResult(ip_address=ip)
        
        # Use thread pool for concurrent port scanning
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {
                executor.submit(self._check_port, ip, port): port
                for port in self.ports
            }
            
            for future in as_completed(futures):
                if self._cancelled:
                    break
                    
                port = futures[future]
                try:
                    port_result = future.result()
                    if port_result.state == "open":
                        result.open_ports.append(port_result)
                    elif port_result.state == "closed":
                        result.closed_count += 1
                    else:
                        result.filtered_count += 1
                except Exception as e:
                    logger.debug(f"Error checking {ip}:{port}: {e}")
                    result.filtered_count += 1
        
        result.scan_time_ms = (datetime.now() - start_time).total_seconds() * 1000
        return result
    
    def _check_port(self, ip: str, port: int) -> PortScanResult:
        """
        Check if a single TCP port is open.
        
        Args:
            ip: Target IP address
            port: Target port
            
        Returns:
            PortScanResult with port state
        """
        start_time = datetime.now()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip, port))
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            if result == 0:
                # Port is open
                service_info = COMMON_PORTS.get(port, (None, None))
                
                port_result = PortScanResult(
                    port=port,
                    state="open",
                    service=service_info[0],
                    service_name=service_info[1],
                    response_time_ms=response_time,
                )
                
                # Try to grab banner
                if self.grab_banners:
                    banner = self._grab_banner(sock, ip, port)
                    if banner:
                        port_result.banner = banner
                
                sock.close()
                return port_result
            else:
                sock.close()
                return PortScanResult(port=port, state="closed")
                
        except socket.timeout:
            return PortScanResult(port=port, state="filtered")
        except Exception as e:
            logger.debug(f"Error scanning {ip}:{port}: {e}")
            return PortScanResult(port=port, state="filtered")
    
    def _grab_banner(self, sock: socket.socket, ip: str, port: int) -> Optional[str]:
        """
        Attempt to grab service banner from open port.
        
        Args:
            sock: Connected socket
            ip: Target IP
            port: Target port
            
        Returns:
            Banner string if available
        """
        try:
            sock.settimeout(self.banner_timeout)
            
            # Some services need a probe to respond
            probes = {
                80: b"HEAD / HTTP/1.0\r\n\r\n",
                443: None,  # SSL handshake needed
                21: None,  # FTP sends banner automatically
                22: None,  # SSH sends banner automatically
                23: None,  # Telnet may send banner
                25: None,  # SMTP sends banner
                110: None,  # POP3 sends banner
                143: None,  # IMAP sends banner
            }
            
            probe = probes.get(port)
            if probe:
                sock.send(probe)
            
            # Receive banner
            banner = sock.recv(1024)
            if banner:
                # Clean up and decode
                try:
                    banner_str = banner.decode('utf-8', errors='ignore').strip()
                    # Limit length
                    return banner_str[:500] if banner_str else None
                except:
                    return banner[:100].hex()
            
        except socket.timeout:
            pass
        except Exception as e:
            logger.debug(f"Banner grab failed for {ip}:{port}: {e}")
        
        return None
    
    def _classify_device(self, result: HostPortScanResult) -> DeviceType:
        """
        Classify device type based on open ports.
        
        Args:
            result: Port scan result
            
        Returns:
            Best guess at device type
        """
        open_port_nums = {p.port for p in result.open_ports}
        
        # Check for camera indicators
        camera_ports = {554, 8000, 8554, 37777, 34567}
        if camera_ports & open_port_nums:
            return DeviceType.CAMERA
        
        # Check for network device indicators
        if 161 in open_port_nums:
            if 22 in open_port_nums or 23 in open_port_nums:
                # Network device with SNMP and management
                if 80 in open_port_nums:
                    return DeviceType.SWITCH  # Managed switch or router
        
        # Check for printer
        if 9100 in open_port_nums or 631 in open_port_nums:
            return DeviceType.PRINTER
        
        # Check for VoIP
        voip_ports = {5060, 5061, 5080, 4569, 2000, 2001}
        if voip_ports & open_port_nums:
            return DeviceType.VOIP_PHONE
        
        # Check for server (multiple services)
        server_ports = {21, 22, 25, 80, 443, 3306, 5432, 3389}
        if len(server_ports & open_port_nums) >= 3:
            return DeviceType.SERVER
        
        # Check for workstation
        if 3389 in open_port_nums and 445 in open_port_nums:
            return DeviceType.WORKSTATION
        
        # Check for IoT
        if 1883 in open_port_nums or 8883 in open_port_nums:
            return DeviceType.IOT_DEVICE
        
        return DeviceType.UNKNOWN
    
    def _get_http_port(self, result: HostPortScanResult) -> Optional[int]:
        """Get the HTTP port from scan result."""
        for port in [80, 8080, 8000, 8081]:
            if any(p.port == port for p in result.open_ports):
                return port
        return None
    
    def _get_https_port(self, result: HostPortScanResult) -> Optional[int]:
        """Get the HTTPS port from scan result."""
        for port in [443, 8443]:
            if any(p.port == port for p in result.open_ports):
                return port
        return None


# Convenience function for quick scans
def quick_port_scan(ip: str, ports: Optional[List[int]] = None) -> HostPortScanResult:
    """
    Quick synchronous port scan of a single host.
    
    Args:
        ip: IP address to scan
        ports: Ports to scan (default: quick preset)
        
    Returns:
        HostPortScanResult
    """
    scanner = TCPPortScanner(ports=ports, grab_banners=False)
    return scanner._scan_host(ip)
