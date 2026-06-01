"""
HTTP Service Scanner Module.

Detects web services and extracts device information from HTTP responses.
"""

import logging
import socket
import ssl
import re
from typing import Optional, Generator, Callable, List, Dict, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from freesdn_agent.scanners.base import BaseScanner, ScanResult, ScanProgress, DeviceType

logger = logging.getLogger(__name__)


# Known device signatures from HTTP responses
DEVICE_SIGNATURES = [
    # Cameras
    {"pattern": r"hikvision", "vendor": "Hikvision", "type": DeviceType.CAMERA},
    {"pattern": r"dahua", "vendor": "Dahua", "type": DeviceType.CAMERA},
    {"pattern": r"axis.*camera", "vendor": "Axis", "type": DeviceType.CAMERA},
    {"pattern": r"vivotek", "vendor": "Vivotek", "type": DeviceType.CAMERA},
    {"pattern": r"foscam", "vendor": "Foscam", "type": DeviceType.CAMERA},
    {"pattern": r"amcrest", "vendor": "Amcrest", "type": DeviceType.CAMERA},
    {"pattern": r"reolink", "vendor": "Reolink", "type": DeviceType.CAMERA},
    {"pattern": r"uniview|unv", "vendor": "Uniview", "type": DeviceType.CAMERA},
    {"pattern": r"hanwha|wisenet", "vendor": "Hanwha", "type": DeviceType.CAMERA},
    {"pattern": r"geovision", "vendor": "GeoVision", "type": DeviceType.CAMERA},
    
    # NVR/DVR
    {"pattern": r"nvr|network\s*video\s*recorder", "vendor": None, "type": DeviceType.NVR},
    {"pattern": r"dvr|digital\s*video\s*recorder", "vendor": None, "type": DeviceType.DVR},
    
    # Network devices
    {"pattern": r"ubiquiti|unifi", "vendor": "Ubiquiti", "type": DeviceType.ACCESS_POINT},
    {"pattern": r"mikrotik|routeros", "vendor": "MikroTik", "type": DeviceType.ROUTER},
    {"pattern": r"cisco", "vendor": "Cisco", "type": DeviceType.SWITCH},
    {"pattern": r"juniper", "vendor": "Juniper", "type": DeviceType.SWITCH},
    {"pattern": r"aruba", "vendor": "Aruba", "type": DeviceType.ACCESS_POINT},
    {"pattern": r"fortinet|fortigate", "vendor": "Fortinet", "type": DeviceType.FIREWALL},
    {"pattern": r"pfsense", "vendor": "pfSense", "type": DeviceType.FIREWALL},
    {"pattern": r"opnsense", "vendor": "OPNsense", "type": DeviceType.FIREWALL},
    {"pattern": r"sonicwall", "vendor": "SonicWall", "type": DeviceType.FIREWALL},
    {"pattern": r"tp-link|tplink", "vendor": "TP-Link", "type": DeviceType.ROUTER},
    {"pattern": r"netgear", "vendor": "Netgear", "type": DeviceType.ROUTER},
    {"pattern": r"linksys", "vendor": "Linksys", "type": DeviceType.ROUTER},
    {"pattern": r"asus", "vendor": "ASUS", "type": DeviceType.ROUTER},
    {"pattern": r"d-link|dlink", "vendor": "D-Link", "type": DeviceType.ROUTER},
    {"pattern": r"zyxel", "vendor": "ZyXEL", "type": DeviceType.SWITCH},
    {"pattern": r"synology", "vendor": "Synology", "type": DeviceType.SERVER},
    {"pattern": r"qnap", "vendor": "QNAP", "type": DeviceType.SERVER},
    
    # VoIP
    {"pattern": r"polycom", "vendor": "Polycom", "type": DeviceType.VOIP_PHONE},
    {"pattern": r"yealink", "vendor": "Yealink", "type": DeviceType.VOIP_PHONE},
    {"pattern": r"grandstream", "vendor": "Grandstream", "type": DeviceType.VOIP_PHONE},
    {"pattern": r"cisco.*phone", "vendor": "Cisco", "type": DeviceType.VOIP_PHONE},
    {"pattern": r"snom", "vendor": "Snom", "type": DeviceType.VOIP_PHONE},
    {"pattern": r"sangoma|digium|s[0-9]{3}.*phone", "vendor": "Sangoma", "type": DeviceType.VOIP_PHONE},
    {"pattern": r"fanvil", "vendor": "Fanvil", "type": DeviceType.VOIP_PHONE},
    {"pattern": r"avaya.*phone|one-x", "vendor": "Avaya", "type": DeviceType.VOIP_PHONE},
    {"pattern": r"mitel", "vendor": "Mitel", "type": DeviceType.VOIP_PHONE},
    {"pattern": r"aastra", "vendor": "Aastra", "type": DeviceType.VOIP_PHONE},
    
    # Printers
    {"pattern": r"hp.*printer|laserjet|officejet", "vendor": "HP", "type": DeviceType.PRINTER},
    {"pattern": r"brother", "vendor": "Brother", "type": DeviceType.PRINTER},
    {"pattern": r"epson", "vendor": "Epson", "type": DeviceType.PRINTER},
    {"pattern": r"canon.*printer", "vendor": "Canon", "type": DeviceType.PRINTER},
    {"pattern": r"xerox", "vendor": "Xerox", "type": DeviceType.PRINTER},
    {"pattern": r"lexmark", "vendor": "Lexmark", "type": DeviceType.PRINTER},
    {"pattern": r"ricoh", "vendor": "Ricoh", "type": DeviceType.PRINTER},
    
    # IoT
    {"pattern": r"shelly", "vendor": "Shelly", "type": DeviceType.IOT_DEVICE},
    {"pattern": r"tasmota", "vendor": "Tasmota", "type": DeviceType.IOT_DEVICE},
    {"pattern": r"esphome", "vendor": "ESPHome", "type": DeviceType.IOT_DEVICE},
    {"pattern": r"sonoff", "vendor": "Sonoff", "type": DeviceType.IOT_DEVICE},
]


@dataclass
class HTTPScanResult:
    """Result of HTTP service scan."""
    ip_address: str
    port: int
    is_https: bool = False
    status_code: Optional[int] = None
    server_header: Optional[str] = None
    title: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    content_preview: Optional[str] = None
    redirect_url: Optional[str] = None
    ssl_info: Optional[Dict] = None
    response_time_ms: Optional[float] = None
    
    @property
    def url(self) -> str:
        """Get the service URL."""
        protocol = "https" if self.is_https else "http"
        if (self.is_https and self.port == 443) or (not self.is_https and self.port == 80):
            return f"{protocol}://{self.ip_address}"
        return f"{protocol}://{self.ip_address}:{self.port}"


class HTTPServiceScanner(BaseScanner):
    """
    HTTP Service Scanner.
    
    Probes HTTP/HTTPS services to identify devices and extract
    information from web interfaces.
    """
    
    SCANNER_NAME = "http_service"
    DISPLAY_NAME = "HTTP Service Scanner"
    REQUIRES_ROOT = False
    
    # Common web management ports
    DEFAULT_HTTP_PORTS = [80, 8080, 8000, 8081, 8888]
    DEFAULT_HTTPS_PORTS = [443, 8443]
    
    def __init__(
        self,
        timeout: float = 5.0,
        concurrency: int = 20,
        http_ports: Optional[List[int]] = None,
        https_ports: Optional[List[int]] = None,
        follow_redirects: bool = True,
        verify_ssl: bool = False,
        grab_content: bool = True,
    ):
        """
        Initialize HTTP service scanner.
        
        Args:
            timeout: Request timeout in seconds
            concurrency: Max concurrent requests
            http_ports: HTTP ports to scan
            https_ports: HTTPS ports to scan
            follow_redirects: Whether to follow redirects
            verify_ssl: Whether to verify SSL certificates
            grab_content: Whether to download page content
        """
        super().__init__(timeout=timeout, concurrency=concurrency)
        self.http_ports = http_ports or self.DEFAULT_HTTP_PORTS
        self.https_ports = https_ports or self.DEFAULT_HTTPS_PORTS
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.grab_content = grab_content
    
    def scan(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
    ) -> Generator[ScanResult, None, None]:
        """
        Scan targets for HTTP/HTTPS services.
        
        Args:
            targets: List of IP addresses to scan
            interface: Not used
            progress_callback: Progress callback
            
        Yields:
            ScanResult for each host with HTTP services
        """
        self.reset()
        
        # Build list of all endpoint combinations
        endpoints = []
        for ip in targets:
            for port in self.http_ports:
                endpoints.append((ip, port, False))
            for port in self.https_ports:
                endpoints.append((ip, port, True))
        
        total_endpoints = len(endpoints)
        completed = 0
        devices_found = 0
        
        # Group results by IP
        results_by_ip: Dict[str, List[HTTPScanResult]] = {}
        
        logger.info(f"Starting HTTP scan of {len(targets)} hosts, {total_endpoints} endpoints")
        
        start_time = datetime.now()
        
        if progress_callback:
            progress_callback(ScanProgress(
                scanner_name=self.SCANNER_NAME,
                status="starting",
                progress=0,
            ))
        
        # Use thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {
                executor.submit(self._probe_endpoint, ip, port, is_https): (ip, port, is_https)
                for ip, port, is_https in endpoints
            }
            
            for future in as_completed(futures):
                if self._cancelled:
                    break
                
                completed += 1
                ip, port, is_https = futures[future]
                
                try:
                    result = future.result()
                    if result and result.status_code:
                        if ip not in results_by_ip:
                            results_by_ip[ip] = []
                        results_by_ip[ip].append(result)
                except Exception as e:
                    logger.debug(f"Error scanning {ip}:{port}: {e}")
                
                if progress_callback and completed % 10 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    progress_callback(ScanProgress(
                        scanner_name=self.SCANNER_NAME,
                        status="running",
                        progress=(completed / total_endpoints) * 100,
                        current_target=ip,
                        devices_found=len(results_by_ip),
                        elapsed_seconds=elapsed,
                    ))
        
        # Convert results to ScanResults
        for ip, http_results in results_by_ip.items():
            if self._cancelled:
                break
            
            device_info = self._analyze_http_results(http_results)
            devices_found += 1
            
            yield ScanResult(
                ip_address=ip,
                device_type=device_info.get("type", DeviceType.UNKNOWN),
                vendor=device_info.get("vendor"),
                model=device_info.get("model"),
                hostname=device_info.get("hostname"),
                discovered_by=self.SCANNER_NAME,
                discovered_at=datetime.utcnow(),
                http_port=device_info.get("http_port"),
                https_port=device_info.get("https_port"),
                extra={
                    "http_services": [
                        {
                            "url": r.url,
                            "port": r.port,
                            "is_https": r.is_https,
                            "status_code": r.status_code,
                            "server": r.server_header,
                            "title": r.title,
                        }
                        for r in http_results
                    ],
                    "title": device_info.get("title"),
                    "server_header": device_info.get("server_header"),
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
        
        logger.info(f"HTTP scan completed: {devices_found} hosts with web services")
    
    def _probe_endpoint(self, ip: str, port: int, is_https: bool) -> Optional[HTTPScanResult]:
        """
        Probe a single HTTP endpoint.
        
        Args:
            ip: Target IP
            port: Target port
            is_https: Whether to use HTTPS
            
        Returns:
            HTTPScanResult or None if not accessible
        """
        protocol = "https" if is_https else "http"
        url = f"{protocol}://{ip}:{port}/"
        
        start_time = datetime.now()
        
        if HTTPX_AVAILABLE:
            return self._probe_with_httpx(ip, port, is_https, url, start_time)
        else:
            return self._probe_with_socket(ip, port, is_https, url, start_time)
    
    def _probe_with_httpx(
        self, ip: str, port: int, is_https: bool, url: str, start_time: datetime
    ) -> Optional[HTTPScanResult]:
        """Probe using httpx library."""
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
                verify=self.verify_ssl,
            ) as client:
                response = client.get(url, headers={
                    "User-Agent": "FreeSDN-Agent/1.0 (Network Discovery)",
                })
                
                response_time = (datetime.now() - start_time).total_seconds() * 1000
                
                result = HTTPScanResult(
                    ip_address=ip,
                    port=port,
                    is_https=is_https,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    server_header=response.headers.get("server"),
                    response_time_ms=response_time,
                )
                
                # Extract title from content
                if self.grab_content and response.text:
                    title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.I)
                    if title_match:
                        result.title = title_match.group(1).strip()[:200]
                    
                    # Store preview
                    result.content_preview = response.text[:2000]
                
                return result
                
        except httpx.ConnectError:
            return None
        except httpx.TimeoutException:
            return None
        except Exception as e:
            logger.debug(f"HTTP probe error for {url}: {e}")
            return None
    
    def _probe_with_socket(
        self, ip: str, port: int, is_https: bool, url: str, start_time: datetime
    ) -> Optional[HTTPScanResult]:
        """Probe using raw sockets (fallback)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if is_https:
                context = ssl.create_default_context()
                if not self.verify_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=ip)
            
            sock.connect((ip, port))
            
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: FreeSDN-Agent/1.0\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            
            # Receive response
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 10000:  # Limit response size
                    break
            
            sock.close()
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Parse response
            response_text = response.decode('utf-8', errors='ignore')
            
            # Extract status code
            status_match = re.search(r'HTTP/\d\.\d (\d+)', response_text)
            status_code = int(status_match.group(1)) if status_match else None
            
            if not status_code:
                return None
            
            result = HTTPScanResult(
                ip_address=ip,
                port=port,
                is_https=is_https,
                status_code=status_code,
                response_time_ms=response_time,
            )
            
            # Extract headers
            header_end = response_text.find('\r\n\r\n')
            if header_end > 0:
                header_text = response_text[:header_end]
                for line in header_text.split('\r\n')[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        result.headers[key.strip().lower()] = value.strip()
                
                result.server_header = result.headers.get('server')
            
            # Extract title
            if self.grab_content:
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', response_text, re.I)
                if title_match:
                    result.title = title_match.group(1).strip()[:200]
                result.content_preview = response_text[header_end+4:header_end+2004] if header_end > 0 else None
            
            return result
            
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"Socket probe error for {url}: {e}")
            return None
    
    def _analyze_http_results(self, results: List[HTTPScanResult]) -> Dict:
        """
        Analyze HTTP results to identify device.
        
        Args:
            results: List of HTTP scan results for one host
            
        Returns:
            Dict with device info
        """
        info = {
            "type": DeviceType.UNKNOWN,
            "vendor": None,
            "model": None,
            "hostname": None,
            "title": None,
            "server_header": None,
            "http_port": None,
            "https_port": None,
        }
        
        # Combine all text for signature matching
        all_text = ""
        
        for result in results:
            # Record ports
            if result.is_https and info["https_port"] is None:
                info["https_port"] = result.port
            elif not result.is_https and info["http_port"] is None:
                info["http_port"] = result.port
            
            # Collect text for analysis
            if result.title:
                all_text += f" {result.title}"
                if info["title"] is None:
                    info["title"] = result.title
            
            if result.server_header:
                all_text += f" {result.server_header}"
                if info["server_header"] is None:
                    info["server_header"] = result.server_header
            
            if result.content_preview:
                all_text += f" {result.content_preview}"
        
        # Match signatures
        all_text_lower = all_text.lower()
        
        for sig in DEVICE_SIGNATURES:
            if re.search(sig["pattern"], all_text_lower, re.I):
                info["type"] = sig["type"]
                if sig["vendor"]:
                    info["vendor"] = sig["vendor"]
                break
        
        return info
