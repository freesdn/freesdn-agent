"""
RTSP Scanner - Discover streaming cameras and media servers.

Real Time Streaming Protocol (RTSP) is used for streaming video from:
- IP cameras
- NVRs/DVRs
- Media servers
- Video encoders

Common RTSP ports: 554 (standard), 8554 (alternate)
"""

import asyncio
import socket
import logging
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Common RTSP ports
RTSP_PORTS = [554, 8554, 5554, 10554]

# Common RTSP paths to probe
RTSP_PATHS = [
    "/",
    "/live",
    "/live/ch00_0",
    "/live/ch01_0", 
    "/Streaming/Channels/1",
    "/Streaming/Channels/101",
    "/cam/realmonitor",
    "/h264",
    "/h264/ch1/main/av_stream",
    "/video1",
    "/videoMain",
    "/stream1",
    "/MediaInput/h264",
    "/onvif1",
    "/onvif-media/media.amp",
]

# Device signatures from RTSP Server header
RTSP_SIGNATURES = {
    # Hikvision
    r"Hikvision|HIKVISION|HikVision": ("Hikvision", "CAMERA"),
    r"DNVRS|Hik-Connect": ("Hikvision", "NVR"),
    
    # Dahua
    r"Dahua|DAHUA": ("Dahua", "CAMERA"),
    r"DH-NVR|DH-DVR": ("Dahua", "NVR"),
    
    # Axis
    r"AXIS|Axis": ("Axis", "CAMERA"),
    
    # Hanwha/Samsung
    r"Hanwha|Samsung|SNB|SNP|SND": ("Hanwha", "CAMERA"),
    
    # Vivotek
    r"Vivotek|VIVOTEK": ("Vivotek", "CAMERA"),
    
    # Bosch
    r"Bosch|BOSCH": ("Bosch", "CAMERA"),
    
    # Panasonic
    r"Panasonic|WV-": ("Panasonic", "CAMERA"),
    
    # Sony
    r"Sony|SNC-": ("Sony", "CAMERA"),
    
    # Uniview
    r"Uniview|UNV": ("Uniview", "CAMERA"),
    
    # FLIR
    r"FLIR": ("FLIR", "CAMERA"),
    
    # Reolink
    r"Reolink": ("Reolink", "CAMERA"),
    
    # Amcrest
    r"Amcrest": ("Amcrest", "CAMERA"),
    
    # Foscam
    r"Foscam": ("Foscam", "CAMERA"),
    
    # VLC
    r"VLC": ("VLC", "MEDIA_SERVER"),
    
    # Live555
    r"Live555|LIVE555": ("Live555", "MEDIA_SERVER"),
    
    # GStreamer
    r"GStreamer": ("GStreamer", "MEDIA_SERVER"),
    
    # FFmpeg
    r"FFmpeg|Lavf": ("FFmpeg", "MEDIA_SERVER"),
    
    # Generic
    r"RTSP|Streaming": ("Generic", "CAMERA"),
}


@dataclass
class RTSPDevice:
    """Represents a discovered RTSP device."""
    ip_address: str
    port: int
    server: str
    paths: List[str]
    requires_auth: bool


class RTSPScanner:
    """Scanner for RTSP streaming devices."""
    
    name = "RTSP"
    protocol = "rtsp"
    SCANNER_NAME = "RTSPScanner"
    DISPLAY_NAME = "RTSP Streaming"
    REQUIRES_ROOT = False
    
    def __init__(self, timeout: float = 3.0, check_paths: bool = False, concurrency: int = 50):
        self.timeout = timeout
        self.check_paths = check_paths  # Whether to probe multiple paths
        self.concurrency = concurrency
        self.is_cancelled = False
        
    def reset(self):
        """Reset scanner state."""
        self.is_cancelled = False
        
    def cancel(self):
        """Cancel the scan."""
        self.is_cancelled = True
        
    def scan(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        progress_callback: Optional[Any] = None,
    ):
        """
        Scan a network for RTSP devices.
        
        Args:
            targets: Networks/IPs to scan (e.g., ["192.168.1.0/24"])
            interface: Network interface (not used)
            progress_callback: Called with scan progress
            
        Yields:
            ScanResult for each discovered device
        """
        from freesdn_agent.scanners.base import ScanResult, DeviceType
        import ipaddress
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        self.reset()
        
        # Collect all IPs to scan
        all_ips = []
        for target in targets:
            try:
                net = ipaddress.ip_network(target, strict=False)
                all_ips.extend([str(ip) for ip in net.hosts()])
            except:
                all_ips.append(target)
        
        logger.info(f"Starting RTSP scan on {len(all_ips)} hosts")
        
        def scan_host(ip):
            """Scan a single host for RTSP services."""
            for port in RTSP_PORTS:
                if self.is_cancelled:
                    return None
                device = self._probe_rtsp_sync(ip, port)
                if device:
                    return self._device_to_dict(device)
            return None
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            future_to_ip = {executor.submit(scan_host, ip): ip for ip in all_ips}
            
            for future in as_completed(future_to_ip):
                if self.is_cancelled:
                    break
                    
                try:
                    result = future.result()
                    if result:
                        logger.info(f"RTSP found: {result['ip_address']}:{result.get('ports', [554])[0]} - {result.get('vendor', 'Unknown')}")
                        yield ScanResult(
                            ip_address=result['ip_address'],
                            mac_address=None,
                            hostname="",
                            vendor=result.get('vendor'),
                            device_type=DeviceType.CAMERA,
                            open_ports=result.get('ports', [554]),
                            services={"rtsp": result.get('server', '')},
                            raw_data={"rtsp": result},
                        )
                except Exception as e:
                    logger.debug(f"RTSP scan error: {e}")
        
        logger.info("RTSP scan complete")
    
    def _probe_rtsp_sync(self, ip: str, port: int) -> Optional[RTSPDevice]:
        """Send RTSP OPTIONS request and parse response (sync version)."""
        import socket
        
        try:
            # Build RTSP OPTIONS request
            request = (
                f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"User-Agent: FreeSDN-Agent/1.0\r\n"
                f"\r\n"
            )
            
            # Connect with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            try:
                # Send request
                sock.send(request.encode())
                
                # Read response
                response = sock.recv(4096)
                response_text = response.decode('utf-8', errors='ignore')
                
                # Check for valid RTSP response
                if "RTSP/1.0" in response_text:
                    device = self._parse_response(ip, port, response_text)
                    return device
                    
            finally:
                sock.close()
                
        except (socket.timeout, socket.error, ConnectionRefusedError):
            pass
        except Exception as e:
            logger.debug(f"RTSP probe error for {ip}:{port}: {e}")
        
        return None
    
    def _parse_response(self, ip: str, port: int, response: str) -> Optional[RTSPDevice]:
        """Parse RTSP response headers."""
        try:
            lines = response.split("\r\n")
            headers = {}
            
            # Check status line
            status_line = lines[0] if lines else ""
            requires_auth = "401" in status_line
            
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            
            server = headers.get("server", "")
            public = headers.get("public", "")
            
            # Available paths based on response
            paths = []
            if "DESCRIBE" in public or not public:
                paths = ["/"]
            
            return RTSPDevice(
                ip_address=ip,
                port=port,
                server=server,
                paths=paths,
                requires_auth=requires_auth,
            )
            
        except Exception as e:
            logger.debug(f"Error parsing RTSP response: {e}")
            return None
    
    def _device_to_dict(self, device: RTSPDevice) -> Dict[str, Any]:
        """Convert an RTSP device to a device dictionary."""
        # Determine vendor and device type
        vendor = ""
        device_type = "CAMERA"
        
        for pattern, (sig_vendor, sig_type) in RTSP_SIGNATURES.items():
            if re.search(pattern, device.server, re.IGNORECASE):
                vendor = sig_vendor
                device_type = sig_type
                break
        
        return {
            "ip_address": device.ip_address,
            "hostname": "",
            "vendor": vendor,
            "model": "",
            "device_type": device_type,
            "protocols": ["rtsp"],
            "ports": [device.port],
            "rtsp_info": {
                "server": device.server,
                "port": device.port,
                "paths": device.paths,
                "requires_auth": device.requires_auth,
                "stream_url": f"rtsp://{device.ip_address}:{device.port}/",
            },
        }


async def scan(network: str, timeout: float = 3.0, **kwargs) -> List[Dict[str, Any]]:
    """Module-level scan function for scanner registry."""
    scanner = RTSPScanner(timeout=timeout)
    return await scanner.scan(network)
