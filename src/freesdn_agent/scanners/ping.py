"""
Ping Scanner.

Network discovery using ICMP ping (via system ping command).
No special privileges required on most systems.
"""

import logging
import subprocess
import platform
import ipaddress
import socket
from typing import Generator, Optional, Callable, List
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from freesdn_agent.scanners.base import BaseScanner, ScanResult, ScanProgress, DeviceType
from freesdn_agent.services.oui_lookup import lookup_vendor

logger = logging.getLogger(__name__)


class PingScanner(BaseScanner):
    """
    Ping-based network scanner.
    
    Uses system ping command to discover live hosts.
    Works without special privileges on most systems.
    """
    
    SCANNER_NAME = "ping"
    DISPLAY_NAME = "ICMP Ping"
    REQUIRES_ROOT = False
    
    def __init__(
        self,
        timeout: float = 1.0,
        concurrency: int = 50,
    ):
        super().__init__(timeout=timeout, concurrency=concurrency)
        self._is_windows = platform.system().lower() == "windows"
    
    def scan(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
    ) -> Generator[ScanResult, None, None]:
        """
        Scan network using ICMP ping.
        
        Args:
            targets: Networks/IPs to scan (e.g., ["192.168.1.0/24"])
            interface: Network interface (not used for ping)
            progress_callback: Called with scan progress
            
        Yields:
            ScanResult for each responding device
        """
        self.reset()
        
        # Collect all IPs to scan from targets
        all_ips = []
        for target in targets:
            ip_list = self._parse_target(target)
            all_ips.extend(ip_list)
        
        if not all_ips:
            logger.warning(f"No valid IPs to scan from targets: {targets}")
            return
        
        logger.info(f"Starting ping scan of {len(all_ips)} addresses")
        
        # Scan using thread pool for concurrency
        completed = 0
        total = len(all_ips)
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            # Submit all ping tasks
            future_to_ip = {
                executor.submit(self._ping_host, ip): ip 
                for ip in all_ips
            }
            
            for future in as_completed(future_to_ip):
                if self.is_cancelled:
                    logger.info("Ping scan cancelled")
                    executor.shutdown(wait=False, cancel_futures=True)
                    return
                
                ip = future_to_ip[future]
                completed += 1
                
                # Report progress
                if progress_callback and completed % 10 == 0:
                    progress = ScanProgress(
                        scanner_name=self.SCANNER_NAME,
                        status="running",
                        progress=(completed / total) * 100,
                        current_target=ip,
                    )
                    progress_callback(progress)
                
                try:
                    result = future.result()
                    if result:
                        yield result
                except Exception as e:
                    logger.debug(f"Ping error for {ip}: {e}")
        
        logger.info(f"Ping scan complete")
    
    def _ping_host(self, ip: str) -> Optional[ScanResult]:
        """
        Ping a single host.
        
        Args:
            ip: IP address to ping
            
        Returns:
            ScanResult if host responds, None otherwise
        """
        try:
            # Build ping command
            if self._is_windows:
                # Windows: -n count, -w timeout in ms
                cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
            else:
                # Linux/Mac: -c count, -W timeout in seconds
                cmd = ["ping", "-c", "1", "-W", str(int(self.timeout)), ip]
            
            # Run ping
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout + 2,
                text=True,
            )
            
            # Check for actual response (not just return code)
            # Windows returns 0 even on timeout sometimes, check output
            stdout = result.stdout.lower()
            
            # Check for success indicators
            is_alive = False
            if result.returncode == 0:
                # Verify actual response in output
                if self._is_windows:
                    # Windows: look for "TTL=" which indicates actual response
                    is_alive = "ttl=" in stdout and "request timed out" not in stdout
                else:
                    # Linux: look for "bytes from" or time response
                    is_alive = "bytes from" in stdout or "time=" in stdout
            
            if is_alive:
                # Host is alive - try to get more info
                hostname = self._resolve_hostname(ip)
                mac_address = self._get_mac_from_arp(ip)
                vendor = lookup_vendor(mac_address) if mac_address else None
                device_type = self._guess_device_type(vendor, hostname)
                
                return ScanResult(
                    ip_address=ip,
                    mac_address=mac_address,
                    hostname=hostname,
                    vendor=vendor,
                    device_type=device_type,
                    discovered_by=self.SCANNER_NAME,
                    discovered_at=datetime.utcnow(),
                )
            
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.debug(f"Ping failed for {ip}: {e}")
        
        return None
    
    def _guess_device_type(self, vendor: Optional[str], hostname: Optional[str]) -> DeviceType:
        """Guess device type based on vendor and hostname."""
        vendor_lower = (vendor or "").lower()
        hostname_lower = (hostname or "").lower()
        
        # Check vendor for known device types
        camera_vendors = ["hikvision", "dahua", "axis", "uniview", "reolink", "amcrest", "foscam", "vivotek"]
        if any(v in vendor_lower for v in camera_vendors):
            return DeviceType.CAMERA
        
        switch_vendors = ["cisco", "juniper", "arista", "dell networking", "netgear", "hp networking"]
        if any(v in vendor_lower for v in switch_vendors):
            return DeviceType.SWITCH
        
        ap_vendors = ["ubiquiti", "aruba", "ruckus", "cambium", "mikrotik"]
        if any(v in vendor_lower for v in ap_vendors):
            return DeviceType.ACCESS_POINT
        
        voip_vendors = ["grandstream", "yealink", "polycom", "sangoma", "cisco-linksys", "snom", "fanvil"]
        if any(v in vendor_lower for v in voip_vendors):
            return DeviceType.VOIP_PHONE
        
        printer_vendors = ["hp", "epson", "canon", "brother", "xerox", "lexmark"]
        if any(v in vendor_lower for v in printer_vendors) and ("print" in hostname_lower or "printer" in vendor_lower):
            return DeviceType.PRINTER
        
        # Check hostname patterns
        if any(x in hostname_lower for x in ["cam", "camera", "nvr", "dvr", "ipc"]):
            return DeviceType.CAMERA
        if any(x in hostname_lower for x in ["switch", "sw-", "sw_"]):
            return DeviceType.SWITCH
        if any(x in hostname_lower for x in ["router", "gateway", "gw-"]):
            return DeviceType.ROUTER
        if any(x in hostname_lower for x in ["phone", "voip", "sip"]):
            return DeviceType.VOIP_PHONE
        if any(x in hostname_lower for x in ["print", "printer"]):
            return DeviceType.PRINTER
        if any(x in hostname_lower for x in ["ap-", "ap_", "wifi", "wap"]):
            return DeviceType.ACCESS_POINT
        
        return DeviceType.UNKNOWN
        
        return None
    
    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Try to resolve hostname from IP."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def _get_mac_from_arp(self, ip: str) -> Optional[str]:
        """Try to get MAC address from ARP cache."""
        try:
            if self._is_windows:
                result = subprocess.run(
                    ["arp", "-a", ip],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                # Parse Windows arp output
                for line in result.stdout.split("\n"):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            # Look for MAC address pattern
                            if "-" in part and len(part) == 17:
                                return part.upper().replace("-", ":")
            else:
                result = subprocess.run(
                    ["arp", "-n", ip],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                # Parse Linux arp output
                for line in result.stdout.split("\n"):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if ":" in part and len(part) == 17:
                                return part.upper()
        except Exception:
            pass
        
        return None
    
    def _parse_target(self, target: str) -> list[str]:
        """
        Parse target string into list of IP addresses.
        
        Supports:
        - CIDR notation: 192.168.1.0/24
        - Range notation: 192.168.1.1-192.168.1.254
        - Single IP: 192.168.1.1
        """
        ip_list = []
        
        try:
            if "/" in target:
                # CIDR notation
                network = ipaddress.ip_network(target, strict=False)
                ip_list = [str(ip) for ip in network.hosts()]
            elif "-" in target:
                # Range notation
                start_ip, end_ip = target.split("-")
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                
                current = start
                while current <= end:
                    ip_list.append(str(current))
                    current = ipaddress.ip_address(int(current) + 1)
            else:
                # Single IP or interface name - try as IP first
                try:
                    ip = ipaddress.ip_address(target)
                    ip_list = [str(ip)]
                except ValueError:
                    # Not an IP, might be interface - skip
                    pass
                
        except Exception as e:
            logger.error(f"Failed to parse target '{target}': {e}")
        
        return ip_list
