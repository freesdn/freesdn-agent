"""
ARP Scanner.

Layer 2 network discovery using ARP protocol.
Requires administrator/root privileges.
"""

import logging
from typing import Optional, Generator, Callable, List
from datetime import datetime
import ipaddress

from freesdn_agent.scanners.base import BaseScanner, ScanResult, ScanProgress, DeviceType
from freesdn_agent.services.oui_lookup import lookup_vendor

logger = logging.getLogger(__name__)


class ARPScanner(BaseScanner):
    """
    ARP-based network scanner.
    
    Uses scapy to send ARP requests and collect responses.
    Requires administrator/root privileges for raw socket access.
    """
    
    SCANNER_NAME = "arp"
    DISPLAY_NAME = "ARP Discovery"
    REQUIRES_ROOT = True
    
    def __init__(
        self,
        timeout: float = 2.0,
        concurrency: int = 50,
        retry_count: int = 1,
    ):
        super().__init__(timeout=timeout, concurrency=concurrency)
        self.retry_count = retry_count
        self._scapy_available = False
        self._check_scapy()
    
    def _check_scapy(self) -> None:
        """Check if scapy is available."""
        try:
            from scapy.all import ARP, Ether, srp
            self._scapy_available = True
        except ImportError:
            logger.warning("scapy not available - ARP scanning disabled")
            self._scapy_available = False
    
    def scan(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
    ) -> Generator[ScanResult, None, None]:
        """
        Scan network using ARP.
        
        Args:
            targets: Networks/IPs to scan (e.g., ["192.168.1.0/24"])
            interface: Network interface to use (optional)
            progress_callback: Called with scan progress
            
        Yields:
            ScanResult for each responding device
        """
        if not self._scapy_available:
            logger.error("scapy not available - cannot perform ARP scan")
            return
        
        self.reset()
        
        # Collect all IPs to scan from targets
        all_ips = []
        for target in targets:
            ip_list = self._parse_target(target)
            all_ips.extend(ip_list)
        
        if not all_ips:
            logger.warning(f"No valid IPs to scan from targets: {targets}")
            return
        
        logger.info(f"Starting ARP scan of {len(all_ips)} addresses")
        
        # Perform scan in batches
        batch_size = self.concurrency
        total_batches = (len(all_ips) + batch_size - 1) // batch_size
        
        for batch_idx, i in enumerate(range(0, len(all_ips), batch_size)):
            if self.is_cancelled:
                logger.info("ARP scan cancelled")
                return
            
            batch = all_ips[i:i + batch_size]
            
            if progress_callback:
                progress = ScanProgress(
                    scanner_name=self.SCANNER_NAME,
                    status="running",
                    progress=((batch_idx + 1) / total_batches) * 100,
                    current_target=batch[0] if batch else None,
                )
                progress_callback(progress)
            
            results = self._scan_batch(batch, interface)
            
            for result in results:
                yield result
    
    def _scan_batch(
        self,
        ip_list: list[str],
        interface: Optional[str] = None
    ) -> list[ScanResult]:
        """Scan a batch of IPs using ARP."""
        results = []
        
        try:
            from scapy.all import ARP, Ether, srp, conf
            
            # Suppress scapy warnings
            conf.verb = 0
            
            # Build ARP packets
            packets = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_list)
            
            # Send packets and receive responses
            kwargs = {"timeout": self.timeout, "verbose": False}
            if interface:
                kwargs["iface"] = interface
            
            answered, _ = srp(packets, **kwargs)
            
            # Process responses
            for sent, received in answered:
                if self.is_cancelled:
                    break
                
                ip_addr = received.psrc
                mac_addr = received.hwsrc.upper()
                
                # Lookup vendor from MAC
                vendor = lookup_vendor(mac_addr)
                
                # Classify device type based on vendor
                device_type = self._classify_device(vendor, mac_addr)
                
                result = ScanResult(
                    ip_address=ip_addr,
                    mac_address=mac_addr,
                    vendor=vendor,
                    device_type=device_type,
                    discovered_by=self.SCANNER_NAME,
                    discovered_at=datetime.utcnow(),
                )
                
                results.append(result)
                logger.debug(f"Found device: {ip_addr} ({mac_addr}) - {vendor}")
            
        except PermissionError:
            logger.error("ARP scan requires administrator/root privileges")
        except Exception as e:
            logger.error(f"ARP scan error: {e}")
        
        return results
    
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
                # Single IP
                ip = ipaddress.ip_address(target)
                ip_list = [str(ip)]
                
        except Exception as e:
            logger.error(f"Failed to parse target '{target}': {e}")
        
        return ip_list
    
    def _classify_device(self, vendor: Optional[str], mac_address: str) -> DeviceType:
        """Classify device type based on vendor and MAC."""
        if not vendor:
            return DeviceType.UNKNOWN
        
        vendor_lower = vendor.lower()
        
        # Camera vendors
        if any(v in vendor_lower for v in ["hikvision", "dahua", "axis", "uniview", "reolink"]):
            return DeviceType.CAMERA
        
        # Network equipment
        if any(v in vendor_lower for v in ["cisco", "juniper", "arista", "dell networking"]):
            return DeviceType.SWITCH
        
        # Access points
        if any(v in vendor_lower for v in ["ubiquiti", "aruba", "ruckus", "cambium"]):
            return DeviceType.ACCESS_POINT
        
        # Routers
        if any(v in vendor_lower for v in ["mikrotik", "netgear", "asus", "tp-link"]):
            return DeviceType.ROUTER
        
        # VoIP
        if any(v in vendor_lower for v in ["grandstream", "yealink", "polycom", "cisco-linksys"]):
            return DeviceType.VOIP_PHONE
        
        # Printers
        if any(v in vendor_lower for v in ["hp", "epson", "canon", "brother", "xerox"]):
            return DeviceType.PRINTER
        
        return DeviceType.UNKNOWN
