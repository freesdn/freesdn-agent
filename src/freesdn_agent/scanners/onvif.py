"""
ONVIF WS-Discovery Scanner for FreeSDN Agent.

Discovers ONVIF-compliant cameras using WS-Discovery protocol.
This is the industry-standard protocol for IP camera discovery.
"""

import logging
import socket
import struct
import uuid
import re
from typing import Generator, Optional, Callable, List
from dataclasses import dataclass

from freesdn_agent.scanners.base import BaseScanner, ScanResult, ScanProgress, DeviceType

logger = logging.getLogger(__name__)


# WS-Discovery constants
MULTICAST_GROUP = "239.255.255.250"
MULTICAST_PORT = 3702
WS_DISCOVERY_NS = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
ONVIF_NS = "http://www.onvif.org/ver10/network/wsdl"

# WS-Discovery Probe message template
PROBE_MESSAGE = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" 
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
               xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
    <soap:Header>
        <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
        <wsa:MessageID>urn:uuid:{message_id}</wsa:MessageID>
        <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    </soap:Header>
    <soap:Body>
        <wsd:Probe>
            <wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>
        </wsd:Probe>
    </soap:Body>
</soap:Envelope>"""


@dataclass
class ONVIFDevice:
    """Parsed ONVIF device information from WS-Discovery response."""
    ip_address: str
    xaddrs: List[str]
    types: List[str]
    scopes: List[str]
    endpoint: Optional[str] = None
    model: Optional[str] = None
    manufacturer: Optional[str] = None
    serial: Optional[str] = None
    hardware_id: Optional[str] = None


class ONVIFScanner(BaseScanner):
    """
    Scanner that discovers ONVIF cameras via WS-Discovery.
    
    Sends multicast Probe messages and parses ProbeMatch responses.
    Works on Layer 3 (IP) so no special privileges needed.
    """
    
    SCANNER_NAME = "onvif"
    DISPLAY_NAME = "ONVIF WS-Discovery"
    REQUIRES_ROOT = False  # WS-Discovery works without privileges
    
    def __init__(self):
        super().__init__()
        self.timeout = 3.0  # Seconds to wait for responses
        self.retries = 2  # Number of probe attempts
    
    def scan(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
    ) -> Generator[ScanResult, None, None]:
        """
        Discover ONVIF cameras on the network.
        
        Args:
            targets: Ignored for WS-Discovery (multicast)
            interface: Network interface to send from
            progress_callback: Called with scan progress
        
        Yields:
            ScanResult for each discovered camera
        """
        logger.info(f"Starting ONVIF WS-Discovery scan (timeout={self.timeout}s)")
        
        # Get local IP for the interface if specified
        local_ip = self._get_interface_ip(interface) if interface else ""
        
        discovered_endpoints = set()
        
        for attempt in range(self.retries):
            if progress_callback:
                progress = ScanProgress(
                    scanner_name=self.SCANNER_NAME,
                    status="running",
                    progress=((attempt + 1) / self.retries) * 100,
                    current_target=MULTICAST_GROUP,
                )
                progress_callback(progress)
            
            try:
                devices = self._send_probe(local_ip)
                
                for device in devices:
                    # Deduplicate by endpoint or IP
                    key = device.endpoint or device.ip_address
                    if key in discovered_endpoints:
                        continue
                    discovered_endpoints.add(key)
                    
                    # Convert to ScanResult
                    result = self._create_result(device)
                    yield result
                    
            except Exception as e:
                logger.error(f"ONVIF probe failed: {e}")
        
        logger.info(f"ONVIF scan complete: {len(discovered_endpoints)} cameras found")
    
    def _send_probe(self, local_ip: str = "") -> List[ONVIFDevice]:
        """
        Send WS-Discovery Probe and collect responses.
        
        Args:
            local_ip: Local IP address to bind to
        
        Returns:
            List of discovered ONVIF devices
        """
        devices = []
        message_id = str(uuid.uuid4())
        probe_data = PROBE_MESSAGE.format(message_id=message_id).encode('utf-8')
        
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.timeout)
        
        try:
            # Bind to specific interface if provided
            if local_ip:
                sock.bind((local_ip, 0))
            
            # Set multicast TTL
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
            
            # Send probe
            sock.sendto(probe_data, (MULTICAST_GROUP, MULTICAST_PORT))
            logger.debug(f"Sent WS-Discovery probe to {MULTICAST_GROUP}:{MULTICAST_PORT}")
            
            # Collect responses
            while True:
                try:
                    data, addr = sock.recvfrom(65535)
                    source_ip = addr[0]
                    
                    # Parse response
                    device = self._parse_probe_match(data.decode('utf-8'), source_ip)
                    if device:
                        devices.append(device)
                        logger.debug(f"Found ONVIF device: {source_ip}")
                        
                except socket.timeout:
                    # No more responses
                    break
                except Exception as e:
                    logger.debug(f"Error processing response: {e}")
                    continue
                    
        finally:
            sock.close()
        
        return devices
    
    def _parse_probe_match(self, xml_data: str, source_ip: str) -> Optional[ONVIFDevice]:
        """
        Parse WS-Discovery ProbeMatch response.
        
        Args:
            xml_data: Raw XML response
            source_ip: IP address of responder
        
        Returns:
            ONVIFDevice if valid response, None otherwise
        """
        try:
            # Simple regex parsing (avoiding XML library for performance)
            # Extract XAddrs (service endpoints)
            xaddrs_match = re.search(r'<[^:]*:?XAddrs[^>]*>([^<]+)</[^:]*:?XAddrs>', xml_data)
            xaddrs = xaddrs_match.group(1).split() if xaddrs_match else []
            
            # Extract Types
            types_match = re.search(r'<[^:]*:?Types[^>]*>([^<]+)</[^:]*:?Types>', xml_data)
            types = types_match.group(1).split() if types_match else []
            
            # Extract Scopes
            scopes_match = re.search(r'<[^:]*:?Scopes[^>]*>([^<]+)</[^:]*:?Scopes>', xml_data)
            scopes_raw = scopes_match.group(1).split() if scopes_match else []
            
            # Extract EndpointReference
            endpoint_match = re.search(r'<[^:]*:?Address[^>]*>([^<]+)</[^:]*:?Address>', xml_data)
            endpoint = endpoint_match.group(1) if endpoint_match else None
            
            # Parse scopes for device info
            model = None
            manufacturer = None
            serial = None
            hardware_id = None
            
            for scope in scopes_raw:
                if '/name/' in scope.lower():
                    model = scope.split('/')[-1]
                elif '/hardware/' in scope.lower():
                    hardware_id = scope.split('/')[-1]
                elif '/manufacturer/' in scope.lower() or '/mfr/' in scope.lower():
                    manufacturer = scope.split('/')[-1]
                elif '/serial/' in scope.lower():
                    serial = scope.split('/')[-1]
            
            # Determine IP from XAddrs if possible
            ip_address = source_ip
            for xaddr in xaddrs:
                ip_match = re.search(r'http[s]?://(\d+\.\d+\.\d+\.\d+)', xaddr)
                if ip_match:
                    ip_address = ip_match.group(1)
                    break
            
            return ONVIFDevice(
                ip_address=ip_address,
                xaddrs=xaddrs,
                types=types,
                scopes=scopes_raw,
                endpoint=endpoint,
                model=model,
                manufacturer=manufacturer,
                serial=serial,
                hardware_id=hardware_id,
            )
            
        except Exception as e:
            logger.debug(f"Failed to parse ProbeMatch: {e}")
            return None
    
    def _create_result(self, device: ONVIFDevice) -> ScanResult:
        """Convert ONVIFDevice to ScanResult."""
        # Build hostname from available info
        hostname = None
        if device.model and device.manufacturer:
            hostname = f"{device.manufacturer} {device.model}"
        elif device.model:
            hostname = device.model
        
        # Build extra info dict
        extra = {
            "discovery_method": "onvif",
            "onvif_compliant": True,
        }
        
        if device.xaddrs:
            extra["xaddrs"] = device.xaddrs
        if device.endpoint:
            extra["endpoint"] = device.endpoint
        if device.serial:
            extra["serial"] = device.serial
        if device.hardware_id:
            extra["hardware_id"] = device.hardware_id
        if device.types:
            extra["types"] = device.types
        
        return ScanResult(
            ip_address=device.ip_address,
            mac_address=None,  # WS-Discovery doesn't provide MAC
            hostname=hostname,
            device_type=DeviceType.CAMERA,
            vendor=device.manufacturer,
            model=device.model,
            firmware=None,
            open_ports=[80, 554, 8080],  # Common ONVIF ports
            protocols=["ONVIF", "RTSP"],
            extra=extra,
        )
    
    def _get_interface_ip(self, interface: str) -> str:
        """Get IP address for network interface."""
        try:
            import netifaces
            
            # Check if interface is actually an IP address
            try:
                socket.inet_aton(interface)
                return interface
            except socket.error:
                pass
            
            # Get interface addresses
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
            
        except Exception as e:
            logger.debug(f"Could not get IP for interface {interface}: {e}")
        
        return ""
