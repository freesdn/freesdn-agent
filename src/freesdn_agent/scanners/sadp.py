"""
Hikvision SADP Scanner for FreeSDN Agent.

Discovers Hikvision cameras using the proprietary SADP (Search Active Devices Protocol).
This protocol is used by Hikvision for device discovery and configuration.
"""

import logging
import socket
import struct
import uuid
import re
from typing import Generator, Optional, Callable, List
from dataclasses import dataclass
from xml.etree import ElementTree as ET

from freesdn_agent.scanners.base import BaseScanner, ScanResult, ScanProgress, DeviceType

logger = logging.getLogger(__name__)


# SADP Protocol constants
SADP_MULTICAST_GROUP = "239.255.255.250"
SADP_PORT = 37020
SADP_SEND_PORT = 37020
SADP_RECV_PORT = 37020

# SADP packet header
SADP_MAGIC = bytes([0x21, 0x02, 0x01, 0x00])  # Magic bytes for SADP


@dataclass
class SADPDevice:
    """Parsed Hikvision device information from SADP response."""
    ip_address: str
    mac_address: str
    subnet_mask: str
    gateway: str
    dhcp_enabled: bool
    device_type: str
    model: str
    serial_number: str
    firmware_version: str
    encoder_version: str
    http_port: int
    device_id: str
    is_activated: bool
    support_https: bool = False
    sdk_server_port: int = 8000


class SADPScanner(BaseScanner):
    """
    Scanner that discovers Hikvision cameras via SADP protocol.
    
    Sends broadcast SADP inquiry packets and parses responses.
    Works on Layer 3 (UDP) so no special privileges needed.
    """
    
    SCANNER_NAME = "sadp"
    DISPLAY_NAME = "Hikvision SADP"
    REQUIRES_ROOT = False  # UDP broadcast works without privileges
    
    def __init__(self):
        super().__init__()
        self.timeout = 3.0  # Seconds to wait for responses
        self.retries = 2  # Number of inquiry attempts
    
    def scan(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
    ) -> Generator[ScanResult, None, None]:
        """
        Discover Hikvision cameras on the network.
        
        Args:
            targets: Ignored for SADP (broadcast)
            interface: Network interface to send from
            progress_callback: Called with scan progress
        
        Yields:
            ScanResult for each discovered camera
        """
        logger.info(f"Starting Hikvision SADP scan (timeout={self.timeout}s)")
        
        # Get local IP for the interface if specified
        local_ip = self._get_interface_ip(interface) if interface else "0.0.0.0"
        
        discovered_macs = set()
        
        for attempt in range(self.retries):
            if progress_callback:
                progress = ScanProgress(
                    scanner_name=self.SCANNER_NAME,
                    status="running",
                    progress=((attempt + 1) / self.retries) * 100,
                    current_target=SADP_MULTICAST_GROUP,
                )
                progress_callback(progress)
            
            try:
                devices = self._send_inquiry(local_ip)
                
                for device in devices:
                    # Deduplicate by MAC
                    if device.mac_address in discovered_macs:
                        continue
                    discovered_macs.add(device.mac_address)
                    
                    # Convert to ScanResult
                    result = self._create_result(device)
                    yield result
                    
            except Exception as e:
                logger.error(f"SADP inquiry failed: {e}")
        
        logger.info(f"SADP scan complete: {len(discovered_macs)} cameras found")
    
    def _send_inquiry(self, local_ip: str = "0.0.0.0") -> List[SADPDevice]:
        """
        Send SADP inquiry and collect responses.
        
        Args:
            local_ip: Local IP address to bind to
        
        Returns:
            List of discovered Hikvision devices
        """
        devices = []
        
        # Create inquiry packet (based on SADP protocol analysis)
        # This is a simplified inquiry that most Hikvision devices respond to
        inquiry_packet = self._create_inquiry_packet()
        
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(self.timeout)
        
        try:
            # Bind to local interface
            sock.bind((local_ip, 0))
            
            # Send inquiry to multicast and broadcast addresses
            sock.sendto(inquiry_packet, (SADP_MULTICAST_GROUP, SADP_PORT))
            sock.sendto(inquiry_packet, ("255.255.255.255", SADP_PORT))
            logger.debug(f"Sent SADP inquiry to {SADP_MULTICAST_GROUP}:{SADP_PORT}")
            
            # Collect responses
            while True:
                try:
                    data, addr = sock.recvfrom(65535)
                    source_ip = addr[0]
                    
                    # Parse response
                    device = self._parse_response(data, source_ip)
                    if device:
                        devices.append(device)
                        logger.debug(f"Found Hikvision device: {device.model} at {source_ip}")
                        
                except socket.timeout:
                    # No more responses
                    break
                except Exception as e:
                    logger.debug(f"Error processing SADP response: {e}")
                    continue
                    
        finally:
            sock.close()
        
        return devices
    
    def _create_inquiry_packet(self) -> bytes:
        """
        Create SADP inquiry packet.
        
        The SADP protocol uses a proprietary binary format with XML payload.
        """
        # Generate a UUID for the inquiry
        inquiry_uuid = uuid.uuid4().hex[:16].upper()
        
        # XML inquiry payload
        xml_payload = f'''<?xml version="1.0" encoding="utf-8"?>
<Probe>
<Uuid>{inquiry_uuid}</Uuid>
<Types>inquiry</Types>
</Probe>'''
        
        xml_bytes = xml_payload.encode('utf-8')
        
        # Build packet header
        # Format: Magic (4) + Payload Length (4) + Unknown (4) + Payload
        header = SADP_MAGIC + struct.pack('<I', len(xml_bytes)) + bytes([0x00] * 4)
        
        return header + xml_bytes
    
    def _parse_response(self, data: bytes, source_ip: str) -> Optional[SADPDevice]:
        """
        Parse SADP response packet.
        
        Args:
            data: Raw response data
            source_ip: IP address of responder
        
        Returns:
            SADPDevice if valid response, None otherwise
        """
        try:
            # Check magic bytes
            if len(data) < 12:
                return None
            
            # Extract XML payload (skip header)
            # Try to find XML start
            xml_start = data.find(b'<?xml')
            if xml_start == -1:
                # Try to find just the root element
                xml_start = data.find(b'<ProbeMatch') 
                if xml_start == -1:
                    xml_start = data.find(b'<Device')
                    if xml_start == -1:
                        return None
            
            xml_data = data[xml_start:].decode('utf-8', errors='ignore')
            
            # Parse XML
            root = ET.fromstring(xml_data)
            
            # Extract device information
            def get_text(element, tags):
                """Get text from element, trying multiple tag names."""
                for tag in tags if isinstance(tags, list) else [tags]:
                    el = element.find(tag)
                    if el is not None and el.text:
                        return el.text.strip()
                    # Try with namespace prefix
                    for child in element:
                        if child.tag.endswith(tag) or tag in child.tag:
                            if child.text:
                                return child.text.strip()
                return ""
            
            # Try to extract MAC address
            mac = get_text(root, ['MAC', 'Mac', 'MacAddress', 'IPv4Address/MAC'])
            if not mac:
                mac = get_text(root, ['MACAddress', 'DeviceMac'])
            
            # Format MAC address
            if mac and len(mac) >= 12:
                mac = mac.replace(':', '').replace('-', '').upper()
                mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
            
            # Extract other fields
            device = SADPDevice(
                ip_address=get_text(root, ['IPv4Address', 'IPAddress', 'IP']) or source_ip,
                mac_address=mac or "00:00:00:00:00:00",
                subnet_mask=get_text(root, ['IPv4SubnetMask', 'SubnetMask', 'Mask']) or "255.255.255.0",
                gateway=get_text(root, ['IPv4Gateway', 'Gateway', 'DefaultGateway']) or "",
                dhcp_enabled=get_text(root, ['DHCP', 'DHCPEnabled']).lower() == 'true',
                device_type=get_text(root, ['DeviceType', 'Type']) or "Camera",
                model=get_text(root, ['DeviceType', 'Model', 'DeviceModel', 'DeviceName']) or "Hikvision Camera",
                serial_number=get_text(root, ['SerialNo', 'SerialNumber', 'DeviceSN']) or "",
                firmware_version=get_text(root, ['FirmwareVersion', 'SoftwareVersion', 'DSPVersion']) or "",
                encoder_version=get_text(root, ['EncoderVersion', 'EncoderReleased']) or "",
                http_port=int(get_text(root, ['HttpPort', 'HTTPPort', 'Port']) or "80"),
                device_id=get_text(root, ['DeviceID', 'Uuid', 'UUID']) or "",
                is_activated=get_text(root, ['Activated', 'DeviceActivated']).lower() != 'false',
                support_https=get_text(root, ['SupportHTTPS', 'HTTPSPort']) != "",
                sdk_server_port=int(get_text(root, ['SDKServerPort', 'CommandPort']) or "8000"),
            )
            
            return device
            
        except ET.ParseError as e:
            logger.debug(f"Failed to parse SADP XML: {e}")
            # Try regex fallback for malformed XML
            return self._parse_response_regex(data, source_ip)
        except Exception as e:
            logger.debug(f"Failed to parse SADP response: {e}")
            return None
    
    def _parse_response_regex(self, data: bytes, source_ip: str) -> Optional[SADPDevice]:
        """Fallback regex parser for malformed SADP responses."""
        try:
            text = data.decode('utf-8', errors='ignore')
            
            def extract(pattern, default=""):
                match = re.search(pattern, text, re.IGNORECASE)
                return match.group(1) if match else default
            
            mac = extract(r'<(?:MAC|MacAddress)[^>]*>([^<]+)</', "00:00:00:00:00:00")
            if len(mac) >= 12 and ':' not in mac:
                mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
            
            return SADPDevice(
                ip_address=extract(r'<(?:IPv4Address|IPAddress|IP)[^>]*>([^<]+)</', source_ip),
                mac_address=mac.upper(),
                subnet_mask=extract(r'<(?:SubnetMask|IPv4SubnetMask)[^>]*>([^<]+)</', "255.255.255.0"),
                gateway=extract(r'<(?:Gateway|IPv4Gateway)[^>]*>([^<]+)</'),
                dhcp_enabled=extract(r'<DHCP[^>]*>([^<]+)</').lower() == 'true',
                device_type=extract(r'<DeviceType[^>]*>([^<]+)</', "Camera"),
                model=extract(r'<(?:DeviceType|Model)[^>]*>([^<]+)</', "Hikvision Camera"),
                serial_number=extract(r'<(?:SerialNo|SerialNumber)[^>]*>([^<]+)</'),
                firmware_version=extract(r'<(?:FirmwareVersion|SoftwareVersion)[^>]*>([^<]+)</'),
                encoder_version=extract(r'<EncoderVersion[^>]*>([^<]+)</'),
                http_port=int(extract(r'<(?:HttpPort|HTTPPort)[^>]*>(\d+)</', "80")),
                device_id=extract(r'<(?:DeviceID|Uuid)[^>]*>([^<]+)</'),
                is_activated=extract(r'<Activated[^>]*>([^<]+)</').lower() != 'false',
            )
        except Exception:
            return None
    
    def _create_result(self, device: SADPDevice) -> ScanResult:
        """Convert SADPDevice to ScanResult."""
        # Build open ports list
        open_ports = [device.http_port, device.sdk_server_port, 554]  # HTTP, SDK, RTSP
        if device.support_https:
            open_ports.append(443)
        
        # Build protocols list
        protocols = ["SADP", "RTSP", "ONVIF"]
        if device.support_https:
            protocols.append("HTTPS")
        
        # Build extra info
        extra = {
            "discovery_method": "sadp",
            "hikvision": True,
            "activated": device.is_activated,
            "dhcp_enabled": device.dhcp_enabled,
            "gateway": device.gateway,
            "subnet_mask": device.subnet_mask,
        }
        
        if device.device_id:
            extra["device_id"] = device.device_id
        if device.encoder_version:
            extra["encoder_version"] = device.encoder_version
        if device.serial_number:
            extra["serial"] = device.serial_number
        
        return ScanResult(
            ip_address=device.ip_address,
            mac_address=device.mac_address,
            hostname=device.model,
            device_type=DeviceType.CAMERA,
            vendor="Hikvision",
            model=device.model,
            firmware=device.firmware_version,
            open_ports=open_ports,
            protocols=protocols,
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
        
        return "0.0.0.0"
