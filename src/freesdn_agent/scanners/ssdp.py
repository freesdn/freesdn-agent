"""
SSDP/UPnP Scanner - Discover UPnP-enabled devices on the network.

Simple Service Discovery Protocol (SSDP) is used by UPnP devices to
announce their presence. This includes:
- Routers and gateways
- Smart TVs
- Media servers
- IoT devices
- Game consoles
- NAS devices
"""

import asyncio
import socket
import logging
import re
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# SSDP multicast address and port
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

# M-SEARCH discovery message
MSEARCH_MSG = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)

# Alternative search targets for specific device types
SEARCH_TARGETS = [
    "ssdp:all",
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:MediaServer:1",
    "urn:schemas-upnp-org:device:MediaRenderer:1",
    "urn:schemas-upnp-org:device:Basic:1",
    "urn:schemas-upnp-org:service:ContentDirectory:1",
]

# Device signatures based on server header and device type
DEVICE_SIGNATURES = {
    # Routers/Gateways
    "InternetGatewayDevice": ("Router", "ROUTER"),
    "WANDevice": ("WAN Gateway", "ROUTER"),
    "WANConnectionDevice": ("Router", "ROUTER"),
    
    # Media devices
    "MediaServer": ("Media Server", "NAS"),
    "MediaRenderer": ("Media Renderer", "MEDIA_PLAYER"),
    "ContentDirectory": ("Media Server", "NAS"),
    
    # TVs and displays
    "dial": ("Smart TV", "TV"),
    "tv": ("Smart TV", "TV"),
    "samsung": ("Samsung TV", "TV"),
    "lgtv": ("LG TV", "TV"),
    "roku": ("Roku", "MEDIA_PLAYER"),
    
    # Gaming
    "xbox": ("Xbox", "GAMING"),
    "playstation": ("PlayStation", "GAMING"),
    
    # Printers
    "printer": ("Network Printer", "PRINTER"),
    "Printer": ("Network Printer", "PRINTER"),
    
    # NAS
    "nas": ("NAS", "NAS"),
    "synology": ("Synology NAS", "NAS"),
    "qnap": ("QNAP NAS", "NAS"),
    "ReadyNAS": ("Netgear NAS", "NAS"),
    
    # Cameras
    "camera": ("IP Camera", "CAMERA"),
    "IPCamera": ("IP Camera", "CAMERA"),
    "axis": ("Axis Camera", "CAMERA"),
    
    # Speakers
    "sonos": ("Sonos Speaker", "SPEAKER"),
    "speaker": ("Smart Speaker", "SPEAKER"),
    "audio": ("Audio Device", "SPEAKER"),
    
    # Smart Home
    "hue": ("Philips Hue", "IOT"),
    "wemo": ("Belkin WeMo", "IOT"),
    "smartthings": ("SmartThings", "IOT"),
}

# Vendor detection from server string
VENDOR_PATTERNS = {
    r"synology": "Synology",
    r"qnap": "QNAP",
    r"netgear": "Netgear",
    r"asus": "ASUS",
    r"linksys": "Linksys",
    r"tp-link|tplink": "TP-Link",
    r"d-link|dlink": "D-Link",
    r"belkin": "Belkin",
    r"samsung": "Samsung",
    r"lg\s": "LG",
    r"sony": "Sony",
    r"panasonic": "Panasonic",
    r"philips": "Philips",
    r"roku": "Roku",
    r"plex": "Plex",
    r"sonos": "Sonos",
    r"bose": "Bose",
    r"microsoft": "Microsoft",
    r"xbox": "Microsoft",
    r"playstation": "Sony",
    r"axis": "Axis",
    r"hikvision": "Hikvision",
    r"dahua": "Dahua",
    r"ubiquiti|unifi": "Ubiquiti",
}


@dataclass
class SSDPDevice:
    """Represents a discovered SSDP/UPnP device."""
    ip_address: str
    port: int
    location: str
    server: str
    usn: str
    st: str
    friendly_name: str = ""
    manufacturer: str = ""
    model_name: str = ""
    model_number: str = ""
    serial_number: str = ""
    device_type: str = ""


class SSDPScanner:
    """Scanner for SSDP/UPnP device discovery."""
    
    name = "SSDP/UPnP"
    protocol = "ssdp"
    SCANNER_NAME = "SSDPScanner"
    
    def __init__(self, timeout: float = 3.0, fetch_details: bool = False, concurrency: int = 10):
        self.timeout = timeout
        self.fetch_details = fetch_details
        self.concurrency = concurrency
        self.discovered_devices: Dict[str, SSDPDevice] = {}
        self.is_cancelled = False
        
    def reset(self):
        """Reset scanner state."""
        self.is_cancelled = False
        self.discovered_devices = {}
        
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
        Perform SSDP discovery on the local network.
        
        Args:
            targets: Networks/IPs to scan (used for filtering)
            interface: Network interface (not used for SSDP multicast)
            progress_callback: Called with scan progress
            
        Yields:
            ScanResult for each discovered device
        """
        from freesdn_agent.scanners.base import ScanResult, DeviceType
        import time
        
        self.reset()
        logger.info(f"Starting SSDP discovery (timeout={self.timeout}s)")
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(0.1)
            sock.bind(('', 0))
            
            # Send M-SEARCH requests
            for st in SEARCH_TARGETS:
                if self.is_cancelled:
                    break
                msg = (
                    f"M-SEARCH * HTTP/1.1\r\n"
                    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
                    f"MAN: \"ssdp:discover\"\r\n"
                    f"MX: 2\r\n"
                    f"ST: {st}\r\n"
                    f"\r\n"
                )
                sock.sendto(msg.encode(), (SSDP_ADDR, SSDP_PORT))
                time.sleep(0.05)
            
            # Collect responses
            end_time = time.time() + self.timeout
            
            while time.time() < end_time and not self.is_cancelled:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip_address = addr[0]
                    
                    device = self._parse_response(data.decode('utf-8', errors='ignore'), ip_address)
                    if device and device.ip_address not in self.discovered_devices:
                        self.discovered_devices[device.ip_address] = device
                        logger.info(f"SSDP discovered: {ip_address} - {device.server[:50] if device.server else 'Unknown'}")
                        
                        # Yield as ScanResult
                        dev_dict = self._device_to_dict(device)
                        if dev_dict:
                            yield ScanResult(
                                ip_address=device.ip_address,
                                mac_address=None,
                                hostname=dev_dict.get("hostname", ""),
                                vendor=dev_dict.get("vendor"),
                                device_type=DeviceType.UNKNOWN,
                                open_ports=[],
                                services={},
                                raw_data={"ssdp": dev_dict},
                            )
                        
                except socket.timeout:
                    time.sleep(0.05)
                except Exception as e:
                    logger.debug(f"Error receiving SSDP: {e}")
                    time.sleep(0.05)
            
            sock.close()
            
        except Exception as e:
            logger.error(f"SSDP scan error: {e}")
        
        logger.info(f"SSDP discovery complete: {len(self.discovered_devices)} devices found")
    
    def _parse_response(self, response: str, ip_address: str) -> Optional[SSDPDevice]:
        """Parse SSDP response headers."""
        try:
            lines = response.split("\r\n")
            
            # Check if this is a valid response
            if not lines[0].startswith("HTTP/1.1 200") and not lines[0].startswith("NOTIFY"):
                return None
            
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().upper()] = value.strip()
            
            location = headers.get("LOCATION", "")
            server = headers.get("SERVER", "")
            usn = headers.get("USN", "")
            st = headers.get("ST", headers.get("NT", ""))
            
            # Extract port from location
            port = 80
            if location:
                parsed = urlparse(location)
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
            
            return SSDPDevice(
                ip_address=ip_address,
                port=port,
                location=location,
                server=server,
                usn=usn,
                st=st,
            )
            
        except Exception as e:
            logger.debug(f"Error parsing SSDP response: {e}")
            return None
    
    async def _fetch_device_details(self):
        """Fetch detailed device information from description URLs."""
        import aiohttp
        
        try:
            timeout = aiohttp.ClientTimeout(total=2)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                tasks = []
                for device in self.discovered_devices.values():
                    if device.location:
                        tasks.append(self._fetch_description(session, device))
                
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                    
        except ImportError:
            logger.debug("aiohttp not available, skipping detail fetch")
        except Exception as e:
            logger.debug(f"Error fetching device details: {e}")
    
    async def _fetch_description(self, session, device: SSDPDevice):
        """Fetch and parse UPnP device description XML."""
        try:
            async with session.get(device.location, ssl=False) as response:
                if response.status == 200:
                    xml_text = await response.text()
                    self._parse_description_xml(device, xml_text)
        except Exception as e:
            logger.debug(f"Error fetching description for {device.ip_address}: {e}")
    
    def _parse_description_xml(self, device: SSDPDevice, xml_text: str):
        """Parse UPnP device description XML."""
        try:
            # Remove XML namespace for easier parsing
            xml_text = re.sub(r'\sxmlns="[^"]+"', '', xml_text)
            root = ET.fromstring(xml_text)
            
            # Find device element
            dev_elem = root.find(".//device")
            if dev_elem is None:
                return
            
            # Extract device information
            device.friendly_name = self._get_xml_text(dev_elem, "friendlyName")
            device.manufacturer = self._get_xml_text(dev_elem, "manufacturer")
            device.model_name = self._get_xml_text(dev_elem, "modelName")
            device.model_number = self._get_xml_text(dev_elem, "modelNumber")
            device.serial_number = self._get_xml_text(dev_elem, "serialNumber")
            device.device_type = self._get_xml_text(dev_elem, "deviceType")
            
        except ET.ParseError as e:
            logger.debug(f"XML parse error: {e}")
        except Exception as e:
            logger.debug(f"Error parsing description XML: {e}")
    
    def _get_xml_text(self, elem, tag: str) -> str:
        """Get text content of an XML element."""
        child = elem.find(tag)
        return child.text if child is not None and child.text else ""
    
    def _device_to_dict(self, device: SSDPDevice) -> Optional[Dict[str, Any]]:
        """Convert an SSDP device to a device dictionary."""
        # Determine device type
        device_type = "UNKNOWN"
        model = device.model_name or device.model_number or ""
        
        # Check all identification strings
        check_strings = [
            device.device_type,
            device.st,
            device.server,
            device.usn,
            device.friendly_name,
            model,
        ]
        check_str = " ".join(s.lower() for s in check_strings if s)
        
        # Match device signatures
        for signature, (sig_model, sig_type) in DEVICE_SIGNATURES.items():
            if signature.lower() in check_str:
                device_type = sig_type
                if not model:
                    model = sig_model
                break
        
        # Determine vendor
        vendor = device.manufacturer
        if not vendor:
            for pattern, vendor_name in VENDOR_PATTERNS.items():
                if re.search(pattern, check_str, re.IGNORECASE):
                    vendor = vendor_name
                    break
        
        # Clean up friendly name for hostname
        hostname = device.friendly_name or ""
        
        return {
            "ip_address": device.ip_address,
            "hostname": hostname,
            "vendor": vendor,
            "model": model,
            "device_type": device_type,
            "protocols": ["ssdp", "upnp"],
            "ports": [device.port] if device.port else [80],
            "ssdp_info": {
                "location": device.location,
                "server": device.server,
                "usn": device.usn,
                "device_type": device.device_type,
                "friendly_name": device.friendly_name,
                "serial": device.serial_number,
            },
        }


async def scan(network: str, timeout: float = 3.0, **kwargs) -> List[Dict[str, Any]]:
    """Module-level scan function for scanner registry."""
    scanner = SSDPScanner(timeout=timeout)
    return await scanner.scan(network)
