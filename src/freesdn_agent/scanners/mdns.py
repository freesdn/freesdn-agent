"""
mDNS/Bonjour Scanner - Discover Apple devices, IoT, printers, and services.

Uses multicast DNS (mDNS) to discover devices advertising services on the
local network. Common service types include:
- _http._tcp - Web interfaces
- _ipp._tcp - Printers
- _airplay._tcp - Apple TV
- _raop._tcp - AirPlay speakers
- _homekit._tcp - HomeKit devices
- _hap._tcp - HomeKit Accessory Protocol
- _googlecast._tcp - Chromecast
- _spotify-connect._tcp - Spotify devices
"""

import asyncio
import socket
import struct
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# mDNS multicast address and port
MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

# Common service types to query
SERVICE_TYPES = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ipp._tcp.local.",           # Internet Printing Protocol
    "_ipps._tcp.local.",          # Secure IPP
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",  # Printer
    "_airplay._tcp.local.",       # Apple AirPlay
    "_raop._tcp.local.",          # Remote Audio Output (AirPlay)
    "_homekit._tcp.local.",       # Apple HomeKit
    "_hap._tcp.local.",           # HomeKit Accessory Protocol
    "_googlecast._tcp.local.",    # Google Chromecast
    "_spotify-connect._tcp.local.",  # Spotify Connect
    "_sonos._tcp.local.",         # Sonos speakers
    "_apple-mobdev2._tcp.local.", # Apple mobile devices
    "_companion-link._tcp.local.", # Apple Continuity
    "_ssh._tcp.local.",           # SSH servers
    "_sftp-ssh._tcp.local.",      # SFTP
    "_smb._tcp.local.",           # SMB/CIFS
    "_afpovertcp._tcp.local.",    # Apple Filing Protocol
    "_nfs._tcp.local.",           # NFS
    "_ftp._tcp.local.",           # FTP
    "_daap._tcp.local.",          # iTunes sharing
    "_dacp._tcp.local.",          # iTunes remote
    "_touch-able._tcp.local.",    # Apple Remote
    "_sleep-proxy._udp.local.",   # Sleep Proxy
    "_workstation._tcp.local.",   # Mac workstations
    "_device-info._tcp.local.",   # Device info
    "_nvstream._tcp.local.",      # NVIDIA GameStream
    "_xbox._tcp.local.",          # Xbox
    "_hue._tcp.local.",           # Philips Hue
    "_mqtt._tcp.local.",          # MQTT
    "_coap._udp.local.",          # CoAP (IoT)
    "_axis-video._tcp.local.",    # Axis cameras
    "_rtsp._tcp.local.",          # RTSP streaming
    "_raop._tcp.local.",          # AirPlay audio
]

# Device signatures based on service and TXT records
DEVICE_SIGNATURES = {
    # Apple devices
    ("_airplay._tcp", "model=AppleTV"): ("Apple TV", "MEDIA_PLAYER"),
    ("_airplay._tcp", "model=iPhone"): ("iPhone", "MOBILE"),
    ("_airplay._tcp", "model=iPad"): ("iPad", "MOBILE"),
    ("_airplay._tcp", "model=Mac"): ("Mac", "COMPUTER"),
    ("_raop._tcp", "am=AppleTV"): ("Apple TV", "MEDIA_PLAYER"),
    ("_raop._tcp", "am=HomePod"): ("HomePod", "SPEAKER"),
    ("_homekit._tcp", ""): ("HomeKit Device", "IOT"),
    ("_hap._tcp", ""): ("HomeKit Accessory", "IOT"),
    ("_companion-link._tcp", ""): ("Apple Device", "MOBILE"),
    ("_apple-mobdev2._tcp", ""): ("Apple Mobile", "MOBILE"),
    
    # Google devices
    ("_googlecast._tcp", "md=Chromecast"): ("Chromecast", "MEDIA_PLAYER"),
    ("_googlecast._tcp", "md=Google Home"): ("Google Home", "SPEAKER"),
    ("_googlecast._tcp", "md=Google Nest"): ("Google Nest", "SPEAKER"),
    ("_googlecast._tcp", "md=Nest Hub"): ("Nest Hub", "DISPLAY"),
    
    # Speakers
    ("_spotify-connect._tcp", ""): ("Spotify Device", "SPEAKER"),
    ("_sonos._tcp", ""): ("Sonos Speaker", "SPEAKER"),
    ("_raop._tcp", ""): ("AirPlay Speaker", "SPEAKER"),
    
    # Printers
    ("_ipp._tcp", ""): ("Network Printer", "PRINTER"),
    ("_ipps._tcp", ""): ("Network Printer", "PRINTER"),
    ("_printer._tcp", ""): ("Network Printer", "PRINTER"),
    ("_pdl-datastream._tcp", ""): ("Network Printer", "PRINTER"),
    
    # Smart Home
    ("_hue._tcp", ""): ("Philips Hue Bridge", "IOT"),
    ("_mqtt._tcp", ""): ("MQTT Device", "IOT"),
    
    # Network services
    ("_ssh._tcp", ""): ("SSH Server", "SERVER"),
    ("_smb._tcp", ""): ("SMB Server", "SERVER"),
    ("_afpovertcp._tcp", ""): ("AFP Server", "SERVER"),
    ("_nfs._tcp", ""): ("NFS Server", "SERVER"),
    ("_http._tcp", ""): ("Web Server", "SERVER"),
    
    # Cameras
    ("_axis-video._tcp", ""): ("Axis Camera", "CAMERA"),
    ("_rtsp._tcp", ""): ("Streaming Device", "CAMERA"),
    
    # Gaming
    ("_nvstream._tcp", ""): ("NVIDIA Shield", "MEDIA_PLAYER"),
    ("_xbox._tcp", ""): ("Xbox", "GAMING"),
}


@dataclass
class MDNSService:
    """Represents a discovered mDNS service."""
    name: str
    service_type: str
    hostname: str
    ip_address: str
    port: int
    txt_records: Dict[str, str]


class MDNSScanner:
    """Scanner for mDNS/Bonjour service discovery."""
    
    name = "mDNS/Bonjour"
    protocol = "mdns"
    SCANNER_NAME = "MDNSScanner"
    
    def __init__(self, timeout: float = 3.0, concurrency: int = 10):
        self.timeout = timeout
        self.concurrency = concurrency
        self.discovered_services: List[MDNSService] = []
        self.discovered_ips: Set[str] = set()
        self.is_cancelled = False
        
    def reset(self):
        """Reset scanner state."""
        self.is_cancelled = False
        self.discovered_services = []
        self.discovered_ips = set()
        
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
        Perform mDNS discovery on the local network.
        
        Note: mDNS uses multicast, so the targets parameter is used
        to filter results to the relevant subnet.
        
        Args:
            targets: Networks/IPs to scan (used for filtering results)
            interface: Network interface (not used for mDNS multicast)
            progress_callback: Called with scan progress
            
        Yields:
            ScanResult for each discovered device
        """
        from freesdn_agent.scanners.base import ScanResult, DeviceType
        
        self.reset()
        logger.info(f"Starting mDNS discovery (timeout={self.timeout}s)")
        
        try:
            # Create UDP socket for mDNS
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.1)
            
            # Bind to mDNS port
            try:
                sock.bind(('', MDNS_PORT))
            except OSError:
                # Port may be in use, try ephemeral port
                sock.bind(('', 0))
            
            # Join multicast group
            mreq = struct.pack("4sl", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            # Send queries for each service type
            import time
            for service_type in SERVICE_TYPES:
                if self.is_cancelled:
                    break
                query = self._build_query(service_type)
                sock.sendto(query, (MDNS_ADDR, MDNS_PORT))
                time.sleep(0.01)  # Small delay between queries
            
            # Collect responses
            import time
            end_time = time.time() + self.timeout
            
            while time.time() < end_time and not self.is_cancelled:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip_address = addr[0]
                    
                    # Parse mDNS response
                    services = self._parse_response(data, ip_address)
                    
                    for service in services:
                        if service.ip_address not in self.discovered_ips:
                            self.discovered_ips.add(service.ip_address)
                            device = self._service_to_device(service)
                            if device:
                                logger.info(f"mDNS discovered: {service.ip_address} - {service.name}")
                                # Yield as ScanResult
                                yield ScanResult(
                                    ip_address=device.get("ip_address", service.ip_address),
                                    mac_address=device.get("mac_address"),
                                    hostname=device.get("hostname", service.hostname),
                                    vendor=device.get("vendor"),
                                    device_type=DeviceType.UNKNOWN,
                                    open_ports=[],
                                    services={},
                                    raw_data={"mdns": device},
                                )
                                
                except socket.timeout:
                    time.sleep(0.05)
                except Exception as e:
                    logger.debug(f"Error receiving mDNS: {e}")
                    time.sleep(0.05)
            
            sock.close()
            
        except Exception as e:
            logger.error(f"mDNS scan error: {e}")
        
        logger.info(f"mDNS discovery complete: {len(self.discovered_ips)} devices found")
    
    def _build_query(self, service_type: str) -> bytes:
        """Build an mDNS query packet for a service type."""
        # DNS header
        transaction_id = 0x0000  # mDNS uses 0
        flags = 0x0000  # Standard query
        questions = 1
        answers = 0
        authority = 0
        additional = 0
        
        header = struct.pack(">HHHHHH", 
            transaction_id, flags, questions, answers, authority, additional)
        
        # Question section
        question = b""
        for label in service_type.split("."):
            if label:
                question += bytes([len(label)]) + label.encode("utf-8")
        question += b"\x00"  # Null terminator
        
        # QTYPE=PTR (12), QCLASS=IN (1) with unicast response bit
        question += struct.pack(">HH", 12, 0x8001)
        
        return header + question
    
    def _parse_response(self, data: bytes, source_ip: str) -> List[MDNSService]:
        """Parse mDNS response packet."""
        services = []
        
        try:
            if len(data) < 12:
                return services
            
            # Parse header
            (transaction_id, flags, questions, answers, 
             authority, additional) = struct.unpack(">HHHHHH", data[:12])
            
            # Skip if no answers
            if answers == 0 and additional == 0:
                return services
            
            offset = 12
            
            # Skip questions
            for _ in range(questions):
                offset = self._skip_name(data, offset)
                offset += 4  # QTYPE + QCLASS
            
            # Parse answers
            records = []
            for _ in range(answers + authority + additional):
                if offset >= len(data):
                    break
                    
                name, offset = self._read_name(data, offset)
                if offset + 10 > len(data):
                    break
                    
                rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
                offset += 10
                
                if offset + rdlength > len(data):
                    break
                
                rdata = data[offset:offset+rdlength]
                offset += rdlength
                
                records.append({
                    "name": name,
                    "type": rtype,
                    "class": rclass,
                    "ttl": ttl,
                    "data": rdata,
                })
            
            # Extract service information from records
            service_info = self._extract_service_info(records, data, source_ip)
            if service_info:
                services.append(service_info)
                
        except Exception as e:
            logger.debug(f"Error parsing mDNS response: {e}")
        
        return services
    
    def _skip_name(self, data: bytes, offset: int) -> int:
        """Skip a DNS name in the packet."""
        while offset < len(data):
            length = data[offset]
            if length == 0:
                return offset + 1
            if length >= 0xC0:  # Compression pointer
                return offset + 2
            offset += length + 1
        return offset
    
    def _read_name(self, data: bytes, offset: int) -> tuple:
        """Read a DNS name from the packet."""
        labels = []
        original_offset = offset
        jumped = False
        max_jumps = 10
        jumps = 0
        
        while offset < len(data) and jumps < max_jumps:
            length = data[offset]
            
            if length == 0:
                offset += 1
                break
            elif length >= 0xC0:  # Compression pointer
                if not jumped:
                    original_offset = offset + 2
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                offset = pointer
                jumped = True
                jumps += 1
            else:
                offset += 1
                if offset + length <= len(data):
                    labels.append(data[offset:offset+length].decode("utf-8", errors="ignore"))
                offset += length
        
        name = ".".join(labels)
        return (name, original_offset if jumped else offset)
    
    def _extract_service_info(self, records: List[dict], data: bytes, source_ip: str) -> Optional[MDNSService]:
        """Extract service information from DNS records."""
        service_name = ""
        service_type = ""
        hostname = ""
        ip_address = source_ip
        port = 0
        txt_records = {}
        
        for record in records:
            rtype = record["type"]
            name = record["name"]
            rdata = record["data"]
            
            if rtype == 1:  # A record
                if len(rdata) == 4:
                    ip_address = socket.inet_ntoa(rdata)
                    
            elif rtype == 12:  # PTR record
                service_name, _ = self._read_name(data, 12 + len(name.encode()) + 6)
                service_type = name
                
            elif rtype == 16:  # TXT record
                txt_records = self._parse_txt_record(rdata)
                
            elif rtype == 33:  # SRV record
                if len(rdata) >= 6:
                    priority, weight, port = struct.unpack(">HHH", rdata[:6])
                    hostname, _ = self._read_name(rdata, 6)
        
        # Build service name from available info
        if not service_name:
            for record in records:
                if record["type"] in [1, 28, 33]:  # A, AAAA, SRV
                    service_name = record["name"]
                    break
        
        # Determine service type from name
        if not service_type:
            for stype in SERVICE_TYPES:
                if stype.replace(".local.", "") in service_name:
                    service_type = stype
                    break
        
        if service_name or service_type:
            return MDNSService(
                name=service_name or hostname or ip_address,
                service_type=service_type,
                hostname=hostname or service_name,
                ip_address=ip_address,
                port=port,
                txt_records=txt_records,
            )
        
        return None
    
    def _parse_txt_record(self, data: bytes) -> Dict[str, str]:
        """Parse TXT record data into key-value pairs."""
        txt_records = {}
        offset = 0
        
        while offset < len(data):
            length = data[offset]
            offset += 1
            
            if length == 0 or offset + length > len(data):
                break
            
            txt = data[offset:offset+length].decode("utf-8", errors="ignore")
            offset += length
            
            if "=" in txt:
                key, value = txt.split("=", 1)
                txt_records[key] = value
            else:
                txt_records[txt] = ""
        
        return txt_records
    
    def _service_to_device(self, service: MDNSService) -> Optional[Dict[str, Any]]:
        """Convert an mDNS service to a device dictionary."""
        # Determine device type and model
        device_type = "UNKNOWN"
        model = ""
        vendor = ""
        
        # Extract service type without .local.
        stype = service.service_type.replace(".local.", "")
        
        # Check TXT records for model info
        txt_str = " ".join(f"{k}={v}" for k, v in service.txt_records.items())
        
        # Check signatures
        for (sig_type, sig_txt), (sig_model, sig_device_type) in DEVICE_SIGNATURES.items():
            if sig_type in stype:
                if not sig_txt or sig_txt in txt_str:
                    model = sig_model
                    device_type = sig_device_type
                    break
        
        # Extract vendor from TXT records
        vendor = service.txt_records.get("vendor", "")
        if not vendor:
            vendor = service.txt_records.get("manufacturer", "")
        if not vendor:
            # Infer vendor from service type or model
            if "apple" in stype.lower() or "airplay" in stype or "raop" in stype:
                vendor = "Apple"
            elif "googlecast" in stype:
                vendor = "Google"
            elif "sonos" in stype:
                vendor = "Sonos"
            elif "hue" in stype:
                vendor = "Philips"
            elif "axis" in stype:
                vendor = "Axis"
        
        # Get model from TXT if not set
        if not model:
            model = service.txt_records.get("model", "")
            if not model:
                model = service.txt_records.get("md", "")
            if not model:
                model = service.txt_records.get("product", "")
        
        # Build hostname
        hostname = service.hostname or service.name
        if hostname.endswith(".local"):
            hostname = hostname[:-6]
        
        return {
            "ip_address": service.ip_address,
            "hostname": hostname,
            "vendor": vendor,
            "model": model,
            "device_type": device_type,
            "protocols": ["mdns"],
            "services": [service.service_type],
            "ports": [service.port] if service.port else [],
            "mdns_info": {
                "service_type": service.service_type,
                "txt_records": service.txt_records,
            },
        }


async def scan(network: str, timeout: float = 3.0, **kwargs) -> List[Dict[str, Any]]:
    """Module-level scan function for scanner registry."""
    scanner = MDNSScanner(timeout=timeout)
    return await scanner.scan(network)
