"""
SIP Scanner - Discover VoIP phones and SIP devices on the network.

Uses SIP OPTIONS requests to detect VoIP phones, PBX systems, and
SIP-enabled devices. This provides deeper VoIP discovery than
port scanning alone.

Common SIP ports:
- 5060: Standard SIP (UDP/TCP)
- 5061: SIP over TLS
- 5080: Alternative SIP port (used by FreeSWITCH, Sangoma)
"""

import asyncio
import socket
import logging
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import random
import string

logger = logging.getLogger(__name__)

# SIP ports to probe
SIP_PORTS = [5060, 5061, 5080, 5070, 5082]

# SIP User-Agent signatures for device identification
SIP_SIGNATURES = {
    # Sangoma/Digium
    r"Sangoma|SRAPS": ("Sangoma", "VOIP_PHONE"),
    r"Digium": ("Digium", "VOIP_PHONE"),
    r"Asterisk": ("Asterisk PBX", "VOIP_PBX"),
    r"FreePBX": ("FreePBX", "VOIP_PBX"),
    
    # Cisco
    r"Cisco.*(SPA|ATA|CP-)": ("Cisco", "VOIP_PHONE"),
    r"Cisco.*CUCM|CallManager": ("Cisco UCM", "VOIP_PBX"),
    r"Cisco": ("Cisco", "VOIP_PHONE"),
    
    # Polycom
    r"Polycom.*(VVX|SoundPoint|SoundStation)": ("Polycom", "VOIP_PHONE"),
    r"PolycomRealPresence": ("Polycom", "VIDEO_CONF"),
    r"Polycom": ("Polycom", "VOIP_PHONE"),
    
    # Yealink
    r"Yealink.*(SIP-T|VP-T|CP)": ("Yealink", "VOIP_PHONE"),
    r"Yealink": ("Yealink", "VOIP_PHONE"),
    
    # Grandstream
    r"Grandstream.*(GXP|GRP|GXV|HT)": ("Grandstream", "VOIP_PHONE"),
    r"Grandstream": ("Grandstream", "VOIP_PHONE"),
    
    # Snom
    r"snom\d+|snom.*D\d+": ("Snom", "VOIP_PHONE"),
    r"snom": ("Snom", "VOIP_PHONE"),
    
    # Fanvil
    r"Fanvil|fanvil": ("Fanvil", "VOIP_PHONE"),
    
    # Avaya
    r"Avaya.*(one-X|96\d+|J\d+)": ("Avaya", "VOIP_PHONE"),
    r"Avaya": ("Avaya", "VOIP_PHONE"),
    
    # Mitel
    r"Mitel|MiVoice|Aastra": ("Mitel", "VOIP_PHONE"),
    r"Aastra": ("Aastra", "VOIP_PHONE"),
    
    # AudioCodes
    r"AudioCodes|Mediant": ("AudioCodes", "VOIP_GATEWAY"),
    
    # FreeSWITCH
    r"FreeSWITCH": ("FreeSWITCH", "VOIP_PBX"),
    
    # Kamailio/OpenSIPS
    r"Kamailio": ("Kamailio", "SIP_PROXY"),
    r"OpenSIPS": ("OpenSIPS", "SIP_PROXY"),
    
    # 3CX
    r"3CX": ("3CX", "VOIP_PBX"),
    
    # Obihai
    r"OBi\d+": ("Obihai", "VOIP_ATA"),
    
    # Linksys/Sipura
    r"Linksys|Sipura": ("Linksys", "VOIP_ATA"),
    
    # Generic VoIP
    r"SIP|VoIP": ("Generic SIP", "VOIP_PHONE"),
}

# Model extraction patterns
MODEL_PATTERNS = {
    "Sangoma": r"(S[357]\d+|D\d+)",
    "Polycom": r"(VVX[- ]?\d+|SoundPoint[- ]?\d+|SoundStation[- ]?\d+)",
    "Yealink": r"(SIP-T\d+\w*|VP-T\d+|CP\d+)",
    "Grandstream": r"(GXP\d+|GRP\d+|GXV\d+|HT\d+)",
    "Cisco": r"(SPA\d+|CP-\d+|ATA\d+)",
    "Snom": r"(\d{3}|D\d+)",
    "Avaya": r"(\d{4}|J\d+|one-X)",
}


@dataclass
class SIPDevice:
    """Represents a discovered SIP device."""
    ip_address: str
    port: int
    user_agent: str
    server: str
    allow: str
    supported: str
    contact: str


class SIPScanner:
    """Scanner for SIP/VoIP device discovery."""
    
    name = "SIP/VoIP"
    protocol = "sip"
    SCANNER_NAME = "SIPScanner"
    
    def __init__(self, timeout: float = 2.0, concurrency: int = 50):
        self.timeout = timeout
        self.concurrency = concurrency
        self.call_id_counter = 0
        self.is_cancelled = False
        
    def reset(self):
        """Reset scanner state."""
        self.is_cancelled = False
        self.call_id_counter = 0
        
    def cancel(self):
        """Cancel the scan."""
        self.is_cancelled = True
        
    def _generate_call_id(self) -> str:
        """Generate a unique Call-ID."""
        self.call_id_counter += 1
        random_part = ''.join(random.choices(string.hexdigits.lower(), k=16))
        return f"{random_part}-{self.call_id_counter}@freesdn"
    
    def _generate_branch(self) -> str:
        """Generate a Via branch parameter."""
        random_part = ''.join(random.choices(string.hexdigits.lower(), k=16))
        return f"z9hG4bK-{random_part}"
    
    def _generate_tag(self) -> str:
        """Generate a From/To tag."""
        return ''.join(random.choices(string.hexdigits.lower(), k=8))
    
    def _build_options_request(self, target_ip: str, target_port: int, local_ip: str) -> bytes:
        """Build a SIP OPTIONS request message."""
        call_id = self._generate_call_id()
        branch = self._generate_branch()
        tag = self._generate_tag()
        
        request = (
            f"OPTIONS sip:{target_ip}:{target_port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:scanner@{local_ip}>;tag={tag}\r\n"
            f"To: <sip:{target_ip}:{target_port}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"Contact: <sip:scanner@{local_ip}:5060>\r\n"
            f"Accept: application/sdp\r\n"
            f"Content-Length: 0\r\n"
            f"User-Agent: FreeSDN-Agent/1.0\r\n"
            f"\r\n"
        )
        return request.encode('utf-8')
    
    def _get_local_ip(self, target_ip: str) -> str:
        """Get local IP address that can reach the target."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target_ip, 5060))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "0.0.0.0"
    
    def scan(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        progress_callback: Optional[Any] = None,
    ):
        """
        Scan a network for SIP devices.
        
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
        
        logger.info(f"Starting SIP scan on {len(all_ips)} hosts")
        
        def scan_host(ip):
            """Scan a single host for SIP services."""
            for port in SIP_PORTS:
                if self.is_cancelled:
                    return None
                device = self._probe_sip_sync(ip, port)
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
                        logger.info(f"SIP found: {result['ip_address']} - {result.get('vendor', 'Unknown')}")
                        yield ScanResult(
                            ip_address=result['ip_address'],
                            mac_address=None,
                            hostname="",
                            vendor=result.get('vendor'),
                            device_type=DeviceType.VOIP,
                            open_ports=[result.get('port', 5060)],
                            services={"sip": result.get('user_agent', '')},
                            raw_data={"sip": result},
                        )
                except Exception as e:
                    logger.debug(f"SIP scan error: {e}")
        
        logger.info("SIP scan complete")
    
    def _probe_sip_sync(self, ip: str, port: int) -> Optional[SIPDevice]:
        """Send SIP OPTIONS request and parse response (sync version)."""
        try:
            local_ip = self._get_local_ip(ip)
            request = self._build_options_request(ip, port, local_ip)
            
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.bind(('', 0))
            
            # Send OPTIONS request
            sock.sendto(request, (ip, port))
            
            # Wait for response
            try:
                data, addr = sock.recvfrom(4096)
                response = data.decode('utf-8', errors='ignore')
                
                # Check for valid SIP response
                if response.startswith("SIP/2.0"):
                    device = self._parse_response(ip, port, response)
                    sock.close()
                    return device
                    
            except socket.timeout:
                pass
            
            sock.close()
            
        except Exception as e:
            logger.debug(f"SIP probe error for {ip}:{port}: {e}")
        
        return None
    
    def _parse_response(self, ip: str, port: int, response: str) -> Optional[SIPDevice]:
        """Parse SIP response headers."""
        try:
            lines = response.split("\r\n")
            headers = {}
            
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            
            return SIPDevice(
                ip_address=ip,
                port=port,
                user_agent=headers.get("user-agent", ""),
                server=headers.get("server", ""),
                allow=headers.get("allow", ""),
                supported=headers.get("supported", ""),
                contact=headers.get("contact", ""),
            )
            
        except Exception as e:
            logger.debug(f"Error parsing SIP response: {e}")
            return None
    
    def _device_to_dict(self, device: SIPDevice) -> Dict[str, Any]:
        """Convert a SIP device to a device dictionary."""
        # Determine vendor and device type
        vendor = ""
        device_type = "VOIP_PHONE"
        model = ""
        
        # Check User-Agent and Server headers
        check_str = f"{device.user_agent} {device.server}"
        
        for pattern, (sig_vendor, sig_type) in SIP_SIGNATURES.items():
            if re.search(pattern, check_str, re.IGNORECASE):
                vendor = sig_vendor
                device_type = sig_type
                break
        
        # Extract model number
        if vendor in MODEL_PATTERNS:
            match = re.search(MODEL_PATTERNS[vendor], check_str, re.IGNORECASE)
            if match:
                model = match.group(1)
        
        # If no model found, use User-Agent as model hint
        if not model and device.user_agent:
            # Clean up User-Agent for model
            model = device.user_agent.split("/")[0].strip()
            if len(model) > 50:
                model = model[:50]
        
        return {
            "ip_address": device.ip_address,
            "hostname": "",
            "vendor": vendor,
            "model": model,
            "device_type": device_type,
            "protocols": ["sip"],
            "ports": [device.port],
            "sip_info": {
                "user_agent": device.user_agent,
                "server": device.server,
                "allow": device.allow,
                "supported": device.supported,
            },
        }


async def scan(network: str, timeout: float = 2.0, **kwargs) -> List[Dict[str, Any]]:
    """Module-level scan function for scanner registry."""
    scanner = SIPScanner(timeout=timeout)
    return await scanner.scan(network)
