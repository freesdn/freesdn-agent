"""
NetBIOS/SMB Scanner Module.

Discovers Windows devices on the network using NetBIOS and SMB protocols.
"""

import logging
import socket
import struct
import re
from typing import Optional, Generator, Callable, List, Dict, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from freesdn_agent.scanners.base import BaseScanner, ScanResult, ScanProgress, DeviceType

logger = logging.getLogger(__name__)


@dataclass
class NetBIOSResult:
    """Result of NetBIOS query."""
    ip_address: str
    netbios_name: Optional[str] = None
    domain: Optional[str] = None
    mac_address: Optional[str] = None
    is_server: bool = False
    is_workstation: bool = False
    is_domain_controller: bool = False
    names: List[Tuple[str, str]] = field(default_factory=list)  # (name, type)
    response_time_ms: Optional[float] = None


@dataclass
class SMBResult:
    """Result of SMB negotiation."""
    ip_address: str
    smb_version: Optional[str] = None
    os_version: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    signing_enabled: bool = False
    signing_required: bool = False
    dialect: Optional[str] = None
    response_time_ms: Optional[float] = None


# NetBIOS name types
NETBIOS_TYPES = {
    0x00: "workstation",
    0x03: "messenger",
    0x06: "ras_server",
    0x1B: "domain_master",
    0x1C: "domain_controller",
    0x1D: "master_browser",
    0x1E: "browser_election",
    0x1F: "netdde",
    0x20: "server",
    0x21: "ras_client",
    0xBE: "network_monitor_agent",
    0xBF: "network_monitor",
}


class NetBIOSScanner(BaseScanner):
    """
    NetBIOS/SMB Scanner for Windows device discovery.
    
    Uses NetBIOS Name Service (port 137) and SMB (port 445) to
    identify Windows devices, servers, and domain controllers.
    """
    
    SCANNER_NAME = "netbios"
    DISPLAY_NAME = "NetBIOS/SMB Scanner"
    REQUIRES_ROOT = False
    
    NETBIOS_PORT = 137
    SMB_PORT = 445
    NETBIOS_SESSION_PORT = 139
    
    def __init__(
        self,
        timeout: float = 2.0,
        concurrency: int = 50,
        scan_netbios: bool = True,
        scan_smb: bool = True,
    ):
        """
        Initialize NetBIOS/SMB scanner.
        
        Args:
            timeout: Query timeout
            concurrency: Max concurrent queries
            scan_netbios: Whether to scan NetBIOS
            scan_smb: Whether to scan SMB
        """
        super().__init__(timeout=timeout, concurrency=concurrency)
        self.scan_netbios = scan_netbios
        self.scan_smb = scan_smb
    
    def scan(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
    ) -> Generator[ScanResult, None, None]:
        """
        Scan targets for NetBIOS/SMB devices.
        
        Args:
            targets: IP addresses to scan
            interface: Not used
            progress_callback: Progress callback
            
        Yields:
            ScanResult for each discovered host
        """
        self.reset()
        
        total = len(targets)
        completed = 0
        devices_found = 0
        
        logger.info(f"Starting NetBIOS/SMB scan of {total} hosts")
        
        start_time = datetime.now()
        
        if progress_callback:
            progress_callback(ScanProgress(
                scanner_name=self.SCANNER_NAME,
                status="starting",
                progress=0,
            ))
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {
                executor.submit(self._scan_host, ip): ip
                for ip in targets
            }
            
            for future in as_completed(futures):
                if self._cancelled:
                    break
                
                completed += 1
                ip = futures[future]
                
                try:
                    netbios_result, smb_result = future.result()
                    
                    if netbios_result or smb_result:
                        devices_found += 1
                        
                        # Combine results
                        device_info = self._combine_results(netbios_result, smb_result)
                        
                        yield ScanResult(
                            ip_address=ip,
                            hostname=device_info.get("hostname"),
                            mac_address=device_info.get("mac_address"),
                            device_type=device_info.get("type", DeviceType.UNKNOWN),
                            vendor=device_info.get("vendor"),
                            discovered_by=self.SCANNER_NAME,
                            discovered_at=datetime.utcnow(),
                            extra={
                                "netbios_name": device_info.get("netbios_name"),
                                "domain": device_info.get("domain"),
                                "os_version": device_info.get("os_version"),
                                "smb_version": device_info.get("smb_version"),
                                "is_server": device_info.get("is_server", False),
                                "is_domain_controller": device_info.get("is_domain_controller", False),
                                "smb_signing": device_info.get("smb_signing"),
                            },
                        )
                except Exception as e:
                    logger.debug(f"NetBIOS/SMB error for {ip}: {e}")
                
                if progress_callback and completed % 10 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    progress_callback(ScanProgress(
                        scanner_name=self.SCANNER_NAME,
                        status="running",
                        progress=(completed / total) * 100,
                        current_target=ip,
                        devices_found=devices_found,
                        elapsed_seconds=elapsed,
                    ))
        
        if progress_callback:
            elapsed = (datetime.now() - start_time).total_seconds()
            progress_callback(ScanProgress(
                scanner_name=self.SCANNER_NAME,
                status="completed" if not self._cancelled else "cancelled",
                progress=100,
                devices_found=devices_found,
                elapsed_seconds=elapsed,
            ))
        
        logger.info(f"NetBIOS/SMB scan completed: {devices_found} hosts")
    
    def _scan_host(self, ip: str) -> Tuple[Optional[NetBIOSResult], Optional[SMBResult]]:
        """
        Scan a single host for NetBIOS and SMB.
        
        Args:
            ip: Target IP
            
        Returns:
            Tuple of (NetBIOSResult, SMBResult)
        """
        netbios_result = None
        smb_result = None
        
        if self.scan_netbios:
            netbios_result = self._query_netbios(ip)
        
        if self.scan_smb:
            smb_result = self._query_smb(ip)
        
        return netbios_result, smb_result
    
    def _query_netbios(self, ip: str) -> Optional[NetBIOSResult]:
        """
        Query NetBIOS Name Service for host information.
        
        Args:
            ip: Target IP
            
        Returns:
            NetBIOSResult or None
        """
        start_time = datetime.now()
        
        try:
            # Build NetBIOS Name Service query
            packet = self._build_nbns_query()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(packet, (ip, self.NETBIOS_PORT))
            
            response, _ = sock.recvfrom(65535)
            sock.close()
            
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Parse response
            result = self._parse_nbns_response(response, ip)
            if result:
                result.response_time_ms = response_time
            
            return result
            
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"NetBIOS query error for {ip}: {e}")
            return None
    
    def _build_nbns_query(self) -> bytes:
        """Build NetBIOS Name Service NBSTAT query."""
        # Transaction ID
        trans_id = struct.pack(">H", 0x0001)
        
        # Flags: standard query
        flags = struct.pack(">H", 0x0000)
        
        # Questions: 1, Answer/Auth/Additional: 0
        counts = struct.pack(">HHHH", 1, 0, 0, 0)
        
        # Query name: *
        # NetBIOS name encoding (space-padded, then encoded)
        query_name = b'\x20' + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + b'\x00'
        
        # Query type: NBSTAT (0x21), Query class: IN (0x0001)
        query_footer = struct.pack(">HH", 0x0021, 0x0001)
        
        return trans_id + flags + counts + query_name + query_footer
    
    def _parse_nbns_response(self, data: bytes, ip: str) -> Optional[NetBIOSResult]:
        """Parse NetBIOS Name Service response."""
        try:
            if len(data) < 12:
                return None
            
            # Skip header (12 bytes) and query section
            # Find the answer section
            offset = 12
            
            # Skip query name
            while offset < len(data) and data[offset] != 0:
                offset += 1
            offset += 5  # Skip null terminator and query type/class
            
            # Skip answer name
            while offset < len(data) and data[offset] != 0:
                if data[offset] & 0xC0 == 0xC0:  # Pointer
                    offset += 2
                    break
                offset += 1
            else:
                offset += 1
            
            if offset >= len(data) - 4:
                return None
            
            # Skip type, class, ttl
            offset += 10
            
            if offset >= len(data) - 2:
                return None
            
            # Get number of names
            num_names = data[offset]
            offset += 1
            
            result = NetBIOSResult(ip_address=ip)
            
            # Parse each name
            for _ in range(num_names):
                if offset + 18 > len(data):
                    break
                
                # Name is 15 bytes + 1 byte type
                name_bytes = data[offset:offset + 15]
                name_type = data[offset + 15]
                flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
                
                name = name_bytes.decode('ascii', errors='ignore').strip()
                type_name = NETBIOS_TYPES.get(name_type, f"0x{name_type:02x}")
                
                result.names.append((name, type_name))
                
                # Extract primary info
                if name_type == 0x00 and not result.netbios_name:
                    result.netbios_name = name
                    result.is_workstation = True
                elif name_type == 0x20:
                    result.is_server = True
                elif name_type == 0x1C:
                    result.domain = name
                    result.is_domain_controller = True
                elif name_type == 0x1B:
                    result.domain = name
                
                offset += 18
            
            # Get MAC address (last 6 bytes of response)
            if len(data) >= offset + 6:
                mac_bytes = data[offset:offset + 6]
                if mac_bytes != b'\x00' * 6:
                    result.mac_address = ':'.join(f'{b:02X}' for b in mac_bytes)
            
            return result if result.netbios_name else None
            
        except Exception as e:
            logger.debug(f"NBNS parse error: {e}")
            return None
    
    def _query_smb(self, ip: str) -> Optional[SMBResult]:
        """
        Perform SMB negotiation to get host information.
        
        Args:
            ip: Target IP
            
        Returns:
            SMBResult or None
        """
        start_time = datetime.now()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, self.SMB_PORT))
            
            # Send SMB1 negotiate request
            negotiate = self._build_smb_negotiate()
            sock.send(negotiate)
            
            # Receive response
            response = sock.recv(4096)
            sock.close()
            
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Parse response
            result = self._parse_smb_response(response, ip)
            if result:
                result.response_time_ms = response_time
            
            return result
            
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception as e:
            logger.debug(f"SMB query error for {ip}: {e}")
            return None
    
    def _build_smb_negotiate(self) -> bytes:
        """Build SMB1/2 negotiate request."""
        # NetBIOS Session header
        smb_packet = b''
        
        # SMB1 Header
        smb1_header = b'\xffSMB'  # Protocol signature
        smb1_header += b'\x72'    # Command: Negotiate
        smb1_header += b'\x00' * 4  # NT Status
        smb1_header += b'\x18'    # Flags
        smb1_header += b'\x53\xc0'  # Flags2 (Unicode, NT Status, Extended Security)
        smb1_header += b'\x00' * 2  # Process ID High
        smb1_header += b'\x00' * 8  # Signature
        smb1_header += b'\x00' * 2  # Reserved
        smb1_header += b'\x00' * 2  # Tree ID
        smb1_header += b'\xff\xfe'  # Process ID
        smb1_header += b'\x00' * 2  # User ID
        smb1_header += b'\x00' * 2  # Multiplex ID
        
        # Negotiate request body
        # Word count
        negotiate_body = b'\x00'  # Word count: 0
        
        # Dialects
        dialects = b'\x02NT LM 0.12\x00'  # SMB1
        dialects += b'\x02SMB 2.002\x00'   # SMB2.0
        dialects += b'\x02SMB 2.???\x00'   # SMB2.x/3.x
        
        # Byte count
        negotiate_body += struct.pack('<H', len(dialects))
        negotiate_body += dialects
        
        smb_packet = smb1_header + negotiate_body
        
        # NetBIOS header (length)
        netbios_header = b'\x00'  # Session message
        netbios_header += struct.pack('>I', len(smb_packet))[1:]  # 3-byte length
        
        return netbios_header + smb_packet
    
    def _parse_smb_response(self, data: bytes, ip: str) -> Optional[SMBResult]:
        """Parse SMB negotiate response."""
        try:
            if len(data) < 40:
                return None
            
            # Skip NetBIOS header
            offset = 4
            
            # Check protocol signature
            if data[offset:offset + 4] == b'\xffSMB':
                # SMB1 response
                return self._parse_smb1_response(data[offset:], ip)
            elif data[offset:offset + 4] == b'\xfeSMB':
                # SMB2/3 response
                return self._parse_smb2_response(data[offset:], ip)
            
            return None
            
        except Exception as e:
            logger.debug(f"SMB parse error: {e}")
            return None
    
    def _parse_smb1_response(self, data: bytes, ip: str) -> Optional[SMBResult]:
        """Parse SMB1 negotiate response."""
        result = SMBResult(ip_address=ip, smb_version="1")
        
        try:
            # SMB1 negotiate response has OS string at variable offset
            # Word count is at offset 32
            if len(data) < 37:
                return result
            
            word_count = data[32]
            
            # Byte count follows the words
            byte_offset = 33 + (word_count * 2)
            if byte_offset + 2 > len(data):
                return result
            
            byte_count = struct.unpack('<H', data[byte_offset:byte_offset + 2])[0]
            
            # The strings start after byte count (in Unicode)
            string_offset = byte_offset + 2
            
            if string_offset < len(data):
                # Try to extract strings (null-terminated Unicode)
                remaining = data[string_offset:]
                
                # Find null-terminated Unicode strings
                strings = []
                current = b''
                i = 0
                while i < len(remaining) - 1:
                    if remaining[i] == 0 and remaining[i + 1] == 0:
                        if current:
                            try:
                                strings.append(current.decode('utf-16-le', errors='ignore'))
                            except:
                                pass
                            current = b''
                        i += 2
                    else:
                        current += bytes([remaining[i], remaining[i + 1]])
                        i += 2
                
                if len(strings) >= 1:
                    result.os_version = strings[0]
                if len(strings) >= 2:
                    result.domain = strings[1] if strings[1] else None
            
            result.dialect = "NT LM 0.12"
            
        except Exception as e:
            logger.debug(f"SMB1 parse error: {e}")
        
        return result
    
    def _parse_smb2_response(self, data: bytes, ip: str) -> Optional[SMBResult]:
        """Parse SMB2/3 negotiate response."""
        result = SMBResult(ip_address=ip)
        
        try:
            if len(data) < 70:
                return result
            
            # Dialect at offset 70
            dialect_raw = struct.unpack('<H', data[70:72])[0]
            
            dialects = {
                0x0202: ("2.0.2", "2.0"),
                0x0210: ("2.1", "2.1"),
                0x0300: ("3.0", "3.0"),
                0x0302: ("3.0.2", "3.0.2"),
                0x0311: ("3.1.1", "3.1.1"),
            }
            
            if dialect_raw in dialects:
                result.dialect, result.smb_version = dialects[dialect_raw]
            else:
                result.smb_version = f"2.x (0x{dialect_raw:04x})"
            
            # Security mode at offset 66
            if len(data) >= 67:
                security_mode = data[66]
                result.signing_enabled = bool(security_mode & 0x01)
                result.signing_required = bool(security_mode & 0x02)
            
        except Exception as e:
            logger.debug(f"SMB2 parse error: {e}")
        
        return result
    
    def _combine_results(
        self, 
        netbios: Optional[NetBIOSResult], 
        smb: Optional[SMBResult]
    ) -> Dict:
        """
        Combine NetBIOS and SMB results.
        
        Args:
            netbios: NetBIOS result
            smb: SMB result
            
        Returns:
            Combined device info dict
        """
        info = {
            "type": DeviceType.UNKNOWN,
            "vendor": "Microsoft",
        }
        
        if netbios:
            info["netbios_name"] = netbios.netbios_name
            info["hostname"] = netbios.netbios_name
            info["mac_address"] = netbios.mac_address
            info["is_server"] = netbios.is_server
            info["is_domain_controller"] = netbios.is_domain_controller
            
            if netbios.domain:
                info["domain"] = netbios.domain
            
            # Determine device type
            if netbios.is_domain_controller:
                info["type"] = DeviceType.SERVER
            elif netbios.is_server:
                info["type"] = DeviceType.SERVER
            elif netbios.is_workstation:
                info["type"] = DeviceType.WORKSTATION
        
        if smb:
            if not info.get("hostname") and smb.hostname:
                info["hostname"] = smb.hostname
            
            if smb.domain:
                info["domain"] = smb.domain
            
            info["os_version"] = smb.os_version
            info["smb_version"] = smb.smb_version
            
            if smb.signing_required:
                info["smb_signing"] = "required"
            elif smb.signing_enabled:
                info["smb_signing"] = "enabled"
            else:
                info["smb_signing"] = "disabled"
        
        return info
