"""
SNMP Scanner Module.

Uses SNMP to discover and identify network devices.
"""

import logging
import socket
import struct
from typing import Optional, Generator, Callable, List, Dict
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from freesdn_agent.scanners.base import BaseScanner, ScanResult, ScanProgress, DeviceType

logger = logging.getLogger(__name__)


# Common SNMP OIDs
OIDS = {
    # System MIB
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysServices": "1.3.6.1.2.1.1.7.0",
    
    # Interface count
    "ifNumber": "1.3.6.1.2.1.2.1.0",
    
    # Entity MIB (for serial numbers, etc.)
    "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2.1",
    "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11.1",
    "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13.1",
    
    # Vendor-specific
    "hrDeviceDescr": "1.3.6.1.2.1.25.3.2.1.3.1",  # Host Resources
}

# Device identification from sysDescr
SNMP_SIGNATURES = [
    # Switches
    {"pattern": "cisco", "vendor": "Cisco", "type": DeviceType.SWITCH},
    {"pattern": "juniper", "vendor": "Juniper", "type": DeviceType.SWITCH},
    {"pattern": "hp.*procurve", "vendor": "HP", "type": DeviceType.SWITCH},
    {"pattern": "aruba", "vendor": "Aruba", "type": DeviceType.SWITCH},
    {"pattern": "dell.*powerswitch", "vendor": "Dell", "type": DeviceType.SWITCH},
    {"pattern": "extreme", "vendor": "Extreme", "type": DeviceType.SWITCH},
    {"pattern": "brocade", "vendor": "Brocade", "type": DeviceType.SWITCH},
    {"pattern": "zyxel", "vendor": "ZyXEL", "type": DeviceType.SWITCH},
    {"pattern": "netgear.*switch", "vendor": "Netgear", "type": DeviceType.SWITCH},
    {"pattern": "unifi.*switch", "vendor": "Ubiquiti", "type": DeviceType.SWITCH},
    
    # Routers
    {"pattern": "mikrotik", "vendor": "MikroTik", "type": DeviceType.ROUTER},
    {"pattern": "routeros", "vendor": "MikroTik", "type": DeviceType.ROUTER},
    {"pattern": "vyatta|vyos", "vendor": "VyOS", "type": DeviceType.ROUTER},
    {"pattern": "edgerouter|ubiquiti.*router", "vendor": "Ubiquiti", "type": DeviceType.ROUTER},
    {"pattern": "netgear.*router", "vendor": "Netgear", "type": DeviceType.ROUTER},
    {"pattern": "tp-link.*router", "vendor": "TP-Link", "type": DeviceType.ROUTER},
    
    # Firewalls
    {"pattern": "fortigate|fortios", "vendor": "Fortinet", "type": DeviceType.FIREWALL},
    {"pattern": "pfsense", "vendor": "pfSense", "type": DeviceType.FIREWALL},
    {"pattern": "opnsense", "vendor": "OPNsense", "type": DeviceType.FIREWALL},
    {"pattern": "sonicwall", "vendor": "SonicWall", "type": DeviceType.FIREWALL},
    {"pattern": "palo alto", "vendor": "Palo Alto", "type": DeviceType.FIREWALL},
    {"pattern": "watchguard", "vendor": "WatchGuard", "type": DeviceType.FIREWALL},
    
    # Access Points
    {"pattern": "unifi.*ap|ubiquiti.*ap", "vendor": "Ubiquiti", "type": DeviceType.ACCESS_POINT},
    {"pattern": "ruckus", "vendor": "Ruckus", "type": DeviceType.ACCESS_POINT},
    {"pattern": "meraki.*mr", "vendor": "Cisco Meraki", "type": DeviceType.ACCESS_POINT},
    {"pattern": "aruba.*iap", "vendor": "Aruba", "type": DeviceType.ACCESS_POINT},
    
    # Cameras
    {"pattern": "hikvision", "vendor": "Hikvision", "type": DeviceType.CAMERA},
    {"pattern": "dahua", "vendor": "Dahua", "type": DeviceType.CAMERA},
    {"pattern": "axis.*camera", "vendor": "Axis", "type": DeviceType.CAMERA},
    
    # NVR/DVR
    {"pattern": "nvr|network video recorder", "vendor": None, "type": DeviceType.NVR},
    {"pattern": "dvr|digital video recorder", "vendor": None, "type": DeviceType.DVR},
    
    # Printers
    {"pattern": "hp.*laserjet|hp.*officejet", "vendor": "HP", "type": DeviceType.PRINTER},
    {"pattern": "brother", "vendor": "Brother", "type": DeviceType.PRINTER},
    {"pattern": "xerox", "vendor": "Xerox", "type": DeviceType.PRINTER},
    {"pattern": "lexmark", "vendor": "Lexmark", "type": DeviceType.PRINTER},
    {"pattern": "ricoh", "vendor": "Ricoh", "type": DeviceType.PRINTER},
    {"pattern": "canon.*printer", "vendor": "Canon", "type": DeviceType.PRINTER},
    {"pattern": "epson", "vendor": "Epson", "type": DeviceType.PRINTER},
    
    # Servers/NAS
    {"pattern": "synology", "vendor": "Synology", "type": DeviceType.SERVER},
    {"pattern": "qnap", "vendor": "QNAP", "type": DeviceType.SERVER},
    {"pattern": "freenas|truenas", "vendor": "TrueNAS", "type": DeviceType.SERVER},
    {"pattern": "windows", "vendor": "Microsoft", "type": DeviceType.SERVER},
    {"pattern": "linux|ubuntu|debian|centos|redhat", "vendor": None, "type": DeviceType.SERVER},
    
    # UPS
    {"pattern": "apc.*ups|smart-ups", "vendor": "APC", "type": DeviceType.IOT_DEVICE},
    {"pattern": "eaton.*ups", "vendor": "Eaton", "type": DeviceType.IOT_DEVICE},
    {"pattern": "cyberpower.*ups", "vendor": "CyberPower", "type": DeviceType.IOT_DEVICE},
    
    # VoIP Phones
    {"pattern": "sangoma|digium", "vendor": "Sangoma", "type": DeviceType.VOIP_PHONE},
    {"pattern": "polycom", "vendor": "Polycom", "type": DeviceType.VOIP_PHONE},
    {"pattern": "yealink", "vendor": "Yealink", "type": DeviceType.VOIP_PHONE},
    {"pattern": "grandstream", "vendor": "Grandstream", "type": DeviceType.VOIP_PHONE},
    {"pattern": "snom", "vendor": "Snom", "type": DeviceType.VOIP_PHONE},
    {"pattern": "fanvil", "vendor": "Fanvil", "type": DeviceType.VOIP_PHONE},
    {"pattern": "cisco.*phone|cp-", "vendor": "Cisco", "type": DeviceType.VOIP_PHONE},
    {"pattern": "avaya", "vendor": "Avaya", "type": DeviceType.VOIP_PHONE},
]


@dataclass
class SNMPResult:
    """Result of SNMP query."""
    ip_address: str
    community: str
    snmp_version: str
    sys_descr: Optional[str] = None
    sys_object_id: Optional[str] = None
    sys_name: Optional[str] = None
    sys_location: Optional[str] = None
    sys_contact: Optional[str] = None
    sys_uptime: Optional[int] = None
    interface_count: Optional[int] = None
    serial_number: Optional[str] = None
    model: Optional[str] = None
    response_time_ms: Optional[float] = None
    extra_oids: Dict[str, str] = field(default_factory=dict)


class SNMPScanner(BaseScanner):
    """
    SNMP Scanner for device discovery.
    
    Queries SNMP-enabled devices to collect system information
    for identification and inventory.
    """
    
    SCANNER_NAME = "snmp"
    DISPLAY_NAME = "SNMP Scanner"
    REQUIRES_ROOT = False
    
    DEFAULT_COMMUNITIES = ["public", "private"]
    SNMP_PORT = 161
    
    def __init__(
        self,
        timeout: float = 2.0,
        concurrency: int = 50,
        communities: Optional[List[str]] = None,
        snmp_versions: Optional[List[str]] = None,
        query_all_oids: bool = True,
    ):
        """
        Initialize SNMP scanner.
        
        Args:
            timeout: Query timeout
            concurrency: Max concurrent queries
            communities: SNMP community strings to try
            snmp_versions: SNMP versions to try (1, 2c)
            query_all_oids: Whether to query extended OIDs
        """
        super().__init__(timeout=timeout, concurrency=concurrency)
        self.communities = communities or self.DEFAULT_COMMUNITIES
        self.snmp_versions = snmp_versions or ["2c", "1"]
        self.query_all_oids = query_all_oids
    
    def scan(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
    ) -> Generator[ScanResult, None, None]:
        """
        Scan targets for SNMP devices.
        
        Args:
            targets: IP addresses to scan
            interface: Not used
            progress_callback: Progress callback
            
        Yields:
            ScanResult for each SNMP-enabled host
        """
        self.reset()
        
        total = len(targets)
        completed = 0
        devices_found = 0
        
        logger.info(f"Starting SNMP scan of {total} hosts")
        
        start_time = datetime.now()
        
        if progress_callback:
            progress_callback(ScanProgress(
                scanner_name=self.SCANNER_NAME,
                status="starting",
                progress=0,
            ))
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {
                executor.submit(self._query_host, ip): ip
                for ip in targets
            }
            
            for future in as_completed(futures):
                if self._cancelled:
                    break
                
                completed += 1
                ip = futures[future]
                
                try:
                    result = future.result()
                    if result:
                        devices_found += 1
                        device_info = self._analyze_snmp_result(result)
                        
                        yield ScanResult(
                            ip_address=ip,
                            hostname=result.sys_name,
                            device_type=device_info.get("type", DeviceType.UNKNOWN),
                            vendor=device_info.get("vendor"),
                            model=result.model,
                            serial_number=result.serial_number,
                            discovered_by=self.SCANNER_NAME,
                            discovered_at=datetime.utcnow(),
                            extra={
                                "snmp_community": result.community,
                                "snmp_version": result.snmp_version,
                                "sys_descr": result.sys_descr,
                                "sys_object_id": result.sys_object_id,
                                "sys_location": result.sys_location,
                                "sys_contact": result.sys_contact,
                                "sys_uptime_seconds": result.sys_uptime,
                                "interface_count": result.interface_count,
                            },
                        )
                except Exception as e:
                    logger.debug(f"SNMP error for {ip}: {e}")
                
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
        
        logger.info(f"SNMP scan completed: {devices_found} SNMP-enabled hosts")
    
    def _query_host(self, ip: str) -> Optional[SNMPResult]:
        """
        Query a single host for SNMP information.
        
        Args:
            ip: Target IP address
            
        Returns:
            SNMPResult if SNMP is available
        """
        # Try each community and version combination
        for community in self.communities:
            for version in self.snmp_versions:
                result = self._try_snmp_query(ip, community, version)
                if result:
                    return result
        
        return None
    
    def _try_snmp_query(self, ip: str, community: str, version: str) -> Optional[SNMPResult]:
        """
        Attempt SNMP query with specific community and version.
        
        Args:
            ip: Target IP
            community: Community string
            version: SNMP version
            
        Returns:
            SNMPResult if successful
        """
        start_time = datetime.now()
        
        # Try to get sysDescr first as a test
        sys_descr = self._get_oid(ip, community, version, OIDS["sysDescr"])
        
        if sys_descr is None:
            return None
        
        response_time = (datetime.now() - start_time).total_seconds() * 1000
        
        result = SNMPResult(
            ip_address=ip,
            community=community,
            snmp_version=version,
            sys_descr=sys_descr,
            response_time_ms=response_time,
        )
        
        # Get additional OIDs
        if self.query_all_oids:
            result.sys_name = self._get_oid(ip, community, version, OIDS["sysName"])
            result.sys_location = self._get_oid(ip, community, version, OIDS["sysLocation"])
            result.sys_contact = self._get_oid(ip, community, version, OIDS["sysContact"])
            result.sys_object_id = self._get_oid(ip, community, version, OIDS["sysObjectID"])
            
            # Try to get uptime
            uptime_raw = self._get_oid(ip, community, version, OIDS["sysUpTime"])
            if uptime_raw:
                try:
                    result.sys_uptime = int(uptime_raw) // 100  # Convert ticks to seconds
                except:
                    pass
            
            # Try to get interface count
            if_num = self._get_oid(ip, community, version, OIDS["ifNumber"])
            if if_num:
                try:
                    result.interface_count = int(if_num)
                except:
                    pass
            
            # Try to get serial and model from Entity MIB
            result.serial_number = self._get_oid(ip, community, version, OIDS["entPhysicalSerialNum"])
            result.model = self._get_oid(ip, community, version, OIDS["entPhysicalModelName"])
        
        return result
    
    def _get_oid(self, ip: str, community: str, version: str, oid: str) -> Optional[str]:
        """
        Get a single OID value via SNMP.
        
        This is a simplified SNMP GET implementation using raw sockets.
        For production use, consider using pysnmp library.
        
        Args:
            ip: Target IP
            community: Community string
            version: SNMP version
            oid: OID to query
            
        Returns:
            OID value as string, or None
        """
        try:
            # Build SNMP GET request packet
            packet = self._build_snmp_get(community, oid, version)
            
            # Send via UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(packet, (ip, self.SNMP_PORT))
            
            # Receive response
            response, _ = sock.recvfrom(65535)
            sock.close()
            
            # Parse response
            value = self._parse_snmp_response(response)
            return value
            
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"SNMP GET error for {ip} OID {oid}: {e}")
            return None
    
    def _build_snmp_get(self, community: str, oid: str, version: str) -> bytes:
        """
        Build a simple SNMP GET request packet.
        
        Args:
            community: Community string
            oid: OID to query
            version: "1" or "2c"
            
        Returns:
            SNMP packet bytes
        """
        # Encode OID
        oid_parts = [int(x) for x in oid.split('.')]
        encoded_oid = bytes([oid_parts[0] * 40 + oid_parts[1]])
        for part in oid_parts[2:]:
            if part < 128:
                encoded_oid += bytes([part])
            else:
                # Multi-byte encoding
                chunks = []
                while part > 0:
                    chunks.append(part & 0x7F)
                    part >>= 7
                for i, chunk in enumerate(reversed(chunks)):
                    if i < len(chunks) - 1:
                        encoded_oid += bytes([chunk | 0x80])
                    else:
                        encoded_oid += bytes([chunk])
        
        # Build varbind (OID + NULL)
        varbind = bytes([0x06, len(encoded_oid)]) + encoded_oid + bytes([0x05, 0x00])
        varbind_list = bytes([0x30, len(varbind)]) + varbind
        varbind_seq = bytes([0x30, len(varbind_list)]) + varbind_list
        
        # Request ID
        request_id = bytes([0x02, 0x04, 0x00, 0x00, 0x00, 0x01])
        
        # Error status and index
        error = bytes([0x02, 0x01, 0x00, 0x02, 0x01, 0x00])
        
        # PDU (GET request = 0xA0)
        pdu_content = request_id + error + varbind_seq
        pdu = bytes([0xA0, len(pdu_content)]) + pdu_content
        
        # Community
        community_bytes = community.encode('ascii')
        community_field = bytes([0x04, len(community_bytes)]) + community_bytes
        
        # Version (0 = v1, 1 = v2c)
        ver_num = 0 if version == "1" else 1
        version_field = bytes([0x02, 0x01, ver_num])
        
        # Message
        message_content = version_field + community_field + pdu
        message = bytes([0x30, len(message_content)]) + message_content
        
        return message
    
    def _parse_snmp_response(self, data: bytes) -> Optional[str]:
        """
        Parse SNMP response and extract value.
        
        Args:
            data: Raw SNMP response bytes
            
        Returns:
            Value as string, or None
        """
        try:
            # Very simplified BER/ASN.1 parsing
            # In production, use a proper library like pyasn1
            
            # Find the value in the varbind
            # Look for common value types after OID
            
            i = 0
            while i < len(data) - 2:
                tag = data[i]
                
                # Check for string types
                if tag == 0x04:  # OCTET STRING
                    length = data[i + 1]
                    if length < 128:
                        value = data[i + 2:i + 2 + length]
                        # Return if it looks like text
                        try:
                            text = value.decode('utf-8', errors='ignore').strip()
                            if text and len(text) > 0:
                                # Skip if it's just nulls or control chars
                                if any(c.isalnum() for c in text):
                                    return text
                        except:
                            pass
                
                # Check for integer
                elif tag == 0x02:  # INTEGER
                    length = data[i + 1]
                    if length < 128 and length <= 4:
                        value = 0
                        for j in range(length):
                            value = (value << 8) | data[i + 2 + j]
                        # Continue searching for string values
                
                # Check for OID
                elif tag == 0x06:  # OBJECT IDENTIFIER
                    length = data[i + 1]
                    if length < 128:
                        i += 2 + length
                        continue
                
                # Check for timeticks
                elif tag == 0x43:  # TimeTicks
                    length = data[i + 1]
                    if length < 128 and length <= 4:
                        value = 0
                        for j in range(length):
                            value = (value << 8) | data[i + 2 + j]
                        return str(value)
                
                # Check for counter/gauge
                elif tag in (0x41, 0x42):  # Counter32, Gauge32
                    length = data[i + 1]
                    if length < 128 and length <= 4:
                        value = 0
                        for j in range(length):
                            value = (value << 8) | data[i + 2 + j]
                        return str(value)
                
                i += 1
            
            return None
            
        except Exception as e:
            logger.debug(f"SNMP parse error: {e}")
            return None
    
    def _analyze_snmp_result(self, result: SNMPResult) -> Dict:
        """
        Analyze SNMP result to identify device type.
        
        Args:
            result: SNMP query result
            
        Returns:
            Dict with device info
        """
        info = {
            "type": DeviceType.UNKNOWN,
            "vendor": None,
        }
        
        if not result.sys_descr:
            return info
        
        sys_descr_lower = result.sys_descr.lower()
        
        import re
        for sig in SNMP_SIGNATURES:
            if re.search(sig["pattern"], sys_descr_lower, re.I):
                info["type"] = sig["type"]
                if sig["vendor"]:
                    info["vendor"] = sig["vendor"]
                return info
        
        # If we have many interfaces, probably a switch
        if result.interface_count and result.interface_count > 8:
            info["type"] = DeviceType.SWITCH
        
        return info
