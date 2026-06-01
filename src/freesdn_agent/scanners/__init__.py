"""Network scanner plugins for FreeSDN Agent."""

from freesdn_agent.scanners.base import BaseScanner, ScanResult, ScanProgress, DeviceType
from freesdn_agent.scanners.arp import ARPScanner
from freesdn_agent.scanners.ping import PingScanner
from freesdn_agent.scanners.onvif import ONVIFScanner
from freesdn_agent.scanners.sadp import SADPScanner
from freesdn_agent.scanners.tcp_port import TCPPortScanner, PORT_PRESETS
from freesdn_agent.scanners.http_service import HTTPServiceScanner
from freesdn_agent.scanners.banner import BannerScanner
from freesdn_agent.scanners.snmp import SNMPScanner
from freesdn_agent.scanners.netbios import NetBIOSScanner
from freesdn_agent.scanners.mdns import MDNSScanner
from freesdn_agent.scanners.ssdp import SSDPScanner
from freesdn_agent.scanners.sip import SIPScanner
from freesdn_agent.scanners.dns import DNSScanner
from freesdn_agent.scanners.rtsp import RTSPScanner

__all__ = [
    # Base classes
    "BaseScanner",
    "ScanResult",
    "ScanProgress",
    "DeviceType",
    
    # Layer 2/3 scanners
    "ARPScanner",
    "PingScanner",
    
    # Layer 4 scanners
    "TCPPortScanner",
    "PORT_PRESETS",
    
    # Application layer scanners
    "ONVIFScanner",
    "SADPScanner",
    "HTTPServiceScanner",
    "BannerScanner",
    "SNMPScanner",
    "NetBIOSScanner",
    
    # Discovery protocols
    "MDNSScanner",
    "SSDPScanner",
    "SIPScanner",
    
    # Additional scanners
    "DNSScanner",
    "RTSPScanner",
]

# Scanner registry for dynamic loading
SCANNER_REGISTRY = {
    "ping": PingScanner,
    "arp": ARPScanner,
    "onvif": ONVIFScanner,
    "sadp": SADPScanner,
    "tcp_port": TCPPortScanner,
    "http_service": HTTPServiceScanner,
    "banner": BannerScanner,
    "snmp": SNMPScanner,
    "netbios": NetBIOSScanner,
    "mdns": MDNSScanner,
    "ssdp": SSDPScanner,
    "sip": SIPScanner,
    "dns": DNSScanner,
    "rtsp": RTSPScanner,
}


def get_scanner(name: str) -> type:
    """Get scanner class by name."""
    return SCANNER_REGISTRY.get(name)


def get_available_scanners() -> dict:
    """Get all available scanners."""
    return {
        name: {
            "class": cls,
            "display_name": cls.DISPLAY_NAME,
            "requires_root": cls.REQUIRES_ROOT,
        }
        for name, cls in SCANNER_REGISTRY.items()
    }
