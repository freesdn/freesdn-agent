"""
Application constants for FreeSDN Agent.
"""

from freesdn_agent import __version__, __app_name__

# Application Info
APP_NAME = __app_name__
APP_VERSION = __version__

# Network Scanning Defaults
DEFAULT_TIMEOUT = 3.0  # seconds
DEFAULT_CONCURRENCY = 50
DEFAULT_ARP_TIMEOUT = 2.0
DEFAULT_ICMP_TIMEOUT = 1.0
DEFAULT_TCP_TIMEOUT = 2.0

# Protocol Ports
SADP_PORT = 37020
SADP_MULTICAST = "239.255.255.250"
ONVIF_WS_DISCOVERY_PORT = 3702
ONVIF_MULTICAST = "239.255.255.250"
SIP_PORT = 5060
SIP_TLS_PORT = 5061
SNMP_PORT = 161
SSDP_PORT = 1900
SSDP_MULTICAST = "239.255.255.250"

# Common HTTP Ports for Devices
DEVICE_HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888]

# MAC OUI Prefixes for Known Vendors (partial list for quick classification)
HIKVISION_OUI_PREFIXES = [
    "00:0c:29", "28:57:be", "44:19:b6", "54:c4:15", "7c:1e:52",
    "80:ea:96", "a4:14:37", "c0:56:e3", "e0:50:8b", "f4:f0:49"
]

DAHUA_OUI_PREFIXES = [
    "3c:ef:8c", "40:2d:c1", "48:8a:e2", "90:02:a9", "a0:bd:cd",
    "b0:a7:b9", "d4:43:0e", "e0:50:8b", "f8:4d:fc"
]

GRANDSTREAM_OUI_PREFIXES = [
    "00:0b:82"
]

TPLINK_OUI_PREFIXES = [
    "00:31:92", "10:27:f5", "14:cc:20", "18:a6:f7", "1c:3b:f3",
    "30:b5:c2", "50:c7:bf", "54:c8:0f", "60:32:b1", "64:6e:97",
    "70:4f:57", "78:8c:b5", "88:c3:97", "90:f6:52", "98:da:c4"
]

UBIQUITI_OUI_PREFIXES = [
    "00:27:22", "04:18:d6", "18:e8:29", "24:a4:3c", "44:d9:e7",
    "68:72:51", "74:83:c2", "78:8a:20", "80:2a:a8", "b4:fb:e4",
    "dc:9f:db", "e0:63:da", "f0:9f:c2", "fc:ec:da"
]

# UI Constants
WINDOW_MIN_WIDTH = 900
WINDOW_MIN_HEIGHT = 650
WINDOW_DEFAULT_WIDTH = 1100
WINDOW_DEFAULT_HEIGHT = 750

# Scan Presets
QUICK_SCAN_PROTOCOLS = ["arp", "icmp"]
CAMERA_SCAN_PROTOCOLS = ["arp", "onvif", "sadp"]
VOIP_SCAN_PROTOCOLS = ["arp", "sip", "mdns"]
FULL_SCAN_PROTOCOLS = ["arp", "icmp", "onvif", "sadp", "sip", "snmp", "mdns", "ssdp"]
