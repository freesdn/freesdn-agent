"""
OUI (MAC Vendor) Lookup Service.

Looks up device vendor from MAC address using the OUI database.
"""

import logging
from typing import Optional
from functools import lru_cache

logger = logging.getLogger(__name__)

# Lazy-loaded vendor lookup instance
_vendor_lookup = None


def _get_vendor_lookup():
    """Get or create the vendor lookup instance."""
    global _vendor_lookup
    
    if _vendor_lookup is None:
        try:
            from mac_vendor_lookup import MacLookup
            _vendor_lookup = MacLookup()
            # Update database if needed (do this on first run)
            # _vendor_lookup.update_vendors()
        except ImportError:
            logger.warning("mac-vendor-lookup not installed")
            _vendor_lookup = False
        except Exception as e:
            logger.warning(f"Failed to initialize MAC vendor lookup: {e}")
            _vendor_lookup = False
    
    return _vendor_lookup


@lru_cache(maxsize=1024)
def lookup_vendor(mac_address: str) -> Optional[str]:
    """
    Look up vendor name from MAC address.
    
    Args:
        mac_address: MAC address in any common format
                     (AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, AABBCCDDEEFF)
    
    Returns:
        Vendor name or None if not found
    """
    if not mac_address:
        return None
    
    # First check our curated list of known vendors
    # (handles rebranded OEM devices like Sangoma phones)
    fallback_result = _fallback_lookup(mac_address)
    if fallback_result:
        return fallback_result
    
    lookup = _get_vendor_lookup()
    
    if lookup is False:
        return None
    
    try:
        vendor = lookup.lookup(mac_address)
        return vendor if vendor else None
    except Exception:
        return None


def _normalize_mac(mac_address: str) -> str:
    """Normalize MAC address to uppercase with colons."""
    # Remove all separators
    mac = mac_address.upper().replace(":", "").replace("-", "").replace(".", "")
    
    # Format with colons
    if len(mac) == 12:
        return ":".join(mac[i:i+2] for i in range(0, 12, 2))
    
    return mac_address.upper()


def _fallback_lookup(mac_address: str) -> Optional[str]:
    """
    Fallback vendor lookup using known OUI prefixes.
    
    This is used when mac-vendor-lookup is not available.
    """
    # Known vendor prefixes (first 3 bytes of MAC)
    KNOWN_VENDORS = {
        # Hikvision
        "28:57:BE": "Hikvision",
        "44:19:B6": "Hikvision",
        "54:C4:15": "Hikvision",
        "7C:1E:52": "Hikvision",
        "80:EA:96": "Hikvision",
        "A4:14:37": "Hikvision",
        "C0:56:E3": "Hikvision",
        "E0:50:8B": "Hikvision",
        "F4:F0:49": "Hikvision",
        
        # Dahua
        "3C:EF:8C": "Dahua",
        "40:2D:C1": "Dahua",
        "48:8A:E2": "Dahua",
        "90:02:A9": "Dahua",
        "A0:BD:CD": "Dahua",
        "B0:A7:B9": "Dahua",
        "D4:43:0E": "Dahua",
        "F8:4D:FC": "Dahua",
        
        # TP-Link
        "00:31:92": "TP-Link",
        "10:27:F5": "TP-Link",
        "14:CC:20": "TP-Link",
        "18:A6:F7": "TP-Link",
        "30:B5:C2": "TP-Link",
        "50:C7:BF": "TP-Link",
        "60:32:B1": "TP-Link",
        "70:4F:57": "TP-Link",
        "98:DA:C4": "TP-Link",
        
        # Ubiquiti
        "00:27:22": "Ubiquiti",
        "04:18:D6": "Ubiquiti",
        "18:E8:29": "Ubiquiti",
        "24:A4:3C": "Ubiquiti",
        "44:D9:E7": "Ubiquiti",
        "68:72:51": "Ubiquiti",
        "74:83:C2": "Ubiquiti",
        "78:8A:20": "Ubiquiti",
        "80:2A:A8": "Ubiquiti",
        "B4:FB:E4": "Ubiquiti",
        "DC:9F:DB": "Ubiquiti",
        "F0:9F:C2": "Ubiquiti",
        "FC:EC:DA": "Ubiquiti",
        
        # MikroTik
        "00:0C:42": "MikroTik",
        "18:FD:74": "MikroTik",
        "2C:C8:1B": "MikroTik",
        "48:8F:5A": "MikroTik",
        "64:D1:54": "MikroTik",
        "6C:3B:6B": "MikroTik",
        "74:4D:28": "MikroTik",
        "B8:69:F4": "MikroTik",
        "C4:AD:34": "MikroTik",
        "CC:2D:E0": "MikroTik",
        "D4:CA:6D": "MikroTik",
        "E4:8D:8C": "MikroTik",
        
        # Grandstream
        "00:0B:82": "Grandstream",
        
        # Yealink
        "00:15:65": "Yealink",
        "80:5E:C0": "Yealink",
        "24:51:42": "Yealink",
        
        # Sangoma/Digium (VoIP phones and PBX)
        "00:0F:D2": "Sangoma",
        "00:0F:F8": "Sangoma",
        "74:EE:2A": "Sangoma",
        "D4:61:9D": "Sangoma",
        "EC:74:D7": "Sangoma",
        
        # Polycom (VoIP phones)
        "00:04:F2": "Polycom",
        "00:E0:DB": "Polycom",
        "64:16:7F": "Polycom",
        
        # Fanvil
        "0C:38:3E": "Fanvil",
        
        # Snom
        "00:04:13": "Snom",
        
        # Avaya
        "00:04:0D": "Avaya",
        "00:09:6E": "Avaya",
        "00:1B:4F": "Avaya",
        
        # Cisco
        "00:00:0C": "Cisco",
        "00:01:42": "Cisco",
        "00:1A:A1": "Cisco",
        "00:1B:0D": "Cisco",
        "00:25:B4": "Cisco",
        "00:26:CB": "Cisco",
        "00:50:56": "Cisco/VMware",
        
        # Aruba
        "00:0B:86": "Aruba",
        "00:1A:1E": "Aruba",
        "00:24:6C": "Aruba",
        "04:BD:88": "Aruba",
        "20:4C:03": "Aruba",
        "24:DE:C6": "Aruba",
        "40:E3:D6": "Aruba",
        "70:3A:0E": "Aruba",
        "9C:1C:12": "Aruba",
        
        # HP
        "00:00:63": "HP",
        "00:08:83": "HP",
        "00:0B:CD": "HP",
        "00:11:0A": "HP",
        "00:14:C2": "HP",
        "00:1E:0B": "HP",
        "00:22:64": "HP",
        "00:25:B3": "HP",
        
        # Dell
        "00:06:5B": "Dell",
        "00:08:74": "Dell",
        "00:0B:DB": "Dell",
        "00:0D:56": "Dell",
        "00:0F:1F": "Dell",
        "00:11:43": "Dell",
        "00:12:3F": "Dell",
        "00:14:22": "Dell",
        
        # Apple
        "00:03:93": "Apple",
        "00:0A:27": "Apple",
        "00:0A:95": "Apple",
        "00:10:FA": "Apple",
        "00:11:24": "Apple",
        "00:14:51": "Apple",
        "00:16:CB": "Apple",
        "00:17:F2": "Apple",
        "00:19:E3": "Apple",
        
        # Microsoft
        "00:03:FF": "Microsoft",
        "00:0D:3A": "Microsoft",
        "00:15:5D": "Microsoft (Hyper-V)",
        "00:17:FA": "Microsoft",
        "00:1D:D8": "Microsoft",
        "28:18:78": "Microsoft",
        "60:45:BD": "Microsoft",
        
        # Samsung
        "00:00:F0": "Samsung",
        "00:02:78": "Samsung",
        "00:07:AB": "Samsung",
        "00:09:18": "Samsung",
        "00:12:47": "Samsung",
        "00:13:77": "Samsung",
        
        # Intel
        "00:02:B3": "Intel",
        "00:03:47": "Intel",
        "00:04:23": "Intel",
        "00:07:E9": "Intel",
        "00:0C:F1": "Intel",
        "00:0E:0C": "Intel",
        "00:0E:35": "Intel",
    }
    
    mac = _normalize_mac(mac_address)
    prefix = mac[:8]  # First 3 bytes (AA:BB:CC)
    
    return KNOWN_VENDORS.get(prefix)
