"""
Device Cache Service.

Maintains a local cache of devices known to the FreeSDN server,
enabling fast duplicate checking before push operations.
"""

import logging
from typing import Dict, Optional, Set, List
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class CachedDevice:
    """Cached device information from server."""
    id: str
    mac_address: Optional[str]
    ip_address: Optional[str]
    name: str
    site_id: str
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    last_seen: Optional[datetime] = None


class DeviceCache:
    """
    Local cache of devices from FreeSDN server.
    
    Enables quick duplicate detection before attempting to push devices,
    reducing unnecessary API calls and providing instant feedback.
    """
    
    def __init__(self):
        """Initialize the device cache."""
        # Cache data
        self._devices_by_mac: Dict[str, CachedDevice] = {}
        self._devices_by_ip: Dict[str, CachedDevice] = {}
        self._devices_by_id: Dict[str, CachedDevice] = {}
        
        # Cache metadata
        self._site_id: Optional[str] = None
        self._last_refresh: Optional[datetime] = None
        self._cache_ttl: timedelta = timedelta(minutes=5)
    
    def is_stale(self) -> bool:
        """Check if cache needs refreshing."""
        if self._last_refresh is None:
            return True
        return datetime.now() - self._last_refresh > self._cache_ttl
    
    def refresh_from_api(self, client, site_id: str) -> int:
        """
        Refresh cache from FreeSDN API.
        
        Args:
            client: SyncFreeSDNClient instance
            site_id: Site ID to fetch devices for
            
        Returns:
            Number of devices cached
        """
        try:
            # Clear existing cache if site changed
            if self._site_id != site_id:
                self.clear()
                self._site_id = site_id
            
            # Fetch all devices from server
            logger.info(f"Fetching devices from API for site {site_id}...")
            response = client.get_devices(site_id=site_id)
            
            # Handle different response formats
            if isinstance(response, dict):
                devices = response.get("items", response.get("data", []))
            else:
                devices = response if response else []
            
            logger.info(f"API returned {len(devices)} devices")
            
            # Clear and rebuild cache
            self._devices_by_mac.clear()
            self._devices_by_ip.clear()
            self._devices_by_id.clear()
            
            # Update cache
            for device_data in devices:
                # API can return mac/ip or mac_address/ip_address
                mac = self._normalize_mac(
                    device_data.get("mac_address") or device_data.get("mac")
                )
                ip = device_data.get("ip_address") or device_data.get("ip")
                
                # Debug first few devices - show normalized MAC for comparison
                if len(self._devices_by_ip) < 5:
                    logger.info(f"  Caching device: IP={ip}, MAC={mac}")
                
                device = CachedDevice(
                    id=str(device_data.get("id", "")),
                    mac_address=mac,
                    ip_address=ip,
                    name=device_data.get("name", ""),
                    site_id=str(device_data.get("site_id", site_id)),
                    vendor=device_data.get("vendor"),
                    device_type=device_data.get("device_type"),
                )
                
                self._devices_by_id[device.id] = device
                
                if mac:
                    self._devices_by_mac[mac] = device
                
                if ip:
                    self._devices_by_ip[ip] = device
            
            self._last_refresh = datetime.now()
            
            # Log sample of cached MACs for debugging
            cached_macs = list(self._devices_by_mac.keys())[:5]
            logger.info(f"Device cache refreshed: {len(self._devices_by_mac)} MACs, {len(self._devices_by_ip)} IPs from site {site_id}")
            logger.info(f"Sample cached MACs: {cached_macs}")
            
            return len(devices)
            
        except Exception as e:
            logger.warning(f"Failed to refresh device cache: {e}", exc_info=True)
            return 0
    
    def clear(self) -> None:
        """Clear all cached data."""
        self._devices_by_mac.clear()
        self._devices_by_ip.clear()
        self._devices_by_id.clear()
        self._last_refresh = None
        self._site_id = None
        logger.debug("Device cache cleared")
    
    def add_device(self, device: CachedDevice) -> None:
        """Add a device to the cache (after successful push)."""
        self._devices_by_id[device.id] = device
        
        if device.mac_address:
            self._devices_by_mac[device.mac_address] = device
        
        if device.ip_address:
            self._devices_by_ip[device.ip_address] = device
    
    def has_mac(self, mac_address: str) -> bool:
        """Check if a MAC address exists in the cache."""
        normalized = self._normalize_mac(mac_address)
        if not normalized:
            return False
        exists = normalized in self._devices_by_mac
        # Log every MAC check for debugging
        logger.debug(f"MAC lookup: {mac_address} -> {normalized} -> {'FOUND' if exists else 'NOT FOUND'}")
        return exists
    
    def has_ip(self, ip_address: str) -> bool:
        """Check if an IP address exists in the cache."""
        if not ip_address:
            return False
        exists = ip_address in self._devices_by_ip
        return exists
    
    def get_by_mac(self, mac_address: str) -> Optional[CachedDevice]:
        """Get cached device by MAC address."""
        normalized = self._normalize_mac(mac_address)
        return self._devices_by_mac.get(normalized) if normalized else None
    
    def get_by_ip(self, ip_address: str) -> Optional[CachedDevice]:
        """Get cached device by IP address."""
        return self._devices_by_ip.get(ip_address)
    
    def get_existing_macs(self) -> Set[str]:
        """Get all cached MAC addresses."""
        return set(self._devices_by_mac.keys())
    
    def get_existing_ips(self) -> Set[str]:
        """Get all cached IP addresses."""
        return set(self._devices_by_ip.keys())
    
    def filter_new_devices(self, devices: List[dict]) -> tuple:
        """
        Filter devices into new and existing.
        
        Args:
            devices: List of device dicts from scan results
            
        Returns:
            Tuple of (new_devices, existing_devices)
        """
        new_devices = []
        existing_devices = []
        
        for device in devices:
            mac = device.get("mac_address")
            ip = device.get("ip_address")
            
            # Check by MAC first (more reliable)
            if mac and self.has_mac(mac):
                existing_devices.append(device)
            # Fall back to IP check
            elif ip and self.has_ip(ip):
                existing_devices.append(device)
            else:
                new_devices.append(device)
        
        return new_devices, existing_devices
    
    def get_stats(self) -> dict:
        """Get cache statistics."""
        return {
            "total_devices": len(self._devices_by_id),
            "devices_with_mac": len(self._devices_by_mac),
            "devices_with_ip": len(self._devices_by_ip),
            "site_id": self._site_id,
            "last_refresh": self._last_refresh.isoformat() if self._last_refresh else None,
            "is_stale": self.is_stale(),
        }
    
    @staticmethod
    def _normalize_mac(mac: Optional[str]) -> Optional[str]:
        """Normalize MAC address to uppercase XX:XX:XX:XX:XX:XX format."""
        if not mac:
            return None
        
        # Remove all separators
        clean = mac.replace(":", "").replace("-", "").replace(".", "").upper()
        
        if len(clean) != 12:
            return None
        
        # Format as XX:XX:XX:XX:XX:XX
        return ":".join([clean[i:i+2] for i in range(0, 12, 2)])


# Global cache instance
_device_cache: Optional[DeviceCache] = None


def get_device_cache() -> DeviceCache:
    """Get the global device cache instance."""
    global _device_cache
    if _device_cache is None:
        _device_cache = DeviceCache()
    return _device_cache


def refresh_device_cache(client, site_id: str) -> int:
    """Refresh the global device cache."""
    cache = get_device_cache()
    return cache.refresh_from_api(client, site_id)


def clear_device_cache() -> None:
    """Clear the global device cache."""
    cache = get_device_cache()
    cache.clear()
