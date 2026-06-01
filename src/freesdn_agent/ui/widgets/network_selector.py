"""
Network Interface Selector Widget.

Dropdown for selecting network interface to scan.
"""

import logging
from typing import Optional

from PySide6.QtWidgets import QComboBox
from PySide6.QtCore import Signal

logger = logging.getLogger(__name__)


def get_network_interfaces() -> list[dict]:
    """
    Get list of available network interfaces with their details.
    
    Returns:
        List of dicts with interface info:
        - name: Interface name (e.g., "Ethernet", "eth0")
        - ip: IP address
        - netmask: Network mask
        - network: Network address (e.g., "192.168.1.0/24")
    """
    interfaces = []
    
    try:
        import netifaces
        
        for iface_name in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(iface_name)
                
                # Get IPv4 addresses
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info.get("addr", "")
                        netmask = addr_info.get("netmask", "255.255.255.0")
                        
                        # Skip loopback and link-local
                        if ip.startswith("127.") or ip.startswith("169.254."):
                            continue
                        
                        # Calculate network
                        network = _calculate_network(ip, netmask)
                        
                        interfaces.append({
                            "name": iface_name,
                            "ip": ip,
                            "netmask": netmask,
                            "network": network,
                        })
                        
            except Exception as e:
                logger.debug(f"Error getting info for interface {iface_name}: {e}")
                
    except ImportError:
        logger.warning("netifaces not installed, using fallback")
        # Fallback: just detect something
        interfaces.append({
            "name": "Unknown",
            "ip": "0.0.0.0",
            "netmask": "255.255.255.0",
            "network": "0.0.0.0/24",
        })
    
    return interfaces


def _calculate_network(ip: str, netmask: str) -> str:
    """Calculate network address from IP and netmask."""
    try:
        ip_parts = [int(x) for x in ip.split(".")]
        mask_parts = [int(x) for x in netmask.split(".")]
        
        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
        network = ".".join(str(x) for x in network_parts)
        
        # Calculate CIDR prefix
        mask_int = sum(mask_parts[i] << (24 - 8 * i) for i in range(4))
        prefix = bin(mask_int).count("1")
        
        return f"{network}/{prefix}"
    except Exception:
        return f"{ip}/24"


class NetworkSelector(QComboBox):
    """Dropdown for selecting network interface."""
    
    interface_changed = Signal(str)  # Interface name
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.setObjectName("networkSelector")
        self.setMinimumWidth(300)
        
        self._interfaces: list[dict] = []
        self._refresh_interfaces()
        
        self.currentIndexChanged.connect(self._on_selection_changed)
    
    def _refresh_interfaces(self) -> None:
        """Refresh the list of network interfaces."""
        self.clear()
        self._interfaces = get_network_interfaces()
        
        if not self._interfaces:
            self.addItem("No network interfaces found")
            self.setEnabled(False)
            return
        
        self.setEnabled(True)
        
        for iface in self._interfaces:
            display_text = f"{iface['name']} - {iface['network']}"
            self.addItem(display_text)
        
        logger.info(f"Found {len(self._interfaces)} network interfaces")
    
    def _on_selection_changed(self, index: int) -> None:
        """Handle selection change."""
        if 0 <= index < len(self._interfaces):
            iface = self._interfaces[index]
            self.interface_changed.emit(iface["name"])
    
    def get_selected_interface(self) -> Optional[str]:
        """Get the selected interface name."""
        index = self.currentIndex()
        if 0 <= index < len(self._interfaces):
            return self._interfaces[index]["name"]
        return None
    
    def get_selected_network(self) -> Optional[str]:
        """Get the selected network (e.g., '192.168.1.0/24')."""
        index = self.currentIndex()
        if 0 <= index < len(self._interfaces):
            return self._interfaces[index]["network"]
        return None
    
    def refresh(self) -> None:
        """Manually refresh the interface list."""
        self._refresh_interfaces()
