"""
DNS Reverse Lookup Scanner - Resolve IP addresses to hostnames.

Uses DNS PTR records to discover hostnames for devices on the network.
This enhances device identification by providing DNS names alongside
IP addresses.
"""

import socket
import logging
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class DNSScanner:
    """Scanner for DNS reverse lookups."""
    
    name = "DNS Reverse"
    protocol = "dns"
    SCANNER_NAME = "DNSScanner"
    DISPLAY_NAME = "DNS Reverse Lookup"
    REQUIRES_ROOT = False
    
    def __init__(self, timeout: float = 2.0, concurrency: int = 50):
        self.timeout = timeout
        self.concurrency = concurrency
        self.is_cancelled = False
        
    def reset(self):
        """Reset scanner state."""
        self.is_cancelled = False
        
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
        Perform DNS reverse lookups on a network.
        
        Args:
            targets: Networks/IPs to scan (e.g., ["192.168.1.0/24"])
            interface: Network interface (not used)
            progress_callback: Called with scan progress
            
        Yields:
            ScanResult for each resolved hostname
        """
        from freesdn_agent.scanners.base import ScanResult, DeviceType
        import ipaddress
        
        self.reset()
        
        # Collect all IPs to scan
        all_ips = []
        for target in targets:
            try:
                net = ipaddress.ip_network(target, strict=False)
                all_ips.extend([str(ip) for ip in net.hosts()])
            except:
                all_ips.append(target)
        
        logger.info(f"Starting DNS reverse lookup scan on {len(all_ips)} hosts")
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            future_to_ip = {
                executor.submit(self._resolve_hostname, ip): ip 
                for ip in all_ips
            }
            
            for future in as_completed(future_to_ip):
                if self.is_cancelled:
                    break
                    
                try:
                    result = future.result()
                    if result and result.get("hostname"):
                        logger.debug(f"DNS resolved: {result['ip_address']} -> {result['hostname']}")
                        yield ScanResult(
                            ip_address=result['ip_address'],
                            mac_address=None,
                            hostname=result['hostname'],
                            vendor=None,
                            device_type=DeviceType.UNKNOWN,
                            open_ports=[],
                            services={},
                            raw_data={"dns": result},
                        )
                except Exception as e:
                    logger.debug(f"DNS lookup error: {e}")
        
        logger.info("DNS scan complete")
    
    def _resolve_hostname(self, ip: str) -> Optional[Dict[str, Any]]:
        """Resolve a single IP address to hostname."""
        try:
            socket.setdefaulttimeout(self.timeout)
            hostname, _, _ = socket.gethostbyaddr(ip)
            
            if hostname and hostname != ip:
                # Extract domain info
                parts = hostname.split(".")
                short_name = parts[0] if parts else hostname
                domain = ".".join(parts[1:]) if len(parts) > 1 else ""
                
                return {
                    "ip_address": ip,
                    "hostname": hostname,
                    "short_name": short_name,
                    "domain": domain,
                    "protocols": ["dns"],
                    "dns_info": {
                        "fqdn": hostname,
                        "resolved": True,
                    },
                }
        except (socket.herror, socket.gaierror, socket.timeout):
            pass
        except Exception as e:
            logger.debug(f"DNS lookup failed for {ip}: {e}")
        
        return None
    
    def resolve_single(self, ip: str) -> Optional[str]:
        """Resolve a single IP to hostname (sync method for enrichment)."""
        result = self._resolve_hostname(ip)
        return result.get("hostname") if result else None


def resolve_hostname(ip: str, timeout: float = 2.0) -> Optional[str]:
    """
    Convenience function to resolve a single IP address.
    
    Args:
        ip: IP address to resolve
        timeout: Timeout in seconds
        
    Returns:
        Hostname if resolved, None otherwise
    """
    scanner = DNSScanner(timeout=timeout)
    return scanner.resolve_single(ip)


async def scan(network: str, timeout: float = 2.0, **kwargs) -> List[Dict[str, Any]]:
    """Module-level scan function for scanner registry."""
    scanner = DNSScanner(timeout=timeout)
    return await scanner.scan(network)
