"""Tests for network scanners."""

import pytest
from freesdn_agent.scanners.base import ScanResult, DeviceType, BaseScanner
from freesdn_agent.scanners.arp import ARPScanner


class TestScanResult:
    """Tests for ScanResult dataclass."""
    
    def test_create_scan_result(self):
        """Test creating a ScanResult."""
        result = ScanResult(
            ip_address="192.168.1.10",
            mac_address="00:0B:82:01:02:03",
            vendor="Grandstream",
            device_type=DeviceType.VOIP_PHONE,
            discovered_by="arp",
        )
        
        assert result.ip_address == "192.168.1.10"
        assert result.mac_address == "00:0B:82:01:02:03"
        assert result.vendor == "Grandstream"
        assert result.device_type == DeviceType.VOIP_PHONE
        assert result.is_new is True
    
    def test_scan_result_to_dict(self):
        """Test converting ScanResult to dict."""
        result = ScanResult(
            ip_address="192.168.1.10",
            mac_address="00:0B:82:01:02:03",
            vendor="Grandstream",
            discovered_by="arp",
        )
        
        data = result.to_dict()
        
        assert data["ip_address"] == "192.168.1.10"
        assert data["mac_address"] == "00:0B:82:01:02:03"
        assert data["vendor"] == "Grandstream"
        assert "discovered_at" in data


class TestARPScanner:
    """Tests for ARP scanner."""
    
    def test_parse_cidr_target(self):
        """Test parsing CIDR notation."""
        scanner = ARPScanner()
        ips = scanner._parse_target("192.168.1.0/30")
        
        # /30 has 4 addresses, 2 usable hosts
        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips
    
    def test_parse_range_target(self):
        """Test parsing IP range."""
        scanner = ARPScanner()
        ips = scanner._parse_target("192.168.1.1-192.168.1.105")

        # .1 through .105 inclusive = 105 addresses
        assert len(ips) == 105
        assert "192.168.1.1" in ips
        assert "192.168.1.105" in ips
    
    def test_parse_single_ip(self):
        """Test parsing single IP."""
        scanner = ARPScanner()
        ips = scanner._parse_target("192.168.1.100")
        
        assert len(ips) == 1
        assert ips[0] == "192.168.1.100"
    
    def test_classify_device_hikvision(self):
        """Test device classification for Hikvision."""
        scanner = ARPScanner()
        device_type = scanner._classify_device("Hikvision", "28:57:BE:AA:BB:CC")
        
        assert device_type == DeviceType.CAMERA
    
    def test_classify_device_grandstream(self):
        """Test device classification for Grandstream."""
        scanner = ARPScanner()
        device_type = scanner._classify_device("Grandstream", "00:0B:82:01:02:03")
        
        assert device_type == DeviceType.VOIP_PHONE
    
    def test_classify_device_ubiquiti(self):
        """Test device classification for Ubiquiti."""
        scanner = ARPScanner()
        device_type = scanner._classify_device("Ubiquiti", "00:27:22:11:22:33")
        
        assert device_type == DeviceType.ACCESS_POINT
    
    def test_classify_device_unknown(self):
        """Test device classification for unknown vendor."""
        scanner = ARPScanner()
        device_type = scanner._classify_device(None, "FF:FF:FF:01:02:03")
        
        assert device_type == DeviceType.UNKNOWN
    
    def test_scanner_cancel(self):
        """Test scanner cancellation."""
        scanner = ARPScanner()
        
        assert scanner.is_cancelled is False
        
        scanner.cancel()
        
        assert scanner.is_cancelled is True
        
        scanner.reset()
        
        assert scanner.is_cancelled is False
