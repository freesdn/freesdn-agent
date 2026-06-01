"""Tests for OUI lookup service."""

import pytest
from freesdn_agent.services.oui_lookup import lookup_vendor, _normalize_mac, _fallback_lookup


class TestOUILookup:
    """Tests for vendor lookup functions."""
    
    def test_normalize_mac_colons(self):
        """Test normalizing MAC with colons."""
        mac = "00:0b:82:01:02:03"
        result = _normalize_mac(mac)
        assert result == "00:0B:82:01:02:03"
    
    def test_normalize_mac_dashes(self):
        """Test normalizing MAC with dashes."""
        mac = "00-0B-82-01-02-03"
        result = _normalize_mac(mac)
        assert result == "00:0B:82:01:02:03"
    
    def test_normalize_mac_no_separator(self):
        """Test normalizing MAC without separators."""
        mac = "000B82010203"
        result = _normalize_mac(mac)
        assert result == "00:0B:82:01:02:03"
    
    def test_fallback_lookup_grandstream(self):
        """Test fallback lookup for Grandstream."""
        vendor = _fallback_lookup("00:0B:82:01:02:03")
        assert vendor == "Grandstream"
    
    def test_fallback_lookup_hikvision(self):
        """Test fallback lookup for Hikvision."""
        vendor = _fallback_lookup("28:57:BE:AA:BB:CC")
        assert vendor == "Hikvision"
    
    def test_fallback_lookup_ubiquiti(self):
        """Test fallback lookup for Ubiquiti."""
        vendor = _fallback_lookup("00:27:22:11:22:33")
        assert vendor == "Ubiquiti"
    
    def test_fallback_lookup_unknown(self):
        """Test fallback lookup for unknown vendor."""
        vendor = _fallback_lookup("FF:FF:FF:01:02:03")
        assert vendor is None
    
    def test_lookup_vendor_empty(self):
        """Test lookup with empty MAC."""
        vendor = lookup_vendor("")
        assert vendor is None
    
    def test_lookup_vendor_none(self):
        """Test lookup with None MAC."""
        vendor = lookup_vendor(None)
        assert vendor is None
