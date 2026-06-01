"""Test configuration and fixtures."""

import pytest
import sys
from pathlib import Path

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


@pytest.fixture
def sample_mac_address():
    """Sample MAC address for testing."""
    return "00:0B:82:01:02:03"


@pytest.fixture
def sample_ip_address():
    """Sample IP address for testing."""
    return "192.168.1.100"


@pytest.fixture
def sample_network():
    """Sample network for testing."""
    return "192.168.1.0/24"


@pytest.fixture
def mock_scan_results():
    """Sample scan results for testing."""
    return [
        {
            "ip_address": "192.168.1.10",
            "mac_address": "00:0B:82:01:02:03",
            "vendor": "Grandstream",
            "device_type": "voip_phone",
        },
        {
            "ip_address": "192.168.1.120",
            "mac_address": "28:57:BE:AA:BB:CC",
            "vendor": "Hikvision",
            "device_type": "camera",
        },
    ]
