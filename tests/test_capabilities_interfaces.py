"""Tests for the friendly-name interface enumeration.

Originally ``compute_capabilities()['interfaces']`` returned the raw
netifaces output, which on Windows is a list of GUIDs like
``{37217669-42DA-4657-A55B-0D995D328250}``. Operators reading the
agent-detail page saw 14 GUIDs and no clue which adapter was which.

The improved enumeration:
- Resolves GUIDs via the registry to their friendly name (Ethernet, Wi-Fi)
- Drops loopback adapters
- Drops adapters with no usable IPv4 (disabled / disconnected)
- Drops link-local-only (169.254.x.x) adapters
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestListInterfacesFiltering:
    def test_skips_loopback(self) -> None:
        from freesdn_agent.services import capabilities as cap

        fake_netifaces = MagicMock()
        fake_netifaces.interfaces.return_value = ["lo", "eth0"]
        fake_netifaces.AF_INET = 2
        fake_netifaces.ifaddresses.side_effect = lambda iface: {
            "eth0": {2: [{"addr": "192.168.1.10", "netmask": "255.255.255.0"}]},
            "lo": {2: [{"addr": "127.0.0.1"}]},
        }[iface]
        with patch.dict("sys.modules", {"netifaces": fake_netifaces}), \
             patch.object(cap, "platform") as mock_platform:
            mock_platform.system.return_value = "Linux"
            result = cap._list_interfaces()
        assert "lo" not in result
        assert "eth0" in result

    def test_skips_adapters_with_no_ipv4(self) -> None:
        from freesdn_agent.services import capabilities as cap

        fake_netifaces = MagicMock()
        fake_netifaces.interfaces.return_value = ["eth0", "eth1"]
        fake_netifaces.AF_INET = 2
        fake_netifaces.ifaddresses.side_effect = lambda iface: {
            "eth0": {2: [{"addr": "192.168.1.10"}]},
            "eth1": {},  # no IPv4 → skip
        }[iface]
        with patch.dict("sys.modules", {"netifaces": fake_netifaces}), \
             patch.object(cap, "platform") as mock_platform:
            mock_platform.system.return_value = "Linux"
            result = cap._list_interfaces()
        assert result == ["eth0"]

    def test_skips_link_local_only_adapters(self) -> None:
        from freesdn_agent.services import capabilities as cap

        fake_netifaces = MagicMock()
        fake_netifaces.interfaces.return_value = ["eth0", "eth1"]
        fake_netifaces.AF_INET = 2
        fake_netifaces.ifaddresses.side_effect = lambda iface: {
            "eth0": {2: [{"addr": "192.168.1.10"}]},
            "eth1": {2: [{"addr": "169.254.1.5"}]},  # APIPA → skip
        }[iface]
        with patch.dict("sys.modules", {"netifaces": fake_netifaces}), \
             patch.object(cap, "platform") as mock_platform:
            mock_platform.system.return_value = "Linux"
            result = cap._list_interfaces()
        assert result == ["eth0"]

    def test_skips_loopback_addresses(self) -> None:
        """Localhost 127.x.x.x bound on a non-'lo' adapter should still
        be excluded (the address filter, not just the name filter)."""
        from freesdn_agent.services import capabilities as cap

        fake_netifaces = MagicMock()
        fake_netifaces.interfaces.return_value = ["eth0"]
        fake_netifaces.AF_INET = 2
        fake_netifaces.ifaddresses.return_value = {
            2: [{"addr": "127.0.0.5"}],
        }
        with patch.dict("sys.modules", {"netifaces": fake_netifaces}), \
             patch.object(cap, "platform") as mock_platform:
            mock_platform.system.return_value = "Linux"
            result = cap._list_interfaces()
        assert result == []


class TestWindowsFriendlyNameResolution:
    def test_friendly_name_used_when_registry_lookup_succeeds(self) -> None:
        from freesdn_agent.services import capabilities as cap

        guid = "{37217669-42DA-4657-A55B-0D995D328250}"
        fake_netifaces = MagicMock()
        fake_netifaces.interfaces.return_value = [guid]
        fake_netifaces.AF_INET = 2
        fake_netifaces.ifaddresses.return_value = {
            2: [{"addr": "192.168.1.100"}],
        }
        with patch.dict("sys.modules", {"netifaces": fake_netifaces}), \
             patch.object(cap, "platform") as mock_platform, \
             patch.object(
                 cap, "_resolve_windows_friendly_name", return_value="Ethernet",
             ):
            mock_platform.system.return_value = "Windows"
            result = cap._list_interfaces()
        assert result == ["Ethernet"]

    def test_guid_kept_when_registry_lookup_fails(self) -> None:
        """If the registry path is missing or unreadable, fall back to
        the raw GUID so the operator at least sees *something*."""
        from freesdn_agent.services import capabilities as cap

        guid = "{37217669-42DA-4657-A55B-0D995D328250}"
        fake_netifaces = MagicMock()
        fake_netifaces.interfaces.return_value = [guid]
        fake_netifaces.AF_INET = 2
        fake_netifaces.ifaddresses.return_value = {
            2: [{"addr": "192.168.1.100"}],
        }
        with patch.dict("sys.modules", {"netifaces": fake_netifaces}), \
             patch.object(cap, "platform") as mock_platform, \
             patch.object(
                 cap, "_resolve_windows_friendly_name", return_value=None,
             ):
            mock_platform.system.return_value = "Windows"
            result = cap._list_interfaces()
        assert result == [guid]

    def test_loopback_friendly_name_filtered(self) -> None:
        """Windows reports 'Loopback Pseudo-Interface 1' as a real
        adapter with 127.0.0.1 bound — should be excluded by both
        name AND address checks."""
        from freesdn_agent.services import capabilities as cap

        guid = "{LOOPBACK-GUID}"
        fake_netifaces = MagicMock()
        fake_netifaces.interfaces.return_value = [guid]
        fake_netifaces.AF_INET = 2
        # Loopback has 127.0.0.1 so address filter catches it first
        fake_netifaces.ifaddresses.return_value = {
            2: [{"addr": "127.0.0.1"}],
        }
        with patch.dict("sys.modules", {"netifaces": fake_netifaces}), \
             patch.object(cap, "platform") as mock_platform:
            mock_platform.system.return_value = "Windows"
            result = cap._list_interfaces()
        assert result == []


class TestComputeCapabilitiesIntegration:
    def test_capabilities_includes_interfaces_field(self) -> None:
        from freesdn_agent.services.capabilities import compute_capabilities

        caps = compute_capabilities("1.0.0")
        assert "interfaces" in caps
        assert isinstance(caps["interfaces"], list)
        # On the dev box this should be the friendly-name list, not GUIDs
        # — but we can only assert shape, not content, without making
        # the test fragile to the test runner's host.
