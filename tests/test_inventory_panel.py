"""Unit tests for the unified Inventory panel's merge logic.

The PySide6 widget itself needs a QApplication so we only test the
``merge_into_inventory`` function which is pure data manipulation.
This covers the user-visible behaviour: a discovered host whose MAC
appears in the managed list should NOT produce a duplicate row.

We side-step the widgets package's ``__init__.py`` (which eagerly
imports PySide6-using modules) by loading inventory_data.py via
importlib.util — that lets the test run in the daemon-only CI env.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


# Load the pure-data module directly so the widgets package's
# QtWidgets imports don't drag PySide6 into the test process.
_INV_DATA_PATH = (
    Path(__file__).resolve().parents[1]
    / "src" / "freesdn_agent" / "ui" / "widgets" / "inventory_data.py"
)
_spec = importlib.util.spec_from_file_location("_inv_data", _INV_DATA_PATH)
_inv_data = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_inv_data)
merge_into_inventory = _inv_data.merge_into_inventory


def _managed(**overrides):
    base = {
        "id": "dev-1",
        "name": "core-switch",
        "ip_address": "192.168.1.1",
        "mac_address": "AA:BB:CC:DD:EE:01",
        "vendor": "NETGEAR",
        "device_type": "switch",
        "status": "online",
        "last_seen": None,
    }
    base.update(overrides)
    return base


def _discovered(**overrides):
    base = {
        "id": "dh-1",
        "ip_address": "192.168.1.2",
        "mac_address": "AA:BB:CC:DD:EE:02",
        "hostname": "printer-x1",
        "vendor": "HP",
        "device_type": "other",
        "ignored": False,
        "last_seen": None,
    }
    base.update(overrides)
    return base


class TestMergeIntoInventory:
    def test_managed_only(self) -> None:
        rows = merge_into_inventory([_managed()], [])
        assert len(rows) == 1
        assert rows[0].status == "Managed"
        assert rows[0].name == "core-switch"

    def test_discovered_only(self) -> None:
        rows = merge_into_inventory([], [_discovered()])
        assert len(rows) == 1
        assert rows[0].status == "Discovered"

    def test_mac_collision_keeps_managed_drops_discovered(self) -> None:
        """When the same MAC is in both lists, only the Managed row
        should appear — the whole point of the unified view."""
        managed = _managed(mac_address="AA:BB:CC:DD:EE:01")
        discovered = _discovered(
            id="dh-dup",
            ip_address="192.168.1.1",
            mac_address="aa-bb-cc-dd-ee-01",  # different format, same MAC
            hostname="ghost-of-core-switch",
        )
        rows = merge_into_inventory([managed], [discovered])
        assert len(rows) == 1
        assert rows[0].status == "Managed"
        assert rows[0].name == "core-switch"

    def test_discovered_no_mac_dedup_by_ip(self) -> None:
        """A discovered row with no MAC should still dedup against
        a managed row at the same IP — otherwise the ghost reappears."""
        managed = _managed(ip_address="10.0.0.5")
        discovered = _discovered(
            id="dh-2",
            ip_address="10.0.0.5",
            mac_address=None,
        )
        rows = merge_into_inventory([managed], [discovered])
        assert len(rows) == 1
        assert rows[0].status == "Managed"

    def test_hypervisor_ip_dedup_when_managed_has_no_mac(self) -> None:
        """The Proxmox-as-hypervisor case: managed Device row has an IP
        but NO MAC (ProxmoxNode has no mac field), while the agent's
        discovered host DID capture a MAC. IP must still collapse them
        to a single Managed row, or the box shows twice."""
        managed = _managed(
            name="proxmox-lab",
            ip_address="192.168.1.150",
            mac_address=None,          # hypervisor rows have no MAC
            device_type="hypervisor",
        )
        discovered = _discovered(
            id="dh-pve",
            ip_address="192.168.1.150",
            mac_address="AA:BB:CC:DD:EE:01",  # agent scan captured a MAC
            vendor="IEEE Registration Authority",
        )
        rows = merge_into_inventory([managed], [discovered])
        assert len(rows) == 1
        assert rows[0].status == "Managed"
        assert rows[0].name == "proxmox-lab"
        assert rows[0].device_type == "hypervisor"

    def test_known_status_from_controller(self) -> None:
        """A discovered host whose backend tagged known_as (a controller
        appliance) should render as Known, not Discovered — that's the
        'oh, this is the MikroTik we already have' behaviour."""
        host = _discovered(
            id="dh-mt",
            ip_address="192.168.1.133",
            mac_address=None,
            known_as={
                "kind": "controller",
                "name": "MikroTik Gateway",
                "detail": "mikrotik controller",
                "ref_type": "controller",
                "ref_id": "c-1",
            },
        )
        rows = merge_into_inventory([], [host])
        assert len(rows) == 1
        assert rows[0].status == "Known"
        assert "mikrotik controller" in rows[0].known_detail
        assert "MikroTik Gateway" in rows[0].known_detail

    def test_known_does_not_override_managed(self) -> None:
        """If a host is also in core.devices (managed) it should still
        collapse to the Managed row, not appear as a separate Known."""
        managed = _managed(ip_address="192.168.1.105", mac_address="AA:BB:CC:DD:EE:02")
        host = _discovered(
            id="dh-x",
            ip_address="192.168.1.105",
            mac_address="AA:BB:CC:DD:EE:02",
            known_as={"kind": "device", "name": "gl-router", "detail": "router",
                      "ref_type": "device", "ref_id": "d-1"},
        )
        rows = merge_into_inventory([managed], [host])
        assert len(rows) == 1
        assert rows[0].status == "Managed"

    def test_ignored_status_preserved(self) -> None:
        rows = merge_into_inventory(
            [],
            [_discovered(ignored=True)],
        )
        assert len(rows) == 1
        assert rows[0].status == "Ignored"

    def test_mixed_no_collision(self) -> None:
        rows = merge_into_inventory(
            [
                _managed(),
                _managed(
                    id="dev-2", ip_address="192.168.1.10",
                    mac_address="11:22:33:44:55:66",
                ),
            ],
            [
                _discovered(),
                _discovered(
                    id="dh-3", ip_address="192.168.1.3",
                    mac_address="77:88:99:AA:BB:CC",
                ),
            ],
        )
        assert len(rows) == 4
        statuses = sorted(r.status for r in rows)
        assert statuses == ["Discovered", "Discovered", "Managed", "Managed"]
