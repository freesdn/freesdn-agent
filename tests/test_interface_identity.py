"""
An interface name was doing three jobs, and two of them were done wrong.

``netifaces`` returns an adapter GUID on Windows -- ``{37217669-42DA-4657-A55B-
0D995D328250}`` -- and the agent used that one string as a label to show the
operator, as a hint for whether the adapter is virtual, and as a stand-in for
the subnet to scan. Only the label had a Windows-aware implementation, and it
was private to the daemon's capability advertiser where the GUI could not
reach it.

Measured on a real Windows host, against the shipped v1.0.0 heuristic:

    100.75.103.94  /32   guid_hit=False  name_hit=True   'Tailscale'
    192.168.10.157 /24   guid_hit=False  name_hit=False  'Ethernet 7'
    172.22.48.1    /20   guid_hit=False  name_hit=True   'vEthernet (Default Switch)'
    172.17.224.1   /20   guid_hit=False  name_hit=True   'vEthernet (WSL ...)'

``guid_hit`` is what the code tested, and it is False for every adapter on the
machine -- the filter written to keep hypervisor switches out of a scan has
never once fired on Windows. So both /20 virtual switches arrived pre-checked
and a default Quick Scan spent 8,188 of its 8,443 addresses on virtual subnets
with nothing behind them.

The third job failed on every platform. ``targets = job.targets or [interface]``
handed the scanner the interface NAME when a scan named an interface but no
targets, and a name parses to no addresses at all:

    _parse_target('eth0')            -> 0 addresses
    _parse_target('{2F90D717-...}')  -> 0 addresses
    _parse_target('192.168.1.0/24')  -> 254 addresses

The scan then logged "No valid IPs to scan" and reported success having looked
at nothing. Every scheduled scan without explicit targets did this -- the
scheduler builds exactly that job -- and the comment above the line already
said "default to interface subnet", which is what it was meant to do all along.
"""

from __future__ import annotations

import asyncio
import platform

import pytest

from freesdn_agent.utils.netiface import (
    friendly_name,
    interface_networks,
    is_overlay,
    local_networks,
)

# ── the overlay filter, which was matching the wrong string ─────


@pytest.mark.parametrize(
    "guid",
    [
        "{37217669-42DA-4657-A55B-0D995D328250}",
        "{2F90D717-DB00-468B-BDD3-D32BDB5AC2B5}",
        "{E30FD47A-C0B0-4825-B0F6-B717EC54A7B7}",
    ],
)
def test_a_guid_never_identifies_an_overlay(guid):
    """
    The regression itself. These are real GUIDs from a host whose adapters are
    Tailscale, a Hyper-V switch and a WSL switch -- all three virtual, none of
    them detectable from the identifier. Testing the GUID is not a stricter
    check that happens to miss; it is a check that cannot ever pass.
    """
    assert is_overlay(guid) is False


@pytest.mark.parametrize(
    "label",
    [
        "Tailscale",
        "vEthernet (Default Switch)",
        "vEthernet (WSL (Hyper-V firewall))",
        "docker0",
        "br-1a2b3c",
        "wg0-wireguard",
        "VMware Network Adapter VMnet8",
    ],
)
def test_the_friendly_name_does_identify_one(label):
    assert is_overlay(label) is True


@pytest.mark.parametrize("label", ["Ethernet", "Ethernet 7", "Wi-Fi", "eth0", "en0"])
def test_a_real_lan_is_not_mistaken_for_an_overlay(label):
    """
    The filter unchecks what it matches, so a false positive silently drops the
    operator's actual network out of the scan -- a worse failure than the one
    being fixed.
    """
    assert is_overlay(label) is False


def test_an_empty_name_is_not_an_overlay():
    assert is_overlay("") is False


# ── resolving the name ──────────────────────────────────────────


def test_an_unresolvable_name_comes_back_unchanged():
    """
    Better to show an operator a GUID than an empty row: it still identifies
    the adapter, and the address beside it is what they actually match on.
    """
    assert friendly_name("{DEAD-BEEF-NOT-AN-ADAPTER}") == "{DEAD-BEEF-NOT-AN-ADAPTER}"
    assert friendly_name("") == ""


@pytest.mark.skipif(platform.system() != "Windows", reason="registry lookup is Windows-only")
def test_windows_adapters_resolve_to_names_a_person_would_recognise():
    """
    Live, against whatever adapters this machine has. Asserts the shape of the
    fix rather than specific names: at least one adapter must stop looking like
    a GUID, or the resolution is not working at all.
    """
    netifaces = pytest.importorskip("netifaces")

    names = [friendly_name(i) for i in netifaces.interfaces()]
    resolved = [n for n in names if not n.startswith("{")]
    assert resolved, f"every adapter is still a GUID: {names}"


def test_a_posix_name_is_returned_untouched(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    assert friendly_name("eth0") == "eth0"


# ── the name as a subnet ────────────────────────────────────────


class _FakeNetifaces:
    AF_INET = 2

    def __init__(self, table):
        self._table = table

    def interfaces(self):
        return list(self._table)

    def ifaddresses(self, iface):
        return {self.AF_INET: self._table.get(iface, [])}


# Real Windows identifiers, so the fake cannot pass a check that only works on
# POSIX names. Using "wsl" as the key here let a mutation survive: the
# identifier itself matched the overlay regex, which is precisely the thing
# that does NOT happen on the platform where this broke.
LAN = "{11111111-0000-0000-0000-00000000000A}"
TAILSCALE = "{22222222-0000-0000-0000-00000000000B}"
WSL = "{33333333-0000-0000-0000-00000000000C}"
DEAD = "{44444444-0000-0000-0000-00000000000D}"

FRIENDLY = {
    LAN: "Ethernet 7",
    TAILSCALE: "Tailscale",
    WSL: "vEthernet (WSL (Hyper-V firewall))",
    DEAD: "Wi-Fi 8",
}


@pytest.fixture
def fake_netifaces(monkeypatch):
    """A Windows host: a LAN, a Tailscale /32, a WSL switch and a dead adapter."""
    import sys as _sys

    table = {
        LAN: [{"addr": "192.168.10.157", "netmask": "255.255.255.0"}],
        TAILSCALE: [{"addr": "100.75.103.94", "netmask": "255.255.255.255"}],
        WSL: [{"addr": "172.17.224.1", "netmask": "255.255.240.0"}],
        DEAD: [{"addr": "169.254.11.2", "netmask": "255.255.0.0"}],
        "lo": [{"addr": "127.0.0.1", "netmask": "255.0.0.0"}],
    }
    monkeypatch.setitem(_sys.modules, "netifaces", _FakeNetifaces(table))
    monkeypatch.setattr(
        "freesdn_agent.utils.netiface.friendly_name",
        lambda i: FRIENDLY.get(i, i),
    )
    return table


def test_an_interface_resolves_to_its_subnet_not_its_address(fake_netifaces):
    """
    The substitution that was missing. ``192.168.10.157/24`` is the agent's own
    address; the thing worth scanning is the network it sits on.
    """
    assert interface_networks(LAN) == ["192.168.10.0/24"]


def test_a_single_host_route_yields_nothing(fake_netifaces):
    """
    A /32 expands to one address -- the agent's own. Scanning it finds the
    machine already running the scan, which is why the GUI labels these
    "won't find peers".
    """
    assert interface_networks(TAILSCALE) == []


def test_a_link_local_adapter_yields_nothing(fake_netifaces):
    """169.254 means DHCP failed, so there is no network behind it."""
    assert interface_networks(DEAD) == []


def test_a_blank_interface_means_auto_detect(fake_netifaces):
    """
    Callers already pass ``[""]`` to mean "figure it out" -- the GUI and the
    scheduler both do. Before, that string went to the scanner as a target.
    """
    assert interface_networks("") == local_networks()
    assert interface_networks(None) == local_networks()


def test_auto_detect_excludes_the_virtual_switches(fake_netifaces):
    """
    Where the exclusion matters most: nothing prompts the operator on an
    unattended scan, so a /20 hypervisor switch is 4,094 addresses nobody
    chose to look at.
    """
    nets = local_networks()

    assert "192.168.10.0/24" in nets
    assert "172.17.224.0/20" not in nets, "the WSL switch is back in the scan"
    assert not any(n.startswith("127.") for n in nets)


# ── the manager, which is what actually reaches a scanner ───────


class _RecordingScanner:
    """Records the targets it is handed instead of touching the network."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self.timeout = 0
        self.concurrency = 1

    def scan(self, targets, interface=None, progress_callback=None):
        self.calls.append(list(targets))
        return iter(())


def _run_job(monkeypatch, scanner, *, interfaces, targets=None, networks=None):
    from freesdn_agent.services import async_scan_manager as mod

    monkeypatch.setattr(
        mod, "interface_networks", lambda i: list(networks if networks is not None else [])
    )
    manager = mod.AsyncScanManager()
    monkeypatch.setattr(manager, "_get_scanners_for_job", lambda job: [scanner])

    job = mod.ScanJob(scan_type=mod.ScanType.QUICK, interfaces=interfaces, targets=targets)
    asyncio.run(manager.run_scan(job))
    return scanner.calls


def test_naming_an_interface_scans_its_subnet(monkeypatch):
    """
    The end-to-end property. A scan that names an interface and gives no
    targets must reach the scanner as addresses, not as the name.
    """
    scanner = _RecordingScanner()
    calls = _run_job(
        monkeypatch, scanner, interfaces=["eth0"], networks=["192.168.10.0/24"]
    )

    assert calls == [["192.168.10.0/24"]]


def test_the_interface_name_is_never_handed_to_a_scanner(monkeypatch):
    """
    Stated as its own assertion because this is the exact shape of the bug and
    it is invisible in the result -- the scan completes, reports success, and
    finds nothing.
    """
    scanner = _RecordingScanner()
    calls = _run_job(
        monkeypatch, scanner, interfaces=["eth0"], networks=["192.168.10.0/24"]
    )

    for targets in calls:
        assert "eth0" not in targets


def test_an_interface_with_no_derivable_network_is_skipped_not_scanned(monkeypatch):
    """
    A /32 or an unplugged adapter yields no networks. Running the scanner
    anyway is what produced "No valid IPs to scan" and a successful-looking
    scan of nothing; it is skipped, and the reason is logged.
    """
    scanner = _RecordingScanner()
    calls = _run_job(monkeypatch, scanner, interfaces=["tailscale"], networks=[])

    assert calls == []


def test_explicit_targets_still_win(monkeypatch):
    """
    The fix only fills in the fallback. An operator who typed targets must get
    exactly those, and must not have the interface's subnet added.
    """
    scanner = _RecordingScanner()
    calls = _run_job(
        monkeypatch,
        scanner,
        interfaces=["eth0"],
        targets=["10.0.0.0/24"],
        networks=["192.168.10.0/24"],
    )

    assert calls == [["10.0.0.0/24"]]


def _widget_source(filename: str) -> str:
    """Read a widget's source without importing it.

    ``freesdn_agent.ui.__init__`` imports MainWindow, so importing any widget
    pulls in PySide6 -- an optional extra CI does not install. These checks are
    structural, so the text is enough.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src" / "freesdn_agent" / "ui" / "widgets"
    return (root / filename).read_text(encoding="utf-8")


# ── the two callers that must not diverge again ─────────────────


def test_the_gui_keeps_the_identifier_and_the_label_apart():
    """
    They cannot be one field: the scanners take the identifier and people read
    the label. Collapsing them either shows braces or breaks scanning.
    """
    src = _widget_source("network_selector.py")
    assert '"name": iface_name' in src, "the scanner's identifier was renamed"
    assert '"label": friendly_name(iface_name)' in src, "no readable label is produced"


def test_the_gui_displays_the_label_and_tests_it_for_overlay():
    """
    Reading "name" here is the original bug; both the row text and the
    auto-check decision have to use the resolved label.
    """
    src = _widget_source("multi_target_selector.py")
    src = src[src.index("def _refresh_interfaces") :]
    src = src[: src.index("def _on_target_change")]
    body = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))

    assert 'iface.get("label")' in body, "the row is built from the raw identifier again"
    assert "is_overlay(label)" in body, "the overlay test is back on the identifier"


def test_there_is_exactly_one_windows_name_resolver():
    """
    The daemon had a working resolver private to its capability advertiser
    while the GUI, which is where an operator actually reads these, had none.
    A second private copy is how that happened.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src" / "freesdn_agent"
    definers = [
        p.relative_to(root).as_posix()
        for p in root.rglob("*.py")
        if "CurrentControlSet" in p.read_text(encoding="utf-8", errors="ignore")
    ]

    assert definers == ["utils/netiface.py"], f"the registry lookup is duplicated: {definers}"
