"""
The agent called its own shipped deployment unprivileged.

``packaging/installers/build_deb.sh`` writes the systemd unit that actually
ships::

    User=freesdn-agent
    AmbientCapabilities=CAP_NET_RAW

Dropping root and granting one capability is the correct way to run a scanner.
Three separate modules then asked ``os.geteuid() == 0`` and got False for it:

  * ``services/capabilities.py`` -- so the agent never advertised the ``arp``
    scanner to the control plane on a .deb install;
  * ``listeners/base.py`` -- so ``safe_run()`` skipped every REQUIRES_ROOT
    listener, including passive LLDP, the daemon's topology source;
  * ``utils/privileges.py`` -- so the GUI warned about limited functionality.

All three held CAP_NET_RAW at the time. The check punished the hardened
configuration and rewarded running as root.

The parser is verified against real Linux rather than assumed. In a container:

    CapEff 00000000a80425fb (root)      -> True
    CapEff 0000000000002000 (.deb shape) -> True
    CapEff 0000000000000000             -> False
"""

from __future__ import annotations

import pytest

from freesdn_agent.utils import privileges

# ── the capability mask ─────────────────────────────────────────


@pytest.mark.parametrize(
    ("capeff", "expected"),
    [
        ("0000000000002000", True),  # exactly CAP_NET_RAW: what the .deb grants
        ("00000000a80425fb", True),  # a real root process in a container
        ("0000000000000000", False),  # genuinely unprivileged
        ("0000000000001000", False),  # bit 12, the neighbour -- must not match
        ("0000000000004000", False),  # bit 14, the other neighbour
    ],
)
def test_cap_net_raw_is_read_off_the_effective_set(monkeypatch, tmp_path, capeff, expected):
    status = tmp_path / "status"
    status.write_text(f"Name:\tagent\nCapEff:\t{capeff}\nCapPrm:\t{capeff}\n", encoding="ascii")

    real_open = open

    def fake_open(path, *a, **kw):
        if str(path) == "/proc/self/status":
            return real_open(status, *a, **kw)
        return real_open(path, *a, **kw)  # pragma: no cover

    monkeypatch.setattr("builtins.open", fake_open)
    assert privileges._linux_has_cap_net_raw() is expected


def test_a_missing_procfs_does_not_claim_the_capability(monkeypatch):
    """
    Fail DOWN, not up. Claiming a capability we cannot prove turns a clean
    "skipped, no privilege" into a scanner that dies at the socket, which is
    harder to diagnose than the honest refusal.
    """

    def boom(path, *a, **kw):
        raise OSError("no procfs")

    monkeypatch.setattr("builtins.open", boom)
    assert privileges._linux_has_cap_net_raw() is False


def test_a_malformed_capeff_does_not_claim_the_capability(monkeypatch, tmp_path):
    status = tmp_path / "status"
    status.write_text("CapEff:\tnot-a-hex-number\n", encoding="ascii")
    real_open = open
    monkeypatch.setattr(
        "builtins.open",
        lambda p, *a, **k: (
            real_open(status, *a, **k) if str(p) == "/proc/self/status" else real_open(p, *a, **k)
        ),
    )
    assert privileges._linux_has_cap_net_raw() is False


# ── the decision the rest of the agent uses ─────────────────────


def test_root_is_privileged(monkeypatch):
    monkeypatch.setattr(privileges.sys, "platform", "linux")
    monkeypatch.setattr(privileges.os, "geteuid", lambda: 0, raising=False)
    assert privileges.has_raw_socket_capability() is True


def test_the_shipped_deployment_is_privileged(monkeypatch):
    """
    THE case. Non-root, holding CAP_NET_RAW -- exactly what the .deb installs,
    and exactly what used to be reported as having no privileges at all.
    """
    monkeypatch.setattr(privileges.sys, "platform", "linux")
    monkeypatch.setattr(privileges.os, "geteuid", lambda: 998, raising=False)
    monkeypatch.setattr(privileges, "_linux_has_cap_net_raw", lambda: True)

    assert privileges.has_raw_socket_capability() is True


def test_an_unprivileged_user_is_still_unprivileged(monkeypatch):
    monkeypatch.setattr(privileges.sys, "platform", "linux")
    monkeypatch.setattr(privileges.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(privileges, "_linux_has_cap_net_raw", lambda: False)

    assert privileges.has_raw_socket_capability() is False


def test_non_linux_unix_still_requires_root(monkeypatch):
    """
    macOS has no ambient capabilities, so euid is the whole answer there. The
    capability path must not be consulted and must not be needed.
    """
    monkeypatch.setattr(privileges.sys, "platform", "darwin")
    monkeypatch.setattr(privileges.os, "geteuid", lambda: 501, raising=False)

    def _should_not_run():  # pragma: no cover - only if the platform gate is wrong
        raise AssertionError("read /proc on a platform that has none")

    monkeypatch.setattr(privileges, "_linux_has_cap_net_raw", _should_not_run)
    assert privileges.has_raw_socket_capability() is False


def test_the_legacy_name_still_answers_the_same(monkeypatch):
    """``check_admin_privileges`` is imported by main.py and utils/__init__."""
    monkeypatch.setattr(privileges, "has_raw_socket_capability", lambda: True)
    assert privileges.check_admin_privileges() is True


# ── one implementation, not three ───────────────────────────────


def test_capabilities_service_delegates():
    """
    It advertises the arp scanner. Its own euid check is why a .deb install
    never offered ARP discovery.
    """
    import inspect

    from freesdn_agent.services import capabilities

    src = inspect.getsource(capabilities._has_raw_socket_privilege)
    assert "has_raw_socket_capability" in src
    assert "geteuid" not in src, "the capabilities service is asking on its own again"


def test_listener_base_delegates():
    """
    It gates every REQUIRES_ROOT listener. Its own euid check is why passive
    LLDP was skipped on a .deb install.
    """
    import inspect

    from freesdn_agent.listeners.base import BaseListener

    src = inspect.getsource(BaseListener._check_privileges)
    assert "has_raw_socket_capability" in src
    assert "geteuid" not in src, "the listener base is asking on its own again"


def test_no_module_outside_privileges_asks_geteuid_directly():
    """
    The ratchet. Three copies had to be found and fixed together to fix this at
    all; a fourth would reintroduce it silently in whatever it gates.
    """
    import pathlib

    root = pathlib.Path(privileges.__file__).resolve().parents[1]
    offenders = []
    for path in root.rglob("*.py"):
        if path.name == "privileges.py":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        code = "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("#"))
        if "geteuid" in code:
            offenders.append(str(path.relative_to(root)))
    assert not offenders, f"privilege checks outside utils/privileges.py: {offenders}"
