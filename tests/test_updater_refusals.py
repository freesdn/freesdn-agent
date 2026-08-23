"""
The updater's refusals, which are the part that actually protects anyone.

``services/updater.py`` downloads a binary over the network and ``os.replace``s
it over the running executable. Its existing tests cover the signing and
key-pinning path well; what had no coverage at all was every REFUSAL around it --
the decisions that determine whether a malicious or merely broken release gets
installed. A signature check is worth nothing if the code reaches
``_stage_binary`` by some route that never consulted it.

These are the routes. Each test states the attack or accident it is standing
against, because a refusal without a reason is the first thing someone deletes
to make a release "work".
"""

from __future__ import annotations

import types

import pytest

from freesdn_agent.services import updater as updater_mod
from freesdn_agent.services.updater import UpdaterService


def _service(**config_overrides) -> UpdaterService:
    config = types.SimpleNamespace(
        server_url="https://controller.example.com",
        agent_id="agent-1",
        auto_update_channel="stable",
        auto_update_require_signature=True,
        release_public_key_sha256=None,
    )
    for k, v in config_overrides.items():
        setattr(config, k, v)
    return UpdaterService(ws_client=None, config=config, agent_version="1.0.0")


# ── download URL: the SSRF boundary ─────────────────────────────


def test_a_relative_path_resolves_against_the_configured_server():
    svc = _service()
    got = svc._validate_download_url("https://controller.example.com", "/dl/agent")
    assert got == "https://controller.example.com/dl/agent"


def test_plain_http_is_refused():
    """
    The binary is executed. Downloading it over a channel anyone on the path can
    rewrite defeats every other control here.
    """
    svc = _service()
    assert svc._validate_download_url("https://c.example.com", "http://c.example.com/x") is None


def test_a_different_host_is_refused():
    """
    A compromised control plane redirecting the download elsewhere is exactly
    the case the hostname check exists for.
    """
    svc = _service()
    assert svc._validate_download_url("https://c.example.com", "https://evil.example/x") is None


def test_the_matching_host_is_allowed():
    svc = _service()
    url = "https://c.example.com/dl/agent"
    assert svc._validate_download_url("https://c.example.com", url) == url


@pytest.mark.parametrize(
    "bad",
    [
        "ftp://c.example.com/x",
        "file:///etc/passwd",
        "HTTPS://c.example.com/x",  # scheme match is case-sensitive: must fail CLOSED
        "https:/c.example.com/x",  # single slash
        "javascript:alert(1)",
        "",
    ],
)
def test_anything_else_is_refused(bad: str):
    """
    The catch-all matters more than the named cases: an unrecognised shape must
    fall through to a refusal, never to a default-allow.
    """
    svc = _service()
    assert svc._validate_download_url("https://c.example.com", bad) is None


# ── staging: never over an interpreter ──────────────────────────


def test_staging_refuses_when_not_frozen(monkeypatch, caplog):
    """
    ``_stage_binary`` os.replace()s over ``sys.executable``. On a source install
    that is the PYTHON INTERPRETER, so staging there would overwrite the user's
    python with an agent binary. run() already refuses source installs; this is
    the second gate on the call that actually does the damage.
    """
    monkeypatch.setattr(updater_mod, "is_frozen", lambda: False)
    svc = _service()

    assert svc._stage_binary(b"payload", "2.0.0") is False


def test_staging_does_not_touch_the_filesystem_when_it_refuses(monkeypatch):
    """
    Refusing after writing a temp file would leave litter next to the binary on
    every check.
    """
    monkeypatch.setattr(updater_mod, "is_frozen", lambda: False)
    called = []
    monkeypatch.setattr(updater_mod.tempfile, "mkstemp", lambda **kw: called.append(kw))
    svc = _service()

    assert svc._stage_binary(b"payload", "2.0.0") is False
    assert called == [], "it started writing before checking whether it was allowed to"


# ── the orchestration refusals ──────────────────────────────────


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _mock_check(monkeypatch, payload):
    """Make the /updates/check call return ``payload`` and nothing else run."""

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, *a, **kw):
            return _Resp(payload)

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", _Client)


def _forbid(monkeypatch, svc, *names):
    """Turn later stages into loud failures so a refusal cannot silently pass them."""
    for name in names:

        def _boom(*a, _n=name, **kw):  # pragma: no cover - only on regression
            raise AssertionError(f"reached {_n} after it should have refused")

        monkeypatch.setattr(svc, name, _boom)


async def test_no_checksum_means_no_update(monkeypatch):
    """
    A release without a checksum cannot be verified at all. Installing it on the
    server's say-so would make every check below decorative.
    """
    svc = _service()
    _mock_check(
        monkeypatch,
        {"update_available": True, "latest_version": "2.0.0", "download_url": "/dl/a"},
    )
    _forbid(monkeypatch, svc, "_download", "_stage_binary")

    assert await svc._do_check_and_apply() is False


async def test_an_unsigned_release_is_refused_by_default(monkeypatch):
    """
    Fail CLOSED. A compromised control plane can swap the binary AND its
    checksum together -- they are served by the same host -- so the checksum
    alone proves nothing. Only the signature needs a key the server does not
    hand out.

    The checksum here is the REAL one for the payload, so the only thing left to
    refuse on is the missing signature.
    """
    import hashlib

    payload = b"payload"
    svc = _service()
    _mock_check(
        monkeypatch,
        {
            "update_available": True,
            "latest_version": "2.0.0",
            "download_url": "/dl/a",
            "checksum_sha256": hashlib.sha256(payload).hexdigest(),
            # no "signature" key at all
        },
    )
    monkeypatch.setattr(svc, "_download", _async_return(payload))
    monkeypatch.setattr(svc, "_report_update_status", _async_return(None))
    _forbid(monkeypatch, svc, "_stage_binary")

    assert await svc._do_check_and_apply() is False


async def test_an_unsigned_release_installs_only_when_explicitly_allowed(monkeypatch):
    """
    The escape hatch has to work, or an operator on a legacy server has no way
    forward and will reach for something worse. It is opt-in and it is loud.
    """
    import hashlib

    payload = b"payload"
    svc = _service(auto_update_require_signature=False)
    _mock_check(
        monkeypatch,
        {
            "update_available": True,
            "latest_version": "2.0.0",
            "download_url": "/dl/a",
            "checksum_sha256": hashlib.sha256(payload).hexdigest(),
        },
    )
    monkeypatch.setattr(svc, "_download", _async_return(payload))
    monkeypatch.setattr(svc, "_report_update_status", _async_return(None))
    staged = []
    monkeypatch.setattr(svc, "_stage_binary", lambda d, v: staged.append(v) or True)
    monkeypatch.setattr(svc, "_trigger_restart", lambda: None)

    assert await svc._do_check_and_apply() is True
    assert staged == ["2.0.0"]


async def test_a_checksum_mismatch_is_refused(monkeypatch):
    """
    require_signature is OFF here on purpose. With it on, this release would be
    refused for having no signature and the test would pass whether or not the
    checksum was ever compared -- which is exactly what it did until a mutation
    run showed that disabling the comparison broke nothing. The checksum has to
    be the ONLY thing left that can say no.
    """
    svc = _service(auto_update_require_signature=False)
    _mock_check(
        monkeypatch,
        {
            "update_available": True,
            "latest_version": "2.0.0",
            "download_url": "/dl/a",
            "checksum_sha256": "bb" * 32,
        },
    )
    monkeypatch.setattr(svc, "_download", _async_return(b"payload"))
    monkeypatch.setattr(svc, "_report_update_status", _async_return(None))
    _forbid(monkeypatch, svc, "_stage_binary")

    assert await svc._do_check_and_apply() is False


async def test_no_update_available_does_nothing(monkeypatch):
    svc = _service()
    _mock_check(monkeypatch, {"update_available": False, "latest_version": "1.0.0"})
    _forbid(monkeypatch, svc, "_download", "_stage_binary")

    assert await svc._do_check_and_apply() is False


def _async_return(value):
    async def _f(*a, **kw):
        return value

    return _f
