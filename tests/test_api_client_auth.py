"""
The API client's writes all failed 403, and its reads did not -- which is why.

``/auth/token`` returns bearer tokens in the body AND sets the browser session
cookies. ``FreeSDNClient`` holds a PERSISTENT ``httpx.AsyncClient``, so those
cookies rode along on every later request, and the server enforces CSRF for
bearer-plus-cookie deliberately: an attacker able to send
"Authorization: Bearer garbage" alongside a victim's cookie would otherwise
bypass it.

CSRF applies to unsafe methods only, so the failure was shaped to hide:

    get_sites()              -> 200, five sites      (looks healthy)
    push_discovery_results() -> 403 CSRF token missing

Verified against a live controller, and after the fix the same call returns
``{'created': 1, ...}``.

Scope, stated honestly: the GUI uses ``SyncFreeSDNClient``, which builds a fresh
``httpx.Client`` per call and is therefore immune BY CONSTRUCTION -- it never hit
this. The async client is exported from ``freesdn_agent.api`` and has no in-tree
consumer, so the breakage was latent rather than live. It is still the public
client anyone writing against this package would reach for first.

The last test here guards the sync client's immunity, because it is an accident
of construction rather than a decision anyone recorded: refactoring it to reuse
one client -- an obvious-looking optimisation -- would silently reintroduce this.
"""

from __future__ import annotations

import httpx
import pytest

from freesdn_agent.api.client import FreeSDNClient, SyncFreeSDNClient

TOKEN_BODY = {
    "access_token": "tok",
    "refresh_token": "ref",
    "expires_in": 3600,
    "token_type": "bearer",
}

SESSION_COOKIES = [
    ("set-cookie", "freesdn_access=abc; Path=/"),
    ("set-cookie", "freesdn_csrf=def; Path=/"),
    ("set-cookie", "freesdn_refresh=ghi; Path=/"),
]


def _handler(seen: list[httpx.Request]):
    """A server that behaves like the real one: tokens in the body, cookies set."""

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/auth/token"):
            return httpx.Response(200, json=TOKEN_BODY, headers=SESSION_COOKIES)
        # Mimic the CSRF middleware: refuse an unsafe method that carries BOTH.
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            has_cookie = "cookie" in {k.lower() for k in request.headers}
            has_bearer = request.headers.get("authorization", "").startswith("Bearer ")
            if has_bearer and has_cookie:
                return httpx.Response(403, json={"error": {"message": "CSRF token missing"}})
        return httpx.Response(200, json={"created": 1})

    return handle


@pytest.fixture
def mock_transport(monkeypatch):
    """Patch httpx so both clients talk to the fake controller above."""
    seen: list[httpx.Request] = []
    transport = httpx.MockTransport(_handler(seen))

    real_async, real_sync = httpx.AsyncClient, httpx.Client
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda **kw: real_async(**{**kw, "transport": transport})
    )
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_sync(**{**kw, "transport": transport}))
    return seen


# ── the async client ────────────────────────────────────────────


async def test_login_drops_the_session_cookies(mock_transport):
    """
    THE regression. Keeping them makes every write carry bearer + cookie.
    """
    async with FreeSDNClient("https://controller.example.com") as c:
        assert await c.login("ops@example.com", "pw") is True
        assert dict(c._client.cookies) == {}, "session cookies survived login; every write will 403"


async def test_a_write_succeeds_after_login(mock_transport):
    """
    The behaviour, not the mechanism. This is the call the agent exists to make,
    and it is the one that was failing.
    """
    async with FreeSDNClient("https://controller.example.com") as c:
        await c.login("ops@example.com", "pw")
        result = await c.push_discovery_results([{"ip_address": "192.168.1.10"}], "site-1")
        assert result == {"created": 1}


async def test_the_write_carries_a_bearer_header(mock_transport):
    """A write that lost its auth entirely would also stop 403ing. Not that."""
    async with FreeSDNClient("https://controller.example.com") as c:
        await c.login("ops@example.com", "pw")
        await c.push_discovery_results([{"ip_address": "192.168.1.10"}], "site-1")

    writes = [r for r in mock_transport if r.method == "POST" and "results" in r.url.path]
    assert writes, "no write reached the server"
    assert writes[-1].headers.get("authorization") == "Bearer tok"


async def test_reads_were_never_the_problem(mock_transport):
    """
    Worth pinning: CSRF applies to unsafe methods only, so GETs stayed healthy
    throughout. That asymmetry is what made this hide -- a connection test and a
    site list both passed while every push failed.
    """
    async with FreeSDNClient("https://controller.example.com") as c:
        await c.login("ops@example.com", "pw")
        assert await c.get_sites() is not None


# ── the sync client's immunity is not an accident to be optimised away ──


def test_the_sync_client_builds_a_fresh_client_per_call():
    """
    ``SyncFreeSDNClient`` never hit this because ``_get_client()`` returns a NEW
    httpx.Client every time, so login's cookies die with the login call. That is
    load-bearing and undocumented, and "reuse one client" is exactly the kind of
    tidy-up someone would make.
    """
    import inspect

    src = inspect.getsource(SyncFreeSDNClient._get_client)
    assert "return httpx.Client(" in src, (
        "the sync client no longer builds a fresh client per call; if it now "
        "holds one, its login cookies will make every write 403"
    )


def test_the_sync_client_does_not_hold_a_client(mock_transport):
    """The property itself, not its spelling."""
    c = SyncFreeSDNClient("https://controller.example.com")
    assert c.login("ops@example.com", "pw") is True
    assert not hasattr(c, "_client"), (
        "the sync client is holding a persistent client; cookies from login "
        "will now ride along on every write"
    )
