"""
The edge-bridge proxy followed redirects, and the agent is the worst place to.

``proxy_http`` exists because the controller often cannot reach an appliance
LAN: it sends a request spec, the agent executes it on that LAN, and returns the
response. The controller chooses the URL, which is the whole trust argument.

A REDIRECT IS CHOSEN BY THE TARGET, NOT THE CONTROLLER. With
``allow_redirects=True``, "fetch this camera's status page" became "fetch
whatever that camera names" -- any host on the agent's LAN, or a cloud metadata
endpoint. That is the redirect-based SSRF bypass, and the backend disables
redirects for exactly this reason in both of its own HTTP clients
(``core/security_utils.py:358``, ``plugins/sdk.py:1771``). The agent, sitting
inside the network the controller cannot reach, is the more valuable pivot of
the three and was the only one following them.

Nothing is lost by refusing: the 3xx and its Location come back to the
controller, which can issue a second proxy_http if that is what it wants. The
decision moves to the party that is actually trusted.

The other two findings here are the same shape -- a value from the wire used
unbounded:

  * ``timeout_seconds: null`` satisfies ``.get("timeout_seconds", 60)`` and
    becomes ``asyncio.wait_for(timeout=None)``, which waits FOREVER. One such
    message pins a task slot for the life of the process, and the agent reports
    health by counting slots, so it would look progressively busier and never
    recover, silently.
  * ``timeout`` and ``max_bytes`` on proxy_http had no ceiling at all.
"""

from __future__ import annotations

import pytest
from aiohttp import web

from freesdn_agent.services import task_executor as te
from freesdn_agent.services.task_executor import TaskExecutor


class _Recorder:
    """Stands in for the WS client."""

    def __init__(self):
        self.reports: list[tuple] = []

    async def send_report(self, kind, data, command_id=None):
        self.reports.append((kind, data, command_id))


def _executor() -> TaskExecutor:
    return TaskExecutor(ws_client=_Recorder(), scan_manager=None, daemon=None)


class _Target:
    """A real aiohttp server on a free port.

    Started by hand rather than with the ``aiohttp_server`` fixture, which needs
    pytest-aiohttp -- not a dependency worth adding for one file when the agent
    already ships aiohttp itself.
    """

    def __init__(self):
        self.hits: list[str] = []
        self._runner = None
        self.port = 0

    async def start(self):

        async def public(request):
            self.hits.append("public")
            return web.Response(text="public page")

        async def secret(request):
            self.hits.append("secret")
            return web.Response(text="SHOULD NOT BE REACHED")

        async def redirector(request):
            self.hits.append("redirector")
            raise web.HTTPFound(location="/secret")

        app = web.Application()
        app.router.add_get("/public", public)
        app.router.add_get("/secret", secret)
        app.router.add_get("/redirect", redirector)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"


@pytest.fixture
async def target():
    t = await _Target().start()
    try:
        yield t
    finally:
        await t.stop()


# ── the redirect ────────────────────────────────────────────────


async def test_a_plain_fetch_still_works(target):
    """Premise: the proxy does its job, or the test below proves nothing."""
    ex = _executor()
    result = await ex._handle_proxy_http({"url": target.url("/public")}, "c1")

    assert result["status_code"] == 200
    assert "public page" in result["body"]


async def test_a_redirect_is_not_followed(target):
    """
    THE finding. The agent must not fetch a location the TARGET chose.
    """
    ex = _executor()
    result = await ex._handle_proxy_http({"url": target.url("/redirect")}, "c1")

    assert result["status_code"] in (301, 302, 303, 307, 308)
    assert "secret" not in result["body"].lower()
    assert "secret" not in target.hits, (
        "the agent followed a redirect chosen by the target -- SSRF pivot into "
        "the LAN the controller cannot reach"
    )


async def test_the_redirect_target_is_handed_back_to_the_controller(target):
    """
    Refusing has to stay useful. The controller gets the Location and can decide
    for itself, which is the point: it is the trusted party, the device is not.
    """
    ex = _executor()
    result = await ex._handle_proxy_http({"url": target.url("/redirect")}, "c1")

    location = {k.lower(): v for k, v in result["headers"].items()}.get("location")
    assert location == "/secret"


# ── bounds on values that arrive over the wire ──────────────────


async def test_a_non_http_scheme_is_refused():
    ex = _executor()
    for url in ("file:///etc/passwd", "ftp://host/x", "gopher://host"):
        result = await ex._handle_proxy_http({"url": url}, "c1")
        assert "error" in result, f"{url} was not refused"


async def test_an_oversized_timeout_is_capped(target, monkeypatch):
    seen = {}

    real = te.aiohttp.ClientTimeout

    def spy(total=None, **kw):
        seen["total"] = total
        return real(total=total, **kw)

    monkeypatch.setattr(te.aiohttp, "ClientTimeout", spy)
    ex = _executor()
    await ex._handle_proxy_http({"url": target.url("/public"), "timeout": 999_999}, "c1")

    assert seen["total"] == te._PROXY_MAX_TIMEOUT


async def test_an_oversized_body_cap_is_capped(target):
    """
    max_bytes sizes a read into memory. Unbounded, one response could size the
    agent's RSS.
    """
    ex = _executor()
    result = await ex._handle_proxy_http({"url": target.url("/public"), "max_bytes": 10**12}, "c1")
    # It still succeeds -- the cap is a ceiling, not a refusal.
    assert result["status_code"] == 200


# ── the command timeout ─────────────────────────────────────────


async def test_an_explicit_null_timeout_does_not_wait_forever():
    """
    ``{"timeout_seconds": null}`` satisfies ``.get(..., 60)`` and used to reach
    ``asyncio.wait_for(timeout=None)``, which never returns. One such message
    would pin a task slot for the life of the process.

    Asserts the value HANDED TO wait_for, not how long the call takes. My first
    version bounded the whole call at 5s and failed against the fix, because the
    fixed code correctly waits the default 60 -- a test that would have passed
    only while the bug made it return instantly.
    """
    ex = _executor()
    captured = _spy_on_wait_for()

    async def _quick(self, payload, cmd_id):
        return {"ok": True}

    monkeypatch_handlers(ex, {"quick": _quick})
    try:
        await ex.handle_command({"id": "c1", "type": "quick", "timeout_seconds": None})
    finally:
        captured["restore"]()

    assert captured["timeout"] is not None, "wait_for would block for ever"
    assert captured["timeout"] == 60


async def test_an_oversized_command_timeout_is_capped():
    ex = _executor()
    captured = _spy_on_wait_for()

    async def _quick(self, payload, cmd_id):
        return {"ok": True}

    monkeypatch_handlers(ex, {"quick": _quick})
    try:
        await ex.handle_command({"id": "c1", "type": "quick", "timeout_seconds": 10**9})
    finally:
        captured["restore"]()

    assert captured["timeout"] == te._COMMAND_MAX_TIMEOUT


def _spy_on_wait_for() -> dict:
    """Record the timeout handle_command passes, without changing behaviour."""
    import asyncio

    import freesdn_agent.services.task_executor as mod

    captured: dict = {}
    real = asyncio.wait_for

    async def spy(aw, timeout):
        captured["timeout"] = timeout
        return await real(aw, timeout)

    mod.asyncio.wait_for = spy
    captured["restore"] = lambda: setattr(mod.asyncio, "wait_for", real)
    return captured


def monkeypatch_handlers(ex: TaskExecutor, handlers: dict) -> None:
    """Give this executor instance its own handler registry."""
    ex._HANDLERS = {**TaskExecutor._HANDLERS, **handlers}
