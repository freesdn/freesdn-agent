"""
Integration tests for ``AgentWSClient``.

Spins up a real ``websockets`` server on localhost and asserts that the
client honours the documented wire protocol:

  1. Connect → send `{"agent_key", "site_id"}` JSON for auth
  2. Receive `{"type": "auth_error"}` → stop reconnecting, close cleanly
  3. Receive `{"type": "auth_ok"}` (or anything non-error) → connected
  4. Drain stale queued messages on (re)connect
  5. `send_report()` produces a `{type, payload, timestamp}` envelope
  6. `{"type": "ping"}` from server gets a `{"type": "pong"}` reply
  7. Commands dispatch to the `on_command` callback

These tests run on an asyncio event loop with a real socket so they
exercise the actual websockets handshake, not a mocked stub. Each test
launches its own server on an ephemeral port so they can run in
parallel without interference.
"""
from __future__ import annotations

import asyncio
import json
import socket
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import websockets

from freesdn_agent.api.ws_client import AgentWSClient


# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

def _free_port() -> int:
    """Grab an ephemeral port number (no leak — close immediately)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _FakeServer:
    """A tiny scriptable WS server that records what the client sent.

    Each test sets ``self.auth_response`` (the JSON the server returns
    after receiving the client's auth message) and optionally
    ``self.scripted_messages`` (server-to-client messages sent after
    the auth handshake).
    """

    def __init__(self) -> None:
        self.received: list[dict[str, Any]] = []
        self.auth_message: dict[str, Any] | None = None
        # ws_client breaks the handshake loop only on auth_success /
        # auth_error — any other type goes into the pre-auth buffer.
        self.auth_response: dict[str, Any] = {"type": "auth_success", "message": "welcome"}
        self.scripted_messages: list[dict[str, Any]] = []
        self.connections = 0
        self._handler_done = asyncio.Event()
        self._server: websockets.WebSocketServer | None = None
        self.port = _free_port()

    async def __aenter__(self) -> "_FakeServer":
        self._server = await websockets.serve(
            self._handle, "127.0.0.1", self.port,
        )
        return self

    async def __aexit__(self, *_exc) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, ws) -> None:
        self.connections += 1
        try:
            # 1. Receive auth message
            raw = await ws.recv()
            self.auth_message = json.loads(raw)

            # 2. Send the canned auth response
            await ws.send(json.dumps(self.auth_response))
            if self.auth_response.get("type") == "auth_error":
                # Client should stop after auth failure — don't push more.
                return

            # 3. Push any scripted server-to-client messages
            for msg in self.scripted_messages:
                await ws.send(json.dumps(msg))

            # 4. Record everything else the client sends until it closes.
            async for raw in ws:
                try:
                    self.received.append(json.loads(raw))
                except json.JSONDecodeError:
                    self.received.append({"_raw": raw})
        except websockets.ConnectionClosed:
            pass
        finally:
            self._handler_done.set()

    async def wait_for_messages(self, n: int, timeout: float = 2.0) -> None:
        """Block until at least n messages have been received from client."""
        async def _poll():
            while len(self.received) < n:
                await asyncio.sleep(0.02)
        await asyncio.wait_for(_poll(), timeout=timeout)


def _mk_client(port: int) -> AgentWSClient:
    """Build a WS client wired to the local fake server."""
    return AgentWSClient(
        agent_id="ag-12345",
        server_url=f"http://127.0.0.1:{port}",
        site_id="site-abc",
        reconnect_delay=1,
        reconnect_max_delay=2,
    )


@pytest.fixture
def fake_keyring():
    """Replace ``keyring.get_password`` so the client doesn't touch the
    real OS keyring during tests."""
    with patch("freesdn_agent.api.ws_client.AgentWSClient._load_agent_key",
               return_value="test-agent-key-xyz"):
        yield


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAuthHandshake:
    @pytest.mark.asyncio
    async def test_sends_agent_key_and_site_id_on_connect(self, fake_keyring) -> None:
        async with _FakeServer() as server:
            client = _mk_client(server.port)
            run_task = asyncio.create_task(client.run())
            try:
                # Give the handshake time to land.
                await asyncio.wait_for(
                    _wait_for(lambda: server.auth_message is not None), timeout=2.0,
                )
                assert server.auth_message == {
                    "agent_key": "test-agent-key-xyz",
                    "site_id": "site-abc",
                }
            finally:
                await client.close()
                await _settle(run_task)

    @pytest.mark.asyncio
    async def test_auth_error_stops_reconnect(self, fake_keyring) -> None:
        """After an auth_error response, the client must not loop and
        retry — otherwise a wrong key floods the server forever."""
        async with _FakeServer() as server:
            server.auth_response = {"type": "auth_error", "message": "bad key"}
            client = _mk_client(server.port)

            run_task = asyncio.create_task(client.run())
            # The run loop should finish on its own when auth_error sets _running=False.
            await asyncio.wait_for(run_task, timeout=3.0)
            assert server.connections == 1, "should not have reconnected"
            assert client.connected is False


class TestPingPong:
    @pytest.mark.asyncio
    async def test_server_ping_gets_pong(self, fake_keyring) -> None:
        async with _FakeServer() as server:
            server.scripted_messages = [{"type": "ping"}]
            client = _mk_client(server.port)
            run_task = asyncio.create_task(client.run())
            try:
                await server.wait_for_messages(1, timeout=2.0)
                assert server.received[0] == {"type": "pong"}
            finally:
                await client.close()
                await _settle(run_task)


class TestSendReport:
    @pytest.mark.asyncio
    async def test_send_report_envelope_shape(self, fake_keyring) -> None:
        async with _FakeServer() as server:
            client = _mk_client(server.port)
            run_task = asyncio.create_task(client.run())
            try:
                await _wait_for(lambda: client.connected, timeout=2.0)
                await client.send_report("heartbeat", {"cpu": 12.3})
                await server.wait_for_messages(1, timeout=2.0)

                msg = server.received[0]
                assert msg["type"] == "heartbeat"
                assert msg["payload"] == {"cpu": 12.3}
                assert "timestamp" in msg
            finally:
                await client.close()
                await _settle(run_task)

    @pytest.mark.asyncio
    async def test_command_id_propagated(self, fake_keyring) -> None:
        async with _FakeServer() as server:
            client = _mk_client(server.port)
            run_task = asyncio.create_task(client.run())
            try:
                await _wait_for(lambda: client.connected, timeout=2.0)
                await client.send_report("task_result", {"ok": True}, command_id="cmd-42")
                await server.wait_for_messages(1, timeout=2.0)
                assert server.received[0]["command_id"] == "cmd-42"
            finally:
                await client.close()
                await _settle(run_task)


class TestCommandDispatch:
    @pytest.mark.asyncio
    async def test_on_command_invoked_for_server_messages(self, fake_keyring) -> None:
        """Non-ping server messages must be forwarded to on_command."""
        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        async with _FakeServer() as server:
            server.scripted_messages = [
                {"type": "task", "task_id": "t1", "command": "scan"},
                {"type": "task", "task_id": "t2", "command": "fingerprint"},
            ]
            client = _mk_client(server.port)
            client.on_command = handler
            run_task = asyncio.create_task(client.run())
            try:
                await _wait_for(lambda: len(received) >= 2, timeout=2.0)
                assert received[0]["task_id"] == "t1"
                assert received[1]["task_id"] == "t2"
            finally:
                await client.close()
                await _settle(run_task)


class TestQueueDrain:
    @pytest.mark.asyncio
    async def test_stale_queue_drained_on_reconnect(self, fake_keyring) -> None:
        """Messages queued while disconnected should NOT be flushed on
        reconnect — they're stale (esp. heartbeats) and would duplicate
        the freshly-sent ones."""
        async with _FakeServer() as server:
            client = _mk_client(server.port)
            # Queue 3 reports BEFORE starting run() — connection is down,
            # so they sit in the send queue.
            await client.send_report("heartbeat", {"n": 1})
            await client.send_report("heartbeat", {"n": 2})
            await client.send_report("heartbeat", {"n": 3})

            run_task = asyncio.create_task(client.run())
            try:
                await _wait_for(lambda: client.connected, timeout=2.0)
                # Give the drain step a moment, then queue a real fresh one.
                await asyncio.sleep(0.05)
                await client.send_report("heartbeat", {"n": 99})
                await server.wait_for_messages(1, timeout=2.0)
                # Only the post-connect heartbeat should reach the server.
                assert len(server.received) == 1
                assert server.received[0]["payload"] == {"n": 99}
            finally:
                await client.close()
                await _settle(run_task)


class TestUrlConstruction:
    def test_https_becomes_wss(self) -> None:
        c = AgentWSClient("aid", "https://example.com", "site")
        assert c.ws_url == "wss://example.com/api/v1/agents/ws/aid"

    def test_http_becomes_ws(self) -> None:
        c = AgentWSClient("aid", "http://example.com:8080/", "site")
        assert c.ws_url == "ws://example.com:8080/api/v1/agents/ws/aid"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _wait_for(predicate, timeout: float = 2.0, interval: float = 0.02) -> None:
    """Poll predicate() until it returns truthy or timeout."""
    async def _poll():
        while not predicate():
            await asyncio.sleep(interval)
    await asyncio.wait_for(_poll(), timeout=timeout)


async def _settle(task: asyncio.Task) -> None:
    """Cancel and await a task without raising CancelledError noise."""
    if not task.done():
        task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass
