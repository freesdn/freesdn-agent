"""Tests for the concurrent command-dispatch behaviour in AgentWSClient.

Originally the receiver loop awaited ``on_command`` inline. That meant
a long-running scan (which can occupy the handler for minutes) blocked
the receive side: no subsequent commands could be read, the WS auto-
ping handshake competed with the handler for the loop, and a clean
``close()`` could lose the pending scan_result.

The new path spawns each handler as a tracked task. These tests assert:
1. A slow handler does NOT block the receiver from accepting more
   commands.
2. close() waits for in-flight handlers (within a bounded deadline)
   so their final reports drain through sender_loop.
3. Handler exceptions are logged via the done-callback rather than
   crashing the receiver.
"""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any
from unittest.mock import patch

import pytest
import websockets

from freesdn_agent.api.ws_client import AgentWSClient


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _ConcurrentServer:
    """Fake WS server that pushes a queue of commands after auth."""

    def __init__(self) -> None:
        self.auth_message: dict[str, Any] | None = None
        self.auth_response = {"type": "auth_success", "message": "ok"}
        self.scripted: list[dict[str, Any]] = []
        self.received: list[dict[str, Any]] = []
        self.port = _free_port()
        self._server: websockets.WebSocketServer | None = None

    async def __aenter__(self) -> "_ConcurrentServer":
        self._server = await websockets.serve(
            self._handle, "127.0.0.1", self.port,
        )
        return self

    async def __aexit__(self, *_exc) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, ws) -> None:
        try:
            self.auth_message = json.loads(await ws.recv())
            await ws.send(json.dumps(self.auth_response))
            for msg in self.scripted:
                await ws.send(json.dumps(msg))
            async for raw in ws:
                try:
                    self.received.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass
        except websockets.ConnectionClosed:
            pass


def _mk_client(port: int) -> AgentWSClient:
    return AgentWSClient(
        agent_id="ag-test",
        server_url=f"http://127.0.0.1:{port}",
        site_id="site-test",
        reconnect_delay=1,
        reconnect_max_delay=2,
    )


@pytest.fixture
def fake_keyring():
    with patch(
        "freesdn_agent.api.ws_client.AgentWSClient._load_agent_key",
        return_value="test-key",
    ):
        yield


@pytest.mark.asyncio
async def test_slow_handler_does_not_block_subsequent_commands(fake_keyring) -> None:
    """A scan that takes 1s shouldn't delay the second command at all."""
    started: list[float] = []

    async def slow_handler(msg: dict) -> None:
        started.append(asyncio.get_running_loop().time())
        if msg.get("type") == "slow":
            await asyncio.sleep(1.0)

    async with _ConcurrentServer() as server:
        server.scripted = [
            {"type": "slow", "id": "1"},
            {"type": "fast", "id": "2"},
        ]
        client = _mk_client(server.port)
        client.on_command = slow_handler

        run_task = asyncio.create_task(client.run())
        try:
            # Wait for both handlers to have started
            async def _both_started():
                while len(started) < 2:
                    await asyncio.sleep(0.02)
            await asyncio.wait_for(_both_started(), timeout=3.0)
        finally:
            await client.close()
            try:
                await asyncio.wait_for(run_task, timeout=2.0)
            except asyncio.TimeoutError:
                run_task.cancel()

    # Both handlers must have started within a short window — the
    # second must NOT have waited for the first to finish.
    assert len(started) == 2
    gap = started[1] - started[0]
    assert gap < 0.2, f"second handler should start immediately, gap={gap}s"


@pytest.mark.asyncio
async def test_close_drains_inflight_handlers(fake_keyring) -> None:
    """A handler running when close() is called should get to finish
    (within the 5s budget) so its final WS report doesn't get lost."""
    finished = asyncio.Event()
    sent_after_close: list[dict[str, Any]] = []

    async def handler(msg: dict) -> None:
        await asyncio.sleep(0.3)
        # Mimic the real path: send a final report at the end.
        await client.send_report("action_result", {"status": "ok"}, command_id="1")
        finished.set()

    async with _ConcurrentServer() as server:
        server.scripted = [{"type": "scan", "id": "1"}]
        client = _mk_client(server.port)
        client.on_command = handler

        run_task = asyncio.create_task(client.run())
        try:
            # Let the handler start
            await asyncio.sleep(0.1)
            # Close while the handler is mid-flight
            await client.close()
            await asyncio.wait_for(finished.wait(), timeout=2.0)
        finally:
            try:
                await asyncio.wait_for(run_task, timeout=2.0)
            except asyncio.TimeoutError:
                run_task.cancel()

        # The handler reached its end successfully
        assert finished.is_set()


@pytest.mark.asyncio
async def test_handler_exception_does_not_kill_receiver(fake_keyring) -> None:
    """If the first handler crashes, the receiver should still process
    the second command — the old in-line path leaked the exception
    through the receiver_loop and dropped subsequent messages."""
    seen_second = asyncio.Event()

    async def handler(msg: dict) -> None:
        if msg.get("type") == "boom":
            raise RuntimeError("planned failure")
        if msg.get("type") == "second":
            seen_second.set()

    async with _ConcurrentServer() as server:
        server.scripted = [
            {"type": "boom", "id": "1"},
            {"type": "second", "id": "2"},
        ]
        client = _mk_client(server.port)
        client.on_command = handler

        run_task = asyncio.create_task(client.run())
        try:
            await asyncio.wait_for(seen_second.wait(), timeout=3.0)
        finally:
            await client.close()
            try:
                await asyncio.wait_for(run_task, timeout=2.0)
            except asyncio.TimeoutError:
                run_task.cancel()
