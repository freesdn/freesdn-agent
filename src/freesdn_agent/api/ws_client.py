"""
WebSocket client for FreeSDN Agent Daemon.

Maintains a persistent WebSocket connection to the FreeSDN control plane
with automatic reconnection, authentication, and bidirectional messaging.

Matches the protocol defined in:
  v2/backend/app/api/v1/endpoints/agents.py  (server side)
  v2/backend/app/services/remote_agent.py    (enums / data classes)
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

import websockets
from websockets.exceptions import (
    ConnectionClosed,
    ConnectionClosedError,
    InvalidStatusCode,
)

logger = logging.getLogger(__name__)


class AgentWSClient:
    """
    Persistent WebSocket client for agent ↔ server communication.

    Handles:
    - Connection with exponential-backoff reconnection
    - Agent-key authentication on connect
    - Outbound message queue (heartbeats, reports, results)
    - Inbound command dispatch
    """

    def __init__(
        self,
        agent_id: str,
        server_url: str,
        site_id: str,
        reconnect_delay: int = 5,
        reconnect_max_delay: int = 300,
    ):
        self.agent_id = agent_id
        self.site_id = site_id

        # Build WebSocket URL from server URL
        ws_scheme = "wss" if server_url.startswith("https") else "ws"
        host = server_url.replace("https://", "").replace("http://", "").rstrip("/")
        self.ws_url = f"{ws_scheme}://{host}/api/v1/agents/ws/{agent_id}"

        self._reconnect_delay = reconnect_delay
        self._reconnect_max_delay = reconnect_max_delay

        self._ws: websockets.WebSocketClientProtocol | None = None
        self._send_queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=500)
        self._running = False
        self._connected = False
        self._agent_key: str | None = None

        # In-flight command handler tasks. Tracked so receiver_loop can
        # dispatch concurrently (long scans don't block the read side or
        # the WS keepalive autoping cycle) and shutdown can wait on them.
        self._inflight_handlers: set[asyncio.Task] = set()

        # Callback for incoming commands (set by daemon.main)
        self.on_command: Callable[[dict], Awaitable[None]] | None = None

    @property
    def connected(self) -> bool:
        return self._connected

    # -----------------------------------------------------------------
    # Credential loading
    # -----------------------------------------------------------------

    def _load_agent_key(self) -> str:
        """Load agent key from OS keyring."""
        try:
            import keyring
            key = keyring.get_password("FreeSDN Agent", f"agent_key:{self.agent_id}")
            if key:
                return key
        except Exception as e:
            logger.warning("Failed to load agent key from keyring: %s", e)

        raise RuntimeError(
            "Agent key not found in keyring. Run 'freesdn-agent register' first."
        )

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    async def send(self, message: dict[str, Any]) -> None:
        """Queue a message for sending. Drops oldest if queue is full."""
        if self._send_queue.full():
            try:
                self._send_queue.get_nowait()  # drop oldest
            except asyncio.QueueEmpty:
                pass
        await self._send_queue.put(message)

    async def send_report(
        self,
        report_type: str,
        payload: dict[str, Any],
        command_id: str | None = None,
    ) -> None:
        """Send a typed report to the server."""
        msg = {
            "type": report_type,
            "payload": payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if command_id:
            msg["command_id"] = command_id
        await self.send(msg)

    async def close(self) -> None:
        """Close the connection and stop reconnecting.

        Waits up to 5s for in-flight command handlers to finish so
        their final scan_result / action_result reports can drain
        through sender_loop before the WS goes away. Anything still
        running after that deadline is cancelled.
        """
        self._running = False

        if self._inflight_handlers:
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        *self._inflight_handlers, return_exceptions=True,
                    ),
                    timeout=5.0,
                )
            except asyncio.TimeoutError:
                for task in list(self._inflight_handlers):
                    task.cancel()

        if self._ws:
            await self._ws.close()
            self._ws = None
        self._connected = False

    # -----------------------------------------------------------------
    # Main loop
    # -----------------------------------------------------------------

    async def run(self) -> None:
        """
        Run the WebSocket client with automatic reconnection.

        This coroutine never returns until close() is called.
        """
        self._running = True
        self._agent_key = self._load_agent_key()
        delay = self._reconnect_delay

        while self._running:
            try:
                await self._connect_and_run()
                # If we reach here the connection was closed normally
                delay = self._reconnect_delay
            except (ConnectionClosed, ConnectionClosedError, OSError) as e:
                logger.warning("WebSocket disconnected: %s", e)
                # VERIFIED.md bug #4: any disconnect that came from a
                # PREVIOUSLY-CONNECTED state should reset the backoff —
                # a transient backend restart shouldn't escalate to a
                # 5-minute reconnect wait just because we'd burned a
                # few cycles failing earlier.
                if self._connected:
                    delay = self._reconnect_delay
            except InvalidStatusCode as e:
                logger.error("WebSocket connection rejected (HTTP %s)", e.status_code)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Unexpected WebSocket error")

            self._connected = False
            if not self._running:
                break

            logger.info("Reconnecting in %ds …", delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, self._reconnect_max_delay)

    # -----------------------------------------------------------------
    # Connection lifecycle
    # -----------------------------------------------------------------

    async def _connect_and_run(self) -> None:
        """Single connection attempt: connect → auth → sender/receiver."""
        logger.info("Connecting to %s", self.ws_url)

        async with websockets.connect(
            self.ws_url,
            ping_interval=20,
            ping_timeout=20,
            close_timeout=10,
        ) as ws:
            self._ws = ws

            # Authenticate
            await ws.send(json.dumps({
                "agent_key": self._agent_key,
                "site_id": self.site_id,
            }))

            # Read until we see auth_success or auth_error. The backend
            # sends auth_success then immediately fires schedule
            # bootstrap-push messages, so we may receive update_schedule
            # commands BEFORE auth_success on the wire. Buffer those
            # and replay into the receiver_loop after auth completes.
            pre_auth_buffer: list[dict] = []
            auth_response: dict | None = None
            while True:
                msg = json.loads(await ws.recv())
                msg_type = msg.get("type", "")
                if msg_type in ("auth_success", "auth_error"):
                    auth_response = msg
                    break
                # Buffer non-auth messages received during handshake
                pre_auth_buffer.append(msg)
                if len(pre_auth_buffer) > 20:  # safety bound
                    logger.warning(
                        "Pre-auth buffer overflow — dropping handshake",
                    )
                    self._running = False
                    return

            if auth_response.get("type") == "auth_error":
                logger.error("Authentication failed: %s", auth_response.get("message"))
                self._running = False
                return

            logger.info("Authenticated: %s", auth_response.get("message", "OK"))
            self._connected = True

            # Replay any pre-auth-buffered messages through the command
            # handler so bootstrap-push schedules don't get lost.
            for buffered in pre_auth_buffer:
                if self.on_command:
                    try:
                        await self.on_command(buffered)
                    except Exception:
                        logger.exception(
                            "Replay of pre-auth message failed: %s",
                            buffered.get("type"),
                        )

            # Drain stale HEARTBEAT messages (they're useless after a
            # gap — a new one will be sent on the next tick) but KEEP
            # scan_result, topology_update, action_result, etc. queued
            # for delivery. Without this filter, an agent that runs a
            # scheduled scan during a backend outage drops the results
            # on the floor when the WS reconnects (VERIFIED.md bug #2).
            kept: list[dict] = []
            drained = 0
            while not self._send_queue.empty():
                try:
                    msg = self._send_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                msg_type = msg.get("type", "")
                if msg_type == "heartbeat":
                    drained += 1
                else:
                    kept.append(msg)
            # Requeue the kept ones in original order
            for msg in kept:
                try:
                    self._send_queue.put_nowait(msg)
                except asyncio.QueueFull:
                    logger.warning(
                        "Send queue full while requeuing %s after reconnect",
                        msg.get("type"),
                    )
                    break
            if drained or kept:
                logger.info(
                    "Drained %d stale heartbeats; kept %d non-heartbeat message(s) for delivery",
                    drained, len(kept),
                )

            # Run sender and receiver concurrently
            sender = asyncio.create_task(self._sender_loop(ws))
            receiver = asyncio.create_task(self._receiver_loop(ws))

            done, pending = await asyncio.wait(
                [sender, receiver],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            # Re-raise first exception from completed tasks
            for task in done:
                task.result()  # raises if the task had an exception

    async def _sender_loop(
        self, ws: websockets.WebSocketClientProtocol
    ) -> None:
        """Send queued messages."""
        while self._running:
            msg = await self._send_queue.get()
            await ws.send(json.dumps(msg, default=str))

    async def _receiver_loop(
        self, ws: websockets.WebSocketClientProtocol
    ) -> None:
        """Receive and dispatch server commands.

        Commands are dispatched as concurrent tasks rather than awaited
        in-line. This matters for long-running operations like a full
        network scan that runs for several minutes: awaiting the handler
        inline would block this loop, which means no other commands
        could be received and (more importantly) any heartbeat reports
        queued by other services would still flow through sender_loop
        but the receive side would be deaf to server-initiated traffic
        — including server pings if the autoping handshake ever needed
        application-level acknowledgement. Spawning tasks keeps both
        directions of the WS live during long handlers.
        """
        async for raw in ws:
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning("Received non-JSON message")
                continue

            msg_type = message.get("type", "")

            if msg_type == "ping":
                await ws.send(json.dumps({"type": "pong"}))
                continue

            if self.on_command:
                self._spawn_command_handler(message, msg_type)

    def _spawn_command_handler(self, message: dict, msg_type: str) -> None:
        """Run on_command as a tracked task so receiver_loop stays free."""
        if self.on_command is None:
            return
        coro = self.on_command(message)
        task = asyncio.create_task(coro, name=f"cmd:{msg_type}")
        self._inflight_handlers.add(task)

        def _cleanup(t: asyncio.Task) -> None:
            self._inflight_handlers.discard(t)
            if t.cancelled():
                return
            exc = t.exception()
            if exc is not None:
                logger.error(
                    "Command handler error for %s: %s",
                    msg_type, exc, exc_info=exc,
                )

        task.add_done_callback(_cleanup)
