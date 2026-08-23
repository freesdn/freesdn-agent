"""Async helpers shared by the daemon's long-lived services."""

from __future__ import annotations

import asyncio

__all__ = ["StoppableSleeper"]


class StoppableSleeper:
    """An interval sleep that a stop() can interrupt immediately.

    The daemon runs five long-lived loops under one ``asyncio.gather``, and
    ``AgentDaemon.stop()`` only sets each service's ``_running`` flag. A loop
    sitting in a bare ``asyncio.sleep(interval)`` cannot see that flag until the
    sleep ends, and gather waits for every one of them, so the process did not
    exit until the SLOWEST loop woke up:

        updater    auto_update_interval, default 3000s, max 86400s
        scheduler  its tick
        heartbeat  30s

    Measured with the real HeartbeatService at interval=6: stop() at 0.3s,
    run() returned at 6.0s. With the updater's default that is fifty minutes,
    so in practice systemd's TimeoutStopSec fires and the daemon is SIGKILLed
    on every restart -- no clean WebSocket close, in-flight work killed
    mid-write, and `systemctl restart` blocking for the full timeout. The
    auto-updater's own restart is the same path, so an update was slow for the
    same reason.

    Usage::

        self._sleeper = StoppableSleeper()
        ...
        while self._running:
            do_work()
            if await self._sleeper.sleep(interval):
                break          # stop was requested

        def stop(self):
            self._running = False
            self._sleeper.wake()
    """

    __slots__ = ("_event",)

    def __init__(self) -> None:
        # Safe to build without a running loop on 3.10+; asyncio.Event no
        # longer binds to a loop at construction time.
        self._event = asyncio.Event()

    def wake(self) -> None:
        """Ask any in-progress sleep to return immediately."""
        self._event.set()

    @property
    def stopping(self) -> bool:
        return self._event.is_set()

    async def sleep(self, seconds: float) -> bool:
        """Sleep up to ``seconds``. Returns True if woken by :meth:`wake`.

        Returning a bool rather than raising keeps the call sites readable: the
        loops here want "should I stop now?", not an exception to catch around
        every interval.
        """
        if self._event.is_set():
            return True
        try:
            await asyncio.wait_for(self._event.wait(), timeout=seconds)
            return True
        except TimeoutError:
            return False
