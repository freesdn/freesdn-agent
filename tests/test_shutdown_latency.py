"""
The daemon could not shut down, and systemd was killing it every restart.

``AgentDaemon.run()`` gathers five long-lived loops and ``stop()`` only sets each
service's ``_running`` flag. A loop sitting in a bare ``asyncio.sleep(interval)``
cannot see that flag until the sleep ends, and ``gather`` waits for all five --
so the process did not exit until the SLOWEST loop woke up.

The slowest is the updater: ``auto_update_interval`` defaults to 3000s and
permits 86400s, in a single sleep. Measured with the real services before the
fix:

    heartbeat (interval 6s): stop() at 0.3s -> run() returned at 6.0s

and with the updater's default that is fifty minutes, so in practice systemd's
TimeoutStopSec fires and the daemon is SIGKILLed. That costs a clean WebSocket
close (the control plane sees a dropped connection rather than a goodbye),
kills in-flight work mid-write, and makes every ``systemctl restart`` block for
the full timeout -- including the restart the auto-updater itself triggers.

After:

    heartbeat (interval 6s):    stop() at 0.3s -> 0.30s
    updater   (interval 3000s): stop() at 0.3s -> 0.31s
"""

from __future__ import annotations

import asyncio
import time
import types

import pytest

from freesdn_agent.services.heartbeat import HeartbeatService
from freesdn_agent.services.scheduler import SchedulerService
from freesdn_agent.services.updater import UpdaterService
from freesdn_agent.utils.aio import StoppableSleeper


class _FakeWS:
    connected = False

    async def send_report(self, *a, **k):
        return None

    async def close(self):
        return None


def _updater() -> UpdaterService:
    config = types.SimpleNamespace(
        auto_update_interval=3000,
        auto_update_enabled=True,
        auto_update_channel="stable",
        server_url="https://controller.example.com",
        agent_id="agent-1",
    )
    return UpdaterService(ws_client=_FakeWS(), config=config, agent_version="1.0.1")


async def _stop_latency(service, *, stop_after: float = 0.2, budget: float = 15.0) -> float:
    """Seconds between stop() and run() actually returning."""
    task = asyncio.create_task(service.run())
    await asyncio.sleep(stop_after)
    t0 = time.monotonic()
    service.stop()
    await asyncio.wait_for(task, timeout=budget)
    return time.monotonic() - t0


# ── the sleeper itself ──────────────────────────────────────────


async def test_sleep_returns_false_when_the_interval_elapses():
    s = StoppableSleeper()
    assert await s.sleep(0.05) is False


async def test_wake_returns_true_immediately():
    s = StoppableSleeper()
    task = asyncio.create_task(s.sleep(300))
    await asyncio.sleep(0.05)
    t0 = time.monotonic()
    s.wake()
    assert await task is True
    assert time.monotonic() - t0 < 1.0


async def test_a_wake_that_arrives_first_is_not_lost():
    """
    stop() can land between two iterations, before the next sleep starts. An
    Event remembers that; a bare sleep would not, and the loop would take one
    more full interval to notice.
    """
    s = StoppableSleeper()
    s.wake()
    t0 = time.monotonic()
    assert await s.sleep(300) is True
    assert time.monotonic() - t0 < 0.5


# ── the services that hold the daemon open ──────────────────────


async def test_heartbeat_stops_promptly():
    latency = await _stop_latency(HeartbeatService(ws_client=_FakeWS(), interval=6))
    assert latency < 1.0, f"took {latency:.1f}s; it waited out its interval"


async def test_the_updater_stops_promptly():
    """
    The one that mattered. Its interval defaults to 3000s, so before the fix
    this could not return inside any sane test budget -- or inside systemd's.
    """
    latency = await _stop_latency(_updater())
    assert latency < 1.0, f"took {latency:.1f}s; a 3000s interval means SIGKILL"


async def test_the_scheduler_stops_promptly():
    svc = SchedulerService(ws_client=_FakeWS(), scan_manager=None, schedules=[])
    latency = await _stop_latency(svc)
    assert latency < 1.0, f"took {latency:.1f}s; its tick is 60s"


@pytest.mark.parametrize(
    "factory",
    [
        lambda: HeartbeatService(ws_client=_FakeWS(), interval=6),
        _updater,
        lambda: SchedulerService(ws_client=_FakeWS(), scan_manager=None, schedules=[]),
    ],
)
def test_every_long_lived_service_wakes_its_sleeper_on_stop(factory):
    """
    Structural, and worth it: a service that keeps a sleeper but forgets to wake
    it in stop() reintroduces exactly this, and the only symptom is a slow
    shutdown nobody times.
    """
    import inspect

    svc = factory()
    assert hasattr(svc, "_sleeper")
    assert "_sleeper.wake()" in inspect.getsource(type(svc).stop)
