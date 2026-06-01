"""
Scheduler service for FreeSDN Agent.

Runs scheduled network scans using a pure-Python cron expression parser.
Supports standard 5-field cron: minute hour day-of-month month day-of-week.

Schedule entries can be defined in local config or pushed from the server
via the ``update_schedule`` WebSocket command for hot-reload.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Main loop tick interval (seconds)
_TICK_INTERVAL = 60

# Maximum concurrent scheduled scan tasks
_MAX_CONCURRENT_SCANS = 4

# Maximum schedule entries accepted
MAX_SCHEDULE_ENTRIES = 50

# Minimum cron interval — reject expressions that fire more than once per 5 min
_MIN_INTERVAL_MINUTES = 5


# =============================================================================
# Cron Expression Parser
# =============================================================================

class CronExpression:
    """
    Minimal 5-field cron expression parser.

    Fields: minute(0-59) hour(0-23) day(1-31) month(1-12) weekday(0-6, 0=Sun)

    Supports:
        *       - any value
        */N     - every N
        N       - exact value
        N-M     - range
        N,M,O   - list
        N-M/S   - range with step
    """

    __slots__ = ("_fields", "_expression")

    def __init__(self, expression: str):
        self._expression = expression.strip()
        parts = self._expression.split()
        if len(parts) != 5:
            raise ValueError(f"Cron expression must have 5 fields, got {len(parts)}: {expression!r}")

        ranges = [
            (0, 59),   # minute
            (0, 23),   # hour
            (1, 31),   # day of month
            (1, 12),   # month
            (0, 6),    # day of week (0=Sun)
        ]
        self._fields: list[set[int]] = [
            self._parse_field(parts[i], ranges[i][0], ranges[i][1])
            for i in range(5)
        ]

    @staticmethod
    def _parse_field(field: str, lo: int, hi: int) -> set[int]:
        """Parse a single cron field into a set of matching integers."""
        values: set[int] = set()

        for part in field.split(","):
            part = part.strip()

            # Handle step: */N or N-M/S
            step = 1
            if "/" in part:
                part, step_str = part.split("/", 1)
                try:
                    step = int(step_str)
                except ValueError:
                    raise ValueError(f"Invalid step value '{step_str}' in cron field")
                if step < 1:
                    raise ValueError(f"Step must be >= 1, got {step}")

            if part == "*":
                values.update(range(lo, hi + 1, step))
            elif "-" in part:
                start_str, end_str = part.split("-", 1)
                try:
                    start, end = int(start_str), int(end_str)
                except ValueError:
                    raise ValueError(f"Invalid range '{start_str}-{end_str}' in cron field")
                if start < lo or end > hi or start > end:
                    raise ValueError(f"Range {start}-{end} out of bounds [{lo}-{hi}]")
                values.update(range(start, end + 1, step))
            else:
                try:
                    val = int(part)
                except ValueError:
                    raise ValueError(f"Invalid value '{part}' in cron field")
                if val < lo or val > hi:
                    raise ValueError(f"Value {val} out of bounds [{lo}-{hi}]")
                values.add(val)

        return values

    def matches(self, dt: datetime) -> bool:
        """Check if a datetime matches this cron expression."""
        minute, hour, day, month = dt.minute, dt.hour, dt.day, dt.month
        # isoweekday: Mon=1 .. Sun=7 → cron convention: Sun=0
        weekday = dt.isoweekday() % 7

        return (
            minute in self._fields[0]
            and hour in self._fields[1]
            and day in self._fields[2]
            and month in self._fields[3]
            and weekday in self._fields[4]
        )

    @property
    def fires_per_hour(self) -> int:
        """Estimate how many times per hour this expression fires."""
        return len(self._fields[0])

    def next_run(self, after: datetime) -> datetime:
        """
        Calculate the next datetime matching this expression after ``after``.

        Searches minute-by-minute up to ~1 year ahead. Raises ValueError
        if no match is found (e.g. impossible expressions like day 31 month 2).
        """
        from datetime import timedelta

        dt = after.replace(second=0, microsecond=0) + timedelta(minutes=1)

        max_iterations = 525960  # ~1 year in minutes
        for _ in range(max_iterations):
            if self.matches(dt):
                return dt
            dt += timedelta(minutes=1)

        raise ValueError(f"No matching time found for cron expression: {self._expression!r}")

    def __repr__(self) -> str:
        return f"CronExpression({self._expression!r})"


# =============================================================================
# Scheduler Service
# =============================================================================

class SchedulerService:
    """
    Runs scheduled scans based on cron expressions.

    Each schedule entry maps to a ``ScheduleEntry`` from config.
    The scheduler ticks every 60 seconds, checks all schedules,
    and fires matching ones via the scan manager.

    Concurrency is bounded by a semaphore to prevent resource exhaustion.
    """

    def __init__(self, ws_client, scan_manager, schedules: list | None = None):
        """
        Args:
            ws_client: AgentWSClient for reporting results.
            scan_manager: AsyncScanManager to run scans.
            schedules: Initial list of ScheduleEntry (from config).
        """
        self._ws = ws_client
        self._scan_manager = scan_manager
        self._running = False
        self._scan_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_SCANS)

        # (ScheduleEntry, CronExpression, last_fired, active_task | None)
        self._schedules: list[list] = []  # mutable inner lists for task tracking

        if schedules:
            self._load_schedules(schedules)

    def _load_schedules(self, entries: list) -> None:
        """Parse schedule entries and build cron expressions."""
        new_schedules: list[list] = []
        for entry in entries[:MAX_SCHEDULE_ENTRIES]:
            if not entry.enabled or not entry.cron:
                continue
            try:
                cron = CronExpression(entry.cron)

                # Reject expressions that fire more often than every 5 minutes
                if cron.fires_per_hour > (60 // _MIN_INTERVAL_MINUTES):
                    logger.warning(
                        "Schedule %r cron %r fires too frequently (>%d/hour) — skipping",
                        entry.name,
                        entry.cron,
                        60 // _MIN_INTERVAL_MINUTES,
                    )
                    continue

                # [entry, cron, last_fired, active_task]
                new_schedules.append([entry, cron, None, None])
                logger.info(
                    "Loaded schedule %r: %s",
                    entry.name,
                    entry.cron,
                )
            except ValueError:
                logger.warning(
                    "Invalid cron expression for schedule %r: %s",
                    entry.name,
                    entry.cron,
                    exc_info=True,
                )

        if len(entries) > MAX_SCHEDULE_ENTRIES:
            logger.warning(
                "Schedule entries capped at %d (received %d)",
                MAX_SCHEDULE_ENTRIES,
                len(entries),
            )

        self._schedules = new_schedules

    def update_schedules(self, entries: list) -> None:
        """Hot-reload schedules (e.g. from server-pushed config)."""
        logger.info("Reloading %d schedule(s)", len(entries))
        self._load_schedules(entries)

    async def run(self) -> None:
        """Main scheduler loop — tick every 60 seconds."""
        self._running = True

        if not self._schedules:
            logger.info("No scheduled scans configured")

        logger.info("Scheduler started with %d schedule(s)", len(self._schedules))

        while self._running:
            try:
                await asyncio.sleep(_TICK_INTERVAL)
            except asyncio.CancelledError:
                break

            if not self._running:
                break

            now = datetime.now(timezone.utc)
            await self._check_schedules(now)

    async def _check_schedules(self, now: datetime) -> None:
        """Fire any schedules matching the current minute."""
        # Snapshot the list to avoid mutation during iteration
        schedules = list(self._schedules)

        for sched in schedules:
            entry, cron, last_fired, active_task = sched

            if not cron.matches(now):
                continue

            # Prevent double-firing within the same minute
            if last_fired and (now - last_fired).total_seconds() < 120:
                continue

            # Don't fire if previous run for this schedule is still active
            if active_task is not None and not active_task.done():
                logger.debug(
                    "Schedule %r still running — skipping this tick",
                    entry.name,
                )
                continue

            sched[2] = now  # last_fired

            logger.info("Scheduled scan firing: %r (%s)", entry.name, entry.cron)
            task = asyncio.create_task(
                self._run_scheduled_scan(entry),
                name=f"scheduled-scan-{entry.name}",
            )
            sched[3] = task  # active_task

    async def _run_scheduled_scan(self, entry) -> None:
        """Execute a single scheduled scan and report the result.

        Emits a `scan_result` WS report tagged with ``schedule_name`` and
        ``duration_seconds`` so the backend can record an
        ``agent_schedule_runs`` row + advance ``last_fired_at``. On
        failure, emits a tagged ``scan_result`` with ``status="failed"``
        and ``error`` text instead — same channel, the backend handler
        records the failure run the same way.
        """
        from freesdn_agent.services.async_scan_manager import ScanJob, ScanType

        # Bounded concurrency
        async with self._scan_semaphore:
            started = datetime.now(timezone.utc)
            try:
                try:
                    scan_type = ScanType(entry.scan_type)
                except ValueError:
                    scan_type = ScanType.QUICK

                job = ScanJob(
                    scan_type=scan_type,
                    interfaces=[entry.interface] if entry.interface else [""],
                    targets=entry.targets or None,
                )

                results = await self._scan_manager.run_scan(job)
                duration = (datetime.now(timezone.utc) - started).total_seconds()
                device_count = len(results) if results else 0

                payload: dict[str, Any] = {
                    "schedule_name": entry.name,
                    "scan_type": entry.scan_type,
                    "targets": entry.targets,
                    "device_count": device_count,
                    "duration_seconds": duration,
                    "status": "completed",
                    "started_at": started.isoformat(),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

                if results:
                    payload["devices"] = [r.to_dict() for r in results]

                await self._ws.send_report("scan_result", payload)
                logger.info(
                    "Scheduled scan %r completed in %.1fs: %d device(s)",
                    entry.name, duration, device_count,
                )

            except Exception as exc:
                duration = (datetime.now(timezone.utc) - started).total_seconds()
                logger.exception("Scheduled scan %r failed", entry.name)
                # Send as a tagged scan_result so the backend records the
                # failure in the same agent_schedule_runs history table
                # (status=failed) instead of as a separate error channel
                # entry. Operators want one timeline of runs, not two.
                try:
                    await self._ws.send_report("scan_result", {
                        "schedule_name": entry.name,
                        "scan_type": entry.scan_type,
                        "status": "failed",
                        "error": str(exc) or "Scheduled scan failed",
                        "duration_seconds": duration,
                        "started_at": started.isoformat(),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                except Exception:
                    pass

    def stop(self) -> None:
        """Signal the scheduler to stop."""
        self._running = False
