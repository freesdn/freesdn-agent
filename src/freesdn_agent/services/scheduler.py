"""
Scheduler service for FreeSDN Agent.

Runs scheduled network scans using a pure-Python cron expression parser.
Supports standard 5-field cron: minute hour day-of-month month day-of-week.

Schedule entries can be defined in local config or pushed from the server
via the ``update_schedule`` WebSocket command for hot-reload.
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from freesdn_agent.utils.aio import StoppableSleeper

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

    __slots__ = ("_fields", "_expression", "_dom_restricted", "_dow_restricted")

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

        # "Restricted" means the operator wrote something other than a bare
        # wildcard. It cannot be inferred from the parsed set: "*" and "0-6"
        # both yield every weekday, but only the second is a restriction the
        # POSIX OR rule applies to.
        self._dom_restricted = parts[2].strip() not in ("*", "?")
        self._dow_restricted = parts[4].strip() not in ("*", "?")

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
        """Check if a datetime matches this cron expression.

        THE DAY FIELDS ARE OR-ED WHEN BOTH ARE RESTRICTED, which is the POSIX /
        Vixie rule and surprises everyone once: "if both fields are restricted
        (i.e. are not ``*``), the command runs when EITHER matches".

        This used to AND them, so ``0 0 1 * 1`` -- read by any operator as "the
        1st of the month, and every Monday" -- fired only on a 1st that happened
        to also be a Monday. About once every seven months instead of roughly
        five times a month, with nothing to say so. Verified against the old
        code before changing it:

            0 0 1 * 1   2026-06-01 (Mon, 1st)  True
                        2026-06-08 (Mon)       False   <- should fire
                        2026-07-01 (Wed, 1st)  False   <- should fire
        """
        minute, hour, day, month = dt.minute, dt.hour, dt.day, dt.month
        # isoweekday: Mon=1 .. Sun=7 → cron convention: Sun=0
        weekday = dt.isoweekday() % 7

        if not (minute in self._fields[0] and hour in self._fields[1]):
            return False
        if month not in self._fields[3]:
            return False

        dom_restricted = self._dom_restricted
        dow_restricted = self._dow_restricted
        dom_match = day in self._fields[2]
        dow_match = weekday in self._fields[4]

        if dom_restricted and dow_restricted:
            return dom_match or dow_match
        # Exactly one restricted (or neither): the unrestricted one matches
        # everything, so AND is the same as OR and this is just both.
        return dom_match and dow_match

    @property
    def fires_per_hour(self) -> int:
        """How many times this fires within an hour that it fires in."""
        return len(self._fields[0])

    @property
    def min_gap_minutes(self) -> int:
        """Smallest gap, in minutes, between two consecutive firings.

        The guard in ``_load_schedules`` says it rejects anything firing more
        often than every N minutes, and it measured FREQUENCY instead --
        ``fires_per_hour``. Those differ: ``0,1,2,3,4 * * * *`` is five firings
        an hour, which passed a twelve-an-hour limit, while actually running
        five scans in five consecutive minutes and then sleeping for fifty-five.
        A minimum-interval guard has to measure the interval.

        Wraps around the hour boundary, so ``0,59 * * * *`` is correctly a gap
        of one minute rather than fifty-nine.
        """
        minutes = sorted(self._fields[0])
        if len(minutes) < 2:
            # Fires at most once an hour -- unless the hour field admits
            # consecutive hours, in which case the gap is the wrap.
            return 60
        gaps = [b - a for a, b in zip(minutes, minutes[1:], strict=False)]
        gaps.append(60 - minutes[-1] + minutes[0])  # across the hour boundary
        return min(gaps)

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

        self._sleeper = StoppableSleeper()

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

                # Reject expressions that fire more often than every N minutes.
                # Measured as the smallest GAP between firings, not as a count
                # per hour: the two are not the same, and the count let five
                # scans in five consecutive minutes through a twelve-an-hour
                # limit.
                if cron.min_gap_minutes < _MIN_INTERVAL_MINUTES:
                    logger.warning(
                        "Schedule %r cron %r fires every %d minute(s), less than the "
                        "%d-minute minimum — skipping",
                        entry.name,
                        entry.cron,
                        cron.min_gap_minutes,
                        _MIN_INTERVAL_MINUTES,
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
                if await self._sleeper.sleep(_TICK_INTERVAL):
                    break
            except asyncio.CancelledError:
                break

            if not self._running:
                break

            now = datetime.now(UTC)
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
            started = datetime.now(UTC)
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
                duration = (datetime.now(UTC) - started).total_seconds()
                device_count = len(results) if results else 0

                payload: dict[str, Any] = {
                    "schedule_name": entry.name,
                    "scan_type": entry.scan_type,
                    "targets": entry.targets,
                    "device_count": device_count,
                    "duration_seconds": duration,
                    "status": "completed",
                    "started_at": started.isoformat(),
                    "timestamp": datetime.now(UTC).isoformat(),
                }

                if results:
                    payload["devices"] = [r.to_dict() for r in results]

                await self._ws.send_report("scan_result", payload)
                logger.info(
                    "Scheduled scan %r completed in %.1fs: %d device(s)",
                    entry.name, duration, device_count,
                )

            except Exception as exc:
                duration = (datetime.now(UTC) - started).total_seconds()
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
                        "timestamp": datetime.now(UTC).isoformat(),
                    })
                except Exception:
                    pass

    def stop(self) -> None:
        """Signal the scheduler to stop."""
        self._running = False
        # Wake the tick so shutdown does not wait out the remainder of it.
        self._sleeper.wake()
