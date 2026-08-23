"""
The cron parser ANDed the two day fields, and the rate guard measured the wrong thing.

``services/scheduler.py`` is 154 statements at 0% coverage and it decides when
unattended scans run. Two faults, both silent -- the schedule simply runs less
often, or more often, than the operator asked for, with nothing to say so.

1. DAY-OF-MONTH AND DAY-OF-WEEK WERE AND-ED.

   POSIX / Vixie cron ORs them when both are restricted: "if both fields are
   restricted (i.e. are not *), the command runs when EITHER matches". Every
   crontab on earth behaves that way, so ``0 0 1 * 1`` reads as "the 1st of the
   month, and every Monday".

   Measured against the old code:

       0 0 1 * 1   2026-06-01 (Mon, 1st)  True
                   2026-06-08 (Mon)       False   <- should fire
                   2026-07-01 (Wed, 1st)  False   <- should fire

   About once every seven months instead of roughly five times a month.

2. THE MINIMUM-INTERVAL GUARD COUNTED FIRINGS PER HOUR.

   Frequency is not interval. ``0,1,2,3,4 * * * *`` is five firings an hour,
   which passed a twelve-an-hour limit, while running five scans in five
   consecutive minutes and then sleeping for fifty-five. ``0,59 * * * *`` is
   two an hour with a one-minute gap across the hour boundary.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from freesdn_agent.services.scheduler import _MIN_INTERVAL_MINUTES, CronExpression

# ── the day fields ──────────────────────────────────────────────


def test_both_day_fields_restricted_means_or():
    """THE fix. Either the date or the weekday is enough."""
    c = CronExpression("0 0 1 * 1")

    assert c.matches(datetime(2026, 6, 1, 0, 0)) is True  # Mon AND 1st
    assert c.matches(datetime(2026, 6, 8, 0, 0)) is True  # Mon only
    assert c.matches(datetime(2026, 7, 1, 0, 0)) is True  # 1st only
    assert c.matches(datetime(2026, 6, 9, 0, 0)) is False  # neither


def test_only_day_of_month_restricted():
    """One wildcard: OR and AND agree, and the restriction must still bite."""
    c = CronExpression("0 0 15 * *")

    assert c.matches(datetime(2026, 6, 15, 0, 0)) is True
    assert c.matches(datetime(2026, 6, 16, 0, 0)) is False


def test_only_day_of_week_restricted():
    c = CronExpression("0 0 * * 1")

    assert c.matches(datetime(2026, 6, 8, 0, 0)) is True  # Monday
    assert c.matches(datetime(2026, 6, 9, 0, 0)) is False


def test_neither_restricted_still_respects_minute_and_hour():
    """
    The OR rule must not leak into the other fields. A wildcard day pair does
    not make every minute match.
    """
    c = CronExpression("30 4 * * *")

    assert c.matches(datetime(2026, 6, 9, 4, 30)) is True
    assert c.matches(datetime(2026, 6, 9, 4, 31)) is False
    assert c.matches(datetime(2026, 6, 9, 5, 30)) is False


def test_month_is_still_anded_even_when_the_days_or():
    """
    Month is not part of the POSIX exception. ``0 0 1 3 1`` means March only,
    on the 1st or a Monday -- not "any Monday of any month".
    """
    c = CronExpression("0 0 1 3 1")

    assert c.matches(datetime(2026, 3, 2, 0, 0)) is True  # Monday in March
    assert c.matches(datetime(2026, 6, 8, 0, 0)) is False  # Monday, wrong month


def test_a_written_out_range_counts_as_restricted():
    """
    ``0-6`` parses to the same set as ``*`` but is a restriction the operator
    wrote. The flag has to come from the TEXT, not the parsed set, or this
    expression would silently go back to AND.
    """
    c = CronExpression("0 0 1 * 0-6")

    # Every weekday matches, so the OR makes this fire daily.
    assert c.matches(datetime(2026, 6, 9, 0, 0)) is True


# ── the interval guard ──────────────────────────────────────────


@pytest.mark.parametrize(
    ("expression", "gap"),
    [
        ("*/15 * * * *", 15),
        ("*/5 * * * *", 5),
        ("0,1,2,3,4 * * * *", 1),  # five an hour, one minute apart
        ("0,30 * * * *", 30),
        ("0,59 * * * *", 1),  # the wrap: :59 then :00
        ("0 3 * * *", 60),  # once an hour at most
    ],
)
def test_the_minimum_gap_is_measured_not_counted(expression: str, gap: int):
    assert CronExpression(expression).min_gap_minutes == gap


def test_the_hour_boundary_is_not_forgotten():
    """
    ``0,59`` is a one-minute gap, not fifty-nine. Measuring only the gaps
    BETWEEN sorted minutes misses the wrap, and the burst it lets through sits
    exactly on the hour change.
    """
    assert CronExpression("0,59 * * * *").min_gap_minutes == 1


def test_frequency_and_interval_are_not_the_same_thing():
    """
    The precise reason the old guard was wrong, pinned so nobody re-derives it:
    an expression can be well under the per-hour limit and still fire every
    minute.
    """
    c = CronExpression("0,1,2,3,4 * * * *")

    assert c.fires_per_hour <= 60 // _MIN_INTERVAL_MINUTES, "premise: it passes a count-based guard"
    assert c.min_gap_minutes < _MIN_INTERVAL_MINUTES, "yet it fires inside the minimum interval"


def test_an_expression_exactly_at_the_limit_is_allowed():
    """A guard that rejected its own stated minimum would be off by one."""
    assert CronExpression("*/5 * * * *").min_gap_minutes == _MIN_INTERVAL_MINUTES


# ── the guard itself, not just the number it consults ───────────


class _Entry:
    """The shape _load_schedules reads off a schedule."""

    def __init__(self, name: str, cron: str, enabled: bool = True):
        self.name = name
        self.cron = cron
        self.enabled = enabled


def _loaded(*entries) -> list[str]:
    """Names of the schedules a SchedulerService actually accepted."""
    from freesdn_agent.services.scheduler import SchedulerService

    svc = SchedulerService(ws_client=None, scan_manager=None, schedules=list(entries))
    return [s[0].name for s in svc._schedules]


def test_a_burst_schedule_is_rejected_by_the_loader():
    """
    The behaviour, not the arithmetic. Testing min_gap_minutes alone left the
    guard itself uncovered -- swapping it back to the per-hour count broke
    nothing, which a mutation run showed.
    """
    assert _loaded(_Entry("burst", "0,1,2,3,4 * * * *")) == []


def test_the_hour_wrap_burst_is_rejected_by_the_loader():
    assert _loaded(_Entry("wrap", "0,59 * * * *")) == []


def test_a_reasonable_schedule_is_accepted():
    """A guard that rejected everything would also pass the tests above."""
    assert _loaded(_Entry("quarter-hourly", "*/15 * * * *")) == ["quarter-hourly"]


def test_a_schedule_exactly_at_the_limit_is_accepted():
    assert _loaded(_Entry("five", "*/5 * * * *")) == ["five"]


def test_a_disabled_schedule_is_not_loaded():
    assert _loaded(_Entry("off", "*/15 * * * *", enabled=False)) == []


def test_one_bad_expression_does_not_lose_the_others():
    """
    A malformed cron is skipped with a warning; it must not take the rest of the
    operator's schedules down with it.
    """
    assert _loaded(
        _Entry("good-1", "*/15 * * * *"),
        _Entry("broken", "not a cron"),
        _Entry("good-2", "0 3 * * *"),
    ) == ["good-1", "good-2"]


# ── parsing still refuses nonsense ──────────────────────────────


@pytest.mark.parametrize(
    "bad",
    [
        "* * * *",  # four fields
        "* * * * * *",  # six
        "60 * * * *",  # minute out of range
        "* 24 * * *",  # hour out of range
        "* * 0 * *",  # day-of-month is 1-based
        "* * * 13 *",  # month out of range
        "* * * * 7",  # cron weekday is 0-6
        "*/0 * * * *",  # zero step
        "5-1 * * * *",  # inverted range
        "abc * * * *",
    ],
)
def test_a_malformed_expression_is_rejected(bad: str):
    """
    A schedule that cannot be parsed is skipped with a warning rather than
    crashing the daemon -- but it has to raise here for that to happen.
    """
    with pytest.raises(ValueError):
        CronExpression(bad)
