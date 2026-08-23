"""Turning scan results into a CSV an operator can read.

Deliberately Qt-free and outside ``ui/``. The format is data serialisation, not
a UI concern, and keeping it here has two concrete payoffs: it can be tested
without standing up a QApplication (PySide6 is an optional extra and CI does not
install it, so anything importable only through ``ui/`` is effectively
untestable), and the CLI can reuse it rather than growing a second, drifting
copy -- which is the shape of most of the bugs already found in this agent.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable
from typing import IO, Any

__all__ = ["EXPORT_COLUMNS", "export_row", "write_csv"]

#: Export columns, in the order an operator reads them. Deliberately the fields
#: that IDENTIFY a device rather than every attribute on ScanResult -- a CSV
#: nobody can scan by eye is not much better than no export.
EXPORT_COLUMNS: list[str] = [
    "ip_address",
    "mac_address",
    "hostname",
    "vendor",
    "device_type",
    "model",
    "manufacturer",
    "serial_number",
    "firmware_version",
    "http_port",
    "https_port",
    "response_time_ms",
    "discovered_by",
    "discovered_at",
]


def export_row(result: Any) -> list[str]:
    """One scan result as a row of strings.

    Tolerant by design: results come from a dozen different scanners and not all
    of them set every field. An AttributeError here would abort an export after
    the operator had already chosen a filename.

    An enum is written as its value and a datetime as ISO-8601, so a column
    reads ``camera`` rather than ``DeviceType.CAMERA``.
    """
    row: list[str] = []
    for column in EXPORT_COLUMNS:
        value = getattr(result, column, None)
        if value is None:
            row.append("")
        elif hasattr(value, "value"):  # enum
            row.append(str(value.value))
        elif hasattr(value, "isoformat"):  # datetime / date
            row.append(value.isoformat())
        else:
            row.append(str(value))
    return row


def write_csv(handle: IO[str], results: Iterable[Any]) -> int:
    """Write a header plus one row per result. Returns the row count.

    Takes an open handle rather than a path so the caller owns the file --
    including the ``newline=""`` the csv module requires. Without it Windows
    turns each row ending into a doubled carriage return and every other row of
    the file shows up blank in Excel.
    """
    writer = csv.writer(handle)
    writer.writerow(EXPORT_COLUMNS)
    count = 0
    for result in results:
        writer.writerow(export_row(result))
        count += 1
    return count
