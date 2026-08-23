"""
"Export Results..." was a menu item that did nothing.

``File -> Export Results...``, shortcut Ctrl+E, and its handler was::

    def _on_export(self) -> None:
        # TODO: Implement export to CSV
        pass

It is not decorative. ``_on_scan_finished`` calls
``action_export.setEnabled(len(results) > 0)``, so the moment any scan returns
anything the item ENABLES -- an operator runs a scan, picks Export, and gets no
dialog, no file, and no error. The same shape as a settings badge with no form
behind it: the UI advertises a capability and provides no path to it.

The format lives in ``utils/export.py``, not in ``ui/``: CSV serialisation is
data, not a UI concern, and PySide6 is an optional extra that CI does not
install -- so anything reachable only through ``ui/`` is effectively untestable.
Keeping it out means the part worth testing, what actually lands in the file, is
covered, and the CLI can reuse it instead of growing a second copy that drifts.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from enum import Enum

import pytest

from freesdn_agent.utils.export import EXPORT_COLUMNS, export_row, write_csv


class _DeviceType(str, Enum):
    CAMERA = "camera"
    UNKNOWN = "unknown"


class _Result:
    """A ScanResult-shaped object; scanners fill in wildly different subsets."""

    def __init__(self, **kw):
        defaults = {
            "ip_address": "192.168.1.10",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "hostname": "cam-01",
            "vendor": "TestCo",
            "device_type": _DeviceType.CAMERA,
            "model": None,
            "manufacturer": None,
            "serial_number": None,
            "firmware_version": None,
            "http_port": 80,
            "https_port": None,
            "response_time_ms": 12.5,
            "discovered_by": "onvif",
            "discovered_at": datetime(2026, 8, 23, 9, 30, tzinfo=UTC),
        }
        defaults.update(kw)
        for k, v in defaults.items():
            setattr(self, k, v)


def _has_qt() -> bool:
    """Whether Qt can actually be USED here, not merely imported.

    ``import PySide6`` is not the question. The package imports fine on a
    headless CI runner and then loading a widget module dies on
    ``libEGL.so.1: cannot open shared object file`` -- the Python package is
    installed, the system libraries behind it are not. Guarding on the import
    alone turned these two skips into two failures the moment CI installed the
    dev extras, which is how the public agent repo went red on its first run.

    Importing QtWidgets is the cheapest thing that forces the shared libraries
    to load, and it is what ``main_window`` needs anyway.
    """
    try:
        from PySide6 import QtWidgets  # noqa: F401
    except Exception:
        return False
    return True


def _row(result) -> dict[str, str]:
    return dict(zip(EXPORT_COLUMNS, export_row(result), strict=True))


def test_a_result_becomes_one_row_per_column():
    assert len(export_row(_Result())) == len(EXPORT_COLUMNS)


def test_the_identifying_fields_are_present():
    """
    A CSV nobody can scan by eye is not much better than no export, so the
    column set is the fields that identify a device, not every attribute.
    """
    for column in ("ip_address", "mac_address", "hostname", "vendor", "device_type"):
        assert column in EXPORT_COLUMNS


def test_missing_values_become_empty_not_none():
    """``None`` would land in the file as the literal text "None"."""
    row = _row(_Result(hostname=None, vendor=None, https_port=None))

    assert row["hostname"] == ""
    assert row["vendor"] == ""
    assert row["https_port"] == ""


def test_an_enum_is_written_as_its_value():
    """Otherwise the column reads "_DeviceType.CAMERA" instead of "camera"."""
    assert _row(_Result())["device_type"] == "camera"


def test_a_datetime_is_written_as_iso8601():
    assert _row(_Result())["discovered_at"].startswith("2026-08-23T09:30")


def test_a_result_missing_an_attribute_entirely_does_not_raise():
    """
    Results come from a dozen scanners and not all of them set every field. An
    AttributeError here would abort an export after the operator has already
    chosen a filename.
    """

    class Sparse:
        ip_address = "10.0.0.1"

    row = _row(Sparse())
    assert row["ip_address"] == "10.0.0.1"
    assert row["vendor"] == ""


def test_the_rows_round_trip_through_the_csv_module():
    """
    The end-to-end property: what is written can be read back, including a
    value containing the delimiter.
    """
    results = [_Result(), _Result(ip_address="192.168.1.11", hostname="cam,02")]

    buf = io.StringIO()
    assert write_csv(buf, results) == 2

    buf.seek(0)
    read_back = list(csv.DictReader(buf))
    assert len(read_back) == 2
    assert read_back[0]["ip_address"] == "192.168.1.10"
    assert read_back[1]["hostname"] == "cam,02", "the comma was not quoted"


@pytest.mark.skipif(not _has_qt(), reason="Qt is not usable here (no PySide6, or no system Qt libraries)")
def test_the_handler_is_no_longer_a_stub():
    """
    The item enables itself after any successful scan, so a `pass` here is a
    control an operator can press for nothing.
    """
    import inspect

    from freesdn_agent.ui.main_window import MainWindow

    src = inspect.getsource(MainWindow._on_export)
    body = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))
    assert "getSaveFileName" in body, "export still does not ask for a filename"
    assert "write_csv" in body, "export still does not write anything"


@pytest.mark.skipif(not _has_qt(), reason="Qt is not usable here (no PySide6, or no system Qt libraries)")
def test_export_state_exists_before_any_scan():
    """
    Ctrl+E can fire before a scan has ever run. Reading an unset attribute
    there would raise instead of saying there is nothing to export.
    """
    import inspect

    from freesdn_agent.ui.main_window import MainWindow

    assert "_last_results" in inspect.getsource(MainWindow.__init__)
