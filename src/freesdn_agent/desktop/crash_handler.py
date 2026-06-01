"""Uncaught-exception handler for the desktop app.

Before this lived in the code, a Python exception bubbling out of a
Qt slot would either silently exit the process or print to a console
the user never sees (PyInstaller-bundled apps have no console).
Result: from the operator's perspective, the app "just disappeared".

This handler:
1. Logs the full traceback through the standard logging stack so it
   reaches the rotating log file the user already trusts.
2. Writes a self-contained crash report to ``crashes/`` under the
   per-user app data dir, named with the failure timestamp. The
   report includes platform info, Python/Qt/agent versions, the
   exception chain, and a stack snapshot. Operators can attach it
   to a support ticket without having to dig through log files.
3. If a ``QApplication`` exists, surfaces a non-blocking dialog with
   the crash summary and a button to copy the report path to the
   clipboard. The dialog defers ``sys.exit`` so the user gets to
   read the message before the process leaves.

KeyboardInterrupt is passed through to the default handler so
``Ctrl+C`` in dev still works.
"""

from __future__ import annotations

import logging
import platform
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

from platformdirs import user_data_dir

from freesdn_agent import __app_name__, __version__

logger = logging.getLogger(__name__)


def _crash_dir() -> Path:
    """Return the directory where crash reports are written."""
    base = Path(user_data_dir(__app_name__, "FreeSDN")) / "crashes"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _write_crash_report(exc_type, exc_value, exc_tb) -> Path:
    """Serialize the exception + environment to a timestamped file."""
    now = datetime.now(timezone.utc)
    name = now.strftime("crash-%Y%m%d-%H%M%S.txt")
    path = _crash_dir() / name

    try:
        from PySide6 import __version__ as qt_version
    except Exception:
        qt_version = "unknown"

    body_lines = [
        f"FreeSDN Agent crash report",
        f"==========================",
        f"Timestamp: {now.isoformat()}",
        f"Agent version: {__version__}",
        f"Python: {sys.version}",
        f"PySide6: {qt_version}",
        f"Platform: {platform.system()} {platform.release()} ({platform.machine()})",
        "",
        f"Exception: {exc_type.__name__}: {exc_value}",
        "",
        "Traceback:",
        "".join(traceback.format_exception(exc_type, exc_value, exc_tb)),
    ]
    try:
        path.write_text("\n".join(body_lines), encoding="utf-8")
    except Exception:
        # We are in the death throes — last resort is logging.
        logger.exception("Failed to write crash report")
    return path


def _show_dialog(exc_type, exc_value, report_path: Path) -> None:
    """Best-effort: surface a Qt dialog if the app loop is alive."""
    try:
        from PySide6.QtWidgets import (
            QApplication, QMessageBox, QPushButton,
        )
    except Exception:
        return

    app = QApplication.instance()
    if app is None:
        return

    box = QMessageBox()
    box.setIcon(QMessageBox.Critical)
    box.setWindowTitle("FreeSDN Agent — Unexpected error")
    box.setText(
        f"<b>{exc_type.__name__}</b>: {exc_value}<br><br>"
        f"A crash report was saved to:<br><code>{report_path}</code><br><br>"
        "The application will close. If this keeps happening, please share "
        "the crash file with support."
    )

    copy_btn = QPushButton("Copy report path")
    box.addButton(copy_btn, QMessageBox.ActionRole)
    box.addButton(QMessageBox.Close)

    def _copy() -> None:
        clip = app.clipboard()
        if clip is not None:
            clip.setText(str(report_path))

    copy_btn.clicked.connect(_copy)
    try:
        box.exec()
    except Exception:
        logger.exception("Crash dialog failed to display")


def install_crash_handler() -> None:
    """Replace ``sys.excepthook`` with the agent's crash handler.

    Safe to call multiple times — the previous hook is preserved
    only for ``KeyboardInterrupt`` pass-through.
    """
    previous = sys.excepthook

    def _hook(exc_type, exc_value, exc_tb) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            previous(exc_type, exc_value, exc_tb)
            return

        try:
            logger.critical(
                "Uncaught exception", exc_info=(exc_type, exc_value, exc_tb),
            )
            path = _write_crash_report(exc_type, exc_value, exc_tb)
            _show_dialog(exc_type, exc_value, path)
        finally:
            # Fall back to default behaviour so the process actually
            # exits with the right code and the OS sees the failure.
            previous(exc_type, exc_value, exc_tb)

    sys.excepthook = _hook
    logger.debug("Crash handler installed")
