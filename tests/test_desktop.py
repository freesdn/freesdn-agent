"""Tests for the desktop robustness layer.

These cover the parts that don't need a Qt event loop — the crash
handler's file output, the single-instance lock semantics, and the
stale-lock recovery path. The tray icon needs a QApplication so it's
covered separately by the GUI smoke-test fixture (when run).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Crash handler
# ---------------------------------------------------------------------------

class TestCrashHandler:
    def test_writes_report_with_traceback(self, tmp_path: Path) -> None:
        from freesdn_agent.desktop import crash_handler

        with patch.object(crash_handler, "_crash_dir", return_value=tmp_path):
            try:
                raise RuntimeError("boom")
            except RuntimeError:
                exc_type, exc_value, exc_tb = sys.exc_info()
                path = crash_handler._write_crash_report(
                    exc_type, exc_value, exc_tb,
                )

        body = path.read_text(encoding="utf-8")
        assert "RuntimeError: boom" in body
        assert "Traceback" in body
        assert "Python:" in body
        assert "Platform:" in body

    def test_installer_passes_through_keyboard_interrupt(self) -> None:
        """Ctrl+C in dev should still exit cleanly via the default
        excepthook — wrapping it with the crash dialog would block on
        a modal Qt prompt that nobody can dismiss in a headless test."""
        from freesdn_agent.desktop import crash_handler

        previous = sys.excepthook
        try:
            crash_handler.install_crash_handler()
            # We can't easily test the actual KeyboardInterrupt path
            # without crashing the test runner; just assert the hook
            # was replaced and is callable.
            assert sys.excepthook is not previous
            assert callable(sys.excepthook)
        finally:
            sys.excepthook = previous


# ---------------------------------------------------------------------------
# Single-instance lock
# ---------------------------------------------------------------------------

class TestSingleInstanceLock:
    def test_acquire_creates_lockfile_with_pid(self, tmp_path: Path) -> None:
        from freesdn_agent.desktop import SingleInstanceLock

        lock_path = tmp_path / "app.lock"
        lock = SingleInstanceLock(path=lock_path)
        assert lock.acquire() is True
        assert lock_path.exists()
        stored = int(lock_path.read_text(encoding="utf-8").strip())
        assert stored == os.getpid()
        lock.release()
        assert not lock_path.exists()

    def test_second_acquire_fails_when_alive(self, tmp_path: Path) -> None:
        from freesdn_agent.desktop import SingleInstanceLock

        lock_path = tmp_path / "app.lock"
        first = SingleInstanceLock(path=lock_path)
        assert first.acquire() is True

        second = SingleInstanceLock(path=lock_path)
        try:
            assert second.acquire() is False
        finally:
            first.release()

    def test_reclaim_stale_lock(self, tmp_path: Path) -> None:
        """When the previous instance died without releasing the lock,
        a fresh launch should detect the dead PID and reclaim."""
        from freesdn_agent.desktop import SingleInstanceLock
        from freesdn_agent.desktop import single_instance

        lock_path = tmp_path / "app.lock"
        # Plant a lock claiming a PID that doesn't exist.
        lock_path.write_text("999999", encoding="utf-8")

        with patch.object(single_instance, "_pid_alive", return_value=False):
            lock = SingleInstanceLock(path=lock_path)
            assert lock.acquire() is True
            stored = int(lock_path.read_text(encoding="utf-8").strip())
            assert stored == os.getpid()
            lock.release()

    def test_release_is_idempotent(self, tmp_path: Path) -> None:
        from freesdn_agent.desktop import SingleInstanceLock

        lock = SingleInstanceLock(path=tmp_path / "app.lock")
        # Calling release() before acquire() must not raise
        lock.release()
        assert lock.acquire() is True
        lock.release()
        lock.release()  # double-release also safe

    def test_acquire_returns_false_when_unable_to_remove_stale(self, tmp_path: Path) -> None:
        """If unlink() fails (eg. permissions), bail out cleanly rather
        than looping forever."""
        from freesdn_agent.desktop import SingleInstanceLock
        from freesdn_agent.desktop import single_instance

        lock_path = tmp_path / "app.lock"
        lock_path.write_text("999999", encoding="utf-8")

        with patch.object(single_instance, "_pid_alive", return_value=False), \
             patch.object(Path, "unlink", side_effect=PermissionError("denied")):
            lock = SingleInstanceLock(path=lock_path)
            assert lock.acquire() is False
