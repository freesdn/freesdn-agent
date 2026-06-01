"""Single-instance enforcement for the desktop app.

Without this, double-clicking the launcher in quick succession (or
having the installer auto-start it while a user-launched copy is
already running) spawns multiple agent windows competing for the
same scan-manager singleton and keyring entry.

Implementation: a stale-resistant file lock under the per-user app
data dir. Each launch:
1. Tries to open ``app.lock`` exclusively (atomic O_CREAT|O_EXCL).
2. On collision, reads the PID stored inside and probes whether
   that process is still alive. If yes -> bail out (caller can
   surface a "already running" toast). If no -> the previous run
   crashed without cleaning up; reclaim the lock.
3. On exit, the lock file is unlinked.

This is cross-platform — no fcntl, no win32 calls, just a PID file
+ a liveness check.
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from platformdirs import user_data_dir

from freesdn_agent import __app_name__

logger = logging.getLogger(__name__)

_LOCK_NAME = "app.lock"


def _lock_path() -> Path:
    base = Path(user_data_dir(__app_name__, "FreeSDN"))
    base.mkdir(parents=True, exist_ok=True)
    return base / _LOCK_NAME


def _pid_alive(pid: int) -> bool:
    """Return True if a process with this PID still exists."""
    if pid <= 0:
        return False
    try:
        # POSIX: signal 0 is a no-op that errors when the target is gone.
        os.kill(pid, 0)
        return True
    except AttributeError:
        pass  # Windows — fall through to the tasklist probe
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but is owned by another user — still "alive"
        # from our perspective, conservative answer.
        return True
    except OSError:
        return False

    # Windows path
    if sys.platform == "win32":
        try:
            import ctypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid,
            )
            if not handle:
                return False
            try:
                exit_code = ctypes.c_ulong()
                ok = ctypes.windll.kernel32.GetExitCodeProcess(
                    handle, ctypes.byref(exit_code),
                )
                return bool(ok) and exit_code.value == STILL_ACTIVE
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            logger.debug("Windows PID probe failed", exc_info=True)
            return False
    return False


class SingleInstanceLock:
    """Holds the per-user app lock for the lifetime of the desktop app."""

    def __init__(self, path: Path | None = None):
        self.path = path or _lock_path()
        self._held = False

    def acquire(self) -> bool:
        """Attempt to take the lock. Returns True on success.

        On collision with a still-alive PID, returns False — the
        caller is expected to surface a "already running" message and
        exit. On collision with a stale PID (previous crash), silently
        reclaims the lock.
        """
        for attempt in range(2):
            try:
                fd = os.open(
                    self.path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
            except FileExistsError:
                stale = self._is_stale()
                if stale:
                    logger.warning(
                        "Removing stale lock at %s", self.path,
                    )
                    try:
                        self.path.unlink()
                    except OSError:
                        return False
                    continue
                return False

            with os.fdopen(fd, "w") as f:
                f.write(str(os.getpid()))
            self._held = True
            return True
        return False

    def _is_stale(self) -> bool:
        try:
            raw = self.path.read_text(encoding="utf-8").strip()
            pid = int(raw)
        except (OSError, ValueError):
            return True
        return not _pid_alive(pid)

    def release(self) -> None:
        if not self._held:
            return
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            logger.debug("Failed to release lock", exc_info=True)
        self._held = False


@contextmanager
def acquire_single_instance() -> Iterator[bool]:
    """Context manager wrapper for :class:`SingleInstanceLock`.

    Yields True if the lock was acquired (proceed to start the UI),
    False if another instance is already running (caller should
    bail out with a user-facing message).
    """
    lock = SingleInstanceLock()
    got = lock.acquire()
    try:
        yield got
    finally:
        lock.release()
