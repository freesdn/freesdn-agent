"""Enterprise robustness layer for the FreeSDN Agent desktop app.

Wraps the PySide6 entry point with:
- :py:mod:`crash_handler` — sys.excepthook that writes a dated crash
  report under the user's app-data dir and surfaces a Qt error dialog
  instead of silently exiting.
- :py:mod:`single_instance` — file-lock based single-instance guard
  so launching the desktop app twice raises the existing window rather
  than starting a second one.
- :py:mod:`tray` — system tray icon with a live connection-status
  badge and minimize-to-tray behaviour for long-running sessions.

None of these are required for the daemon mode (which has no Qt at
all); they only activate when ``freesdn_agent.main:main`` runs.
"""

from freesdn_agent.desktop.crash_handler import install_crash_handler
from freesdn_agent.desktop.single_instance import (
    acquire_single_instance,
    SingleInstanceLock,
)

__all__ = [
    "install_crash_handler",
    "acquire_single_instance",
    "SingleInstanceLock",
    "AgentTrayIcon",
]


def __getattr__(name: str):
    """Lazy import for PySide6-dependent submodules.

    Keeps the desktop package importable from headless contexts (eg.
    pytest collection in a non-Qt env, or the daemon entry point
    pulling in the crash handler) without forcing a PySide6 install.
    Resolved on attribute access — `from freesdn_agent.desktop import
    AgentTrayIcon` still works exactly as before.
    """
    if name == "AgentTrayIcon":
        from freesdn_agent.desktop.tray import AgentTrayIcon as _Tray
        return _Tray
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
