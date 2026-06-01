"""System tray icon for the desktop app.

Goals for the enterprise pass:
- Operator can minimize the window without quitting the agent —
  scheduled scans keep running in the background.
- Tray icon's badge colour reflects the live connection state to
  the FreeSDN control plane so an "is my agent talking to the server
  right now?" check is a glance at the tray.
- Right-click menu exposes: Show window, Run quick scan, Quit.
  Double-click brings the window forward.

This is a thin wrapper around ``QSystemTrayIcon`` — nothing here
talks to the network. The state-update slot is fed by the existing
scan_manager / WS connection signals from the main window.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QAction, QColor, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from freesdn_agent import __app_name__, __version__

logger = logging.getLogger(__name__)


class AgentTrayIcon(QObject):
    """System tray surface for the agent app.

    Subclasses :class:`QObject` rather than :class:`QSystemTrayIcon`
    so the icon itself can be lazily constructed on first show and
    we keep the API surface (signals) Pythonic.
    """

    show_requested = Signal()
    quit_requested = Signal()
    quick_scan_requested = Signal()
    run_scan_requested = Signal()  # generic "open scan tab"

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._tray: QSystemTrayIcon | None = None
        self._connected = False
        self._scan_running = False

    @staticmethod
    def is_available() -> bool:
        """Some Linux desktops don't expose a tray. Fail open."""
        return QSystemTrayIcon.isSystemTrayAvailable()

    def install(self, parent: Optional[QObject] = None) -> None:
        """Build the tray icon + context menu and show it."""
        if self._tray is not None:
            return
        if not self.is_available():
            logger.info("System tray not available — skipping tray install")
            return

        self._tray = QSystemTrayIcon(parent)
        self._tray.setToolTip(f"{__app_name__} v{__version__} — offline")
        self._tray.setIcon(self._build_icon(connected=False, scanning=False))

        menu = QMenu()

        act_show = QAction("Show window", menu)
        act_show.triggered.connect(self.show_requested.emit)
        menu.addAction(act_show)

        act_scan = QAction("Run quick scan", menu)
        act_scan.triggered.connect(self.quick_scan_requested.emit)
        menu.addAction(act_scan)

        menu.addSeparator()

        act_quit = QAction("Quit FreeSDN Agent", menu)
        act_quit.triggered.connect(self.quit_requested.emit)
        menu.addAction(act_quit)

        self._tray.setContextMenu(menu)
        self._tray.activated.connect(self._on_activated)
        self._tray.show()
        logger.info("System tray icon installed")

    def update_state(
        self,
        *,
        connected: bool | None = None,
        scanning: bool | None = None,
    ) -> None:
        """Refresh icon + tooltip when connection or scan state changes."""
        if self._tray is None:
            return
        if connected is not None:
            self._connected = connected
        if scanning is not None:
            self._scan_running = scanning

        if self._scan_running:
            state_text = "scanning"
        elif self._connected:
            state_text = "online"
        else:
            state_text = "offline"

        self._tray.setIcon(
            self._build_icon(self._connected, self._scan_running),
        )
        self._tray.setToolTip(
            f"{__app_name__} v{__version__} — {state_text}",
        )

    def show_message(
        self,
        title: str,
        body: str,
        *,
        is_error: bool = False,
        ttl_ms: int = 5000,
    ) -> None:
        if self._tray is None:
            return
        icon = (
            QSystemTrayIcon.MessageIcon.Critical
            if is_error
            else QSystemTrayIcon.MessageIcon.Information
        )
        self._tray.showMessage(title, body, icon, ttl_ms)

    def hide(self) -> None:
        if self._tray is not None:
            self._tray.hide()
            self._tray = None

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        # Double-click brings the main window to the front. Single-click
        # on Windows fires Trigger; we ignore that to avoid surprising
        # focus theft.
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_requested.emit()

    # ------------------------------------------------------------------
    # Icon synthesis — keeps us free of bundling PNGs
    # ------------------------------------------------------------------

    @staticmethod
    def _build_icon(connected: bool, scanning: bool) -> QIcon:
        """Render a 64x64 circle in the colour reflecting current state.

        Doing this in code avoids needing a resource file in the
        PyInstaller bundle. The colours match the web UI's badges:
        emerald=online, amber=scanning, slate=offline.
        """
        size = 64
        pix = QPixmap(size, size)
        pix.fill(QColor("transparent"))
        if scanning:
            colour = QColor("#f59e0b")  # amber-500
        elif connected:
            colour = QColor("#10b981")  # emerald-500
        else:
            colour = QColor("#64748b")  # slate-500

        painter = QPainter(pix)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setBrush(colour)
            painter.setPen(QColor("#ffffff"))
            painter.drawEllipse(4, 4, size - 8, size - 8)
        finally:
            painter.end()
        return QIcon(pix)


def emit_callback(signal_emitter: AgentTrayIcon, name: str) -> Callable[..., None]:
    """Convenience for wiring legacy Qt slots to tray signals."""
    sig = getattr(signal_emitter, name)
    return lambda *_a, **_kw: sig.emit()
