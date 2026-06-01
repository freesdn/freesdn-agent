"""
FreeSDN Agent - Main Application Entry Point

Initializes and runs the PySide6 application with the enterprise
robustness layer wired in:
- Crash handler that writes timestamped reports + surfaces a Qt
  dialog instead of silently exiting on uncaught exceptions.
- Single-instance lock that bounces a second launch to the existing
  window instead of starting a competing process.
- System tray icon with a live connection-status badge and a
  minimize-to-tray option so the daemon keeps running scheduled
  scans after the operator closes the window.
"""

import sys
import logging
from pathlib import Path

from freesdn_agent import __version__, __app_name__
from freesdn_agent.utils.logging import setup_logging
from freesdn_agent.utils.privileges import check_admin_privileges, show_privilege_warning


def main() -> int:
    """Main entry point for FreeSDN Agent."""

    # Setup logging first so crash handler can lean on it
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info(f"Starting {__app_name__} v{__version__}")

    # Install the crash handler BEFORE any Qt work so even a Qt
    # import failure surfaces a useful report file.
    from freesdn_agent.desktop import install_crash_handler
    install_crash_handler()

    # Check for admin privileges (required for raw socket scanning)
    if not check_admin_privileges():
        logger.warning("Running without administrator privileges - some features may be limited")

    # Import Qt after logging setup
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox
        from PySide6.QtCore import Qt, qInstallMessageHandler, QtMsgType
        from PySide6.QtGui import QIcon, QFont

        # Install custom message handler to filter benign Qt warnings
        def qt_message_handler(mode, context, message):
            """Custom Qt message handler to filter known benign warnings."""
            # Suppress the known QFont::setPointSize warning
            if "QFont::setPointSize" in message and "Point size <= 0" in message:
                return  # Suppress this known Qt bug
            # Log other messages normally
            if mode == QtMsgType.QtWarningMsg:
                logger.warning(f"Qt: {message}")
            elif mode == QtMsgType.QtCriticalMsg:
                logger.error(f"Qt: {message}")
            elif mode == QtMsgType.QtFatalMsg:
                logger.critical(f"Qt: {message}")

        qInstallMessageHandler(qt_message_handler)
    except ImportError as e:
        logger.error(f"Failed to import PySide6: {e}")
        logger.error("Please install PySide6: pip install PySide6")
        return 1

    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName(__app_name__)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("FreeSDN")
    app.setOrganizationDomain("freesdn.org")

    # Set default application font to prevent -1 point size warnings
    default_font = QFont("Segoe UI", 10)
    default_font.setStyleHint(QFont.SansSerif)
    app.setFont(default_font)

    # Single-instance enforcement — second launch raises the existing
    # window instead of starting a competing process that fights for
    # the same scan-manager singleton and keyring.
    from freesdn_agent.desktop import SingleInstanceLock
    lock = SingleInstanceLock()
    if not lock.acquire():
        QMessageBox.information(
            None,
            f"{__app_name__} already running",
            (
                f"{__app_name__} is already running on this user account. "
                "Look for it in the system tray or task list."
            ),
        )
        logger.warning("Second instance refused — lock held by another process")
        return 0

    # Import and create main window
    from freesdn_agent.ui.main_window import MainWindow
    from freesdn_agent.ui.styles.theme import ThemeManager, ThemeMode
    from freesdn_agent.core.config import Config
    from freesdn_agent.desktop import AgentTrayIcon

    # Load configuration
    config = Config.load()

    # Apply theme based on configuration
    theme_manager = ThemeManager.instance()
    theme_mode = ThemeMode(config.ui.theme) if config.ui.theme in [m.value for m in ThemeMode] else ThemeMode.SYSTEM
    theme_manager.apply_theme(theme_mode, app)

    # Create main window
    window = MainWindow()

    # System tray — wire to window helpers if the platform supports it.
    # On X11/Linux without a tray daemon, this no-ops and the window
    # behaves like the old single-process model.
    tray = AgentTrayIcon(app)
    tray.install(parent=window)
    tray.show_requested.connect(lambda: _raise_window(window))
    tray.quit_requested.connect(app.quit)
    if hasattr(window, "trigger_quick_scan"):
        tray.quick_scan_requested.connect(window.trigger_quick_scan)
    # Expose tray to the window so it can flip badge colour when the
    # scan manager / WS connection state changes.
    setattr(window, "_tray", tray)

    # Allow Qt's last-window-closed behaviour to be overridden so
    # closing the main window minimises to tray (if tray was created
    # successfully). The MainWindow's closeEvent decides which path
    # to take based on the presence of `self._tray`.
    app.setQuitOnLastWindowClosed(not tray.is_available())

    window.show()

    # Show privilege warning if needed
    if not check_admin_privileges():
        show_privilege_warning(window)

    logger.info("Application initialized successfully")

    try:
        return app.exec()
    finally:
        lock.release()


def _raise_window(window) -> None:
    """Bring the main window to the foreground from the tray."""
    try:
        window.showNormal()
        window.raise_()
        window.activateWindow()
    except Exception:  # pragma: no cover — best-effort UI raise
        logging.getLogger(__name__).debug("Window raise failed", exc_info=True)


if __name__ == "__main__":
    sys.exit(main())
