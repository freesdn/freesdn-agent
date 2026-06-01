"""
Main Window for FreeSDN Agent.

The primary application window containing all UI components.
"""

import logging
from typing import Optional

from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QSplitter,
    QStatusBar,
    QMenuBar,
    QMenu,
    QToolBar,
    QTabWidget,
    QLabel,
    QMessageBox,
    QApplication,
)
from PySide6.QtCore import Qt, QSize, Signal, Slot
from PySide6.QtGui import QAction, QIcon, QCloseEvent

from freesdn_agent import __version__, __app_name__
from freesdn_agent.core.config import get_config, Config
from freesdn_agent.core.constants import (
    WINDOW_MIN_WIDTH,
    WINDOW_MIN_HEIGHT,
    WINDOW_DEFAULT_WIDTH,
    WINDOW_DEFAULT_HEIGHT,
)
from freesdn_agent.ui.widgets.connection_panel import ConnectionPanel
from freesdn_agent.ui.widgets.scan_panel import ScanPanel
from freesdn_agent.ui.widgets.results_table import ResultsTable
from freesdn_agent.ui.widgets.progress_widget import ProgressWidget
from freesdn_agent.ui.widgets.status_bar import AgentStatusBar
from freesdn_agent.ui.widgets.managed_devices_panel import ManagedDevicesPanel
from freesdn_agent.ui.widgets.discovery_panel import DiscoveryPanel
from freesdn_agent.ui.widgets.inventory_panel import InventoryPanel
from freesdn_agent.ui.dialogs.settings import SettingsDialog
from freesdn_agent.ui.dialogs.about import AboutDialog
from freesdn_agent.ui.styles.theme import ThemeManager, ThemeMode
from freesdn_agent.services.scan_manager import get_scan_manager, ScanType
from freesdn_agent.services.device_cache import get_device_cache, refresh_device_cache

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Main application window."""
    
    # Signals
    scan_started = Signal()
    scan_stopped = Signal()
    scan_completed = Signal(list)  # List of discovered devices
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        
        self.config = get_config()
        self.scan_manager = get_scan_manager()
        
        self._setup_window()
        self._create_menu_bar()
        self._create_toolbar()
        self._create_central_widget()
        self._create_status_bar()
        self._connect_scan_manager()
        self._restore_geometry()
        
        logger.info("Main window initialized")
    
    def _connect_scan_manager(self) -> None:
        """Connect scan manager signals to UI."""
        self.scan_manager.scan_started.connect(self._on_scan_started)
        self.scan_manager.scan_finished.connect(self._on_scan_finished)
        self.scan_manager.scan_error.connect(self._on_scan_error)
        self.scan_manager.scan_progress.connect(self._on_scan_progress)
        self.scan_manager.device_found.connect(self._on_device_found)
        self.scan_manager.scanner_started.connect(self._on_scanner_started)
        self.scan_manager.scanner_finished.connect(self._on_scanner_finished)
    
    def _setup_window(self) -> None:
        """Configure window properties."""
        self.setWindowTitle(f"{__app_name__} v{__version__}")
        self.setMinimumSize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        
        # Set window icon (if available)
        # self.setWindowIcon(QIcon(":/icons/app.png"))
    
    def _create_menu_bar(self) -> None:
        """Create the application menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        self.action_connect = QAction("&Connect to FreeSDN...", self)
        self.action_connect.setShortcut("Ctrl+Shift+C")
        self.action_connect.triggered.connect(self._on_connect)
        file_menu.addAction(self.action_connect)
        
        file_menu.addSeparator()
        
        self.action_export = QAction("&Export Results...", self)
        self.action_export.setShortcut("Ctrl+E")
        self.action_export.setEnabled(False)
        self.action_export.triggered.connect(self._on_export)
        file_menu.addAction(self.action_export)
        
        file_menu.addSeparator()
        
        self.action_exit = QAction("E&xit", self)
        self.action_exit.setShortcut("Alt+F4")
        self.action_exit.triggered.connect(self.close)
        file_menu.addAction(self.action_exit)
        
        # Scan menu
        scan_menu = menubar.addMenu("&Scan")
        
        self.action_quick_scan = QAction("&Quick Scan", self)
        self.action_quick_scan.setShortcut("F5")
        self.action_quick_scan.triggered.connect(self._on_quick_scan)
        scan_menu.addAction(self.action_quick_scan)
        
        self.action_camera_scan = QAction("&Camera Scan", self)
        self.action_camera_scan.setShortcut("F6")
        self.action_camera_scan.triggered.connect(self._on_camera_scan)
        scan_menu.addAction(self.action_camera_scan)
        
        self.action_voip_scan = QAction("&VoIP Scan", self)
        self.action_voip_scan.setShortcut("F7")
        self.action_voip_scan.triggered.connect(self._on_voip_scan)
        scan_menu.addAction(self.action_voip_scan)
        
        self.action_full_scan = QAction("&Full Scan", self)
        self.action_full_scan.setShortcut("F8")
        self.action_full_scan.triggered.connect(self._on_full_scan)
        scan_menu.addAction(self.action_full_scan)
        
        scan_menu.addSeparator()
        
        self.action_stop_scan = QAction("&Stop Scan", self)
        self.action_stop_scan.setShortcut("Escape")
        self.action_stop_scan.setEnabled(False)
        self.action_stop_scan.triggered.connect(self._on_stop_scan)
        scan_menu.addAction(self.action_stop_scan)
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        
        self.action_settings = QAction("&Settings...", self)
        self.action_settings.setShortcut("Ctrl+,")
        self.action_settings.triggered.connect(self._on_settings)
        tools_menu.addAction(self.action_settings)
        
        # View menu
        view_menu = menubar.addMenu("&View")
        
        theme_menu = view_menu.addMenu("Theme")
        
        self.action_theme_system = QAction("Follow System", self)
        self.action_theme_system.setCheckable(True)
        self.action_theme_system.triggered.connect(lambda: self._on_theme_change(ThemeMode.SYSTEM))
        theme_menu.addAction(self.action_theme_system)
        
        self.action_theme_dark = QAction("Dark", self)
        self.action_theme_dark.setCheckable(True)
        self.action_theme_dark.triggered.connect(lambda: self._on_theme_change(ThemeMode.DARK))
        theme_menu.addAction(self.action_theme_dark)
        
        self.action_theme_light = QAction("Light", self)
        self.action_theme_light.setCheckable(True)
        self.action_theme_light.triggered.connect(lambda: self._on_theme_change(ThemeMode.LIGHT))
        theme_menu.addAction(self.action_theme_light)
        
        # Update checkmarks based on current theme
        self._update_theme_menu()
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        self.action_about = QAction("&About...", self)
        self.action_about.triggered.connect(self._on_about)
        help_menu.addAction(self.action_about)
    
    def _create_toolbar(self) -> None:
        """Create the main toolbar."""
        # Note: Scan buttons removed from toolbar to avoid duplicate UI.
        # Use the Network Discovery panel or Scan menu instead.
        pass
    
    def _create_central_widget(self) -> None:
        """Create the main content area with a tabbed layout.

        The pre-tabs layout stacked ConnectionPanel + ScanPanel + a
        QSplitter (Managed | Discovery) + ProgressWidget vertically.
        That worked at wide desktop sizes but at tablet / narrower
        widths the ScanPanel got squished, the interface list collapsed
        to zero height, and the Targets textbox bled into other widgets.

        New layout — same set of widgets but reorganized:

          ┌─ Connection bar (always visible)
          ┌─ Tabs:
          │   • Scan       → ScanPanel (multi-target selector + buttons)
          │   • Discovered → DiscoveryPanel (newly-found, adopt flow)
          │   • Managed    → ManagedDevicesPanel (backend inventory)
          └─ Progress bar (always visible)

        Each tab gets the FULL window width for its content, which
        means the multi-target selector inside the Scan tab can run
        its side-by-side (>=900px) or stacked (<900px) layout cleanly
        without competing with siblings for vertical space.
        """
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # ── Connection bar (always visible) ───────────────────────
        self.connection_panel = ConnectionPanel()
        self.connection_panel.connection_changed.connect(self._on_connection_changed)
        main_layout.addWidget(self.connection_panel)

        # ── Tabs ──────────────────────────────────────────────────
        self.tabs = QTabWidget()
        self.tabs.setObjectName("mainTabs")
        self.tabs.setDocumentMode(True)
        self.tabs.setTabPosition(QTabWidget.North)
        self.tabs.setStyleSheet("""
            QTabWidget#mainTabs::pane {
                border: 1px solid rgba(0,0,0,0.08);
                border-radius: 4px;
                top: -1px;
                padding: 8px;
            }
            QTabWidget#mainTabs::tab-bar {
                left: 8px;
            }
            QTabBar::tab {
                padding: 8px 16px;
                margin-right: 2px;
                border: 1px solid rgba(0,0,0,0.08);
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                background: rgba(0,0,0,0.03);
            }
            QTabBar::tab:selected {
                background: white;
                font-weight: 600;
            }
            QTabBar::tab:hover:!selected {
                background: rgba(0,0,0,0.06);
            }
        """)

        # Tab 1: Scan — host for the multi-target selector + scan profile buttons
        self.scan_panel = ScanPanel()
        self.scan_panel.scan_requested.connect(self._on_scan_requested)
        self.tabs.addTab(self.scan_panel, "Scan")

        # Tab 2: Inventory — unified view of managed + discovered devices.
        # Replaces the legacy two-tab split (Discovered + Managed) so
        # the operator sees one truth: every device the system knows
        # about, tagged with its lifecycle status. The old panels are
        # still instantiated for the data-loading path (DiscoveryPanel
        # holds the most-recent scan results in memory, ManagedPanel
        # caches managed MACs for the discovery filter) but they're
        # not added as tabs anymore.
        self.inventory_panel = InventoryPanel()
        self.inventory_panel.adopt_requested.connect(self._on_inventory_adopt)
        self.inventory_panel.refresh_requested.connect(self._on_refresh_managed)
        self.tabs.addTab(self.inventory_panel, "Inventory")

        # Keep the legacy panels alive (hidden) so existing code that
        # mutates them — set_managed_macs, set_managed_ips, scan-result
        # ingestion — keeps working without a rewrite. The data flows
        # into them as before; we just don't show them.
        self.discovery_panel = DiscoveryPanel()
        self.discovery_panel.device_selected.connect(self._on_device_selected)
        self.discovery_panel.adopt_requested.connect(self._on_adopt_devices)
        self.discovery_panel.adopt_all_requested.connect(self._on_adopt_all)
        self.discovery_panel.hide()

        self.managed_panel = ManagedDevicesPanel()
        self.managed_panel.device_selected.connect(self._on_managed_device_selected)
        self.managed_panel.refresh_requested.connect(self._on_refresh_managed)
        self.managed_panel.hide()

        # Auto-switch to "Discovered" tab when a scan produces results
        # — this saves a manual click in the most common flow:
        # "click Quick Scan → wait → see what was found".
        self._autoswitch_after_scan = True

        main_layout.addWidget(self.tabs, stretch=1)

        # Keep old results table reference for compatibility but hide it
        self.results_table = ResultsTable()
        self.results_table.hide()

        # ── Progress bar (always visible) ─────────────────────────
        self.progress_widget = ProgressWidget()
        main_layout.addWidget(self.progress_widget)
    
    def _create_status_bar(self) -> None:
        """Create the status bar."""
        self.status_bar = AgentStatusBar()
        self.setStatusBar(self.status_bar)
    
    def _restore_geometry(self) -> None:
        """Restore window geometry from config."""
        ui = self.config.ui
        
        # Set size
        self.resize(ui.window_width, ui.window_height)
        
        # Set position if saved
        if ui.window_x is not None and ui.window_y is not None:
            self.move(ui.window_x, ui.window_y)
        else:
            # Center on screen
            self._center_on_screen()
    
    def _center_on_screen(self) -> None:
        """Center the window on the primary screen."""
        from PySide6.QtWidgets import QApplication
        from PySide6.QtGui import QScreen
        
        screen = QApplication.primaryScreen()
        if screen:
            geometry = screen.availableGeometry()
            x = (geometry.width() - self.width()) // 2 + geometry.x()
            y = (geometry.height() - self.height()) // 2 + geometry.y()
            self.move(x, y)
    
    def _save_geometry(self) -> None:
        """Save window geometry to config."""
        self.config.ui.window_width = self.width()
        self.config.ui.window_height = self.height()
        self.config.ui.window_x = self.x()
        self.config.ui.window_y = self.y()
        self.config.save()
    
    # --- Event Handlers ---
    
    def closeEvent(self, event: QCloseEvent) -> None:
        """Handle window close event.

        When a system tray icon is available the close button is
        repurposed as "minimize to tray" — scheduled scans / WS
        connection keep running in the background. The user quits
        through the tray menu's Quit action (which calls
        ``QApplication.quit`` and lets ``app.exec()`` return cleanly).

        Without a tray (or in headless test environments) we fall
        back to the legacy behaviour of accepting the close.
        """
        if getattr(self, "_tray", None) is not None and self._tray.is_available():
            # First time only — let the user know where the app went.
            if not getattr(self, "_minimized_to_tray_once", False):
                try:
                    self._tray.show_message(
                        "FreeSDN Agent",
                        "The agent is still running in the system tray. "
                        "Right-click the icon to quit.",
                    )
                    self._minimized_to_tray_once = True
                except Exception:
                    logger.debug("Tray notification failed", exc_info=True)
            self._save_geometry()
            self.hide()
            event.ignore()
            return

        # TODO: Check if scan is running and prompt to stop
        self._save_geometry()
        logger.info("Application closing")
        event.accept()

    # ------------------------------------------------------------------
    # Tray bridge
    # ------------------------------------------------------------------

    @Slot()
    def trigger_quick_scan(self) -> None:
        """Public entry point for the tray's "Run quick scan" action."""
        self._on_quick_scan()

    def _notify_tray(
        self, *, connected: bool | None = None, scanning: bool | None = None,
    ) -> None:
        tray = getattr(self, "_tray", None)
        if tray is None:
            return
        try:
            tray.update_state(connected=connected, scanning=scanning)
        except Exception:
            logger.debug("Tray update failed", exc_info=True)
    
    # --- Action Slots ---
    
    @Slot()
    def _on_connect(self) -> None:
        """Handle connect action."""
        self.connection_panel.show_connect_dialog()
    
    @Slot()
    def _on_export(self) -> None:
        """Handle export action."""
        # TODO: Implement export to CSV
        pass
    
    @Slot()
    def _on_quick_scan(self) -> None:
        """Start a quick scan."""
        self._start_scan(ScanType.QUICK)
    
    @Slot()
    def _on_camera_scan(self) -> None:
        """Start a camera-focused scan."""
        self._start_scan(ScanType.CAMERA)
    
    @Slot()
    def _on_voip_scan(self) -> None:
        """Start a VoIP-focused scan."""
        self._start_scan(ScanType.VOIP)
    
    @Slot()
    def _on_full_scan(self) -> None:
        """Start a full scan."""
        self._start_scan(ScanType.FULL)
    
    def _start_scan(self, scan_type: ScanType) -> None:
        """Start a scan of the specified type.

        Uses the new MultiTargetSelector: ``get_selected_interfaces()``
        returns the checked interface names (for the scanners that need
        a specific NIC to send from — ARP, mDNS, SSDP, etc.) and
        ``get_targets()`` returns the resolved target CIDRs/IPs/ranges
        (either from the user's Targets textbox, or from the checked
        interfaces' auto-detected subnets if the textbox was empty).
        """
        interfaces = self.scan_panel.get_selected_interfaces()
        targets = self.scan_panel.get_targets()

        # Surface parse errors from the Targets textbox
        target_errors = self.scan_panel.target_selector.has_errors()
        if target_errors:
            QMessageBox.warning(
                self,
                "Invalid Targets",
                "Some entries in the Targets list are invalid:\n\n"
                + "\n".join(f"• {e}" for e in target_errors[:10])
                + ("\n…" if len(target_errors) > 10 else ""),
            )
            return

        if not interfaces and not targets:
            QMessageBox.warning(
                self,
                "Nothing to Scan",
                "Check at least one network interface, or type a "
                "target in the Targets box.",
            )
            return

        # Refresh managed devices if connected to FreeSDN
        client = self.connection_panel.get_client()
        site_id = self.connection_panel.get_site_id()
        if client and site_id:
            try:
                self._load_managed_devices()
            except Exception as e:
                logger.warning(f"Failed to refresh managed devices: {e}", exc_info=True)

        # Clear previous discovery results
        self.discovery_panel.clear_devices()

        # Start scan via manager. ScanJob.targets already accepts a
        # list[str] — the orchestrator was never the bottleneck; the
        # UI was.
        success = self.scan_manager.start_scan(
            scan_type=scan_type,
            interfaces=interfaces or [""],  # empty list → scanner auto-detects
            targets=targets,
        )

        if not success:
            QMessageBox.warning(
                self,
                "Scan Failed",
                "Could not start scan. A scan may already be in progress."
            )
    
    @Slot()
    def _on_stop_scan(self) -> None:
        """Stop the current scan."""
        self.scan_manager.stop_scan()
        self.scan_panel.stop_scan()
    
    @Slot(str)
    def _on_scan_started(self, scan_type: str) -> None:
        """Handle scan started from manager."""
        self.action_stop_scan.setEnabled(True)
        self.action_export.setEnabled(False)
        self.scan_panel._set_scanning(True)
        self.progress_widget.set_scanning(True)
        self.progress_widget.set_status(f"Starting {scan_type} scan...")
        self.status_bar.set_scan_status(True)
        self.scan_started.emit()
        self._notify_tray(scanning=True)

    @Slot(list)
    def _on_scan_finished(self, results: list) -> None:
        """Handle scan finished from manager."""
        self.action_stop_scan.setEnabled(False)
        self.action_export.setEnabled(len(results) > 0)
        self.scan_panel.on_scan_completed()
        self.progress_widget.set_scanning(False)
        self.progress_widget.set_status(f"Scan complete: {len(results)} devices found")
        self.status_bar.set_scan_status(False)
        self.scan_completed.emit(results)
        self._notify_tray(scanning=False)

        # Update the Discovered tab title with the new count, and
        # auto-switch to it so the user immediately sees results.
        # If the user manually navigated to a different tab during the
        # scan, respect that and don't yank them away.
        if hasattr(self, "tabs"):
            try:
                count = len(results)
                # Inventory is now the second tab (index 1) since we
                # merged Discovered + Managed into a single view.
                self.tabs.setTabText(1, f"Inventory ({count})" if count else "Inventory")
                if self._autoswitch_after_scan and self.tabs.currentIndex() == 0:
                    self.tabs.setCurrentIndex(1)
            except Exception:
                pass

        # If connected to a FreeSDN backend, push the discovery results
        # so they persist to ``devices.discovered_hosts`` and are
        # visible from the web UI / available for adoption. Before
        # this wiring, GUI-initiated scan findings only lived in the
        # agent's local panel and were lost on agent restart.
        try:
            client = self.connection_panel.get_client() if hasattr(self, "connection_panel") else None
            site_id = self.connection_panel.get_site_id() if hasattr(self, "connection_panel") else None
            if client and site_id and results:
                hosts_payload = self._results_to_payload(results)
                if hosts_payload:
                    self._push_results_to_backend(client, site_id, hosts_payload)
        except Exception:
            logger.exception("Failed to push discovery results to backend")

    def _results_to_payload(self, results: list) -> list[dict]:
        """Convert ScanResult dataclasses to the POST /discovery/results shape.

        - JSON-safe (datetimes ISO-formatted)
        - device_type enum → string value
        - discovered_via populated from ScanResult.discovered_by (scanner name)
        - merged by (mac) primary, (ip) fallback so the 6 interfaces × ping
          scanner don't produce N copies of the same host
        - drops rows whose IP matches a known FreeSDN controller (the
          discovery panel already hides them; we also avoid polluting the
          current site's discovered_hosts with hosts already managed
          elsewhere in the org)
        """
        from dataclasses import asdict as _asdict
        from datetime import datetime as _dt, date as _date

        def _json_safe(value):
            if isinstance(value, (_dt, _date)):
                return value.isoformat()
            if isinstance(value, dict):
                return {k: _json_safe(v) for k, v in value.items()}
            if isinstance(value, (list, tuple, set)):
                return [_json_safe(v) for v in value]
            return value

        # Build managed-IP skiplist from the discovery panel (same source
        # the UI uses; populated by _load_managed_devices).
        managed_ips: set[str] = getattr(
            self.discovery_panel, "_managed_ips", set()
        ) or set()

        def _norm_mac(m: str | None) -> str | None:
            if not m:
                return None
            return m.replace(":", "").replace("-", "").replace(".", "").upper()

        merged: dict[str, dict] = {}  # key = mac-or-ip → merged dict
        for r in results:
            if hasattr(r, "__dataclass_fields__"):
                d = _asdict(r)
            elif isinstance(r, dict):
                d = dict(r)
            else:
                continue
            d = _json_safe(d)

            ip = d.get("ip_address") or d.get("ip")
            if not ip:
                continue
            d["ip_address"] = ip

            # Skip already-managed controllers (UniFi/MikroTik/OpenWrt/etc.)
            if ip in managed_ips:
                continue

            # ``device_type`` may be an enum
            dt = d.get("device_type")
            if dt is not None and hasattr(dt, "value"):
                d["device_type"] = dt.value
            elif dt is not None:
                d["device_type"] = str(dt)

            # Source attribution: ScanResult uses `discovered_by`, older
            # code paths used `scanner` or `source`. Map whichever is set.
            scanner = (
                d.pop("discovered_by", None)
                or d.pop("scanner", None)
                or d.get("source")
            )
            if scanner and "discovered_via" not in d:
                d["discovered_via"] = [str(scanner)]

            mac_norm = _norm_mac(d.get("mac_address"))
            key = f"mac:{mac_norm}" if mac_norm else f"ip:{ip}"

            if key in merged:
                # Merge: union discovered_via, keep first non-None field
                cur = merged[key]
                cur_via = set(cur.get("discovered_via") or [])
                new_via = set(d.get("discovered_via") or [])
                cur["discovered_via"] = sorted(cur_via | new_via)
                for k, v in d.items():
                    if v in (None, "", [], {}) or k == "discovered_via":
                        continue
                    if cur.get(k) in (None, "", [], {}):
                        cur[k] = v
            else:
                merged[key] = d

        return list(merged.values())

    def _push_results_to_backend(self, client, site_id: str, hosts: list[dict]) -> None:
        """POST the host list to /api/v1/discovery/results.

        Synchronous in the GUI thread because the sync FreeSDN client is
        used (matches how the panel reads ``get_client()``). The HTTP
        call is short (<1s for a few hundred hosts) so a UI hiccup is
        acceptable; this can be moved to a worker if it ever blocks.

        After the push, reload managed + discovered so the unified
        Inventory tab reflects the new state (including any rows the
        backend's auto-adopt path just promoted to Managed).
        """
        try:
            summary = client.push_discovery_results(hosts, site_id)
            logger.info(
                "Pushed %d discoveries to backend (created=%s, updated=%s, skipped=%s, routed=%s)",
                len(hosts),
                summary.get("created"),
                summary.get("updated"),
                summary.get("skipped"),
                summary.get("routed"),
            )

            # Per-site route summary — backend auto-routes by subnet so an
            # agent scanning 192.168.1.0/24 with "Branch Office" picked
            # in the UI will see rows land in the Demo Lab site (whose
            # subnets claim that CIDR) instead. We resolve site_id →
            # name from the connection panel's cached site list so the
            # status text is human-readable.
            routed = summary.get("routed") or {}
            sites = self.connection_panel.get_sites() if hasattr(
                self.connection_panel, "get_sites"
            ) else []
            id_to_name = {str(s.get("id")): s.get("name", "?") for s in (sites or [])}

            if len(routed) > 1:
                # Multiple destination sites — show the breakdown.
                breakdown = ", ".join(
                    f"{n} → {id_to_name.get(sid, sid[:8])}"
                    for sid, n in sorted(routed.items(), key=lambda kv: -kv[1])
                )
                self.progress_widget.set_status(
                    f"Scan complete: {len(hosts)} found — {breakdown}"
                )
            else:
                # Single destination (or zero) — keep the prior compact form
                self.progress_widget.set_status(
                    f"Scan complete: {len(hosts)} found, "
                    f"{summary.get('created', 0)} new, "
                    f"{summary.get('updated', 0)} updated on backend"
                )
        except Exception as exc:
            logger.warning("Backend push failed: %s", exc)
            self.progress_widget.set_status(
                f"Scan complete locally ({len(hosts)} found) — backend push failed"
            )

        # Refresh the unified Inventory snapshot now that the backend
        # has the new discoveries (and may have auto-adopted some of
        # them). Best-effort — failures here are already user-visible
        # via the status bar.
        try:
            self._load_managed_devices()
        except Exception:
            logger.debug("Post-push inventory refresh failed", exc_info=True)

    @Slot(str)
    def _on_scan_error(self, error: str) -> None:
        """Handle scan error from manager."""
        logger.error(f"Scan error: {error}")
        self.progress_widget.set_status(f"Error: {error}")
    
    @Slot(object)
    def _on_scan_progress(self, progress) -> None:
        """Handle scan progress update."""
        self.progress_widget.update_progress(progress)
    
    @Slot(object)
    def _on_device_found(self, result) -> None:
        """Handle device found during scan."""
        # Convert result to dict if needed
        if hasattr(result, '__dataclass_fields__'):
            from dataclasses import asdict
            device_dict = asdict(result)
            if hasattr(result, 'device_type') and result.device_type:
                device_dict['device_type'] = result.device_type.value if hasattr(result.device_type, 'value') else str(result.device_type)
        else:
            device_dict = dict(result) if not isinstance(result, dict) else result
        
        mac = device_dict.get("mac_address")
        ip = device_dict.get("ip_address")
        
        # Add to discovery panel (it will filter out managed devices)
        added = self.discovery_panel.add_device(device_dict)
        
        if added:
            logger.debug(f"Device discovered: {ip} (MAC: {mac})")
        else:
            logger.debug(f"Device {ip} filtered (already managed)")
        
        self.progress_widget.increment_devices_found()
    
    @Slot(str)
    def _on_scanner_started(self, scanner_name: str) -> None:
        """Handle scanner started."""
        self.progress_widget.set_status(f"Running {scanner_name}...")
    
    @Slot(str)
    def _on_scanner_finished(self, scanner_name: str) -> None:
        """Handle scanner finished."""
        logger.debug(f"Scanner finished: {scanner_name}")
    
    @Slot()
    def _on_settings(self) -> None:
        """Open settings dialog."""
        dialog = SettingsDialog(self.config, self)
        if dialog.exec():
            # Reload config
            self.config = get_config()
    
    @Slot()
    def _on_about(self) -> None:
        """Show about dialog."""
        dialog = AboutDialog(self)
        dialog.exec()
    
    @Slot(bool)
    def _on_connection_changed(self, connected: bool) -> None:
        """Handle connection status change."""
        self.status_bar.set_connection_status(connected)
        
        # Enable/disable adopt functionality
        self.discovery_panel.set_adopt_enabled(connected)
        
        # Load managed devices from server when connected
        if connected:
            self._load_managed_devices()
            self.managed_panel.start_auto_refresh(interval_seconds=60)
        else:
            self.managed_panel.set_devices([])
            self.managed_panel.set_status("Not connected")
            self.managed_panel.stop_auto_refresh()
            self.discovery_panel.set_managed_macs(set())
    
    def _load_managed_devices(self) -> None:
        """Load managed devices from FreeSDN server."""
        client = self.connection_panel.get_client()
        site_id = self.connection_panel.get_site_id()
        
        if not client or not site_id:
            return
        
        try:
            self.managed_panel.set_status("Loading devices...")
            QApplication.processEvents()
            
            # Fetch devices for the selected site (for display)
            response = client.get_devices(site_id=site_id)
            
            # Handle paginated response
            if isinstance(response, dict):
                site_devices = response.get("items", response.get("data", []))
            else:
                site_devices = response if response else []
            
            self.managed_panel.set_devices(site_devices)
            self.managed_panel.set_status(f"Connected to site")
            self._latest_managed = list(site_devices)

            # Pull discovered hosts from the backend so the unified
            # Inventory panel shows everything the system knows about
            # this site — not just whatever's currently in the local
            # ScanPanel buffer. Best-effort: if the call fails we still
            # have the managed list and the local discoveries.
            try:
                disc_response = client.get_discovered_hosts(
                    site_id=site_id, show_adopted=False,
                )
                discovered_hosts = (
                    disc_response if isinstance(disc_response, list) else []
                )
            except Exception as exc:
                logger.debug("Could not fetch discovered hosts: %s", exc)
                discovered_hosts = []
            self._latest_discovered = discovered_hosts
            self._refresh_inventory_panel()

            # For MAC filtering, fetch ALL devices across all sites
            # This prevents adopting devices that exist in other sites
            all_response = client.get_devices()  # No site filter
            if isinstance(all_response, dict):
                all_devices = all_response.get("items", all_response.get("data", []))
            else:
                all_devices = all_response if all_response else []
            
            # Build MAC set from all devices
            # Support both 'mac' and 'mac_address' field names (API returns 'mac')
            all_macs = set()
            for device in all_devices:
                mac = device.get("mac_address") or device.get("mac")
                if mac:
                    normalized = mac.replace(":", "").replace("-", "").replace(".", "").upper()
                    all_macs.add(normalized)
            
            # Update discovery panel with ALL managed MACs for filtering
            self.discovery_panel.set_managed_macs(all_macs)

            # Controllers (UniFi/MikroTik/OpenWrt/...) have no MAC in the
            # schema. Pull them and feed their IPs as a secondary filter
            # so scan rows for managed gateways aren't shown as unknown.
            controller_ips: set[str] = set()
            try:
                ctrl_resp = client.get_controllers()
                if isinstance(ctrl_resp, dict):
                    controllers = ctrl_resp.get("items", ctrl_resp.get("data", []))
                else:
                    controllers = ctrl_resp or []
                for c in controllers:
                    host = c.get("host") or c.get("management_ip") or c.get("ip_address")
                    if host:
                        controller_ips.add(str(host))
            except Exception as exc:
                logger.debug("Could not fetch controllers for IP filter: %s", exc)
            self.discovery_panel.set_managed_ips(controller_ips)

            logger.info(
                f"Loaded {len(site_devices)} site devices, {len(all_macs)} total MACs, "
                f"{len(controller_ips)} controller IPs for filtering"
            )
            
        except Exception as e:
            logger.error(f"Failed to load managed devices: {e}")
            self.managed_panel.set_status(f"Error: {e}")
    
    @Slot()
    def _on_refresh_managed(self) -> None:
        """Handle refresh request for managed devices."""
        self._load_managed_devices()

    def _refresh_inventory_panel(self) -> None:
        """Push the latest managed + discovered snapshots into the
        unified Inventory panel. Safe to call repeatedly.
        """
        if not hasattr(self, "inventory_panel"):
            return
        managed = getattr(self, "_latest_managed", []) or []
        discovered = getattr(self, "_latest_discovered", []) or []
        try:
            self.inventory_panel.set_inventory(managed, discovered)
            site_name = (
                self.connection_panel.get_site_name()
                if hasattr(self.connection_panel, "get_site_name")
                else "site"
            )
            self.inventory_panel.set_status(f"Connected to {site_name}")
        except Exception:
            logger.debug("Inventory panel refresh failed", exc_info=True)

    @Slot(dict)
    def _on_inventory_adopt(self, host: dict) -> None:
        """Bridge inventory-panel Adopt clicks into the existing adopt
        flow that the DiscoveryPanel already wires to ``_on_adopt_devices``.
        Keeps the bulk-adopt + driver-pick UX consistent across the
        unified view and the legacy panel.
        """
        try:
            self._on_adopt_devices([host])
        except Exception:
            logger.exception("Adopt from inventory panel failed")
    
    @Slot(dict)
    def _on_managed_device_selected(self, device: dict) -> None:
        """Handle device selection in managed panel."""
        # TODO: Show device details panel
        logger.debug(f"Managed device selected: {device.get('name')} ({device.get('ip_address')})")
    
    @Slot(str)
    def _on_scan_requested(self, scan_type: str) -> None:
        """Handle scan request from scan panel."""
        logger.info(f"Scan requested: {scan_type}")

        # Map string to ScanType enum
        type_map = {
            "quick": ScanType.QUICK,
            "camera": ScanType.CAMERA,
            "voip": ScanType.VOIP,
            "iot": ScanType.IOT,
            "port": ScanType.PORT,
            "windows": ScanType.WINDOWS,
            "full": ScanType.FULL,
        }

        scan_type_enum = type_map.get(scan_type.lower())
        if scan_type_enum:
            self._start_scan(scan_type_enum)

        # Full Scan also kicks off a brief LLDP capture window in
        # parallel. Best-effort: failures (no privileges, scapy
        # missing) log + skip without blocking the host scan.
        if scan_type.lower() == "full":
            import asyncio as _aio
            _aio.create_task(
                self._capture_lldp_during_full_scan(),
                name="lldp-capture-during-full-scan",
            )

    async def _capture_lldp_during_full_scan(self) -> None:
        """Run a 30s LLDP sniff alongside Full Scan and push edges to backend."""
        try:
            from freesdn_agent.scanners.lldp_capture import capture_lldp_edges

            interfaces = self.scan_panel.get_selected_interfaces() or None
            edges = await capture_lldp_edges(
                duration_seconds=30, interfaces=interfaces,
            )
            if not edges:
                logger.info("LLDP capture finished with no edges")
                return

            client = self.connection_panel.get_client() if hasattr(
                self, "connection_panel"
            ) else None
            site_id = self.connection_panel.get_site_id() if hasattr(
                self, "connection_panel"
            ) else None
            if not client or not site_id:
                logger.warning("LLDP edges captured but no client/site for push")
                return

            summary = client.push_topology_edges(edges, site_id)
            logger.info(
                "LLDP edges pushed: %d captured, server says %s",
                len(edges), summary,
            )
        except Exception:
            logger.exception("LLDP capture-during-full-scan failed")
    
    @Slot(dict)
    def _on_device_selected(self, device: dict) -> None:
        """Handle device selection in discovery panel."""
        # TODO: Show device details panel
        logger.debug(f"Device selected: {device.get('ip_address')}")
    
    @Slot(list)
    def _on_adopt_devices(self, devices: list) -> None:
        """Handle adopt selected devices request."""
        logger.info(f"Adopt {len(devices)} selected devices requested")
        self._adopt_devices(devices)
    
    @Slot()
    def _on_adopt_all(self) -> None:
        """Handle adopt all devices request."""
        all_devices = self.discovery_panel.get_devices_with_mac()
        logger.info(f"Adopt all {len(all_devices)} devices requested")
        self._adopt_devices(all_devices)
    
    def _adopt_devices(self, devices: list) -> None:
        """Open the AdoptDialog to review + adopt selected devices.

        Routes through POST /discovery/adopt/bulk which:
        - auto-matches driver from each row's fingerprint (or "generic" fallback)
        - marks the matching DiscoveredHost row as is_adopted on success
        - returns per-row succeeded/failed status

        The user can override the auto-matched driver inside the dialog
        before submit. After the dialog closes we refresh both the
        Discovered list (so adopted rows disappear) and the Managed list
        (so the new Device shows up).
        """
        if not devices:
            return

        client = self.connection_panel.get_client()
        site_id = self.connection_panel.get_site_id()
        site_name = self.connection_panel.get_site_name()

        if not client or not site_id:
            QMessageBox.warning(
                self,
                "Not Connected",
                "Please connect to FreeSDN first.",
            )
            return

        # Bulk endpoint caps at 100 per request — split here if needed.
        if len(devices) > 100:
            QMessageBox.warning(
                self,
                "Too Many Devices",
                f"Bulk adoption is capped at 100 devices per submit; you "
                f"selected {len(devices)}. Adopt in smaller batches.",
            )
            return

        # Fetch driver list once for the picker. Soft-fail to an empty
        # list — the dialog will still let the user submit with Auto.
        drivers: list[dict] = []
        try:
            drivers = client.list_drivers() or []
        except Exception as exc:
            logger.warning("Could not load drivers, picker will only offer Auto: %s", exc)

        from freesdn_agent.ui.dialogs.adopt import AdoptDialog

        dlg = AdoptDialog(
            devices=devices,
            drivers=drivers,
            site_id=site_id,
            site_name=site_name,
            client=client,
            parent=self,
        )
        dlg.adoption_finished.connect(self._on_adoption_finished)
        dlg.exec()

    @Slot(dict)
    def _on_adoption_finished(self, result: dict) -> None:
        """Refresh tabs after AdoptDialog completes its bulk submit."""
        logger.info(
            "Adoption completed: %s/%s succeeded, %s failed",
            result.get("succeeded", 0),
            result.get("total", 0),
            result.get("failed", 0),
        )
        # Pull adopted IPs/MACs out of the result and remove them from
        # the Discovered panel locally so the user gets immediate
        # feedback without waiting for a backend re-fetch.
        for row in result.get("results", []):
            if row.get("status") == "adopted":
                ip = row.get("ip_address")
                # discovery_panel currently keys removal by MAC; fall back
                # to a no-op when we don't have one — the load below will
                # reconcile.
                for dev in list(self.discovery_panel.model._devices):
                    if dev.get("ip_address") == ip:
                        mac = dev.get("mac_address")
                        if mac:
                            self.discovery_panel.remove_device_by_mac(mac)
                        break

        # Re-pull managed devices so the new rows appear in the
        # Managed tab + are added to the dedup filter for future scans.
        self._load_managed_devices()
    
    def _on_theme_change(self, mode: ThemeMode) -> None:
        """Handle theme change from menu."""
        theme_manager = ThemeManager.instance()
        app = QApplication.instance()
        if app:
            theme_manager.apply_theme(mode, app)
            # Save preference
            self.config.ui.theme = mode.value
            self.config.save()
            self._update_theme_menu()
    
    def _update_theme_menu(self) -> None:
        """Update theme menu checkmarks."""
        current_mode = self.config.ui.theme
        self.action_theme_system.setChecked(current_mode == ThemeMode.SYSTEM.value)
        self.action_theme_dark.setChecked(current_mode == ThemeMode.DARK.value)
        self.action_theme_light.setChecked(current_mode == ThemeMode.LIGHT.value)
