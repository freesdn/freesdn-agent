"""
Scan Panel Widget.

Provides scan controls and network interface selection.
"""

import logging
from typing import Optional

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QComboBox,
    QGridLayout,
    QSizePolicy,
)
from PySide6.QtCore import Qt, Signal, Slot

from freesdn_agent.ui.widgets.network_selector import NetworkSelector
from freesdn_agent.ui.widgets.multi_target_selector import MultiTargetSelector

logger = logging.getLogger(__name__)


class ScanPanel(QFrame):
    """Panel with scan controls."""
    
    # Signals
    scan_requested = Signal(str)  # Scan type: quick, camera, voip, full
    scan_stop_requested = Signal()
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        
        self._scanning = False
        self._setup_ui()
    
    def _setup_ui(self) -> None:
        """Setup the panel UI."""
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setObjectName("scanPanel")
        # ScanPanel is the host for the new selector — it MUST claim
        # vertical room so the selector below can render its
        # interfaces + targets boxes at usable sizes. Without an
        # explicit size policy the parent QVBoxLayout in main_window
        # squeezed the panel to the section title height + buttons,
        # leaving the selector at ~30px.
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # Floor: enough for title + selector (minimumSizeHint=340) +
        # button grid (~120px) + padding. Window can still shrink
        # below this — Qt will clip — but the default geometry
        # always gives the panel room.
        self.setMinimumHeight(520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Section title
        title = QLabel("Network Discovery")
        title.setObjectName("sectionTitle")
        title.setStyleSheet("font-size: 15px; font-weight: 600; padding: 0;")
        layout.addWidget(title)

        # Multi-target selector — responsive (stacked at <900px,
        # side-by-side above). Stretch=1 so it takes the available
        # space between the title and the scan-buttons grid.
        self.target_selector = MultiTargetSelector()
        layout.addWidget(self.target_selector, stretch=1)
        
        # Scan buttons grid
        buttons_layout = QGridLayout()
        buttons_layout.setSpacing(12)
        
        # Row 1 - Basic scans
        # Quick Scan
        self.quick_scan_btn = self._create_scan_button(
            "Quick Scan",
            "ARP + ICMP ping\nFast host discovery (~30 sec)",
            "quickScanBtn"
        )
        self.quick_scan_btn.clicked.connect(self.start_quick_scan)
        buttons_layout.addWidget(self.quick_scan_btn, 0, 0)
        
        # Camera Scan
        self.camera_scan_btn = self._create_scan_button(
            "Camera Scan",
            "ONVIF + Hikvision SADP\nDiscover IP cameras (~2 min)",
            "cameraScanBtn"
        )
        self.camera_scan_btn.clicked.connect(self.start_camera_scan)
        buttons_layout.addWidget(self.camera_scan_btn, 0, 1)
        
        # VoIP Scan
        self.voip_scan_btn = self._create_scan_button(
            "VoIP Scan",
            "SIP + mDNS\nDiscover phones (~2 min)",
            "voipScanBtn"
        )
        self.voip_scan_btn.clicked.connect(self.start_voip_scan)
        buttons_layout.addWidget(self.voip_scan_btn, 0, 2)
        
        # IoT Scan
        self.iot_scan_btn = self._create_scan_button(
            "IoT Scan",
            "mDNS + SSDP/UPnP\nSmart home devices (~2 min)",
            "iotScanBtn"
        )
        self.iot_scan_btn.clicked.connect(self.start_iot_scan)
        buttons_layout.addWidget(self.iot_scan_btn, 0, 3)
        
        # Row 2 - Advanced scans
        # Port Scan
        self.port_scan_btn = self._create_scan_button(
            "Port Scan",
            "TCP ports + HTTP detection\nIdentify services (~3 min)",
            "portScanBtn"
        )
        self.port_scan_btn.clicked.connect(self.start_port_scan)
        buttons_layout.addWidget(self.port_scan_btn, 1, 0)
        
        # Windows/SMB Scan
        self.windows_scan_btn = self._create_scan_button(
            "Windows Scan",
            "NetBIOS + SMB\nDiscover Windows devices (~2 min)",
            "windowsScanBtn"
        )
        self.windows_scan_btn.clicked.connect(self.start_windows_scan)
        buttons_layout.addWidget(self.windows_scan_btn, 1, 1)
        
        # Full Scan
        self.full_scan_btn = self._create_scan_button(
            "Full Scan",
            "All 12 protocols\nComprehensive discovery (~5 min)",
            "fullScanBtn"
        )
        self.full_scan_btn.clicked.connect(self.start_full_scan)
        buttons_layout.addWidget(self.full_scan_btn, 1, 2)
        
        layout.addLayout(buttons_layout)
        
        # Stop button row - always visible but disabled until scan starts
        action_row = QHBoxLayout()
        action_row.setSpacing(12)
        
        action_row.addStretch()
        
        # Stop button - styled prominently
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.setObjectName("stopScanBtn")
        self.stop_btn.setFixedSize(150, 40)
        self.stop_btn.setEnabled(False)  # Disabled until scan starts
        self.stop_btn.setStyleSheet("""
            QPushButton#stopScanBtn {
                background-color: #dc2626;
                color: white;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton#stopScanBtn:hover {
                background-color: #b91c1c;
            }
            QPushButton#stopScanBtn:pressed {
                background-color: #991b1b;
            }
            QPushButton#stopScanBtn:disabled {
                background-color: #9ca3af;
                color: #e5e7eb;
            }
        """)
        self.stop_btn.clicked.connect(self.stop_scan)
        action_row.addWidget(self.stop_btn)
        
        action_row.addStretch()
        
        layout.addLayout(action_row)
    
    def _create_scan_button(self, title: str, description: str, object_name: str) -> QPushButton:
        """Create a styled scan button."""
        btn = QPushButton()
        btn.setObjectName(object_name)
        btn.setMinimumSize(180, 80)
        
        # Use rich text for multi-line
        btn.setText(f"{title}")
        btn.setToolTip(description)
        
        return btn
    
    def _set_scanning(self, scanning: bool) -> None:
        """Update UI for scanning state."""
        self._scanning = scanning
        
        # Toggle buttons
        self.quick_scan_btn.setEnabled(not scanning)
        self.camera_scan_btn.setEnabled(not scanning)
        self.voip_scan_btn.setEnabled(not scanning)
        self.iot_scan_btn.setEnabled(not scanning)
        self.port_scan_btn.setEnabled(not scanning)
        self.windows_scan_btn.setEnabled(not scanning)
        self.full_scan_btn.setEnabled(not scanning)
        # NetworkSelector was replaced by MultiTargetSelector in the
        # multi-subnet UX commit. Disable the new widget so the user
        # can't change targets mid-scan.
        self.target_selector.setEnabled(not scanning)
        
        # Enable/disable stop button
        self.stop_btn.setEnabled(scanning)
    
    @Slot()
    def start_quick_scan(self) -> None:
        """Start a quick scan."""
        if not self._scanning:
            self._set_scanning(True)
            self.scan_requested.emit("quick")
    
    @Slot()
    def start_camera_scan(self) -> None:
        """Start a camera scan."""
        if not self._scanning:
            self._set_scanning(True)
            self.scan_requested.emit("camera")
    
    @Slot()
    def start_voip_scan(self) -> None:
        """Start a VoIP scan."""
        if not self._scanning:
            self._set_scanning(True)
            self.scan_requested.emit("voip")
    
    @Slot()
    def start_iot_scan(self) -> None:
        """Start an IoT/Smart Home scan."""
        if not self._scanning:
            self._set_scanning(True)
            self.scan_requested.emit("iot")
    
    @Slot()
    def start_port_scan(self) -> None:
        """Start a port scan."""
        if not self._scanning:
            self._set_scanning(True)
            self.scan_requested.emit("port")
    
    @Slot()
    def start_windows_scan(self) -> None:
        """Start a Windows/SMB scan."""
        if not self._scanning:
            self._set_scanning(True)
            self.scan_requested.emit("windows")
    
    @Slot()
    def start_full_scan(self) -> None:
        """Start a full scan."""
        if not self._scanning:
            self._set_scanning(True)
            self.scan_requested.emit("full")
    
    @Slot()
    def stop_scan(self) -> None:
        """Stop the current scan."""
        if self._scanning:
            self._set_scanning(False)
            self.scan_stop_requested.emit()
    
    def on_scan_completed(self) -> None:
        """Handle scan completion."""
        self._set_scanning(False)
    
    def get_selected_interface(self) -> Optional[str]:
        """Backward-compat: returns the FIRST checked interface, or None.

        Kept so callers built around the single-select model still work.
        New code should use ``get_selected_interfaces()``.
        """
        names = self.target_selector.get_selected_interfaces()
        return names[0] if names else None

    def get_selected_network(self) -> Optional[str]:
        """Backward-compat: returns the FIRST target, or None.

        New code should use ``get_targets()``.
        """
        targets = self.target_selector.get_targets()
        return targets[0] if targets else None

    def get_selected_interfaces(self) -> list[str]:
        """Return ALL checked interface names."""
        return self.target_selector.get_selected_interfaces()

    def get_targets(self) -> list[str]:
        """Return all scan targets — typed CIDRs/IPs/ranges if any,
        otherwise the checked interfaces' subnets."""
        return self.target_selector.get_targets()
