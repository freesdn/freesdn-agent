"""
Settings Dialog for FreeSDN Agent.
"""

import logging
from typing import Optional

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QWidget,
    QFormLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QSpinBox,
    QDoubleSpinBox,
    QCheckBox,
    QComboBox,
    QDialogButtonBox,
    QGroupBox,
    QApplication,
)
from PySide6.QtCore import Qt

from freesdn_agent.core.config import Config
from freesdn_agent.ui.styles.theme import ThemeManager, ThemeMode

logger = logging.getLogger(__name__)


class SettingsDialog(QDialog):
    """Settings configuration dialog."""
    
    def __init__(self, config: Config, parent: Optional[QWidget] = None):
        super().__init__(parent)
        
        self.config = config
        self._setup_ui()
        self._load_settings()
    
    def _setup_ui(self) -> None:
        """Setup the dialog UI."""
        self.setWindowTitle("Settings")
        self.setMinimumSize(500, 450)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Tab widget
        tabs = QTabWidget()
        
        # Scan Settings Tab
        scan_tab = self._create_scan_tab()
        tabs.addTab(scan_tab, "Scan Settings")
        
        # UI Settings Tab
        ui_tab = self._create_ui_tab()
        tabs.addTab(ui_tab, "Appearance")
        
        # Connection Tab
        connection_tab = self._create_connection_tab()
        tabs.addTab(connection_tab, "Connection")
        
        layout.addWidget(tabs)
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel | QDialogButtonBox.Apply
        )
        button_box.accepted.connect(self._save_and_accept)
        button_box.rejected.connect(self.reject)
        button_box.button(QDialogButtonBox.Apply).clicked.connect(self._save_settings)
        layout.addWidget(button_box)
    
    def _create_scan_tab(self) -> QWidget:
        """Create scan settings tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Performance group
        perf_group = QGroupBox("Performance")
        perf_layout = QFormLayout(perf_group)
        
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(1.0, 30.0)
        self.timeout_spin.setSingleStep(0.5)
        self.timeout_spin.setSuffix(" seconds")
        perf_layout.addRow("Scan Timeout:", self.timeout_spin)
        
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(10, 200)
        self.concurrency_spin.setSingleStep(10)
        perf_layout.addRow("Concurrency:", self.concurrency_spin)
        
        layout.addWidget(perf_group)
        
        # Default Scanners group - reorganized into categories
        scanners_group = QGroupBox("Default Scanners")
        scanners_layout = QGridLayout(scanners_group)
        scanners_layout.setColumnStretch(0, 1)
        scanners_layout.setColumnStretch(1, 1)
        
        # Left column - Basic discovery
        row = 0
        basic_label = QLabel("<b>Basic Discovery</b>")
        scanners_layout.addWidget(basic_label, row, 0)
        row += 1
        
        self.enable_icmp = QCheckBox("ICMP Ping")
        self.enable_arp = QCheckBox("ARP Scan (Layer 2)")
        self.enable_ports = QCheckBox("TCP Port Scan")
        self.enable_http = QCheckBox("HTTP Service Detection")
        self.enable_banner = QCheckBox("SSH/Telnet Banner")
        
        scanners_layout.addWidget(self.enable_icmp, row, 0)
        row += 1
        scanners_layout.addWidget(self.enable_arp, row, 0)
        row += 1
        scanners_layout.addWidget(self.enable_ports, row, 0)
        row += 1
        scanners_layout.addWidget(self.enable_http, row, 0)
        row += 1
        scanners_layout.addWidget(self.enable_banner, row, 0)
        
        # Right column - Protocol-specific
        row = 0
        proto_label = QLabel("<b>Protocol-Specific</b>")
        scanners_layout.addWidget(proto_label, row, 1)
        row += 1
        
        self.enable_onvif = QCheckBox("ONVIF (IP Cameras)")
        self.enable_sadp = QCheckBox("Hikvision SADP")
        self.enable_snmp = QCheckBox("SNMP (Network Devices)")
        self.enable_netbios = QCheckBox("NetBIOS/SMB (Windows)")
        self.enable_mdns = QCheckBox("mDNS/Bonjour")
        self.enable_ssdp = QCheckBox("SSDP/UPnP")
        self.enable_sip = QCheckBox("SIP (VoIP)")
        
        scanners_layout.addWidget(self.enable_onvif, row, 1)
        row += 1
        scanners_layout.addWidget(self.enable_sadp, row, 1)
        row += 1
        scanners_layout.addWidget(self.enable_snmp, row, 1)
        row += 1
        scanners_layout.addWidget(self.enable_netbios, row, 1)
        row += 1
        scanners_layout.addWidget(self.enable_mdns, row, 1)
        row += 1
        scanners_layout.addWidget(self.enable_ssdp, row, 1)
        row += 1
        scanners_layout.addWidget(self.enable_sip, row, 1)
        
        layout.addWidget(scanners_group)
        
        layout.addStretch()
        return widget
    
    def _create_ui_tab(self) -> QWidget:
        """Create UI settings tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Appearance group
        appearance_group = QGroupBox("Appearance")
        appearance_layout = QFormLayout(appearance_group)
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItem("Follow System", ThemeMode.SYSTEM.value)
        self.theme_combo.addItem("Dark", ThemeMode.DARK.value)
        self.theme_combo.addItem("Light", ThemeMode.LIGHT.value)
        self.theme_combo.currentIndexChanged.connect(self._on_theme_changed)
        appearance_layout.addRow("Theme:", self.theme_combo)
        
        layout.addWidget(appearance_group)
        
        # Behavior group
        behavior_group = QGroupBox("Behavior")
        behavior_layout = QVBoxLayout(behavior_group)
        
        self.show_known = QCheckBox("Show known devices in results")
        self.auto_push = QCheckBox("Automatically push new devices to FreeSDN")
        
        behavior_layout.addWidget(self.show_known)
        behavior_layout.addWidget(self.auto_push)
        
        layout.addWidget(behavior_group)
        
        layout.addStretch()
        return widget
    
    def _on_theme_changed(self, index: int) -> None:
        """Handle theme selection change - apply immediately."""
        theme_value = self.theme_combo.currentData()
        if theme_value:
            theme_mode = ThemeMode(theme_value)
            theme_manager = ThemeManager.instance()
            app = QApplication.instance()
            if app:
                theme_manager.apply_theme(theme_mode, app)
    
    def _create_connection_tab(self) -> QWidget:
        """Create connection settings tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        
        # Server group
        server_group = QGroupBox("FreeSDN Server")
        server_layout = QFormLayout(server_group)
        
        self.server_url = QLineEdit()
        self.server_url.setPlaceholderText("https://freesdn.example.com")
        server_layout.addRow("Server URL:", self.server_url)
        
        info_label = QLabel(
            "Note: Credentials are stored securely in your system's keychain."
        )
        info_label.setStyleSheet("color: #94a3b8; font-size: 11px;")
        info_label.setWordWrap(True)
        server_layout.addRow("", info_label)
        
        layout.addWidget(server_group)
        
        layout.addStretch()
        return widget
    
    def _load_settings(self) -> None:
        """Load current settings into UI."""
        # Scan settings
        self.timeout_spin.setValue(self.config.scan.timeout)
        self.concurrency_spin.setValue(self.config.scan.concurrency)
        
        # Basic discovery
        self.enable_icmp.setChecked(self.config.scan.enable_icmp)
        self.enable_arp.setChecked(self.config.scan.enable_arp)
        self.enable_ports.setChecked(self.config.scan.enable_ports)
        self.enable_http.setChecked(self.config.scan.enable_http)
        self.enable_banner.setChecked(self.config.scan.enable_banner)
        
        # Protocol-specific
        self.enable_onvif.setChecked(self.config.scan.enable_onvif)
        self.enable_sadp.setChecked(self.config.scan.enable_sadp)
        self.enable_snmp.setChecked(self.config.scan.enable_snmp)
        self.enable_netbios.setChecked(self.config.scan.enable_netbios)
        self.enable_mdns.setChecked(self.config.scan.enable_mdns)
        self.enable_ssdp.setChecked(self.config.scan.enable_ssdp)
        self.enable_sip.setChecked(self.config.scan.enable_sip)
        
        # UI settings
        theme_index = self.theme_combo.findData(self.config.ui.theme)
        if theme_index >= 0:
            self.theme_combo.setCurrentIndex(theme_index)
        
        self.show_known.setChecked(self.config.ui.show_known_devices)
        self.auto_push.setChecked(self.config.ui.auto_push_new)
        
        # Connection settings
        self.server_url.setText(self.config.freesdn.url)
    
    def _save_settings(self) -> None:
        """Save settings from UI to config."""
        # Scan settings
        self.config.scan.timeout = self.timeout_spin.value()
        self.config.scan.concurrency = self.concurrency_spin.value()
        
        # Basic discovery
        self.config.scan.enable_icmp = self.enable_icmp.isChecked()
        self.config.scan.enable_arp = self.enable_arp.isChecked()
        self.config.scan.enable_ports = self.enable_ports.isChecked()
        self.config.scan.enable_http = self.enable_http.isChecked()
        self.config.scan.enable_banner = self.enable_banner.isChecked()
        
        # Protocol-specific
        self.config.scan.enable_onvif = self.enable_onvif.isChecked()
        self.config.scan.enable_sadp = self.enable_sadp.isChecked()
        self.config.scan.enable_snmp = self.enable_snmp.isChecked()
        self.config.scan.enable_netbios = self.enable_netbios.isChecked()
        self.config.scan.enable_mdns = self.enable_mdns.isChecked()
        self.config.scan.enable_ssdp = self.enable_ssdp.isChecked()
        self.config.scan.enable_sip = self.enable_sip.isChecked()
        
        # UI settings
        self.config.ui.theme = self.theme_combo.currentData()
        self.config.ui.show_known_devices = self.show_known.isChecked()
        self.config.ui.auto_push_new = self.auto_push.isChecked()
        
        # Connection settings
        self.config.freesdn.url = self.server_url.text().strip()
        
        # Save to disk
        self.config.save()
        logger.info("Settings saved")
    
    def _save_and_accept(self) -> None:
        """Save settings and close dialog."""
        self._save_settings()
        self.accept()
