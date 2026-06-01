"""
Managed Devices Panel.

Displays devices that are already registered in the FreeSDN database.
Similar to the "Online Devices" panel in Hikvision tools.
"""

import logging
from typing import Optional, List
from datetime import datetime

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableView,
    QHeaderView,
    QPushButton,
    QLabel,
    QFrame,
    QAbstractItemView,
    QLineEdit,
    QComboBox,
)
from PySide6.QtCore import Qt, Signal, Slot, QSortFilterProxyModel, QTimer
from PySide6.QtGui import QColor, QBrush, QStandardItemModel, QStandardItem, QIcon

logger = logging.getLogger(__name__)


class ManagedDeviceModel(QStandardItemModel):
    """Model for managed device data."""
    
    COLUMNS = [
        ("Status", 70),
        ("Name", 150),
        ("IP Address", 120),
        ("MAC Address", 140),
        ("Type", 90),
        ("Vendor", 140),
        ("Last Seen", 140),
    ]
    
    COL_STATUS = 0
    COL_NAME = 1
    COL_IP = 2
    COL_MAC = 3
    COL_TYPE = 4
    COL_VENDOR = 5
    COL_LAST_SEEN = 6
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHorizontalHeaderLabels([col[0] for col in self.COLUMNS])
        self._devices = []
        self._devices_by_mac = {}  # For quick lookup
    
    def set_devices(self, devices: List[dict]) -> None:
        """Set all devices (replaces existing)."""
        self.removeRows(0, self.rowCount())
        self._devices.clear()
        self._devices_by_mac.clear()
        
        for device in devices:
            self._add_device_row(device)
    
    def _add_device_row(self, device: dict) -> None:
        """Add a single device row."""
        self._devices.append(device)
        
        # Index by MAC for quick lookup
        # Support both 'mac' and 'mac_address' field names (API returns 'mac')
        mac = device.get("mac_address") or device.get("mac")
        if mac:
            normalized_mac = mac.replace(":", "").replace("-", "").upper()
            self._devices_by_mac[normalized_mac] = device
        
        row = []
        
        # Status
        status = device.get("status", "unknown")
        status_item = QStandardItem(status.title())
        if status == "online":
            status_item.setForeground(QBrush(QColor("#22c55e")))
        elif status == "offline":
            status_item.setForeground(QBrush(QColor("#ef4444")))
        else:
            status_item.setForeground(QBrush(QColor("#94a3b8")))
        status_item.setTextAlignment(Qt.AlignCenter)
        row.append(status_item)
        
        # Name
        name = device.get("name") or device.get("hostname") or "Unnamed"
        name_item = QStandardItem(name)
        name_item.setData(device, Qt.UserRole)  # Store full device data
        row.append(name_item)
        
        # IP Address - support both 'ip' and 'ip_address' field names (API returns 'ip')
        ip_str = device.get("ip_address") or device.get("ip") or ""
        ip_item = QStandardItem(ip_str)
        try:
            ip_parts = tuple(int(p) for p in ip_str.split("."))
            ip_item.setData(ip_parts, Qt.UserRole + 1)
        except:
            ip_item.setData((0, 0, 0, 0), Qt.UserRole + 1)
        row.append(ip_item)
        
        # MAC Address - support both 'mac' and 'mac_address' field names
        mac_value = device.get("mac_address") or device.get("mac") or ""
        mac_item = QStandardItem(mac_value.upper() if mac_value else "")
        row.append(mac_item)
        
        # Type
        device_type = device.get("device_type") or "unknown"
        type_item = QStandardItem(device_type.replace("_", " ").title())
        row.append(type_item)
        
        # Vendor
        vendor = device.get("vendor") or "Unknown"
        vendor_item = QStandardItem(vendor)
        row.append(vendor_item)
        
        # Last Seen
        last_seen = device.get("last_seen")
        if last_seen:
            try:
                if isinstance(last_seen, str):
                    dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                else:
                    dt = last_seen
                last_seen_str = dt.strftime("%Y-%m-%d %H:%M")
            except:
                last_seen_str = str(last_seen)[:16]
        else:
            last_seen_str = "-"
        last_seen_item = QStandardItem(last_seen_str)
        row.append(last_seen_item)
        
        self.appendRow(row)
    
    def has_mac(self, mac_address: str) -> bool:
        """Check if a MAC address exists in managed devices."""
        if not mac_address:
            return False
        normalized = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
        return normalized in self._devices_by_mac
    
    def get_device_by_mac(self, mac_address: str) -> Optional[dict]:
        """Get device by MAC address."""
        if not mac_address:
            return None
        normalized = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
        return self._devices_by_mac.get(normalized)
    
    def get_all_macs(self) -> set:
        """Get all managed MAC addresses (normalized)."""
        return set(self._devices_by_mac.keys())
    
    def get_device_count(self) -> int:
        """Get total device count."""
        return len(self._devices)


class ManagedDevicesPanel(QFrame):
    """Panel showing devices registered in FreeSDN database."""
    
    # Signals
    device_selected = Signal(dict)
    refresh_requested = Signal()
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._setup_ui()
        
        # Auto-refresh timer (every 60 seconds)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._on_auto_refresh)
    
    def _setup_ui(self) -> None:
        """Setup the panel UI."""
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setObjectName("managedDevicesPanel")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Header
        header = QWidget()
        header.setObjectName("panelHeader")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 8, 12, 8)
        
        title = QLabel("Managed Devices")
        title.setObjectName("panelTitle")
        title.setStyleSheet("font-size: 13px; font-weight: bold;")
        header_layout.addWidget(title)
        
        self.count_label = QLabel("0 devices")
        self.count_label.setStyleSheet("color: #64748b; font-size: 12px; margin-left: 8px;")
        header_layout.addWidget(self.count_label)
        
        header_layout.addStretch()
        
        # Filter
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter...")
        self.filter_input.setFixedWidth(150)
        self.filter_input.setStyleSheet("""
            QLineEdit {
                padding: 4px 8px;
                border: 1px solid #374151;
                border-radius: 4px;
                background: #1e293b;
                color: #e2e8f0;
            }
        """)
        self.filter_input.textChanged.connect(self._on_filter_changed)
        header_layout.addWidget(self.filter_input)
        
        # Refresh button
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setObjectName("secondaryBtn")
        self.refresh_btn.setStyleSheet("""
            QPushButton#secondaryBtn {
                background-color: #374151;
                color: #e2e8f0;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 12px;
            }
            QPushButton#secondaryBtn:hover {
                background-color: #4b5563;
            }
        """)
        self.refresh_btn.clicked.connect(self._on_refresh_clicked)
        header_layout.addWidget(self.refresh_btn)
        
        layout.addWidget(header)
        
        # Table
        self.model = ManagedDeviceModel(self)
        self.proxy_model = QSortFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        self.proxy_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.proxy_model.setFilterKeyColumn(-1)  # Search all columns
        
        self.table = QTableView()
        self.table.setObjectName("managedDevicesTable")
        self.table.setModel(self.proxy_model)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(ManagedDeviceModel.COL_IP, Qt.AscendingOrder)
        
        # Header settings
        header_view = self.table.horizontalHeader()
        header_view.setStretchLastSection(True)
        for col, (_, width) in enumerate(ManagedDeviceModel.COLUMNS):
            self.table.setColumnWidth(col, width)
        header_view.setSectionResizeMode(ManagedDeviceModel.COL_VENDOR, QHeaderView.Stretch)
        
        # Table settings
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        
        # Style
        self.table.setStyleSheet("""
            QTableView {
                background-color: transparent;
                alternate-background-color: rgba(30, 41, 59, 0.5);
                border: none;
                gridline-color: transparent;
            }
            QTableView::item {
                padding: 6px 8px;
                border: none;
            }
            QTableView::item:selected {
                background-color: rgba(14, 165, 233, 0.3);
            }
            QHeaderView::section {
                background-color: #1e293b;
                color: #94a3b8;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #374151;
                font-weight: bold;
                font-size: 11px;
                text-transform: uppercase;
            }
        """)
        
        self.table.clicked.connect(self._on_row_clicked)
        layout.addWidget(self.table)
        
        # Status bar
        status_bar = QWidget()
        status_bar.setObjectName("panelStatusBar")
        status_layout = QHBoxLayout(status_bar)
        status_layout.setContentsMargins(12, 6, 12, 6)
        
        self.status_label = QLabel("Not connected")
        self.status_label.setStyleSheet("color: #64748b; font-size: 11px;")
        status_layout.addWidget(self.status_label)
        
        status_layout.addStretch()
        
        self.last_refresh_label = QLabel("")
        self.last_refresh_label.setStyleSheet("color: #64748b; font-size: 11px;")
        status_layout.addWidget(self.last_refresh_label)
        
        layout.addWidget(status_bar)
    
    def set_devices(self, devices: List[dict]) -> None:
        """Set the managed devices list."""
        self.model.set_devices(devices)
        self._update_count()
        self.last_refresh_label.setText(f"Updated: {datetime.now().strftime('%H:%M:%S')}")
    
    def _update_count(self) -> None:
        """Update the device count label."""
        total = self.model.get_device_count()
        visible = self.proxy_model.rowCount()
        
        if visible < total:
            self.count_label.setText(f"{visible} of {total} devices")
        else:
            self.count_label.setText(f"{total} devices")
    
    def has_mac(self, mac_address: str) -> bool:
        """Check if MAC exists in managed devices."""
        return self.model.has_mac(mac_address)
    
    def get_all_macs(self) -> set:
        """Get all managed MAC addresses."""
        return self.model.get_all_macs()
    
    def set_status(self, message: str) -> None:
        """Set status message."""
        self.status_label.setText(message)
    
    def start_auto_refresh(self, interval_seconds: int = 60) -> None:
        """Start auto-refresh timer."""
        self._refresh_timer.start(interval_seconds * 1000)
    
    def stop_auto_refresh(self) -> None:
        """Stop auto-refresh timer."""
        self._refresh_timer.stop()
    
    @Slot(str)
    def _on_filter_changed(self, text: str) -> None:
        """Handle filter text change."""
        self.proxy_model.setFilterFixedString(text)
        self._update_count()
    
    @Slot()
    def _on_refresh_clicked(self) -> None:
        """Handle refresh button click."""
        self.refresh_requested.emit()
    
    @Slot()
    def _on_auto_refresh(self) -> None:
        """Handle auto-refresh timer."""
        self.refresh_requested.emit()
    
    def _on_row_clicked(self, index) -> None:
        """Handle row click."""
        source_index = self.proxy_model.mapToSource(index)
        name_item = self.model.item(source_index.row(), ManagedDeviceModel.COL_NAME)
        if name_item:
            device = name_item.data(Qt.UserRole)
            if device:
                self.device_selected.emit(device)
