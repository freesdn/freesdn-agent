"""
Discovery Results Panel.

Displays newly discovered devices from network scans.
Only shows devices that are NOT already in the managed devices list.
"""

import logging
from typing import Optional, List, Set
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
    QMenu,
    QApplication,
)
from PySide6.QtCore import Qt, Signal, Slot, QSortFilterProxyModel
from PySide6.QtGui import QColor, QBrush, QAction, QStandardItemModel, QStandardItem

logger = logging.getLogger(__name__)


class DiscoveryDeviceModel(QStandardItemModel):
    """Model for discovered device data."""
    
    COLUMNS = [
        ("", 30),  # Checkbox
        ("IP Address", 120),
        ("MAC Address", 140),
        ("Vendor", 160),
        ("Type", 100),
        ("Hostname", 150),
    ]
    
    COL_CHECK = 0
    COL_IP = 1
    COL_MAC = 2
    COL_VENDOR = 3
    COL_TYPE = 4
    COL_HOSTNAME = 5
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHorizontalHeaderLabels([col[0] for col in self.COLUMNS])
        self._devices = []
    
    def add_device(self, device: dict) -> None:
        """Add a device to the model."""
        self._devices.append(device)
        
        row = []
        
        # Checkbox
        check_item = QStandardItem()
        check_item.setCheckable(True)
        check_item.setCheckState(Qt.Unchecked)
        check_item.setData(device, Qt.UserRole)
        row.append(check_item)
        
        # IP Address
        ip_str = device.get("ip_address", "")
        ip_item = QStandardItem(ip_str)
        try:
            ip_parts = tuple(int(p) for p in ip_str.split("."))
            ip_item.setData(ip_parts, Qt.UserRole + 1)
        except:
            ip_item.setData((0, 0, 0, 0), Qt.UserRole + 1)
        row.append(ip_item)
        
        # MAC Address
        mac_value = device.get("mac_address") or ""
        mac_item = QStandardItem(mac_value.upper() if mac_value else "")
        row.append(mac_item)
        
        # Vendor
        vendor = device.get("vendor") or "Unknown"
        vendor_item = QStandardItem(vendor)
        row.append(vendor_item)
        
        # Type
        device_type = device.get("device_type") or "unknown"
        type_item = QStandardItem(device_type.replace("_", " ").title())
        row.append(type_item)
        
        # Hostname
        hostname = device.get("hostname") or ""
        hostname_item = QStandardItem(hostname)
        row.append(hostname_item)
        
        self.appendRow(row)
    
    def clear_devices(self) -> None:
        """Clear all devices."""
        self._devices.clear()
        self.removeRows(0, self.rowCount())
    
    def get_device(self, row: int) -> Optional[dict]:
        """Get device data for a row."""
        if 0 <= row < len(self._devices):
            return self._devices[row]
        return None
    
    def get_devices(self) -> List[dict]:
        """Get all devices."""
        return self._devices.copy()
    
    def get_device_count(self) -> int:
        """Get device count."""
        return len(self._devices)


class IPSortProxyModel(QSortFilterProxyModel):
    """Proxy model that sorts IP addresses correctly."""
    
    def lessThan(self, left, right):
        if left.column() == DiscoveryDeviceModel.COL_IP:
            left_ip = left.data(Qt.UserRole + 1)
            right_ip = right.data(Qt.UserRole + 1)
            if left_ip and right_ip:
                return left_ip < right_ip
        return super().lessThan(left, right)


class DiscoveryPanel(QFrame):
    """Panel showing newly discovered devices from network scans."""
    
    # Signals
    device_selected = Signal(dict)
    adopt_requested = Signal(list)  # List of devices to adopt
    adopt_all_requested = Signal()
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._managed_macs: Set[str] = set()  # MAC addresses already in database
        self._managed_ips: Set[str] = set()  # IPs already managed (controllers, etc.)
        self._adopt_enabled = False
        self._setup_ui()
    
    def _setup_ui(self) -> None:
        """Setup the panel UI."""
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setObjectName("discoveryPanel")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Header
        header = QWidget()
        header.setObjectName("panelHeader")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 8, 12, 8)
        
        title = QLabel("Discovered Devices")
        title.setObjectName("panelTitle")
        title.setStyleSheet("font-size: 13px; font-weight: bold;")
        header_layout.addWidget(title)
        
        self.count_label = QLabel("0 devices")
        self.count_label.setStyleSheet("color: #64748b; font-size: 12px; margin-left: 8px;")
        header_layout.addWidget(self.count_label)
        
        header_layout.addStretch()
        
        # Selection info
        self.selection_label = QLabel("")
        self.selection_label.setStyleSheet("color: #0ea5e9; font-size: 12px;")
        header_layout.addWidget(self.selection_label)
        
        # Adopt Selected button
        self.adopt_selected_btn = QPushButton("Adopt Selected")
        self.adopt_selected_btn.setObjectName("primaryBtn")
        self.adopt_selected_btn.setEnabled(False)
        self.adopt_selected_btn.setStyleSheet("""
            QPushButton#primaryBtn {
                background-color: #22c55e;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 14px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton#primaryBtn:hover {
                background-color: #16a34a;
            }
            QPushButton#primaryBtn:disabled {
                background-color: #4b5563;
                color: #9ca3af;
            }
        """)
        self.adopt_selected_btn.clicked.connect(self._on_adopt_selected)
        header_layout.addWidget(self.adopt_selected_btn)
        
        # Adopt All button
        self.adopt_all_btn = QPushButton("Adopt All")
        self.adopt_all_btn.setObjectName("secondaryBtn")
        self.adopt_all_btn.setEnabled(False)
        self.adopt_all_btn.setStyleSheet("""
            QPushButton#secondaryBtn {
                background-color: #0ea5e9;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 14px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton#secondaryBtn:hover {
                background-color: #0284c7;
            }
            QPushButton#secondaryBtn:disabled {
                background-color: #4b5563;
                color: #9ca3af;
            }
        """)
        self.adopt_all_btn.clicked.connect(self._on_adopt_all)
        header_layout.addWidget(self.adopt_all_btn)
        
        layout.addWidget(header)
        
        # Table
        self.model = DiscoveryDeviceModel(self)
        self.proxy_model = IPSortProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        
        self.model.itemChanged.connect(self._on_item_changed)
        
        self.table = QTableView()
        self.table.setObjectName("discoveryTable")
        self.table.setModel(self.proxy_model)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(DiscoveryDeviceModel.COL_IP, Qt.AscendingOrder)
        
        # Header settings
        header_view = self.table.horizontalHeader()
        header_view.setStretchLastSection(True)
        for col, (_, width) in enumerate(DiscoveryDeviceModel.COLUMNS):
            self.table.setColumnWidth(col, width)
        header_view.setSectionResizeMode(DiscoveryDeviceModel.COL_HOSTNAME, QHeaderView.Stretch)
        
        # Table settings
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        
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
        
        # Footer / Status
        footer = QWidget()
        footer.setObjectName("panelFooter")
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(12, 6, 12, 6)
        
        self.status_label = QLabel("Run a scan to discover devices")
        self.status_label.setStyleSheet("color: #64748b; font-size: 11px;")
        footer_layout.addWidget(self.status_label)
        
        footer_layout.addStretch()
        
        self.scan_time_label = QLabel("")
        self.scan_time_label.setStyleSheet("color: #64748b; font-size: 11px;")
        footer_layout.addWidget(self.scan_time_label)
        
        layout.addWidget(footer)
    
    def set_managed_macs(self, macs: Set[str]) -> None:
        """Set the list of MAC addresses that are already managed."""
        self._managed_macs = macs
        logger.info(f"Discovery panel: {len(macs)} managed MACs set for filtering")

    def set_managed_ips(self, ips: Set[str]) -> None:
        """Set IPs already known to FreeSDN (controllers etc., which have no MAC in DB)."""
        self._managed_ips = {ip.strip() for ip in ips if ip}
        logger.info(f"Discovery panel: {len(self._managed_ips)} managed IPs set for filtering")

    def add_device(self, device: dict) -> bool:
        """
        Add a discovered device if it's not already managed.

        Returns:
            True if device was added, False if filtered out (already managed)
        """
        mac = device.get("mac_address")
        ip = device.get("ip_address")

        # Filter out devices already in managed list (MAC or IP match)
        if mac:
            normalized = mac.replace(":", "").replace("-", "").replace(".", "").upper()
            if normalized in self._managed_macs:
                logger.debug(f"Device {ip} filtered (MAC {mac} already managed)")
                return False
        if ip and ip in self._managed_ips:
            logger.debug(f"Device {ip} filtered (IP already managed as controller)")
            return False
        
        self.model.add_device(device)
        self._update_count()
        return True
    
    def clear_devices(self) -> None:
        """Clear all discovered devices."""
        self.model.clear_devices()
        self._update_count()
        self.scan_time_label.setText("")
        self.status_label.setText("Run a scan to discover devices")
    
    def remove_device_by_mac(self, mac_address: str) -> None:
        """Remove a device by MAC address (after adoption)."""
        if not mac_address:
            return
        
        normalized = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
        
        # Find and remove the row
        for row in range(self.model.rowCount() - 1, -1, -1):
            check_item = self.model.item(row, DiscoveryDeviceModel.COL_CHECK)
            if check_item:
                device = check_item.data(Qt.UserRole)
                if device:
                    device_mac = device.get("mac_address") or ""
                    if device_mac:
                        device_normalized = device_mac.replace(":", "").replace("-", "").replace(".", "").upper()
                        if device_normalized == normalized:
                            self.model.removeRow(row)
                            break
        
        # Also remove from internal list (handle None mac_address safely)
        self.model._devices = [
            d for d in self.model._devices 
            if not d.get("mac_address") or 
               (d.get("mac_address") or "").replace(":", "").replace("-", "").replace(".", "").upper() != normalized
        ]
        
        # Add to managed macs set
        self._managed_macs.add(normalized)
        self._update_count()
    
    def _update_count(self) -> None:
        """Update the device count label."""
        total = self.model.get_device_count()
        with_mac = sum(1 for d in self.model.get_devices() if d.get("mac_address"))
        
        if total > 0:
            self.count_label.setText(f"{total} devices ({with_mac} with MAC)")
            self.adopt_all_btn.setEnabled(with_mac > 0 and self._adopt_enabled)
        else:
            self.count_label.setText("0 devices")
            self.adopt_all_btn.setEnabled(False)
    
    def set_status(self, message: str) -> None:
        """Set status message."""
        self.status_label.setText(message)
    
    def set_scan_time(self, seconds: float) -> None:
        """Set scan time display."""
        if seconds < 60:
            self.scan_time_label.setText(f"Scan time: {seconds:.1f}s")
        else:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            self.scan_time_label.setText(f"Scan time: {minutes}m {secs}s")
    
    def set_adopt_enabled(self, enabled: bool) -> None:
        """Enable or disable adopt functionality."""
        self._adopt_enabled = enabled
        self._update_count()
        self._update_selection_count()
    
    def get_devices_with_mac(self) -> List[dict]:
        """Get all devices that have MAC addresses."""
        return [d for d in self.model.get_devices() if d.get("mac_address")]
    
    def get_all_devices(self) -> List[dict]:
        """Get all discovered devices."""
        return self.model.get_devices()
    
    def _on_item_changed(self, item: QStandardItem) -> None:
        """Handle item changes (checkbox state)."""
        if item.column() == DiscoveryDeviceModel.COL_CHECK:
            self._update_selection_count()
    
    def _update_selection_count(self) -> None:
        """Update selection count and button state."""
        checked = self._get_checked_devices()
        checked_count = len(checked)
        
        if checked_count > 0:
            self.selection_label.setText(f"{checked_count} selected")
            self.adopt_selected_btn.setEnabled(self._adopt_enabled)
        else:
            self.selection_label.setText("")
            self.adopt_selected_btn.setEnabled(False)
    
    def _get_checked_devices(self) -> List[dict]:
        """Get list of checked devices."""
        devices = []
        for row in range(self.model.rowCount()):
            item = self.model.item(row, DiscoveryDeviceModel.COL_CHECK)
            if item and item.checkState() == Qt.Checked:
                device = item.data(Qt.UserRole)
                if device:
                    devices.append(device)
        return devices
    
    @Slot()
    def _on_adopt_selected(self) -> None:
        """Handle adopt selected button click."""
        devices = self._get_checked_devices()
        if devices:
            self.adopt_requested.emit(devices)
    
    @Slot()
    def _on_adopt_all(self) -> None:
        """Handle adopt all button click."""
        self.adopt_all_requested.emit()
    
    def _on_row_clicked(self, index) -> None:
        """Handle row click."""
        source_index = self.proxy_model.mapToSource(index)
        device = self.model.get_device(source_index.row())
        if device:
            self.device_selected.emit(device)
    
    def _show_context_menu(self, position) -> None:
        """Show context menu."""
        index = self.table.indexAt(position)
        menu = QMenu(self)
        
        # Selection actions
        select_all = QAction("Select All", self)
        select_all.triggered.connect(self._select_all)
        menu.addAction(select_all)
        
        select_none = QAction("Select None", self)
        select_none.triggered.connect(self._select_none)
        menu.addAction(select_none)
        
        if index.isValid():
            source_index = self.proxy_model.mapToSource(index)
            device = self.model.get_device(source_index.row())
            
            if device:
                menu.addSeparator()
                
                copy_ip = QAction("Copy IP Address", self)
                copy_ip.triggered.connect(lambda: self._copy_to_clipboard(device.get("ip_address", "")))
                menu.addAction(copy_ip)
                
                if device.get("mac_address"):
                    copy_mac = QAction("Copy MAC Address", self)
                    copy_mac.triggered.connect(lambda: self._copy_to_clipboard(device.get("mac_address", "")))
                    menu.addAction(copy_mac)
        
        menu.exec(self.table.viewport().mapToGlobal(position))
    
    def _select_all(self) -> None:
        """Select all devices."""
        for row in range(self.model.rowCount()):
            item = self.model.item(row, DiscoveryDeviceModel.COL_CHECK)
            if item:
                item.setCheckState(Qt.Checked)
    
    def _select_none(self) -> None:
        """Deselect all devices."""
        for row in range(self.model.rowCount()):
            item = self.model.item(row, DiscoveryDeviceModel.COL_CHECK)
            if item:
                item.setCheckState(Qt.Unchecked)
    
    def _copy_to_clipboard(self, text: str) -> None:
        """Copy text to clipboard."""
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(text)
