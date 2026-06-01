"""
Results Table Widget.

Displays discovered devices in a sortable, resizable data grid.
Uses QTableView with QStandardItemModel for proper data table behavior.
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
    QMenu,
    QAbstractItemView,
    QStyledItemDelegate,
    QCheckBox,
)
from PySide6.QtCore import Qt, Signal, Slot, QSortFilterProxyModel
from PySide6.QtGui import QColor, QBrush, QAction, QStandardItemModel, QStandardItem

logger = logging.getLogger(__name__)


class DeviceTableModel(QStandardItemModel):
    """Model for device data with sorting support."""
    
    # Column definitions - added checkbox and push columns
    COLUMNS = [
        ("", 30),  # Checkbox
        ("Status", 60),
        ("IP Address", 120),
        ("MAC Address", 140),
        ("Vendor", 180),
        ("Type", 100),
        ("Hostname", 140),
        ("", 70),  # Push button
    ]
    
    COL_CHECK = 0
    COL_STATUS = 1
    COL_IP = 2
    COL_MAC = 3
    COL_VENDOR = 4
    COL_TYPE = 5
    COL_HOSTNAME = 6
    COL_PUSH = 7
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHorizontalHeaderLabels([col[0] for col in self.COLUMNS])
        self._devices = []
    
    def add_device(self, device: dict) -> None:
        """Add a device to the model."""
        self._devices.append(device)
        
        row = []
        
        # Checkbox (for selection)
        check_item = QStandardItem()
        check_item.setCheckable(True)
        check_item.setCheckState(Qt.Unchecked)
        check_item.setData(device, Qt.UserRole)  # Store device data
        row.append(check_item)
        
        # Status
        is_new = device.get("is_new", True)
        status_item = QStandardItem("New" if is_new else "Known")
        status_item.setForeground(QBrush(QColor("#22c55e" if is_new else "#64748b")))
        status_item.setTextAlignment(Qt.AlignCenter)
        row.append(status_item)
        
        # IP Address - store as sortable data
        ip_str = device.get("ip_address", "")
        ip_item = QStandardItem(ip_str)
        # Store IP as tuple of ints for proper sorting
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
        
        # Push button placeholder (will be handled by delegate)
        push_item = QStandardItem("Push")
        push_item.setTextAlignment(Qt.AlignCenter)
        row.append(push_item)
        
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
    
    def get_devices(self) -> list[dict]:
        """Get all devices."""
        return self._devices.copy()


class IPSortProxyModel(QSortFilterProxyModel):
    """Proxy model that sorts IP addresses correctly."""
    
    def lessThan(self, left, right):
        # Check if this is the IP column (column 1)
        if left.column() == DeviceTableModel.COL_IP:
            left_ip = left.data(Qt.UserRole + 1)
            right_ip = right.data(Qt.UserRole + 1)
            if left_ip and right_ip:
                return left_ip < right_ip
        
        # Default string comparison
        return super().lessThan(left, right)


class ResultsTable(QFrame):
    """Table displaying discovered devices with sorting and resizing."""
    
    # Signals
    device_selected = Signal(dict)  # Selected device data
    push_requested = Signal(dict)  # Device to push
    push_selected_requested = Signal(list)  # List of devices to push
    push_all_requested = Signal()
    check_database_requested = Signal()  # Request to check devices against database
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        
        self._push_enabled = False
        self._setup_ui()
    
    def _setup_ui(self) -> None:
        """Setup the table UI."""
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setObjectName("resultsPanel")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Header row
        header = QWidget()
        header.setObjectName("resultsHeader")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 12, 16, 12)
        
        title = QLabel("Discovery Results")
        title.setObjectName("sectionTitle")
        title.setStyleSheet("font-size: 14px; font-weight: bold; padding: 2px 0;")
        header_layout.addWidget(title)
        
        self.count_label = QLabel("0 devices")
        self.count_label.setStyleSheet("color: #94a3b8;")
        header_layout.addWidget(self.count_label)
        
        header_layout.addStretch()
        
        # Selection info
        self.selection_label = QLabel("")
        self.selection_label.setStyleSheet("color: #0ea5e9; font-size: 12px;")
        header_layout.addWidget(self.selection_label)
        
        # Check Database button
        self.check_db_btn = QPushButton("🔍 Check Database")
        self.check_db_btn.setObjectName("checkDbBtn")
        self.check_db_btn.setEnabled(False)
        self.check_db_btn.setToolTip("Check if devices exist in FreeSDN database by MAC address")
        self.check_db_btn.setStyleSheet("""
            QPushButton#checkDbBtn {
                background-color: #6366f1;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton#checkDbBtn:hover {
                background-color: #4f46e5;
            }
            QPushButton#checkDbBtn:disabled {
                background-color: #94a3b8;
            }
        """)
        self.check_db_btn.clicked.connect(self._on_check_database)
        header_layout.addWidget(self.check_db_btn)

        # Push Selected button
        self.push_selected_btn = QPushButton("↗ Push Selected")
        self.push_selected_btn.setObjectName("pushSelectedBtn")
        self.push_selected_btn.setEnabled(False)
        self.push_selected_btn.setStyleSheet("""
            QPushButton#pushSelectedBtn {
                background-color: #22c55e;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton#pushSelectedBtn:hover {
                background-color: #16a34a;
            }
            QPushButton#pushSelectedBtn:disabled {
                background-color: #94a3b8;
            }
        """)
        self.push_selected_btn.clicked.connect(self._on_push_selected)
        header_layout.addWidget(self.push_selected_btn)
        
        # Push All button
        self.push_all_btn = QPushButton("↗ Push All New")
        self.push_all_btn.setObjectName("pushAllBtn")
        self.push_all_btn.setEnabled(False)
        self.push_all_btn.setStyleSheet("""
            QPushButton#pushAllBtn {
                background-color: #0ea5e9;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton#pushAllBtn:hover {
                background-color: #0284c7;
            }
            QPushButton#pushAllBtn:disabled {
                background-color: #94a3b8;
            }
        """)
        self.push_all_btn.clicked.connect(self._on_push_all)
        header_layout.addWidget(self.push_all_btn)
        
        layout.addWidget(header)
        
        # Create model and proxy for sorting
        self.model = DeviceTableModel(self)
        self.proxy_model = IPSortProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        
        # Connect model changes to update selection count
        self.model.itemChanged.connect(self._on_item_changed)
        
        # Table View
        self.table = QTableView()
        self.table.setObjectName("resultsTable")
        self.table.setModel(self.proxy_model)
        
        # Enable sorting
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(DeviceTableModel.COL_IP, Qt.AscendingOrder)
        
        # Configure header - allow resizing
        header_view = self.table.horizontalHeader()
        header_view.setStretchLastSection(True)
        header_view.setSectionsMovable(True)
        header_view.setSectionsClickable(True)
        header_view.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        
        # Set initial column widths
        for col, (_, width) in enumerate(DeviceTableModel.COLUMNS):
            self.table.setColumnWidth(col, width)
        
        # Make vendor column stretch
        header_view.setSectionResizeMode(DeviceTableModel.COL_VENDOR, QHeaderView.Stretch)
        
        # Table settings
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        
        # Row height
        self.table.verticalHeader().setDefaultSectionSize(32)
        
        # Style - uses theme-aware colors
        self.table.setStyleSheet("""
            QTableView#resultsTable {
                border: none;
                background-color: transparent;
                alternate-background-color: rgba(255, 255, 255, 0.02);
                gridline-color: transparent;
            }
            QTableView#resultsTable::item {
                padding: 4px 8px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            }
            QTableView#resultsTable::item:selected {
                background-color: rgba(14, 165, 233, 0.2);
                color: #0ea5e9;
            }
            QHeaderView::section {
                background-color: rgba(255, 255, 255, 0.05);
                color: #94a3b8;
                font-weight: bold;
                padding: 8px;
                border: none;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }
            QHeaderView::section:hover {
                background-color: rgba(255, 255, 255, 0.1);
            }
        """)
        
        # Context menu
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        
        # Selection handling
        self.table.selectionModel().selectionChanged.connect(self._on_selection_changed)
        
        # Double-click handling
        self.table.doubleClicked.connect(self._on_double_click)
        
        layout.addWidget(self.table)
        
        # Footer with stats
        footer = QWidget()
        footer.setObjectName("resultsFooter")
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(16, 8, 16, 8)
        
        self.footer_stats = QLabel("")
        self.footer_stats.setStyleSheet("color: #64748b; font-size: 11px;")
        footer_layout.addWidget(self.footer_stats)
        
        footer_layout.addStretch()
        
        self.scan_time_label = QLabel("")
        self.scan_time_label.setStyleSheet("color: #64748b; font-size: 11px;")
        footer_layout.addWidget(self.scan_time_label)
        
        layout.addWidget(footer)
    
    def add_device(self, device) -> None:
        """Add a device to the table."""
        # Convert ScanResult to dict if needed
        if hasattr(device, '__dataclass_fields__'):
            from dataclasses import asdict
            device_dict = asdict(device)
            if hasattr(device, 'device_type') and device.device_type:
                device_dict['device_type'] = device.device_type.value if hasattr(device.device_type, 'value') else str(device.device_type)
            # Default to new if not set
            if 'is_new' not in device_dict:
                device_dict['is_new'] = True
        else:
            device_dict = device
            # Default to new if not set
            if 'is_new' not in device_dict:
                device_dict['is_new'] = True
        
        self.model.add_device(device_dict)
        self._update_count()
    
    def clear_results(self) -> None:
        """Clear all results."""
        self.model.clear_devices()
        self._update_count()
        self.scan_time_label.setText("")
    
    def _update_count(self) -> None:
        """Update the device count label."""
        devices = self.model.get_devices()
        total = len(devices)
        new_count = sum(1 for d in devices if d.get("is_new", True))
        
        # Count by type
        type_counts = {}
        for d in devices:
            dtype = d.get("device_type", "unknown")
            type_counts[dtype] = type_counts.get(dtype, 0) + 1
        
        # Count with MAC addresses (real discoveries)
        with_mac = sum(1 for d in devices if d.get("mac_address"))
        known_count = total - new_count
        
        if new_count > 0 and known_count > 0:
            self.count_label.setText(f"{total} devices ({new_count} new, {known_count} known)")
        elif new_count > 0:
            self.count_label.setText(f"{total} devices ({new_count} new)")
        elif known_count > 0:
            self.count_label.setText(f"{total} devices (all known)")
        else:
            self.count_label.setText(f"{total} devices")
        
        # Footer stats
        if total > 0:
            stats_parts = []
            if with_mac > 0:
                stats_parts.append(f"{with_mac} with MAC")
            for dtype, count in sorted(type_counts.items()):
                if dtype != "unknown" and count > 0:
                    stats_parts.append(f"{count} {dtype}")
            self.footer_stats.setText(" | ".join(stats_parts) if stats_parts else "")
        else:
            self.footer_stats.setText("")
        
        # Enable push all if there are new devices
        self.push_all_btn.setEnabled(new_count > 0 and self._push_enabled)
        
        # Enable check database if there are devices with MACs
        self.check_db_btn.setEnabled(with_mac > 0 and self._push_enabled)
    
    def set_scan_time(self, seconds: float) -> None:
        """Set the scan time display."""
        if seconds < 60:
            self.scan_time_label.setText(f"Scan time: {seconds:.1f}s")
        else:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            self.scan_time_label.setText(f"Scan time: {minutes}m {secs}s")
    
    def set_push_enabled(self, enabled: bool) -> None:
        """Enable or disable push functionality."""
        self._push_enabled = enabled
        self._update_count()
        self._update_selection_count()
    
    def _on_item_changed(self, item: QStandardItem) -> None:
        """Handle item changes (checkbox state)."""
        if item.column() == DeviceTableModel.COL_CHECK:
            self._update_selection_count()
    
    def _update_selection_count(self) -> None:
        """Update the selection count and button state."""
        checked_count = self._get_checked_count()
        
        if checked_count > 0:
            self.selection_label.setText(f"{checked_count} selected")
            self.push_selected_btn.setEnabled(self._push_enabled)
        else:
            self.selection_label.setText("")
            self.push_selected_btn.setEnabled(False)
    
    def _get_checked_count(self) -> int:
        """Get number of checked rows."""
        count = 0
        for row in range(self.model.rowCount()):
            item = self.model.item(row, DeviceTableModel.COL_CHECK)
            if item and item.checkState() == Qt.Checked:
                count += 1
        return count
    
    def _get_checked_devices(self) -> List[dict]:
        """Get list of checked devices."""
        devices = []
        for row in range(self.model.rowCount()):
            item = self.model.item(row, DeviceTableModel.COL_CHECK)
            if item and item.checkState() == Qt.Checked:
                device = item.data(Qt.UserRole)
                if device:
                    devices.append(device)
        return devices
    
    def select_all(self) -> None:
        """Select all devices."""
        for row in range(self.model.rowCount()):
            item = self.model.item(row, DeviceTableModel.COL_CHECK)
            if item:
                item.setCheckState(Qt.Checked)
        self._update_selection_count()
    
    def select_none(self) -> None:
        """Deselect all devices."""
        for row in range(self.model.rowCount()):
            item = self.model.item(row, DeviceTableModel.COL_CHECK)
            if item:
                item.setCheckState(Qt.Unchecked)
        self._update_selection_count()
    
    def update_device_status(self, mac_address: str, is_new: bool) -> None:
        """
        Update the is_new status for a device by MAC address.
        
        Args:
            mac_address: MAC address of the device to update
            is_new: New status (True=New, False=Known)
        """
        # Normalize MAC for comparison
        def normalize_mac(mac: str) -> str:
            if not mac:
                return ""
            clean = mac.replace(":", "").replace("-", "").replace(".", "").upper()
            return clean
        
        target_mac = normalize_mac(mac_address)
        
        for row in range(self.model.rowCount()):
            check_item = self.model.item(row, DeviceTableModel.COL_CHECK)
            if check_item:
                device = check_item.data(Qt.UserRole)
                if device:
                    device_mac = normalize_mac(device.get("mac_address", ""))
                    if device_mac == target_mac:
                        # Update the device data
                        device["is_new"] = is_new
                        check_item.setData(device, Qt.UserRole)
                        
                        # Update the status cell display
                        status_item = self.model.item(row, DeviceTableModel.COL_STATUS)
                        if status_item:
                            status_item.setText("New" if is_new else "Known")
                            status_item.setForeground(QBrush(QColor("#22c55e" if is_new else "#64748b")))
                        
                        # Also update the internal devices list
                        if row < len(self.model._devices):
                            self.model._devices[row]["is_new"] = is_new
                        break
        
        # Update the count label
        self._update_count()
    
    def get_devices_with_mac(self) -> List[dict]:
        """Get all devices that have MAC addresses (for database checking)."""
        devices = []
        for device in self.model.get_devices():
            if device.get("mac_address"):
                devices.append(device)
        return devices

    def _on_selection_changed(self) -> None:
        """Handle row selection."""
        indexes = self.table.selectionModel().selectedRows()
        if indexes:
            proxy_index = indexes[0]
            source_index = self.proxy_model.mapToSource(proxy_index)
            row = source_index.row()
            device = self.model.get_device(row)
            if device:
                self.device_selected.emit(device)
    
    def _on_double_click(self, index) -> None:
        """Handle double-click on a row."""
        source_index = self.proxy_model.mapToSource(index)
        row = source_index.row()
        device = self.model.get_device(row)
        if device and self._push_enabled:
            self.push_requested.emit(device)
    
    @Slot()
    def _on_push_all(self) -> None:
        """Handle push all button click."""
        self.push_all_requested.emit()
    
    @Slot()
    def _on_push_selected(self) -> None:
        """Handle push selected button click."""
        devices = self._get_checked_devices()
        if devices:
            self.push_selected_requested.emit(devices)
    
    @Slot()
    def _on_check_database(self) -> None:
        """Handle check database button click."""
        self.check_database_requested.emit()
    
    def _show_context_menu(self, position) -> None:
        """Show context menu for table."""
        index = self.table.indexAt(position)
        
        menu = QMenu(self)
        
        # Selection actions (always available)
        select_all = QAction("Select All", self)
        select_all.triggered.connect(self.select_all)
        menu.addAction(select_all)
        
        select_none = QAction("Select None", self)
        select_none.triggered.connect(self.select_none)
        menu.addAction(select_none)
        
        if index.isValid():
            source_index = self.proxy_model.mapToSource(index)
            row = source_index.row()
            device = self.model.get_device(row)
            
            if device:
                menu.addSeparator()
                
                # Copy actions
                copy_ip = QAction("Copy IP Address", self)
                copy_ip.triggered.connect(lambda: self._copy_to_clipboard(device.get("ip_address", "")))
                menu.addAction(copy_ip)
                
                if device.get("mac_address"):
                    copy_mac = QAction("Copy MAC Address", self)
                    copy_mac.triggered.connect(lambda: self._copy_to_clipboard(device.get("mac_address", "")))
                    menu.addAction(copy_mac)
                
                # Push action
                if device.get("is_new", True) and self._push_enabled:
                    menu.addSeparator()
                    push_action = QAction("Push to FreeSDN", self)
                    push_action.triggered.connect(lambda: self.push_requested.emit(device))
                    menu.addAction(push_action)
        
        # Push selected if any checked
        checked = self._get_checked_count()
        if checked > 0 and self._push_enabled:
            menu.addSeparator()
            push_selected = QAction(f"Push {checked} Selected", self)
            push_selected.triggered.connect(self._on_push_selected)
            menu.addAction(push_selected)
        
        menu.exec(self.table.viewport().mapToGlobal(position))
    
    def _copy_to_clipboard(self, text: str) -> None:
        """Copy text to clipboard."""
        from PySide6.QtWidgets import QApplication
        if text:
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
