"""
Inventory Panel — unified view of managed + discovered devices.

Replaces the old Discovered / Managed split. The two-tab UX put the
operator in the position of reconciling two lists ("is 192.168.1.1
in BOTH? do I need to manually link them?"). This panel shows one
truth: every device the system knows about at the selected site,
tagged with its lifecycle status.

Status column values:
- ``Managed``   — row exists in ``core.devices``; canonical inventory
- ``Discovered``— row exists in ``devices.discovered_hosts`` only
- ``Ignored``   — discovered host the operator dismissed

The row source determines what actions are available:
- Discovered → ``Adopt`` button promotes it into Managed.
- Managed    → ``Open`` button surfaces the device detail (future).
- Both       → MAC match collapses them into a single row tagged
  Managed (we never show the discovered row when a managed peer
  exists, that was the whole confusion).
"""

import logging
from datetime import datetime
from typing import List, Optional, Set

from freesdn_agent.ui.widgets.inventory_data import (
    InventoryRow,
    merge_into_inventory,
    normalize_mac,
    format_last_seen,
)

from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableView,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
    QTimer,
    Signal,
    Slot,
)
from PySide6.QtGui import QBrush, QColor

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Table model
# ---------------------------------------------------------------------------

class InventoryModel(QAbstractTableModel):
    HEADERS = [
        "Status", "Name", "IP Address", "MAC Address",
        "Vendor", "Type", "Last Seen",
    ]

    COL_STATUS = 0
    COL_NAME = 1
    COL_IP = 2
    COL_MAC = 3
    COL_VENDOR = 4
    COL_TYPE = 5
    COL_LAST_SEEN = 6

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[InventoryRow] = []

    def set_rows(self, rows: List[InventoryRow]) -> None:
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def get_row(self, source_row: int) -> Optional[InventoryRow]:
        if 0 <= source_row < len(self._rows):
            return self._rows[source_row]
        return None

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == self.COL_STATUS:
                return row.status
            if col == self.COL_NAME:
                # For a Known host, surface what FreeSDN knows it as
                # right in the name cell ("← MikroTik gateway").
                if row.status == "Known" and row.known_detail:
                    return f"{row.name}  ←  {row.known_detail}"
                return row.name
            if col == self.COL_IP:
                return row.ip or "—"
            if col == self.COL_MAC:
                return row.mac or "—"
            if col == self.COL_VENDOR:
                return row.vendor
            if col == self.COL_TYPE:
                return row.device_type.replace("_", " ").title()
            if col == self.COL_LAST_SEEN:
                return row.last_seen

        if role == Qt.ToolTipRole and row.status == "Known" and row.known_detail:
            return f"FreeSDN already knows this host: {row.known_detail}"

        if role == Qt.ForegroundRole and col == self.COL_STATUS:
            colour = {
                "Managed": "#22c55e",     # emerald — adopted into inventory
                "Known": "#a855e7",       # violet — known via controller/sync
                "Discovered": "#0ea5e9",  # sky — genuinely new
                "Ignored": "#64748b",     # slate
            }.get(row.status, "#94a3b8")
            return QBrush(QColor(colour))

        if role == Qt.UserRole:
            return row

        return None


# ---------------------------------------------------------------------------
# Panel widget
# ---------------------------------------------------------------------------

class InventoryPanel(QFrame):
    """Unified Managed + Discovered inventory view.

    Emits ``adopt_requested(host_dict)`` when the operator clicks Adopt
    on a Discovered row. The main window wires that to the same code
    path the legacy DiscoveryPanel used.
    """

    adopt_requested = Signal(dict)
    refresh_requested = Signal()
    row_selected = Signal(InventoryRow)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._setup_ui()
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(
            lambda: self.refresh_requested.emit(),
        )

    def _setup_ui(self) -> None:
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setObjectName("inventoryPanel")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QWidget()
        header.setObjectName("panelHeader")
        hbar = QHBoxLayout(header)
        hbar.setContentsMargins(12, 8, 12, 8)

        title = QLabel("Inventory")
        title.setStyleSheet("font-size: 13px; font-weight: bold;")
        hbar.addWidget(title)

        self.count_label = QLabel("0 devices")
        self.count_label.setStyleSheet("color: #64748b; font-size: 12px; margin-left: 8px;")
        hbar.addWidget(self.count_label)

        hbar.addStretch()

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter…")
        self.filter_input.setFixedWidth(180)
        self.filter_input.textChanged.connect(self._on_filter_changed)
        hbar.addWidget(self.filter_input)

        self.status_combo = QComboBox()
        self.status_combo.addItems(["All", "Managed", "Known", "Discovered", "Ignored"])
        self.status_combo.currentTextChanged.connect(self._on_status_changed)
        hbar.addWidget(self.status_combo)

        self.adopt_btn = QPushButton("Adopt selected")
        self.adopt_btn.setEnabled(False)
        self.adopt_btn.clicked.connect(self._on_adopt_clicked)
        hbar.addWidget(self.adopt_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(
            lambda: self.refresh_requested.emit(),
        )
        hbar.addWidget(self.refresh_btn)

        layout.addWidget(header)

        # Table
        self.model = InventoryModel(self)
        self.proxy_model = QSortFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        self.proxy_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.proxy_model.setFilterKeyColumn(-1)

        self.table = QTableView()
        self.table.setObjectName("inventoryTable")
        self.table.setModel(self.proxy_model)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(InventoryModel.COL_IP, Qt.AscendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)

        h_header = self.table.horizontalHeader()
        h_header.setStretchLastSection(True)
        for col, width in [
            (InventoryModel.COL_STATUS, 90),
            (InventoryModel.COL_NAME, 180),
            (InventoryModel.COL_IP, 120),
            (InventoryModel.COL_MAC, 140),
            (InventoryModel.COL_VENDOR, 160),
            (InventoryModel.COL_TYPE, 100),
        ]:
            self.table.setColumnWidth(col, width)
        h_header.setSectionResizeMode(InventoryModel.COL_NAME, QHeaderView.Stretch)

        self.table.clicked.connect(self._on_row_clicked)
        layout.addWidget(self.table)

        # Status bar
        status_bar = QWidget()
        sbar = QHBoxLayout(status_bar)
        sbar.setContentsMargins(12, 6, 12, 6)
        self.status_label = QLabel("Not connected")
        self.status_label.setStyleSheet("color: #64748b; font-size: 11px;")
        sbar.addWidget(self.status_label)
        sbar.addStretch()
        self.updated_label = QLabel("")
        self.updated_label.setStyleSheet("color: #64748b; font-size: 11px;")
        sbar.addWidget(self.updated_label)
        layout.addWidget(status_bar)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_inventory(
        self,
        managed: List[dict],
        discovered: List[dict],
    ) -> None:
        rows = merge_into_inventory(managed, discovered)
        self.model.set_rows(rows)
        self._update_count()
        self.updated_label.setText(
            f"Updated: {datetime.now().strftime('%H:%M:%S')}",
        )

    def set_status(self, message: str) -> None:
        self.status_label.setText(message)

    def start_auto_refresh(self, interval_seconds: int = 60) -> None:
        self._refresh_timer.start(interval_seconds * 1000)

    def stop_auto_refresh(self) -> None:
        self._refresh_timer.stop()

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    @Slot(str)
    def _on_filter_changed(self, text: str) -> None:
        self.proxy_model.setFilterFixedString(text)
        self._update_count()

    @Slot(str)
    def _on_status_changed(self, status: str) -> None:
        if status == "All":
            self.proxy_model.setFilterKeyColumn(-1)
            self.proxy_model.setFilterFixedString(self.filter_input.text())
        else:
            # Filter on the status column with an exact match
            self.proxy_model.setFilterKeyColumn(InventoryModel.COL_STATUS)
            self.proxy_model.setFilterFixedString(status)
        self._update_count()

    def _on_row_clicked(self, index: QModelIndex) -> None:
        source_index = self.proxy_model.mapToSource(index)
        row = self.model.get_row(source_index.row())
        if row is None:
            return
        self.adopt_btn.setEnabled(row.status == "Discovered")
        self.row_selected.emit(row)

    def _on_adopt_clicked(self) -> None:
        index = self.table.currentIndex()
        if not index.isValid():
            return
        source_index = self.proxy_model.mapToSource(index)
        row = self.model.get_row(source_index.row())
        if row is None or row.status != "Discovered":
            return
        self.adopt_requested.emit(row.raw)

    def _update_count(self) -> None:
        visible = self.proxy_model.rowCount()
        total = self.model.rowCount()
        all_rows = [self.model.get_row(i) for i in range(total)]
        managed = sum(1 for r in all_rows if r and r.status == "Managed")
        known = sum(1 for r in all_rows if r and r.status == "Known")
        discovered = sum(1 for r in all_rows if r and r.status == "Discovered")
        parts = f"{managed} managed, {known} known, {discovered} new"
        if visible < total:
            self.count_label.setText(f"{visible} of {total} ({parts})")
        else:
            self.count_label.setText(f"{total} devices ({parts})")
