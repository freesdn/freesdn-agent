"""Adoption review dialog.

Drives the adopt flow from the Discovered tab. Shows a table with one
row per selected host, each pre-filled with the auto-matched driver
(or "auto-pick" if the user defers it to the backend). The user can
override per row before hitting Adopt.

After submit we show a result section in-place (succeeded / failed /
skipped per IP) so the operator doesn't lose context to another dialog.
"""

from __future__ import annotations

import logging
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

logger = logging.getLogger(__name__)


# Sentinel used in the driver column when the user wants the backend to
# auto-pick. We send driver_id=None to /adopt/bulk in this case.
AUTO_DRIVER_LABEL = "Auto (server picks)"
AUTO_DRIVER_VALUE = ""  # empty string → None on submit


class AdoptDialog(QDialog):
    """Modal review dialog for bulk adoption.

    Signals:
        adoption_finished(dict): emitted after the bulk POST returns. The
            payload is the BulkAdoptResponse dict — caller uses it to
            refresh Discovered + Managed tabs.
    """

    adoption_finished = Signal(dict)

    def __init__(
        self,
        devices: list[dict],
        drivers: list[dict],
        site_id: str,
        site_name: str,
        client,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self._devices = devices
        self._drivers = drivers
        self._site_id = site_id
        self._site_name = site_name
        self._client = client
        self._result: dict | None = None

        # Pull credentials so the operator can attach one at adopt time
        # (matches the web UI). Best-effort — if the call fails we just
        # show "No credential" and devices adopt credential-less (they
        # still reach ONLINE via the agent-heartbeat liveness path).
        self._credentials: list[dict] = []
        try:
            self._credentials = client.get_credentials(site_id) or []
        except Exception:
            logger.debug("Could not load credentials for adopt dialog", exc_info=True)

        self.setWindowTitle("Adopt Discovered Devices")
        self.setModal(True)
        self.resize(820, 560)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # Header
        header = QLabel(
            f"<b>Adopt {len(self._devices)} device(s)</b><br>"
            f"<span style='color: #64748b;'>Site: {self._site_name}</span>"
        )
        header.setStyleSheet("font-size: 13px;")
        layout.addWidget(header)

        # Driver-picker table
        self.table = QTableWidget(len(self._devices), 4, self)
        self.table.setHorizontalHeaderLabels(["IP", "MAC", "Vendor", "Driver"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 120)
        self.table.setColumnWidth(1, 160)
        self.table.setColumnWidth(2, 160)

        for row, dev in enumerate(self._devices):
            self.table.setItem(
                row, 0, QTableWidgetItem(dev.get("ip_address", ""))
            )
            self.table.setItem(
                row, 1, QTableWidgetItem(dev.get("mac_address") or "—")
            )
            self.table.setItem(
                row, 2, QTableWidgetItem(dev.get("vendor") or "Unknown")
            )
            combo = self._make_driver_combo(dev)
            self.table.setCellWidget(row, 3, combo)

        layout.addWidget(self.table, stretch=1)

        # Result placeholder — populated after submit
        self.result_label = QLabel("")
        self.result_label.setVisible(False)
        self.result_label.setWordWrap(True)
        self.result_label.setStyleSheet(
            "padding: 8px; border-radius: 4px; background: #f1f5f9;"
        )
        layout.addWidget(self.result_label)

        # Credential picker — applied to all devices in this batch.
        # Per-row would clutter the table; a batch credential is the
        # common case (a site usually shares one admin credential).
        cred_row = QHBoxLayout()
        cred_label = QLabel("Credential:")
        cred_row.addWidget(cred_label)
        self.cred_combo = QComboBox()
        self.cred_combo.addItem("No credential (track only)", "")
        for c in self._credentials:
            label = c.get("name") or "Unnamed"
            if c.get("username"):
                label = f"{label}  ({c['username']})"
            self.cred_combo.addItem(label, str(c.get("id")))
        cred_row.addWidget(self.cred_combo, stretch=1)
        if not self._credentials:
            hint = QLabel("No stored credentials — create one in the web UI to enable adapter management.")
            hint.setObjectName("detailsLabel")
            hint.setWordWrap(True)
            cred_row.addWidget(hint, stretch=2)
        layout.addLayout(cred_row)

        # Footer buttons
        footer = QHBoxLayout()
        self.set_all_label = QLabel("Set all to:")
        footer.addWidget(self.set_all_label)
        self.set_all_combo = self._build_driver_combo()
        footer.addWidget(self.set_all_combo)
        self.apply_all_btn = QPushButton("Apply to all")
        self.apply_all_btn.clicked.connect(self._on_apply_to_all)
        footer.addWidget(self.apply_all_btn)
        footer.addStretch()

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.Cancel
        )
        self.adopt_btn = self.buttons.addButton(
            "Adopt", QDialogButtonBox.AcceptRole
        )
        self.adopt_btn.setStyleSheet(
            "padding: 6px 16px; background: #0ea5e9; color: white; "
            "border: none; border-radius: 4px; font-weight: 600;"
        )
        self.buttons.rejected.connect(self.reject)
        self.adopt_btn.clicked.connect(self._on_adopt)
        footer.addWidget(self.buttons)

        layout.addLayout(footer)

    def _build_driver_combo(self) -> QComboBox:
        combo = QComboBox()
        combo.addItem(AUTO_DRIVER_LABEL, AUTO_DRIVER_VALUE)
        for d in self._drivers:
            combo.addItem(f"{d.get('name')} ({d.get('id')})", d.get("id"))
        return combo

    def _make_driver_combo(self, device: dict) -> QComboBox:
        """Pre-select the recommended driver if backend tagged one,
        otherwise stay on Auto so the server picks at submit time.
        Mac vendor isn't a perfect signal, so Auto is the safe default."""
        combo = self._build_driver_combo()
        # Backend may have set `recommended_driver` on the host row
        rec = device.get("recommended_driver")
        if rec:
            idx = combo.findData(rec)
            if idx >= 0:
                combo.setCurrentIndex(idx)
        return combo

    def _on_apply_to_all(self) -> None:
        driver_id = self.set_all_combo.currentData()
        for row in range(self.table.rowCount()):
            combo: QComboBox = self.table.cellWidget(row, 3)
            idx = combo.findData(driver_id)
            if idx >= 0:
                combo.setCurrentIndex(idx)

    def _build_payload(self) -> list[dict]:
        credential_id = self.cred_combo.currentData() or None
        payload: list[dict] = []
        for row, dev in enumerate(self._devices):
            combo: QComboBox = self.table.cellWidget(row, 3)
            driver_id = combo.currentData() or None  # "" → None → server auto
            entry: dict = {
                "ip_address": dev.get("ip_address"),
                "name": dev.get("hostname")
                or f"discovered-{dev.get('ip_address', 'unknown')}",
                "site_id": self._site_id,
                "device_type": dev.get("device_type") or "other",
            }
            if dev.get("mac_address"):
                entry["mac_address"] = dev["mac_address"]
            if driver_id:
                entry["driver_id"] = driver_id
            if credential_id:
                entry["credential_id"] = credential_id
            payload.append(entry)
        return payload

    def _on_adopt(self) -> None:
        payload = self._build_payload()
        self.adopt_btn.setEnabled(False)
        self.adopt_btn.setText("Adopting…")
        try:
            self._result = self._client.bulk_adopt_devices(payload)
        except Exception as exc:
            logger.exception("bulk_adopt_devices failed")
            self._result = {
                "total": len(payload),
                "succeeded": 0,
                "failed": len(payload),
                "results": [
                    {"ip_address": p["ip_address"], "status": "failed", "error": str(exc)}
                    for p in payload
                ],
            }
        self._render_result()
        self.adoption_finished.emit(self._result)
        self.adopt_btn.setText("Close")
        self.adopt_btn.setEnabled(True)
        self.adopt_btn.clicked.disconnect()
        self.adopt_btn.clicked.connect(self.accept)
        self.buttons.button(QDialogButtonBox.Cancel).setVisible(False)

    def _render_result(self) -> None:
        if not self._result:
            return
        total = self._result.get("total", 0)
        ok = self._result.get("succeeded", 0)
        bad = self._result.get("failed", 0)
        msg = f"<b>Adoption complete</b> — {ok}/{total} adopted, {bad} failed."
        # Per-row status into the table (replace driver col with status)
        status_by_ip = {r.get("ip_address"): r for r in self._result.get("results", [])}
        for row in range(self.table.rowCount()):
            ip = self.table.item(row, 0).text()
            res = status_by_ip.get(ip)
            if not res:
                continue
            status = res.get("status", "unknown")
            err = res.get("error", "")
            cell_text = (
                f"✓ adopted ({res.get('driver_id', '')})"
                if status == "adopted"
                else f"✗ {err or status}"
            )
            item = QTableWidgetItem(cell_text)
            # Color cue
            if status == "adopted":
                item.setForeground(Qt.darkGreen)
            else:
                item.setForeground(Qt.red)
            self.table.removeCellWidget(row, 3)
            self.table.setItem(row, 3, item)
        self.result_label.setText(msg)
        self.result_label.setVisible(True)

    def get_result(self) -> dict | None:
        return self._result
