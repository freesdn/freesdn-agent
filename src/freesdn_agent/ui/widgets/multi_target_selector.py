"""
Multi-target selector widget — responsive design.

Replaces the single-select ``NetworkSelector`` with a layout that
adapts from tablet to wide desktop:

- At narrow widths (<900 px): interfaces / targets / pre-flight stack
  vertically with proper minimums so nothing disappears.
- At wide widths (>=900 px): interfaces (left) + targets (right) sit
  side-by-side so the user sees both at once without scrolling.

Both modes use:

- ``QGroupBox`` containers so sections are visually separated.
- ``QSizePolicy.Expanding`` on the list + text widgets so they grow
  with available space, but with ``setMinimumHeight`` floors so they
  never collapse to invisible (the v1 bug — fixed maximums without
  minimums let the parent layout squish them to 0 px).
- A bold pre-flight status label that's always visible.

Public collector API unchanged:
- ``get_selected_interfaces() -> list[str]``
- ``get_targets() -> list[str]``
- ``get_excludes() -> list[str]``
- ``has_errors() -> list[str]``
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Optional

from PySide6.QtCore import Qt, QSize, Signal
from PySide6.QtGui import QFont, QResizeEvent
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

logger = logging.getLogger(__name__)


# Breakpoint between stacked (narrow) and side-by-side (wide) layout.
_WIDE_BREAKPOINT_PX = 900


# ---------------------------------------------------------------------------
# Target spec parsing
# ---------------------------------------------------------------------------

def parse_target_spec(text: str) -> tuple[list[str], list[str], list[str]]:
    """Parse the free-form Targets textbox into (includes, excludes, errors).

    Each non-empty, non-comment line is one entry. Entries prefixed with
    ``!`` or ``-`` are excludes; everything else is an include. Accepted
    shapes for both:

      192.168.1.0/24          (CIDR)
      192.168.1.105             (single IP)
      192.168.1.10-50         (range, last-octet shorthand)
      192.168.1.10-192.168.1.150 (range, full)
      # comment

    Returns three lists. ``errors`` carries per-line error messages so
    the caller can surface them to the user without aborting the whole
    spec.
    """
    includes: list[str] = []
    excludes: list[str] = []
    errors: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        is_exclude = False
        if line.startswith(("!", "-")) and not _looks_like_ip_range(line):
            is_exclude = True
            line = line[1:].strip()

        if not line:
            continue

        try:
            _validate_target(line)
        except ValueError as exc:
            errors.append(f"{raw_line!r}: {exc}")
            continue

        (excludes if is_exclude else includes).append(line)

    return includes, excludes, errors


def _looks_like_ip_range(s: str) -> bool:
    if not s.startswith("-"):
        return False
    rest = s[1:]
    return "-" in rest


def _validate_target(spec: str) -> str:
    if "-" in spec and "/" not in spec:
        left, _, right = spec.partition("-")
        try:
            left_ip = ipaddress.ip_address(left.strip())
        except ValueError as exc:
            raise ValueError(f"bad range start: {exc}") from exc

        right = right.strip()
        if "." not in right and ":" not in right:
            try:
                last_octet = int(right)
            except ValueError as exc:
                raise ValueError(f"bad range end: {exc}") from exc
            if not (0 <= last_octet <= 255):
                raise ValueError("octet out of range")
        else:
            try:
                ipaddress.ip_address(right)
            except ValueError as exc:
                raise ValueError(f"bad range end: {exc}") from exc
        return spec

    try:
        net = ipaddress.ip_network(spec, strict=False)
    except ValueError as exc:
        raise ValueError(f"not a CIDR or IP: {exc}") from exc

    if net.is_multicast or net.is_reserved:
        raise ValueError(f"multicast/reserved range not allowed: {net}")
    return str(net)


def estimate_host_count(targets: list[str]) -> int:
    total = 0
    for spec in targets:
        try:
            if "-" in spec and "/" not in spec:
                left, _, right = spec.partition("-")
                left_ip = ipaddress.ip_address(left.strip())
                right = right.strip()
                if "." not in right and ":" not in right:
                    end_octet = int(right)
                    base = int(left_ip) & ~0xFF
                    right_int = base | end_octet
                else:
                    right_int = int(ipaddress.ip_address(right))
                total += max(0, right_int - int(left_ip) + 1)
            else:
                total += ipaddress.ip_network(spec, strict=False).num_addresses
        except Exception:
            total += 1
    return total


# ---------------------------------------------------------------------------
# Routing table introspection
# ---------------------------------------------------------------------------

def _list_routed_destinations() -> list[str]:
    """Return non-default routes' destination CIDRs (best-effort).

    Default routes (0/0) and /32 host routes are excluded.
    """
    cidrs: set[str] = set()
    try:
        import netifaces

        for iface_name in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(iface_name).get(netifaces.AF_INET, [])
                for addr in addrs:
                    ip = addr.get("addr", "")
                    mask = addr.get("netmask", "")
                    if not ip or not mask:
                        continue
                    if ip.startswith("127.") or ip.startswith("169.254."):
                        continue
                    try:
                        prefix = sum(bin(int(o)).count("1") for o in mask.split("."))
                    except Exception:
                        continue
                    if prefix == 32:
                        continue
                    try:
                        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                    except Exception:
                        continue
                    cidrs.add(str(net))
            except Exception:
                continue
    except ImportError:
        logger.debug("netifaces not available for route detection")

    return sorted(cidrs)


# ---------------------------------------------------------------------------
# Widget
# ---------------------------------------------------------------------------

_OVERLAY_HINTS = re.compile(
    r"(tailscale|wireguard|tap|tun|docker|veth|br-|hyper-v|wsl|vmnet|vpn)",
    re.IGNORECASE,
)


class MultiTargetSelector(QFrame):
    """Responsive multi-select interface list + free-form targets.

    Adapts layout at the ``_WIDE_BREAKPOINT_PX`` threshold so it works
    cleanly on tablets (stacked) and wide desktops (side-by-side).
    """

    targets_changed = Signal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._interfaces: list[dict] = []
        self._is_wide: bool | None = None  # tracks current layout mode
        self._setup_ui()
        self._refresh_interfaces()

    # -----------------------------------------------------------------
    # UI construction
    # -----------------------------------------------------------------

    def _setup_ui(self) -> None:
        """Build sub-widgets but DON'T add them to a layout yet.

        ``_apply_layout()`` (called from resizeEvent) decides whether
        the layout is stacked or side-by-side based on current width.
        """
        # Frame style — subtle outer border so the section is visually
        # contained even when embedded in a busy parent.
        self.setFrameShape(QFrame.NoFrame)

        # --- Interfaces group ---
        self._iface_group = QGroupBox("Interfaces — pick one or more")
        self._iface_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        iface_layout = QVBoxLayout(self._iface_group)
        iface_layout.setContentsMargins(12, 18, 12, 12)
        iface_layout.setSpacing(8)

        self._iface_list = QListWidget()
        self._iface_list.setSelectionMode(QListWidget.NoSelection)
        # Minimum height = 5 items × ~28px each; expands beyond that as
        # the window grows. Setting a real minimum is what was missing
        # in v1 — the parent layout squished the list to 0.
        self._iface_list.setMinimumHeight(150)
        self._iface_list.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._iface_list.itemChanged.connect(self._on_target_change)
        iface_layout.addWidget(self._iface_list, stretch=1)

        # Auto-detect button row
        auto_row = QHBoxLayout()
        self._autodetect_btn = QPushButton("Auto-detect from routes")
        self._autodetect_btn.setToolTip(
            "Add every non-/32 directly-attached and routed-to network "
            "to the Targets list."
        )
        self._autodetect_btn.clicked.connect(self._on_autodetect)
        auto_row.addWidget(self._autodetect_btn)
        auto_row.addStretch()
        iface_layout.addLayout(auto_row)

        # --- Targets group ---
        self._targets_group = QGroupBox("Targets — CIDRs, single IPs, ranges (leave empty to scan checked interfaces)")
        self._targets_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        tgt_layout = QVBoxLayout(self._targets_group)
        tgt_layout.setContentsMargins(12, 18, 12, 12)
        tgt_layout.setSpacing(8)

        hint = QLabel(
            "Prefix with <code>!</code> to exclude. "
            "Use <code>192.168.1.10-50</code> for ranges, <code>#</code> for comments."
        )
        hint.setTextFormat(Qt.RichText)
        hint.setStyleSheet("color: #6b7280;")
        hint.setWordWrap(True)
        tgt_layout.addWidget(hint)

        self._targets_text = QPlainTextEdit()
        self._targets_text.setPlaceholderText(
            "192.168.1.0/24\n"
            "10.0.0.0/24\n"
            "10.10.10.10-50      # range\n"
            "!10.10.10.30        # exclude this host\n"
            "# lines starting with # are ignored"
        )
        # Same min/expanding policy — the v1 bug was setting only a
        # maximum which let the parent collapse it.
        self._targets_text.setMinimumHeight(140)
        self._targets_text.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # Monospace font so CIDRs line up. 11pt looks right on Win+Mac+Linux.
        mono = QFont("Consolas, Monaco, Menlo, monospace", 10)
        self._targets_text.setFont(mono)
        self._targets_text.textChanged.connect(self._on_target_change)
        tgt_layout.addWidget(self._targets_text, stretch=1)

        # --- Pre-flight status (always full-width below both groups) ---
        self._preflight = QLabel("")
        self._preflight.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._preflight.setMinimumHeight(28)
        self._preflight.setStyleSheet(
            "QLabel { "
            "  padding: 6px 12px; "
            "  background-color: rgba(59, 130, 246, 0.08); "
            "  border-left: 3px solid #3b82f6; "
            "  border-radius: 3px; "
            "  font-weight: 500; "
            "}"
        )
        self._preflight.setWordWrap(True)

        # --- Outer layout (set in _apply_layout, mode-dependent) ---
        self._outer = QVBoxLayout(self)
        self._outer.setContentsMargins(0, 0, 0, 0)
        self._outer.setSpacing(10)

        # Start in stacked mode; resizeEvent flips to side-by-side
        # when the widget gets a real width.
        self._apply_layout(force_wide=False)

    def _apply_layout(self, *, force_wide: bool | None = None) -> None:
        """Switch between stacked (narrow) and side-by-side (wide) layout.

        Called by resizeEvent + once during _setup_ui. Idempotent: only
        rebuilds when crossing the breakpoint.
        """
        if force_wide is None:
            wide = self.width() >= _WIDE_BREAKPOINT_PX
        else:
            wide = force_wide

        if wide == self._is_wide:
            return  # no change

        # Clear the outer layout — but detach widgets without deleting
        # them so we can re-parent into the new layout.
        for i in reversed(range(self._outer.count())):
            item = self._outer.takeAt(i)
            w = item.widget() if item else None
            if w is not None:
                w.setParent(None)
            # Sub-layouts handled implicitly when their owning widget
            # is reparented.

        # Detach the two groups from their previous parent (a prior
        # QSplitter or QHBoxLayout) before adding to the new container.
        self._iface_group.setParent(None)
        self._targets_group.setParent(None)
        self._preflight.setParent(None)

        if wide:
            # Side-by-side via a splitter so the user can drag the
            # divider — interfaces vs targets — to taste.
            split = QSplitter(Qt.Horizontal)
            split.setHandleWidth(6)
            split.setChildrenCollapsible(False)
            split.addWidget(self._iface_group)
            split.addWidget(self._targets_group)
            split.setStretchFactor(0, 1)
            split.setStretchFactor(1, 1)
            split.setSizes([400, 400])  # default 50/50
            self._outer.addWidget(split, stretch=1)
        else:
            # Stacked vertically. Each group expands as the parent
            # gives it room.
            self._outer.addWidget(self._iface_group, stretch=1)
            self._outer.addWidget(self._targets_group, stretch=1)

        # Pre-flight always at the bottom, full width
        self._outer.addWidget(self._preflight)

        self._is_wide = wide

    def resizeEvent(self, event: QResizeEvent) -> None:  # noqa: N802
        super().resizeEvent(event)
        # Cheap: _apply_layout is no-op unless we crossed the breakpoint.
        self._apply_layout()

    def sizeHint(self) -> QSize:  # noqa: N802
        # Give the parent a hint that we want a reasonable amount of
        # room — otherwise QVBoxLayouts above us (e.g. inside ScanPanel)
        # will allocate the minimum.
        return QSize(700, 380)

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        # The floor: a tablet/portrait window can still show both
        # sections + the preflight strip without overlap.
        return QSize(420, 340)

    # -----------------------------------------------------------------
    # Interface refresh
    # -----------------------------------------------------------------

    def _refresh_interfaces(self) -> None:
        from freesdn_agent.ui.widgets.network_selector import get_network_interfaces

        self._iface_list.clear()
        self._interfaces = get_network_interfaces()

        for iface in self._interfaces:
            name = iface["name"]
            ip = iface["ip"]
            network = iface["network"]
            cidr_suffix = network.split("/")[-1] if "/" in network else "?"
            is_single_host = cidr_suffix == "32"
            is_overlay = bool(_OVERLAY_HINTS.search(name))

            # Two-line item: friendlier name on top, details below.
            warn = ""
            if is_single_host:
                warn = "   ⚠ single-host (won't find peers)"
            elif is_overlay:
                warn = "   ⚠ overlay interface"

            label = f"{name}\n    {ip}   /{cidr_suffix}{warn}"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, iface)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(
                Qt.Unchecked if (is_single_host or is_overlay) else Qt.Checked
            )
            self._iface_list.addItem(item)

        self._update_preflight()

    # -----------------------------------------------------------------
    # Slots
    # -----------------------------------------------------------------

    def _on_target_change(self) -> None:
        self._update_preflight()
        self.targets_changed.emit()

    def _on_autodetect(self) -> None:
        existing = self._targets_text.toPlainText().strip()
        existing_lines = {
            l.strip() for l in existing.splitlines()
            if l.strip() and not l.startswith("#")
        }
        for cidr in _list_routed_destinations():
            if cidr not in existing_lines:
                if existing and not existing.endswith("\n"):
                    existing += "\n"
                existing += cidr + "\n"
        self._targets_text.setPlainText(existing)
        self._update_preflight()

    def _update_preflight(self) -> None:
        targets, excludes = self._collect_targets_and_excludes()
        if not targets:
            iface_nets = [
                iface["network"]
                for iface in self._checked_interfaces()
                if not iface["network"].endswith("/32")
            ]
            count = estimate_host_count(iface_nets) if iface_nets else 0
            if iface_nets:
                self._preflight.setText(
                    f"<b>Pre-flight:</b> ~{count:,} hosts across {len(iface_nets)} "
                    f"checked interface{'s' if len(iface_nets) != 1 else ''}."
                )
            else:
                self._preflight.setText(
                    "<b>Pre-flight:</b> nothing to scan — check an interface or enter a target."
                )
            return
        count = estimate_host_count(targets)
        excl_note = f" ({len(excludes)} excluded)" if excludes else ""
        self._preflight.setText(
            f"<b>Pre-flight:</b> ~{count:,} hosts across {len(targets)} "
            f"target{'s' if len(targets) != 1 else ''}{excl_note}."
        )

    # -----------------------------------------------------------------
    # Helpers + public API
    # -----------------------------------------------------------------

    def _checked_interfaces(self) -> list[dict]:
        out: list[dict] = []
        for i in range(self._iface_list.count()):
            item = self._iface_list.item(i)
            if item.checkState() == Qt.Checked:
                out.append(item.data(Qt.UserRole))
        return out

    def _collect_targets_and_excludes(self) -> tuple[list[str], list[str]]:
        includes, excludes, errors = parse_target_spec(self._targets_text.toPlainText())
        if errors:
            logger.debug("Target spec errors: %s", errors)
        return includes, excludes

    def get_selected_interfaces(self) -> list[str]:
        return [iface["name"] for iface in self._checked_interfaces()]

    def get_targets(self) -> list[str]:
        includes, excludes = self._collect_targets_and_excludes()
        if includes:
            return includes + [f"!{e}" for e in excludes]
        return [
            iface["network"]
            for iface in self._checked_interfaces()
            if not iface["network"].endswith("/32")
        ]

    def get_excludes(self) -> list[str]:
        _, excludes = self._collect_targets_and_excludes()
        return excludes

    def has_errors(self) -> list[str]:
        _, _, errors = parse_target_spec(self._targets_text.toPlainText())
        return errors
