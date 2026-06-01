"""
Progress Widget.

Displays scan progress with progress bar and status text.
"""

import logging
import time
from typing import Optional

from PySide6.QtWidgets import (
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QProgressBar,
    QFrame,
)
from PySide6.QtCore import Qt, Signal, Slot, QTimer

logger = logging.getLogger(__name__)


class ProgressWidget(QFrame):
    """Widget showing scan progress."""
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        
        self._devices_found = 0
        self._scan_start_time: Optional[float] = None
        self._is_scanning = False
        
        # Timer for updating elapsed time
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update_elapsed_time)
        
        self._setup_ui()
        self.reset()
    
    def _setup_ui(self) -> None:
        """Setup the widget UI."""
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setObjectName("progressPanel")
        self.setFixedHeight(70)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("scanProgress")
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(8)
        layout.addWidget(self.progress_bar)
        
        # Status row
        status_layout = QHBoxLayout()
        status_layout.setSpacing(16)
        
        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("progressStatus")
        status_layout.addWidget(self.status_label)
        
        status_layout.addStretch()
        
        self.stats_label = QLabel("")
        self.stats_label.setObjectName("progressStats")
        self.stats_label.setStyleSheet("color: #94a3b8;")
        status_layout.addWidget(self.stats_label)
        
        self.time_label = QLabel("")
        self.time_label.setObjectName("progressTime")
        self.time_label.setStyleSheet("color: #94a3b8;")
        status_layout.addWidget(self.time_label)
        
        layout.addLayout(status_layout)
    
    def reset(self) -> None:
        """Reset progress to initial state."""
        self._timer.stop()
        self._devices_found = 0
        self._scan_start_time = None
        self._is_scanning = False
        
        self.progress_bar.setValue(0)
        self.status_label.setText("Ready")
        self.status_label.setStyleSheet("")  # Reset style
        self.stats_label.setText("")
        self.time_label.setText("")
    
    def set_scanning(self, scanning: bool) -> None:
        """Set scanning state."""
        self._is_scanning = scanning
        if scanning:
            self._devices_found = 0
            self._scan_start_time = time.time()
            self.set_indeterminate("Initializing scan...")
            self._timer.start(1000)  # Update every second
        else:
            self._timer.stop()
            self.set_determinate()
    
    def set_status(self, status: str) -> None:
        """Update status text."""
        self.status_label.setText(status)
        self.status_label.setStyleSheet("")  # Reset style
    
    def increment_devices_found(self) -> None:
        """Increment the devices found counter."""
        self._devices_found += 1
        self.stats_label.setText(f"Found: {self._devices_found}")
    
    def update_progress(self, progress) -> None:
        """Update from ScanProgress object."""
        if hasattr(progress, 'current') and hasattr(progress, 'total') and progress.total > 0:
            pct = int((progress.current / progress.total) * 100)
            self.set_determinate()
            self.progress_bar.setValue(pct)
        
        if hasattr(progress, 'phase') and hasattr(progress, 'current_target'):
            self.status_label.setText(f"{progress.phase}: {progress.current_target}")
    
    def _update_elapsed_time(self) -> None:
        """Update the elapsed time display."""
        if self._scan_start_time:
            elapsed = int(time.time() - self._scan_start_time)
            mins, secs = divmod(elapsed, 60)
            if mins > 0:
                self.time_label.setText(f"{mins}m {secs}s")
            else:
                self.time_label.setText(f"{secs}s")
    
    def set_progress(
        self,
        value: int,
        status: str = "",
        found: int = 0,
        new: int = 0,
        elapsed: str = ""
    ) -> None:
        """
        Update progress display.
        
        Args:
            value: Progress percentage (0-100)
            status: Status text (e.g., "ARP Scan: 192.168.1.0/24")
            found: Total devices found
            new: New devices found
            elapsed: Elapsed time string
        """
        self.progress_bar.setValue(value)
        
        if status:
            self.status_label.setText(status)
        
        if found > 0:
            if new > 0 and new != found:
                self.stats_label.setText(f"Found: {found} │ New: {new}")
            else:
                self.stats_label.setText(f"Found: {found}")
        else:
            self.stats_label.setText("")
        
        if elapsed:
            self.time_label.setText(elapsed)
    
    def set_indeterminate(self, status: str = "Scanning...") -> None:
        """Set progress bar to indeterminate mode."""
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(0)  # Indeterminate mode
        self.status_label.setText(status)
    
    def set_determinate(self) -> None:
        """Set progress bar back to determinate mode."""
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
    
    def set_complete(self, found: int = 0, new: int = 0, elapsed: str = "") -> None:
        """Mark scan as complete."""
        self.set_determinate()
        self.progress_bar.setValue(100)
        self.status_label.setText("Scan Complete")
        self.status_label.setStyleSheet("color: #22c55e; font-weight: 600;")
        
        if found > 0:
            if new > 0 and new != found:
                self.stats_label.setText(f"Found: {found} │ New: {new}")
            else:
                self.stats_label.setText(f"Found: {found}")
        
        if elapsed:
            self.time_label.setText(elapsed)
    
    def set_error(self, message: str = "Scan failed") -> None:
        """Mark scan as failed."""
        self.set_determinate()
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Error: {message}")
        self.status_label.setStyleSheet("color: #ef4444; font-weight: 600;")
    
    def set_cancelled(self) -> None:
        """Mark scan as cancelled."""
        self.set_determinate()
        self.status_label.setText("Scan Cancelled")
        self.status_label.setStyleSheet("color: #94a3b8;")
