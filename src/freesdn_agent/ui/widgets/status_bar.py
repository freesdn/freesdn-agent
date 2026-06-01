"""
Custom Status Bar for FreeSDN Agent.
"""

import logging
from typing import Optional

from PySide6.QtWidgets import QStatusBar, QLabel, QWidget, QHBoxLayout
from PySide6.QtCore import Qt

from freesdn_agent import __version__

logger = logging.getLogger(__name__)


class AgentStatusBar(QStatusBar):
    """Custom status bar with connection and interface info."""
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        
        self._setup_ui()
    
    def _setup_ui(self) -> None:
        """Setup the status bar UI."""
        self.setObjectName("agentStatusBar")
        
        # Main status message (left)
        self.status_label = QLabel("Ready")
        self.addWidget(self.status_label)
        
        # Spacer
        self.addWidget(QLabel(""), stretch=1)
        
        # Interface info
        self.interface_label = QLabel("")
        self.interface_label.setStyleSheet("color: #94a3b8;")
        self.addPermanentWidget(self.interface_label)
        
        # Separator
        sep1 = QLabel("│")
        sep1.setStyleSheet("color: #334155;")
        self.addPermanentWidget(sep1)
        
        # Connection status
        self.connection_label = QLabel("Disconnected")
        self.connection_label.setStyleSheet("color: #64748b;")
        self.addPermanentWidget(self.connection_label)
        
        # Separator
        sep2 = QLabel("│")
        sep2.setStyleSheet("color: #334155;")
        self.addPermanentWidget(sep2)
        
        # Version
        version_label = QLabel(f"v{__version__}")
        version_label.setStyleSheet("color: #64748b;")
        self.addPermanentWidget(version_label)
    
    def set_status(self, message: str) -> None:
        """Set the main status message."""
        self.status_label.setText(message)
    
    def set_connection_status(self, connected: bool, server: str = "") -> None:
        """Update connection status display."""
        if connected:
            self.connection_label.setText("Connected")
            self.connection_label.setStyleSheet("color: #22c55e; font-weight: 600;")
        else:
            self.connection_label.setText("Disconnected")
            self.connection_label.setStyleSheet("color: #64748b;")
    
    def set_interface(self, interface: str, network: str = "") -> None:
        """Update selected interface display."""
        if network:
            self.interface_label.setText(f"Interface: {interface} ({network})")
        else:
            self.interface_label.setText(f"Interface: {interface}")
    
    def set_scan_status(self, scanning: bool) -> None:
        """Update scan status display."""
        if scanning:
            self.status_label.setText("Scanning...")
            self.status_label.setStyleSheet("color: #0ea5e9; font-weight: 600;")
        else:
            self.status_label.setText("Ready")
            self.status_label.setStyleSheet("")
