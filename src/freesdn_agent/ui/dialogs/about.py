"""
About Dialog for FreeSDN Agent.
"""

from typing import Optional

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QPixmap

from freesdn_agent import __version__, __app_name__


class AboutDialog(QDialog):
    """About information dialog."""
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        
        self._setup_ui()
    
    def _setup_ui(self) -> None:
        """Setup the dialog UI."""
        self.setWindowTitle(f"About {__app_name__}")
        self.setFixedSize(400, 300)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setAlignment(Qt.AlignCenter)
        
        # App icon (using styled text as placeholder for enterprise look)
        icon_label = QLabel("F")
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setFixedSize(64, 64)
        icon_label.setStyleSheet("""
            font-size: 32px;
            font-weight: bold;
            color: #ffffff;
            background-color: #0ea5e9;
            border-radius: 12px;
        """)
        layout.addWidget(icon_label, alignment=Qt.AlignCenter)
        
        # App name
        name_label = QLabel(__app_name__)
        name_label.setAlignment(Qt.AlignCenter)
        name_label.setStyleSheet("font-size: 20px; font-weight: bold; padding: 4px 0;")
        layout.addWidget(name_label)
        
        # Version
        version_label = QLabel(f"Version {__version__}")
        version_label.setAlignment(Qt.AlignCenter)
        version_label.setStyleSheet("color: #94a3b8; font-size: 13px; padding: 2px 0;")
        layout.addWidget(version_label)
        
        layout.addSpacing(16)
        
        # Description
        desc_label = QLabel(
            "Desktop network discovery tool for the FreeSDN platform.\n"
            "Discover cameras, VoIP phones, and network devices using\n"
            "Layer 2 protocols like ARP, ONVIF, and Hikvision SADP."
        )
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #94a3b8; font-size: 12px; line-height: 1.5; padding: 4px 0;")
        layout.addWidget(desc_label)
        
        layout.addStretch()
        
        # Copyright
        copyright_label = QLabel("© 2026 FreeSDN Project")
        copyright_label.setAlignment(Qt.AlignCenter)
        copyright_label.setStyleSheet("color: #64748b; font-size: 11px;")
        layout.addWidget(copyright_label)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.setFixedWidth(100)
        close_btn.clicked.connect(self.accept)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
