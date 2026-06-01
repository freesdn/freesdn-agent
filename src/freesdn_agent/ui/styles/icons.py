"""
Icon utilities for FreeSDN Agent.

Provides consistent icon access using Qt's built-in standard icons
for an enterprise-grade appearance.
"""

from enum import Enum
from typing import Optional

from PySide6.QtWidgets import QStyle, QApplication, QWidget
from PySide6.QtGui import QIcon, QPixmap, QPainter, QColor
from PySide6.QtCore import Qt, QSize


class AppIcons(Enum):
    """Application icon identifiers mapped to Qt standard icons."""
    
    # Status icons
    SUCCESS = "SP_DialogApplyButton"
    ERROR = "SP_DialogCancelButton"  
    WARNING = "SP_MessageBoxWarning"
    INFO = "SP_MessageBoxInformation"
    QUESTION = "SP_MessageBoxQuestion"
    
    # Connection icons
    CONNECTED = "SP_DriveNetIcon"
    DISCONNECTED = "SP_DriveHDIcon"
    
    # Action icons
    REFRESH = "SP_BrowserReload"
    STOP = "SP_BrowserStop"
    PLAY = "SP_MediaPlay"
    PAUSE = "SP_MediaPause"
    
    # File/folder icons
    FOLDER = "SP_DirIcon"
    FOLDER_OPEN = "SP_DirOpenIcon"
    FILE = "SP_FileIcon"
    
    # Navigation
    ARROW_UP = "SP_ArrowUp"
    ARROW_DOWN = "SP_ArrowDown"
    ARROW_LEFT = "SP_ArrowLeft"
    ARROW_RIGHT = "SP_ArrowRight"
    
    # Dialog icons
    DIALOG_OPEN = "SP_DialogOpenButton"
    DIALOG_SAVE = "SP_DialogSaveButton"
    DIALOG_CLOSE = "SP_DialogCloseButton"
    DIALOG_OK = "SP_DialogOkButton"
    DIALOG_CANCEL = "SP_DialogCancelButton"
    DIALOG_HELP = "SP_DialogHelpButton"
    
    # Computer/network
    COMPUTER = "SP_ComputerIcon"
    NETWORK = "SP_DriveNetIcon"
    DESKTOP = "SP_DesktopIcon"
    
    # Misc
    TRASH = "SP_TrashIcon"
    SETTINGS = "SP_FileDialogDetailedView"
    SEARCH = "SP_FileDialogContentsView"


def get_standard_icon(icon_id: AppIcons, widget: Optional[QWidget] = None) -> QIcon:
    """
    Get a Qt standard icon.
    
    Args:
        icon_id: Icon identifier from AppIcons enum
        widget: Optional widget to get style from
        
    Returns:
        QIcon instance
    """
    style = widget.style() if widget else QApplication.style()
    if style is None:
        return QIcon()
    
    icon_name = icon_id.value
    standard_pixmap = getattr(QStyle.StandardPixmap, icon_name, None)
    
    if standard_pixmap is not None:
        return style.standardIcon(standard_pixmap)
    
    return QIcon()


def create_colored_circle(color: str, size: int = 12) -> QPixmap:
    """
    Create a colored circle pixmap for status indicators.
    
    Args:
        color: Color hex string (e.g., "#22c55e")
        size: Diameter in pixels
        
    Returns:
        QPixmap with a colored circle
    """
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setBrush(QColor(color))
    painter.setPen(Qt.NoPen)
    painter.drawEllipse(1, 1, size - 2, size - 2)
    painter.end()
    
    return pixmap


class StatusIndicator:
    """Status indicator text replacements for enterprise look."""
    
    # Connection status (use filled/outline circles via styled labels)
    CONNECTED = "[Connected]"
    DISCONNECTED = "[Disconnected]"
    
    # Scan status
    SCANNING = "Scanning..."
    SCAN_COMPLETE = "Scan Complete"
    SCAN_FAILED = "Scan Failed"
    SCAN_CANCELLED = "Scan Cancelled"
    
    # Test connection
    TESTING = "Testing..."
    TEST_SUCCESS = "Connection OK"
    TEST_FAILED = "Connection Failed"
    
    # Generic
    READY = "Ready"
    ERROR = "Error"
    WARNING = "Warning"
    SUCCESS = "Success"


def get_status_prefix(status: str) -> str:
    """
    Get appropriate prefix for status messages.
    
    Instead of emojis, use simple text prefixes or nothing
    for a cleaner enterprise look.
    
    Args:
        status: Status type ("success", "error", "warning", "info")
        
    Returns:
        Appropriate prefix string
    """
    prefixes = {
        "success": "",  # Green color will indicate success
        "error": "",    # Red color will indicate error
        "warning": "",  # Yellow color will indicate warning
        "info": "",     # Default color for info
        "testing": "",  # In-progress indicator
    }
    return prefixes.get(status.lower(), "")
