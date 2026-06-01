"""
Theme Manager for FreeSDN Agent.

Handles application theming with dark/light mode support.
Supports following system theme and manual toggle.
"""

import logging
from pathlib import Path
from typing import Optional
from enum import Enum

from PySide6.QtWidgets import QApplication, QStyleFactory
from PySide6.QtGui import QPalette, QColor, QGuiApplication
from PySide6.QtCore import QObject, Signal, Slot

logger = logging.getLogger(__name__)


class ThemeMode(str, Enum):
    """Theme mode options."""
    SYSTEM = "system"
    DARK = "dark"
    LIGHT = "light"


def is_system_dark_mode() -> bool:
    """Check if the system is using dark mode."""
    try:
        # Try to detect system theme via QPalette
        palette = QGuiApplication.palette()
        window_color = palette.color(QPalette.Window)
        # If window background is dark, system is in dark mode
        return window_color.lightness() < 128
    except Exception:
        # Default to dark if detection fails
        return True


class ThemeManager(QObject):
    """Manages application themes with OS detection and toggle support."""
    
    # Signal emitted when theme changes
    theme_changed = Signal(str)  # 'dark' or 'light'
    
    # Color palette — neutral slate scale aligned with the FreeSDN web
    # UI so the desktop reads as a true companion (was a dated
    # purple-navy #1a1a2e/#16213e). Depth hierarchy: primary (darkest)
    # → secondary (bars) → card (lifts off the background).
    DARK_COLORS = {
        "background_primary": "#0b1120",    # app body, near-black navy
        "background_secondary": "#0f172a",  # slate-900 — menu/tool/status bars
        "background_card": "#1e293b",       # slate-800 — cards lift off bg
        "background_input": "#0f172a",      # slate-900 — inputs recede
        "accent_primary": "#0ea5e9",        # sky-500
        "accent_success": "#22c55e",        # green-500
        "accent_warning": "#f59e0b",        # amber-500
        "accent_danger": "#ef4444",         # red-500
        "text_primary": "#f1f5f9",          # slate-100
        "text_secondary": "#94a3b8",        # slate-400
        "text_muted": "#64748b",            # slate-500
        "border": "#1e293b",                # slate-800 — subtle hairlines
        "border_light": "#334155",          # slate-700 — hover/active edges
    }

    LIGHT_COLORS = {
        "background_primary": "#f8fafc",    # slate-50 — soft, not stark white
        "background_secondary": "#f1f5f9",  # slate-100
        "background_card": "#ffffff",
        "background_input": "#f8fafc",
        "accent_primary": "#0284c7",        # sky-600
        "accent_success": "#16a34a",
        "accent_warning": "#d97706",
        "accent_danger": "#dc2626",
        "text_primary": "#0f172a",
        "text_secondary": "#475569",
        "text_muted": "#94a3b8",
        "border": "#e2e8f0",                # slate-200
        "border_light": "#cbd5e1",          # slate-300
    }
    
    _instance: Optional["ThemeManager"] = None
    
    def __new__(cls) -> "ThemeManager":
        """Singleton pattern for theme manager."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        super().__init__()
        self._initialized = True
        self._current_theme = "dark"
        self._theme_mode = ThemeMode.SYSTEM
        self._app: Optional[QApplication] = None
    
    @classmethod
    def instance(cls) -> "ThemeManager":
        """Get the singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    @property
    def current_theme(self) -> str:
        """Get the current active theme ('dark' or 'light')."""
        return self._current_theme
    
    @property
    def theme_mode(self) -> ThemeMode:
        """Get the current theme mode (system, dark, or light)."""
        return self._theme_mode
    
    def set_app(self, app: QApplication) -> None:
        """Set the application instance."""
        self._app = app
    
    def apply_theme(self, mode: ThemeMode, app: Optional[QApplication] = None) -> None:
        """Apply theme based on mode setting."""
        if app:
            self._app = app
        if not self._app:
            logger.warning("No QApplication instance set")
            return
            
        self._theme_mode = mode
        
        if mode == ThemeMode.SYSTEM:
            use_dark = is_system_dark_mode()
        elif mode == ThemeMode.DARK:
            use_dark = True
        else:
            use_dark = False
        
        if use_dark:
            self._apply_dark_theme()
        else:
            self._apply_light_theme()
    
    def _apply_dark_theme(self) -> None:
        """Apply dark theme to application."""
        if not self._app:
            return
        self._current_theme = "dark"
        stylesheet = self._generate_stylesheet(self.DARK_COLORS)
        self._app.setStyleSheet(stylesheet)
        self.theme_changed.emit("dark")
        logger.info("Applied dark theme")
    
    def _apply_light_theme(self) -> None:
        """Apply light theme to application."""
        if not self._app:
            return
        self._current_theme = "light"
        stylesheet = self._generate_stylesheet(self.LIGHT_COLORS)
        self._app.setStyleSheet(stylesheet)
        self.theme_changed.emit("light")
        logger.info("Applied light theme")
    
    def apply_dark_theme(self, app: QApplication) -> None:
        """Apply dark theme to application (legacy API)."""
        self._app = app
        self._theme_mode = ThemeMode.DARK
        self._apply_dark_theme()
    
    def apply_light_theme(self, app: QApplication) -> None:
        """Apply light theme to application (legacy API)."""
        self._app = app
        self._theme_mode = ThemeMode.LIGHT
        self._apply_light_theme()
    
    def toggle_theme(self, app: Optional[QApplication] = None) -> str:
        """Toggle between dark and light theme."""
        if app:
            self._app = app
        if not self._app:
            return self._current_theme
            
        if self._current_theme == "dark":
            self._theme_mode = ThemeMode.LIGHT
            self._apply_light_theme()
            return "light"
        else:
            self._theme_mode = ThemeMode.DARK
            self._apply_dark_theme()
            return "dark"
    
    def get_colors(self) -> dict:
        """Get current theme colors."""
        if self._current_theme == "dark":
            return self.DARK_COLORS.copy()
        return self.LIGHT_COLORS.copy()
    
    def _generate_stylesheet(self, colors: dict) -> str:
        """Generate Qt stylesheet from color palette."""
        return f"""
            /* Global Styles */
            QMainWindow, QDialog {{
                background-color: {colors["background_primary"]};
                color: {colors["text_primary"]};
                font-size: 13px;
            }}
            
            QWidget {{
                font-family: "Segoe UI", "SF Pro Display", system-ui, sans-serif;
                font-size: 13px;
                color: {colors["text_primary"]};
            }}
            
            /* Fix font inheritance */
            QLabel {{
                font-size: 13px;
                padding: 2px 0px;
            }}
            
            /* Menu Bar */
            QMenuBar {{
                background-color: {colors["background_secondary"]};
                border-bottom: 1px solid {colors["border"]};
                padding: 4px;
                font-size: 13px;
            }}
            
            QMenuBar::item {{
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 13px;
            }}
            
            QMenuBar::item:selected {{
                background-color: {colors["background_card"]};
            }}
            
            QMenu {{
                background-color: {colors["background_card"]};
                border: 1px solid {colors["border"]};
                border-radius: 8px;
                padding: 4px;
                font-size: 13px;
            }}
            
            QMenu::item {{
                padding: 8px 24px;
                border-radius: 4px;
                font-size: 13px;
            }}
            
            QMenu::item:selected {{
                background-color: {colors["accent_primary"]};
            }}
            
            QMenu::separator {{
                height: 1px;
                background-color: {colors["border"]};
                margin: 4px 8px;
            }}
            
            /* Tool Bar */
            QToolBar {{
                background-color: {colors["background_secondary"]};
                border-bottom: 1px solid {colors["border"]};
                padding: 6px;
                spacing: 4px;
                font-size: 13px;
            }}
            
            QToolBar QToolButton {{
                font-size: 13px;
                padding: 4px 8px;
            }}
            
            QToolBar::separator {{
                width: 1px;
                background-color: {colors["border"]};
                margin: 4px 8px;
            }}
            
            /* Status Bar */
            QStatusBar {{
                background-color: {colors["background_secondary"]};
                border-top: 1px solid {colors["border"]};
                padding: 4px 8px;
                font-size: 12px;
            }}
            
            QStatusBar QLabel {{
                font-size: 12px;
            }}
            
            /* Frames/Panels */
            QFrame#connectionPanel,
            QFrame#scanPanel,
            QFrame#resultsPanel,
            QFrame#progressPanel {{
                background-color: {colors["background_card"]};
                border: 1px solid {colors["border"]};
                border-radius: 8px;
            }}
            
            QWidget#resultsHeader {{
                background-color: transparent;
                border-bottom: 1px solid {colors["border"]};
            }}
            
            /* Labels */
            QLabel {{
                color: {colors["text_primary"]};
            }}
            
            QLabel#sectionTitle {{
                font-size: 14px;
                font-weight: bold;
            }}
            
            QLabel#serverLabel {{
                font-size: 14px;
            }}
            
            QLabel#detailsLabel {{
                color: {colors["text_secondary"]};
                font-size: 12px;
            }}
            
            /* Buttons — subtle elevated fill on cards, accent edge on hover */
            QPushButton {{
                background-color: {colors["background_card"]};
                border: 1px solid {colors["border_light"]};
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 13px;
                font-weight: 500;
                color: {colors["text_primary"]};
            }}

            QPushButton:hover {{
                background-color: {colors["border_light"]};
                border-color: {colors["accent_primary"]};
            }}

            QPushButton:pressed {{
                background-color: {colors["background_secondary"]};
            }}
            
            QPushButton:disabled {{
                background-color: {colors["background_input"]};
                color: {colors["text_muted"]};
                border-color: {colors["border"]};
            }}
            
            /* Primary Button (scan buttons) */
            QPushButton#quickScanBtn,
            QPushButton#cameraScanBtn,
            QPushButton#voipScanBtn,
            QPushButton#fullScanBtn {{
                background-color: {colors["background_input"]};
                border: 1px solid {colors["border_light"]};
                border-radius: 10px;
                padding: 18px;
                font-size: 13px;
                font-weight: 600;
                color: {colors["text_primary"]};
            }}

            QPushButton#quickScanBtn:hover,
            QPushButton#cameraScanBtn:hover,
            QPushButton#voipScanBtn:hover,
            QPushButton#fullScanBtn:hover {{
                background-color: {colors["accent_primary"]};
                border-color: {colors["accent_primary"]};
                color: white;
            }}
            
            QPushButton#stopScanBtn {{
                background-color: {colors["accent_danger"]};
                border-color: {colors["accent_danger"]};
                color: white;
            }}
            
            QPushButton#stopScanBtn:hover {{
                background-color: #dc2626;
            }}
            
            QPushButton#pushAllBtn {{
                background-color: {colors["accent_success"]};
                border-color: {colors["accent_success"]};
                color: white;
            }}
            
            QPushButton#pushAllBtn:hover {{
                background-color: #16a34a;
            }}
            
            QPushButton#pushAllBtn:disabled {{
                background-color: {colors["background_input"]};
                border-color: {colors["border"]};
                color: {colors["text_muted"]};
            }}
            
            QPushButton#pushBtn {{
                background-color: transparent;
                border: 1px solid {colors["accent_success"]};
                color: {colors["accent_success"]};
                border-radius: 4px;
                padding: 4px 8px;
            }}
            
            QPushButton#pushBtn:hover {{
                background-color: {colors["accent_success"]};
                color: white;
            }}
            
            /* Connect Button */
            QPushButton#connectButton {{
                background-color: {colors["accent_primary"]};
                border-color: {colors["accent_primary"]};
                color: white;
            }}
            
            QPushButton#connectButton:hover {{
                background-color: #0284c7;
            }}
            
            /* Combo Box */
            QComboBox {{
                background-color: {colors["background_input"]};
                border: 1px solid {colors["border"]};
                border-radius: 6px;
                padding: 8px 12px;
                padding-right: 30px;
                font-size: 13px;
                color: {colors["text_primary"]};
            }}
            
            QComboBox:hover {{
                border-color: {colors["border_light"]};
            }}
            
            QComboBox::drop-down {{
                border: none;
                padding-right: 8px;
            }}
            
            QComboBox::down-arrow {{
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid {colors["text_secondary"]};
                margin-right: 8px;
            }}
            
            QComboBox QAbstractItemView {{
                background-color: {colors["background_card"]};
                border: 1px solid {colors["border"]};
                border-radius: 6px;
                font-size: 13px;
                padding: 4px;
                selection-background-color: {colors["accent_primary"]};
            }}
            
            /* Line Edit */
            QLineEdit {{
                background-color: {colors["background_input"]};
                border: 1px solid {colors["border"]};
                border-radius: 6px;
                padding: 8px 12px;
                min-height: 18px;
                font-size: 13px;
                color: {colors["text_primary"]};
                selection-background-color: {colors["accent_primary"]};
            }}
            
            QLineEdit:hover {{
                border-color: {colors["border_light"]};
            }}
            
            QLineEdit:focus {{
                border-color: {colors["accent_primary"]};
            }}
            
            QLineEdit::placeholder {{
                color: {colors["text_muted"]};
            }}
            
            /* Form Labels */
            QFormLayout QLabel {{
                font-size: 13px;
                padding: 4px 0;
                min-height: 20px;
            }}
            
            /* Table */
            QTableWidget {{
                background-color: {colors["background_card"]};
                border: none;
                gridline-color: {colors["border"]};
                selection-background-color: {colors["background_input"]};
                font-size: 13px;
            }}
            
            QTableWidget::item {{
                padding: 8px;
                border-bottom: 1px solid {colors["border"]};
                font-size: 13px;
            }}
            
            QTableWidget::item:selected {{
                background-color: {colors["accent_primary"]};
                color: white;
            }}
            
            QHeaderView::section {{
                background-color: {colors["background_secondary"]};
                color: {colors["text_secondary"]};
                padding: 10px 8px;
                border: none;
                border-bottom: 1px solid {colors["border"]};
                font-size: 11px;
                font-weight: 600;
                text-transform: uppercase;
            }}
            
            /* Progress Bar */
            QProgressBar {{
                background-color: {colors["background_input"]};
                border: none;
                border-radius: 4px;
                text-align: center;
            }}
            
            QProgressBar::chunk {{
                background-color: {colors["accent_primary"]};
                border-radius: 4px;
            }}
            
            /* Scroll Bar */
            QScrollBar:vertical {{
                background-color: {colors["background_card"]};
                width: 10px;
                border-radius: 5px;
            }}
            
            QScrollBar::handle:vertical {{
                background-color: {colors["border"]};
                border-radius: 5px;
                min-height: 30px;
            }}
            
            QScrollBar::handle:vertical:hover {{
                background-color: {colors["border_light"]};
            }}
            
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            
            QScrollBar:horizontal {{
                background-color: {colors["background_card"]};
                height: 10px;
                border-radius: 5px;
            }}
            
            QScrollBar::handle:horizontal {{
                background-color: {colors["border"]};
                border-radius: 5px;
                min-width: 30px;
            }}
            
            QScrollBar::handle:horizontal:hover {{
                background-color: {colors["border_light"]};
            }}
            
            QScrollBar::add-line:horizontal,
            QScrollBar::sub-line:horizontal {{
                width: 0px;
            }}
            
            /* Dialog */
            QDialog {{
                background-color: {colors["background_card"]};
            }}
            
            QDialogButtonBox QPushButton {{
                min-width: 80px;
            }}
            
            /* Checkbox */
            QCheckBox {{
                spacing: 8px;
                font-size: 13px;
                color: {colors["text_primary"]};
            }}
            
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border: 2px solid {colors["border"]};
                border-radius: 4px;
                background-color: {colors["background_input"]};
            }}
            
            QCheckBox::indicator:hover {{
                border-color: {colors["accent_primary"]};
            }}
            
            QCheckBox::indicator:checked {{
                background-color: {colors["accent_primary"]};
                border-color: {colors["accent_primary"]};
            }}
            
            QCheckBox::indicator:checked:hover {{
                background-color: #0284c7;
                border-color: #0284c7;
            }}
            
            QCheckBox::indicator:disabled {{
                border-color: {colors["border"]};
                background-color: {colors["background_secondary"]};
            }}
            
            /* Radio Button */
            QRadioButton {{
                spacing: 8px;
                font-size: 13px;
                color: {colors["text_primary"]};
            }}
            
            QRadioButton::indicator {{
                width: 18px;
                height: 18px;
                border: 2px solid {colors["border"]};
                border-radius: 10px;
                background-color: {colors["background_input"]};
            }}
            
            QRadioButton::indicator:hover {{
                border-color: {colors["accent_primary"]};
            }}
            
            QRadioButton::indicator:checked {{
                background-color: {colors["accent_primary"]};
                border-color: {colors["accent_primary"]};
            }}
            
            QRadioButton::indicator:checked:hover {{
                background-color: #0284c7;
                border-color: #0284c7;
            }}
            
            /* Group Box */
            QGroupBox {{
                font-size: 13px;
                font-weight: bold;
                border: 1px solid {colors["border"]};
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
                color: {colors["text_primary"]};
            }}
            
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 12px;
                padding: 0 6px;
                background-color: {colors["background_card"]};
            }}
            
            /* Spin Box */
            QSpinBox, QDoubleSpinBox {{
                background-color: {colors["background_input"]};
                border: 1px solid {colors["border"]};
                border-radius: 6px;
                padding: 6px 8px;
                font-size: 13px;
                color: {colors["text_primary"]};
            }}
            
            QSpinBox:hover, QDoubleSpinBox:hover {{
                border-color: {colors["border_light"]};
            }}
            
            QSpinBox:focus, QDoubleSpinBox:focus {{
                border-color: {colors["accent_primary"]};
            }}
            
            QSpinBox::up-button, QDoubleSpinBox::up-button {{
                background-color: {colors["background_secondary"]};
                border-left: 1px solid {colors["border"]};
                border-top-right-radius: 5px;
            }}
            
            QSpinBox::down-button, QDoubleSpinBox::down-button {{
                background-color: {colors["background_secondary"]};
                border-left: 1px solid {colors["border"]};
                border-bottom-right-radius: 5px;
            }}
            
            /* Tab Widget */
            QTabWidget::pane {{
                border: 1px solid {colors["border"]};
                border-radius: 8px;
                background-color: {colors["background_card"]};
                padding: 8px;
            }}
            
            QTabBar::tab {{
                background-color: {colors["background_secondary"]};
                color: {colors["text_secondary"]};
                border: 1px solid {colors["border"]};
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                padding: 10px 20px;
                margin-right: 2px;
                font-size: 13px;
            }}
            
            QTabBar::tab:selected {{
                background-color: {colors["background_card"]};
                color: {colors["text_primary"]};
                border-bottom: 2px solid {colors["accent_primary"]};
            }}
            
            QTabBar::tab:hover:!selected {{
                background-color: {colors["background_card"]};
            }}
            
            /* Message Box */
            QMessageBox {{
                background-color: {colors["background_card"]};
                font-size: 13px;
            }}
            
            QMessageBox QLabel {{
                font-size: 13px;
            }}
            
            QMessageBox QPushButton {{
                font-size: 13px;
            }}
            
            /* Tool Tip */
            QToolTip {{
                background-color: {colors["background_card"]};
                color: {colors["text_primary"]};
                border: 1px solid {colors["border"]};
                border-radius: 4px;
                padding: 6px 10px;
                font-size: 12px;
            }}
            
            /* Catch-all for any remaining widgets */
            QAbstractButton, QAbstractSpinBox, QAbstractScrollArea {{
                font-size: 13px;
            }}
            
            QDialogButtonBox QPushButton {{
                font-size: 13px;
            }}
        """
