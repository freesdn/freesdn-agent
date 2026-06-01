"""
Connection Panel Widget.

Displays FreeSDN connection status and provides connection management.
"""

import logging
from typing import Optional

from PySide6.QtWidgets import (
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QDialog,
    QLineEdit,
    QFormLayout,
    QDialogButtonBox,
    QComboBox,
    QMessageBox,
    QApplication,
    QCheckBox,
)
from PySide6.QtCore import Qt, Signal, Slot, QThread, QObject, QTimer
from PySide6.QtGui import QFont, QCursor

from freesdn_agent.core.config import get_config
from freesdn_agent.core.credentials import save_credentials, load_credentials, delete_credentials
from freesdn_agent.api.client import SyncFreeSDNClient
from freesdn_agent.core.exceptions import ConnectionError, AuthenticationError

logger = logging.getLogger(__name__)


class ConnectionPanel(QFrame):
    """Panel showing FreeSDN connection status."""
    
    # Signals
    connection_changed = Signal(bool)  # True if connected
    site_changed = Signal(str)  # Site ID
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        
        self.config = get_config()
        self._connected = False
        self._site_name = None
        self._site_id = None
        self._sites = []  # List of available sites
        self._client = None
        
        self._setup_ui()
        self._update_display()
        
        # Auto-connect on startup if we have saved credentials
        QTimer.singleShot(500, self._auto_connect)
    
    def _setup_ui(self) -> None:
        """Setup the panel UI."""
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setObjectName("connectionPanel")
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(16)
        
        # Connection icon/indicator
        self.status_indicator = QLabel()
        self.status_indicator.setObjectName("connectionIndicator")
        self.status_indicator.setFixedSize(12, 12)
        layout.addWidget(self.status_indicator)
        
        # Connection info
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)
        
        self.server_label = QLabel("Not Connected")
        self.server_label.setObjectName("serverLabel")
        self.server_label.setStyleSheet("font-size: 14px; font-weight: bold; padding: 2px 0;")
        info_layout.addWidget(self.server_label)
        
        self.details_label = QLabel("Click 'Connect' to connect to FreeSDN")
        self.details_label.setObjectName("detailsLabel")
        self.details_label.setStyleSheet("color: #94a3b8; font-size: 12px; padding: 2px 0;")
        info_layout.addWidget(self.details_label)
        
        layout.addLayout(info_layout, stretch=1)
        
        # Site selector (hidden when not connected)
        self.site_combo = QComboBox()
        self.site_combo.setObjectName("siteCombo")
        self.site_combo.setMinimumWidth(180)
        self.site_combo.setVisible(False)
        self.site_combo.currentIndexChanged.connect(self._on_site_changed)
        layout.addWidget(self.site_combo)
        
        # Connect button
        self.connect_button = QPushButton("Connect")
        self.connect_button.setObjectName("connectButton")
        self.connect_button.setFixedWidth(100)
        self.connect_button.clicked.connect(self.show_connect_dialog)
        layout.addWidget(self.connect_button)
    
    def _update_display(self) -> None:
        """Update the display based on connection state."""
        if self._connected:
            self.status_indicator.setStyleSheet(
                "background-color: #22c55e; border-radius: 6px;"
            )
            self.server_label.setText(self.config.freesdn.url)
            self.details_label.setText("Connected")
            self.connect_button.setText("Disconnect")
            
            # Show site selector when connected
            self.site_combo.setVisible(True)
        else:
            self.status_indicator.setStyleSheet(
                "background-color: #64748b; border-radius: 6px;"
            )
            self.server_label.setText("Not Connected")
            self.details_label.setText("Click 'Connect' to connect to FreeSDN")
            self.connect_button.setText("Connect")
            
            # Hide site selector when disconnected
            self.site_combo.setVisible(False)
    
    def _on_site_changed(self, index: int) -> None:
        """Handle site selection change."""
        if index >= 0 and index < len(self._sites):
            site = self._sites[index]
            self._site_id = site.get("id")
            self._site_name = site.get("name")
            logger.info(f"Site changed to: {self._site_name} ({self._site_id})")
            self.site_changed.emit(self._site_id)
    
    @Slot()
    def show_connect_dialog(self) -> None:
        """Show the connection dialog."""
        if self._connected:
            # Disconnect
            self._disconnect()
        else:
            # Show connect dialog
            dialog = ConnectDialog(self)
            if dialog.exec() == QDialog.Accepted:
                url = dialog.get_url()
                username = dialog.get_username()
                password = dialog.get_password()
                remember = dialog.get_remember()
                self._connect(url, username, password, remember)
    
    def _auto_connect(self) -> None:
        """Attempt auto-connect using saved credentials."""
        url = self.config.freesdn.url
        if not url:
            return
        
        # Try to load saved credentials
        creds = load_credentials(url)
        if creds:
            logger.info(f"Found saved credentials for {url}, attempting auto-connect...")
            self._connect(url, creds.username, creds.password, save_creds=False, silent=True)
    
    def _connect(self, url: str, username: str, password: str, 
                 save_creds: bool = True, silent: bool = False) -> None:
        """Attempt to connect to FreeSDN."""
        logger.info(f"Connecting to {url}...")
        
        # Set busy cursor
        QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
        
        try:
            # Create API client and attempt login
            client = SyncFreeSDNClient(url)
            
            # Test connection first
            if not client.test_connection():
                QApplication.restoreOverrideCursor()
                if not silent:
                    QMessageBox.critical(
                        self,
                        "Connection Failed",
                        f"Could not connect to server at {url}\n\nPlease verify the URL and that the server is running."
                    )
                else:
                    logger.warning(f"Auto-connect failed: server not responding at {url}")
                return
            
            # Attempt authentication
            try:
                client.login(username, password)
            except AuthenticationError as e:
                QApplication.restoreOverrideCursor()
                if not silent:
                    QMessageBox.critical(
                        self,
                        "Authentication Failed",
                        f"Invalid username or password.\n\n{str(e)}"
                    )
                else:
                    logger.warning(f"Auto-connect failed: authentication error")
                    # Delete invalid saved credentials
                    delete_credentials(url)
                return
            
            # Save URL to config
            self.config.freesdn.url = url
            self.config.save()
            
            # Save credentials if requested
            if save_creds:
                save_credentials(url, username, password)
                logger.info("Saved credentials to system keyring")
            
            self._connected = True
            self._client = client
            
            # Get sites and populate the selector
            try:
                sites_response = client.get_sites()
                sites = sites_response.get("items", []) if isinstance(sites_response, dict) else sites_response
                self._sites = sites if sites else []
                
                # Populate site combo. When the org has duplicate site
                # names (test-fixture pollution can produce many
                # "Branch" entries, and legit orgs sometimes name
                # multiple physical sites the same), tag duplicates
                # with the leading hex of the site_id so the operator
                # can tell which one they're selecting. Single-occurrence
                # names stay clean.
                self.site_combo.blockSignals(True)
                self.site_combo.clear()
                name_counts: dict[str, int] = {}
                for site in self._sites:
                    name = (site.get("name") or "Unknown Site").strip()
                    name_counts[name] = name_counts.get(name, 0) + 1
                for site in self._sites:
                    name = (site.get("name") or "Unknown Site").strip()
                    sid = (site.get("id") or "")[:8]
                    label = (
                        f"{name}  ·  {sid}"
                        if name_counts.get(name, 0) > 1
                        else name
                    )
                    self.site_combo.addItem(label)
                self.site_combo.blockSignals(False)
                
                # Select first site by default
                if self._sites:
                    self._site_id = self._sites[0].get("id")
                    self._site_name = self._sites[0].get("name", "Unknown Site")
                    self.site_combo.setCurrentIndex(0)
                else:
                    self._site_id = None
                    self._site_name = None
            except Exception as e:
                logger.warning(f"Failed to get sites: {e}")
                self._sites = []
                self._site_id = None
                self._site_name = None
            
            self._update_display()
            self.connection_changed.emit(True)
            
            logger.info(f"Connected to FreeSDN (site: {self._site_name}, {len(self._sites)} sites available)")
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            if not silent:
                QMessageBox.critical(
                    self,
                    "Connection Error",
                    f"An error occurred while connecting:\n\n{str(e)}"
                )
        finally:
            QApplication.restoreOverrideCursor()
    
    def _disconnect(self) -> None:
        """Disconnect from FreeSDN."""
        logger.info("Disconnecting from FreeSDN...")
        
        # Ask if user wants to forget saved credentials
        reply = QMessageBox.question(
            self,
            "Disconnect",
            "Do you also want to forget the saved login credentials?",
            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Cancel:
            return
        
        if reply == QMessageBox.Yes:
            # Delete saved credentials
            url = self.config.freesdn.url
            if url:
                delete_credentials(url)
                logger.info("Deleted saved credentials")
        
        self._connected = False
        self._site_name = None
        self._site_id = None
        self._sites = []
        self._client = None
        
        # Clear site combo
        self.site_combo.clear()
        
        self._update_display()
        self.connection_changed.emit(False)
        
        logger.info("Disconnected from FreeSDN")
    
    def is_connected(self) -> bool:
        """Check if connected to FreeSDN."""
        return self._connected
    
    def get_client(self) -> Optional[SyncFreeSDNClient]:
        """Get the API client if connected."""
        return self._client if self._connected else None
    
    def get_site_id(self) -> Optional[str]:
        """Get the current site ID."""
        return self._site_id
    
    def get_site_name(self) -> Optional[str]:
        """Get the current site name."""
        return self._site_name

    def get_sites(self) -> list[dict]:
        """All sites available to the authenticated user.

        Used by the scan-completion status to map site_id → name when
        the backend's auto-router lands rows in a non-selected site.
        """
        return list(self._sites or [])


class ConnectDialog(QDialog):
    """Dialog for connecting to FreeSDN server."""
    
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        
        self.config = get_config()
        self._setup_ui()
        self._load_saved_credentials()
    
    def _setup_ui(self) -> None:
        """Setup the dialog UI."""
        self.setWindowTitle("Connect to FreeSDN")
        self.setFixedSize(450, 340)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Title
        title = QLabel("Connect to FreeSDN Server")
        title.setStyleSheet("font-size: 16px; font-weight: bold; padding: 4px 0;")
        layout.addWidget(title)
        
        # Form
        form_layout = QFormLayout()
        form_layout.setSpacing(12)
        form_layout.setLabelAlignment(Qt.AlignRight)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://freesdn.example.com")
        self.url_input.setText(self.config.freesdn.url)
        self.url_input.setMinimumHeight(32)
        self.url_input.textChanged.connect(self._on_url_changed)
        form_layout.addRow("Server URL:", self.url_input)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("admin@example.com")
        self.username_input.setMinimumHeight(32)
        form_layout.addRow("Email:", self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("••••••••")
        self.password_input.setMinimumHeight(32)
        form_layout.addRow("Password:", self.password_input)
        
        layout.addLayout(form_layout)
        
        # Remember me checkbox
        self.remember_checkbox = QCheckBox("Remember credentials")
        self.remember_checkbox.setChecked(True)
        self.remember_checkbox.setStyleSheet("padding: 4px 0;")
        layout.addWidget(self.remember_checkbox)
        
        # Test connection button and status
        test_row = QHBoxLayout()
        
        self.test_button = QPushButton("Test Connection")
        self.test_button.setFixedWidth(130)
        self.test_button.clicked.connect(self._test_connection)
        test_row.addWidget(self.test_button)
        
        self.test_status = QLabel("")
        self.test_status.setStyleSheet("font-size: 12px; padding: 4px 0;")
        test_row.addWidget(self.test_status, stretch=1)
        
        layout.addLayout(test_row)
        
        layout.addStretch()
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self._validate_and_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        # Focus on first empty field
        if self.url_input.text():
            self.username_input.setFocus()
        else:
            self.url_input.setFocus()
    
    def _load_saved_credentials(self) -> None:
        """Load saved credentials if URL is set."""
        url = self.url_input.text().strip()
        if url:
            creds = load_credentials(url)
            if creds:
                self.username_input.setText(creds.username)
                self.password_input.setText(creds.password)
                self.password_input.setFocus()
                self.password_input.selectAll()
    
    def _on_url_changed(self, text: str) -> None:
        """Handle URL change - load credentials for new URL."""
        # Clear current credentials
        self.username_input.clear()
        self.password_input.clear()
        self.test_status.clear()
        
        # Try to load credentials for this URL
        if text.strip():
            creds = load_credentials(text.strip())
            if creds:
                self.username_input.setText(creds.username)
                self.password_input.setText(creds.password)
    
    def _test_connection(self) -> None:
        """Test the connection to the server."""
        url = self.url_input.text().strip()
        
        if not url:
            self.test_status.setText("Please enter a server URL")
            self.test_status.setStyleSheet("color: #ef4444; font-size: 12px; padding: 4px 0;")
            return
        
        # Show testing status
        self.test_status.setText("Testing connection...")
        self.test_status.setStyleSheet("color: #f59e0b; font-size: 12px; padding: 4px 0;")
        self.test_button.setEnabled(False)
        QApplication.processEvents()
        
        try:
            client = SyncFreeSDNClient(url)
            if client.test_connection():
                self.test_status.setText("Connection successful")
                self.test_status.setStyleSheet("color: #22c55e; font-size: 12px; font-weight: 600; padding: 4px 0;")
            else:
                self.test_status.setText("Server not responding")
                self.test_status.setStyleSheet("color: #ef4444; font-size: 12px; padding: 4px 0;")
        except Exception as e:
            error_msg = str(e)[:40]
            self.test_status.setText(f"Failed: {error_msg}")
            self.test_status.setStyleSheet("color: #ef4444; font-size: 12px; padding: 4px 0;")
        finally:
            self.test_button.setEnabled(True)
    
    def _validate_and_accept(self) -> None:
        """Validate inputs and accept dialog."""
        if not self.url_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Server URL is required.")
            self.url_input.setFocus()
            return
        
        if not self.username_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Email is required.")
            self.username_input.setFocus()
            return
        
        if not self.password_input.text():
            QMessageBox.warning(self, "Validation Error", "Password is required.")
            self.password_input.setFocus()
            return
        
        self.accept()
    
    def get_url(self) -> str:
        """Get the server URL."""
        return self.url_input.text().strip()
    
    def get_username(self) -> str:
        """Get the username."""
        return self.username_input.text().strip()
    
    def get_password(self) -> str:
        """Get the password."""
        return self.password_input.text()
    
    def get_remember(self) -> bool:
        """Get whether to remember credentials."""
        return self.remember_checkbox.isChecked()
