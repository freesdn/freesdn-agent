"""
Configuration management for FreeSDN Agent.

Handles persistent storage of user preferences and connection settings.
"""

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from appdirs import user_config_dir

from freesdn_agent import __app_name__

logger = logging.getLogger(__name__)


class FreeSDNConnection(BaseModel):
    """FreeSDN server connection settings."""
    
    url: str = ""
    site_id: str | None = None
    site_name: str | None = None
    # Note: Tokens stored in system keyring, not config file
    
    
class ScanSettings(BaseModel):
    """Default scan settings."""
    
    timeout: float = 3.0
    concurrency: int = 50
    
    # Basic discovery scanners
    enable_arp: bool = True
    enable_icmp: bool = True
    enable_ports: bool = True
    enable_http: bool = True
    enable_banner: bool = True
    
    # Protocol-specific scanners
    enable_onvif: bool = True
    enable_sadp: bool = True
    enable_snmp: bool = True
    enable_netbios: bool = True
    enable_sip: bool = False
    enable_mdns: bool = False
    enable_ssdp: bool = False


class UISettings(BaseModel):
    """UI preferences."""
    
    theme: str = "system"  # "system", "dark", or "light"
    window_width: int = 1100
    window_height: int = 750
    window_x: int | None = None
    window_y: int | None = None
    show_known_devices: bool = True
    auto_push_new: bool = False


class DaemonConfig(BaseModel):
    """Daemon-mode configuration for headless agent."""

    agent_id: str = ""
    server_url: str = ""
    websocket_url: str = ""
    site_id: str = ""
    heartbeat_interval: int = Field(default=30, ge=10, le=3600)
    reconnect_delay: int = Field(default=5, ge=1, le=300)
    reconnect_max_delay: int = Field(default=300, ge=10, le=3600)
    log_level: str = "INFO"
    log_file: str = ""
    log_max_size_mb: int = Field(default=50, ge=1, le=1024)
    log_backup_count: int = Field(default=5, ge=0, le=100)
    auto_update_enabled: bool = True
    auto_update_interval: int = Field(default=3000, ge=300, le=86400)  # 5min-24h
    auto_update_channel: str = "stable"  # "stable" | "beta"
    # require a valid ECDSA signature before installing any auto-update.
    # Default ON — an unsigned release is refused (a swapped binary+checksum proves
    # nothing without the backend's private key). Disable ONLY for a legacy/fully
    # trusted server that cannot sign.
    auto_update_require_signature: bool = True
    # optional SHA-256 fingerprint (hex) of the backend's release-signing
    # PUBLIC key, pinned at install. When set, the fetched public key must match it
    # — defeating a compromised public-key endpoint swapping in its own key.
    release_public_key_sha256: str | None = None


class ScheduleEntry(BaseModel):
    """Scheduled scan definition."""

    name: str = ""
    scan_type: str = "quick"
    targets: list[str] = Field(default_factory=list)
    interface: str = ""
    cron: str = ""
    enabled: bool = True


class PassiveConfig(BaseModel):
    """Passive listener configuration."""

    enable_lldp: bool = False
    enable_cdp: bool = False
    enable_snmp_traps: bool = False
    snmp_trap_port: int = Field(default=162, ge=1, le=65535)
    enable_syslog: bool = False
    syslog_port: int = Field(default=514, ge=1, le=65535)
    enable_dhcp_watcher: bool = False


class Config(BaseModel):
    """Main configuration model."""

    version: str = "1"
    freesdn: FreeSDNConnection = Field(default_factory=FreeSDNConnection)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    ui: UISettings = Field(default_factory=UISettings)
    daemon: DaemonConfig = Field(default_factory=DaemonConfig)
    schedules: list[ScheduleEntry] = Field(default_factory=list)
    passive: PassiveConfig = Field(default_factory=PassiveConfig)
    recent_interfaces: list[str] = Field(default_factory=list)
    
    @classmethod
    def get_config_dir(cls) -> Path:
        """Get the platform-specific config directory."""
        config_dir = Path(user_config_dir(__app_name__, "FreeSDN"))
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir
    
    @classmethod
    def get_config_file(cls) -> Path:
        """Get the config file path."""
        return cls.get_config_dir() / "config.json"
    
    @classmethod
    def load(cls) -> "Config":
        """Load configuration from disk or create default."""
        config_file = cls.get_config_file()
        
        if config_file.exists():
            try:
                data = json.loads(config_file.read_text(encoding="utf-8"))
                logger.info(f"Loaded config from {config_file}")
                return cls.model_validate(data)
            except Exception as e:
                logger.warning(f"Failed to load config: {e}, using defaults")
        
        logger.info("Using default configuration")
        return cls()
    
    def save(self) -> None:
        """Save configuration to disk."""
        config_file = self.get_config_file()
        
        try:
            config_file.write_text(
                self.model_dump_json(indent=2),
                encoding="utf-8"
            )
            logger.info(f"Saved config to {config_file}")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            raise
    
    def update(self, **kwargs: Any) -> None:
        """Update config fields and save."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.save()


# Global config instance (lazy loaded)
_config: Config | None = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = Config.load()
    return _config


def reset_config() -> Config:
    """Reset to default configuration."""
    global _config
    _config = Config()
    _config.save()
    return _config
