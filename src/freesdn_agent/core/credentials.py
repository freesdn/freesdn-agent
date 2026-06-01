"""
Secure credentials management for FreeSDN Agent.

Uses the system keyring (Windows Credential Manager, macOS Keychain, 
Linux Secret Service) to securely store authentication credentials.
"""

import logging
from typing import Optional, NamedTuple

logger = logging.getLogger(__name__)

# Service name for keyring storage
SERVICE_NAME = "FreeSDN Agent"


class Credentials(NamedTuple):
    """Stored credentials."""
    username: str
    password: str


def save_credentials(url: str, username: str, password: str) -> bool:
    """
    Save credentials to system keyring.
    
    Args:
        url: Server URL (used as account identifier)
        username: Username
        password: Password
        
    Returns:
        True if saved successfully, False otherwise
    """
    try:
        import keyring
        
        # Store username and password separately
        # Use URL as the "account" to support multiple servers
        account_key = _normalize_url(url)
        
        keyring.set_password(SERVICE_NAME, f"{account_key}:username", username)
        keyring.set_password(SERVICE_NAME, f"{account_key}:password", password)
        
        logger.info(f"Saved credentials for {account_key}")
        return True
        
    except ImportError:
        logger.warning("keyring module not available, credentials will not be persisted")
        return False
    except Exception as e:
        logger.error(f"Failed to save credentials: {e}")
        return False


def load_credentials(url: str) -> Optional[Credentials]:
    """
    Load credentials from system keyring.
    
    Args:
        url: Server URL to load credentials for
        
    Returns:
        Credentials if found, None otherwise
    """
    try:
        import keyring
        
        account_key = _normalize_url(url)
        
        username = keyring.get_password(SERVICE_NAME, f"{account_key}:username")
        password = keyring.get_password(SERVICE_NAME, f"{account_key}:password")
        
        if username and password:
            logger.debug(f"Loaded credentials for {account_key}")
            return Credentials(username=username, password=password)
        
        return None
        
    except ImportError:
        logger.warning("keyring module not available")
        return None
    except Exception as e:
        logger.error(f"Failed to load credentials: {e}")
        return None


def delete_credentials(url: str) -> bool:
    """
    Delete credentials from system keyring.
    
    Args:
        url: Server URL to delete credentials for
        
    Returns:
        True if deleted successfully, False otherwise
    """
    try:
        import keyring
        
        account_key = _normalize_url(url)
        
        try:
            keyring.delete_password(SERVICE_NAME, f"{account_key}:username")
        except keyring.errors.PasswordDeleteError:
            pass  # Already deleted
            
        try:
            keyring.delete_password(SERVICE_NAME, f"{account_key}:password")
        except keyring.errors.PasswordDeleteError:
            pass  # Already deleted
        
        logger.info(f"Deleted credentials for {account_key}")
        return True
        
    except ImportError:
        logger.warning("keyring module not available")
        return False
    except Exception as e:
        logger.error(f"Failed to delete credentials: {e}")
        return False


def has_credentials(url: str) -> bool:
    """
    Check if credentials exist for the given URL.
    
    Args:
        url: Server URL to check
        
    Returns:
        True if credentials exist, False otherwise
    """
    creds = load_credentials(url)
    return creds is not None


def _normalize_url(url: str) -> str:
    """
    Normalize URL for use as keyring account key.
    
    Removes protocol and trailing slashes for consistency.
    """
    url = url.strip()
    
    # Remove protocol
    for prefix in ["https://", "http://"]:
        if url.lower().startswith(prefix):
            url = url[len(prefix):]
            break
    
    # Remove trailing slash
    url = url.rstrip("/")
    
    return url.lower()
