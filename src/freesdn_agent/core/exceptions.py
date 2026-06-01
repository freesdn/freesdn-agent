"""
Custom exceptions for FreeSDN Agent.
"""


class AgentError(Exception):
    """Base exception for all agent errors."""
    pass


class ScanError(AgentError):
    """Error during network scanning."""
    pass


class PrivilegeError(AgentError):
    """Insufficient privileges for operation."""
    pass


class ConnectionError(AgentError):
    """Error connecting to FreeSDN server."""
    pass


class AuthenticationError(AgentError):
    """Authentication with FreeSDN failed."""
    pass


class ConfigurationError(AgentError):
    """Invalid configuration."""
    pass
