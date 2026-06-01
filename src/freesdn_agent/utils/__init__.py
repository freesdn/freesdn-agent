"""Utility modules for FreeSDN Agent."""

from freesdn_agent.utils.logging import setup_logging
from freesdn_agent.utils.platform import get_platform, is_windows, is_linux, is_macos
from freesdn_agent.utils.privileges import check_admin_privileges

__all__ = [
    "setup_logging",
    "get_platform",
    "is_windows",
    "is_linux",
    "is_macos",
    "check_admin_privileges",
]
