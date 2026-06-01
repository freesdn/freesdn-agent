"""Business services for FreeSDN Agent.

Importing this package must not pull in optional GUI dependencies
(PySide6). The desktop ``scan_manager`` lives in this directory but is
NOT re-exported here — daemon code imports it explicitly via the full
module path, and the desktop GUI imports it from there too. Re-exporting
it at package level coupled the daemon's services package to Qt and
broke test collection in headless / daemon-only environments.

Callers that want the GUI scan orchestrator should import:
    from freesdn_agent.services.scan_manager import ScanManager

Callers that want the daemon-side async scanner should import:
    from freesdn_agent.services.async_scan_manager import AsyncScanManager
"""

from freesdn_agent.services.oui_lookup import lookup_vendor

__all__ = [
    "lookup_vendor",
]
