"""UI widget components for FreeSDN Agent."""

from freesdn_agent.ui.widgets.connection_panel import ConnectionPanel
from freesdn_agent.ui.widgets.scan_panel import ScanPanel
from freesdn_agent.ui.widgets.results_table import ResultsTable
from freesdn_agent.ui.widgets.progress_widget import ProgressWidget
from freesdn_agent.ui.widgets.network_selector import NetworkSelector
from freesdn_agent.ui.widgets.status_bar import AgentStatusBar
from freesdn_agent.ui.widgets.managed_devices_panel import ManagedDevicesPanel
from freesdn_agent.ui.widgets.discovery_panel import DiscoveryPanel

__all__ = [
    "ConnectionPanel",
    "ScanPanel",
    "ResultsTable",
    "ProgressWidget",
    "NetworkSelector",
    "AgentStatusBar",
    "ManagedDevicesPanel",
    "DiscoveryPanel",
]
