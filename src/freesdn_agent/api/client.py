"""
FreeSDN API Client.

Handles REST API communication with FreeSDN server.
"""

import logging
from typing import Optional, Any
from datetime import datetime, timedelta

import httpx
from pydantic import BaseModel

from freesdn_agent.core.exceptions import ConnectionError, AuthenticationError

logger = logging.getLogger(__name__)


class TokenInfo(BaseModel):
    """JWT token information."""
    access_token: str
    refresh_token: str
    expires_at: datetime


class FreeSDNClient:
    """REST API client for FreeSDN server."""
    
    def __init__(self, base_url: str):
        """
        Initialize the client.
        
        Args:
            base_url: FreeSDN server URL (e.g., https://freesdn.example.com)
        """
        self.base_url = base_url.rstrip("/")
        self._token_info: Optional[TokenInfo] = None
        self._client: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self) -> "FreeSDNClient":
        """Async context manager entry."""
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30.0,
            follow_redirects=True,
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    @property
    def is_authenticated(self) -> bool:
        """Check if client has valid authentication."""
        if not self._token_info:
            return False
        # Check if token is expired (with 1 minute buffer)
        return datetime.utcnow() < self._token_info.expires_at - timedelta(minutes=1)
    
    async def login(self, username: str, password: str) -> bool:
        """
        Authenticate with FreeSDN server via OAuth2 password grant.

        Uses /auth/token (OAuth2 form endpoint) which returns raw bearer tokens
        in the JSON body — the correct path for non-browser agent clients.
        /auth/login is the browser endpoint and no longer returns tokens in the
        JSON body.

        Args:
            username: Username (email)
            password: Password

        Returns:
            True if authentication successful

        Raises:
            AuthenticationError: If authentication fails
        """
        if not self._client:
            raise ConnectionError("Client not initialized. Use async context manager.")

        try:
            # Use OAuth2 password-grant endpoint which returns bearer tokens in
            # the response body.  The browser /auth/login endpoint no longer
            # returns tokens in JSON (tokens are httpOnly
            # cookies for browsers; Bearer headers for API / agent callers).
            response = await self._client.post(
                "/api/v1/auth/token",
                data={"username": username, "password": password},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if response.status_code == 200:
                data = response.json()
                self._token_info = TokenInfo(
                    access_token=data["access_token"],
                    refresh_token=data["refresh_token"],
                    expires_at=datetime.utcnow() + timedelta(seconds=data.get("expires_in", 3600)),
                )
                # Store credentials so refresh_token() can re-authenticate
                # when the access token expires (/auth/refresh
                # no longer returns tokens in JSON; agent must re-login via
                # /auth/token instead).
                self._stored_creds = {"username": username, "password": password}
                logger.info(f"Successfully authenticated as {username}")
                return True
            elif response.status_code == 401:
                raise AuthenticationError("Invalid username or password")
            else:
                raise AuthenticationError(f"Authentication failed: {response.status_code}")

        except httpx.RequestError as e:
            raise ConnectionError(f"Failed to connect to server: {e}")
    
    async def refresh_token(self) -> bool:
        """Refresh the access token via the OAuth2 /auth/token endpoint.

        /auth/refresh is the browser cookie endpoint and no longer returns raw
        tokens in the JSON body.  Non-browser agent callers
        that need a fresh bearer token should re-authenticate via
        POST /auth/token (OAuth2 password grant) which always returns tokens in
        the response body.

        Note: this client stores credentials only for the session; if they are
        no longer available the method returns False and the caller must invoke
        ``login()`` with fresh credentials.
        """
        if not self._client or not self._token_info:
            return False

        # Stored credentials for re-authentication.  The attribute is only
        # present when the caller used ``login_with_credentials()`` (see below).
        creds = getattr(self, "_stored_creds", None)
        if not creds:
            logger.warning(
                "Cannot refresh token: no stored credentials available. "
                "Call login() again with username/password."
            )
            return False

        try:
            return await self.login(creds["username"], creds["password"])
        except Exception as e:
            logger.warning(f"Failed to refresh token: {e}")
            return False
    
    def _get_headers(self) -> dict:
        """Get request headers with authentication."""
        headers = {"Content-Type": "application/json"}
        if self._token_info:
            headers["Authorization"] = f"Bearer {self._token_info.access_token}"
        return headers
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> httpx.Response:
        """Make an authenticated request."""
        if not self._client:
            raise ConnectionError("Client not initialized")
        
        # Refresh token if needed
        if self._token_info and not self.is_authenticated:
            await self.refresh_token()
        
        headers = self._get_headers()
        headers.update(kwargs.pop("headers", {}))
        
        return await self._client.request(
            method,
            endpoint,
            headers=headers,
            **kwargs
        )
    
    # --- API Methods ---
    
    async def get_sites(self) -> list[dict]:
        """Get list of sites."""
        response = await self._request("GET", "/api/v1/sites")
        response.raise_for_status()
        return response.json()
    
    async def get_devices(self, site_id: Optional[str] = None) -> list[dict]:
        """Get list of devices."""
        params = {}
        if site_id:
            params["site_id"] = site_id
        
        response = await self._request("GET", "/api/v1/devices", params=params)
        response.raise_for_status()
        return response.json()
    
    async def create_device(self, device_data: dict) -> dict:
        """Create a new device."""
        response = await self._request("POST", "/api/v1/devices", json=device_data)
        response.raise_for_status()
        return response.json()
    
    async def bulk_create_devices(self, devices: list[dict]) -> dict:
        """Bulk create devices."""
        response = await self._request(
            "POST",
            "/api/v1/devices/bulk",
            json={"devices": devices}
        )
        response.raise_for_status()
        return response.json()
    
    async def push_discovery_results(self, results: list[dict], site_id: str) -> dict:
        """Push discovery results to FreeSDN's POST /api/v1/discovery/results.

        Pass-through; backend Pydantic shapes / discards unknown fields.
        Returns the upsert summary: ``{created, updated, skipped, site_id}``.
        """
        response = await self._request(
            "POST",
            "/api/v1/discovery/results",
            json={"results": results, "site_id": site_id}
        )
        response.raise_for_status()
        return response.json()
    
    async def test_connection(self) -> bool:
        """Test connection to FreeSDN server."""
        try:
            if not self._client:
                async with httpx.AsyncClient(base_url=self.base_url, timeout=10.0) as client:
                    # Try /health first (root level), then /api/v1/health as fallback
                    response = await client.get("/health")
                    if response.status_code == 200:
                        return True
                    response = await client.get("/api/v1/health")
                    return response.status_code == 200
            else:
                response = await self._client.get("/health")
                if response.status_code == 200:
                    return True
                response = await self._client.get("/api/v1/health")
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"Connection test failed: {e}")
            return False


class SyncFreeSDNClient:
    """
    Synchronous wrapper for FreeSDNClient.
    
    Use this from UI code where async is not convenient.
    """
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self._token_info: Optional[TokenInfo] = None
    
    def _get_client(self) -> httpx.Client:
        """Get a sync HTTP client."""
        return httpx.Client(
            base_url=self.base_url,
            timeout=30.0,
            follow_redirects=True,
        )
    
    def _get_headers(self) -> dict:
        """Get request headers with authentication."""
        headers = {"Content-Type": "application/json"}
        if self._token_info:
            headers["Authorization"] = f"Bearer {self._token_info.access_token}"
        return headers
    
    @property
    def is_authenticated(self) -> bool:
        """Check if client has valid authentication."""
        if not self._token_info:
            return False
        return datetime.utcnow() < self._token_info.expires_at - timedelta(minutes=1)
    
    def test_connection(self) -> bool:
        """Test connection to FreeSDN server."""
        try:
            with self._get_client() as client:
                # Try /health first (root level), then /api/v1/health as fallback
                response = client.get("/health")
                if response.status_code == 200:
                    return True
                # Try alternate endpoint
                response = client.get("/api/v1/health")
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"Connection test failed: {e}")
            return False
    
    def login(self, username: str, password: str) -> bool:
        """Authenticate with FreeSDN server via the OAuth2 password grant.

        Uses /auth/token (OAuth2 form endpoint), which returns bearer tokens in
        the JSON body — the correct path for non-browser agent clients. The
        browser /auth/login endpoint no longer returns tokens in JSON
: tokens are httpOnly cookies for browsers and Bearer
        headers for API / agent callers.
        """
        try:
            with self._get_client() as client:
                response = client.post(
                    "/api/v1/auth/token",
                    data={"username": username, "password": password},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                if response.status_code == 200:
                    data = response.json()
                    self._token_info = TokenInfo(
                        access_token=data["access_token"],
                        refresh_token=data["refresh_token"],
                        expires_at=datetime.utcnow() + timedelta(seconds=data.get("expires_in", 3600))
                    )
                    logger.info(f"Successfully authenticated as {username}")
                    return True
                elif response.status_code == 401:
                    raise AuthenticationError("Invalid username or password")
                else:
                    raise AuthenticationError(f"Authentication failed: {response.status_code}")

        except httpx.RequestError as e:
            raise ConnectionError(f"Failed to connect to server: {e}")
    
    def get_sites(self) -> list[dict]:
        """Get list of sites."""
        with self._get_client() as client:
            response = client.get("/api/v1/sites", headers=self._get_headers())
            response.raise_for_status()
            return response.json()
    
    def get_devices(self, site_id: Optional[str] = None) -> list[dict]:
        """Get list of devices."""
        params = {}
        if site_id:
            params["site_id"] = site_id

        with self._get_client() as client:
            response = client.get("/api/v1/devices", params=params, headers=self._get_headers())
            response.raise_for_status()
            return response.json()

    def get_discovered_hosts(
        self,
        site_id: Optional[str] = None,
        show_adopted: bool = False,
        limit: int = 500,
    ) -> list[dict]:
        """Get discovered hosts (devices.discovered_hosts) from the backend.

        Powers the unified Inventory panel — the agent's local scan
        results are merged with whatever the backend already knows
        about so an operator never sees a stale ghost row.
        """
        params: dict[str, Any] = {"limit": limit, "show_adopted": show_adopted}
        if site_id:
            params["site_id"] = site_id
        with self._get_client() as client:
            response = client.get(
                "/api/v1/discovery/discovered-hosts",
                params=params,
                headers=self._get_headers(),
            )
            response.raise_for_status()
            return response.json()

    def list_drivers(self) -> list[dict]:
        """List available adapter drivers from the backend.

        Backend returns the DRIVER_REGISTRY (driver_id, name, vendor,
        device_types, capabilities). The agent uses this to populate the
        driver-picker dialog when the user wants to override the
        auto-matched driver.
        """
        with self._get_client() as client:
            response = client.get("/api/v1/discovery/drivers", headers=self._get_headers())
            response.raise_for_status()
            return response.json()

    def match_driver(
        self,
        *,
        ip_address: str,
        mac_address: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: Optional[str] = None,
        open_ports: Optional[list[int]] = None,
        fingerprint_data: Optional[dict] = None,
    ) -> dict:
        """Ask the backend which driver best matches this host."""
        payload: dict[str, Any] = {
            "ip_address": ip_address,
            "open_ports": open_ports or [],
            "fingerprint_data": fingerprint_data or {},
        }
        if mac_address:
            payload["mac_address"] = mac_address
        if vendor:
            payload["vendor"] = vendor
        if device_type:
            payload["device_type"] = device_type
        with self._get_client() as client:
            response = client.post(
                "/api/v1/discovery/match-drivers",
                json=payload,
                headers=self._get_headers(),
            )
            response.raise_for_status()
            return response.json()

    def bulk_adopt_devices(self, devices: list[dict]) -> dict:
        """Adopt up to 100 discovered hosts at once via /discovery/adopt/bulk.

        Each entry must include ip_address, name, site_id. driver_id is
        optional — backend auto-matches against the matching DiscoveredHost
        and falls back to 'generic' for unknowns.
        """
        with self._get_client() as client:
            response = client.post(
                "/api/v1/discovery/adopt/bulk",
                json={"devices": devices},
                headers=self._get_headers(),
            )
            response.raise_for_status()
            return response.json()

    def get_controllers(self, site_id: Optional[str] = None) -> list[dict]:
        """List controllers (UniFi/MikroTik/OpenWrt/OPNsense/etc.).

        Controllers don't carry a MAC in the schema — match against IP/host
        instead so they get flagged as already-managed during discovery.
        """
        params = {}
        if site_id:
            params["site_id"] = site_id
        with self._get_client() as client:
            response = client.get("/api/v1/controllers/", params=params, headers=self._get_headers())
            response.raise_for_status()
            return response.json()

    def get_credentials(self, site_id: Optional[str] = None) -> list[dict]:
        """List stored credentials for the adopt-dialog picker.

        Lets the desktop adopt flow attach a credential at adoption time
        (matching the web UI), so a device that needs auth to be fully
        manageable doesn't land credential-less.
        """
        params = {}
        if site_id:
            params["site_id"] = site_id
        with self._get_client() as client:
            response = client.get(
                "/api/v1/credentials", params=params, headers=self._get_headers(),
            )
            response.raise_for_status()
            data = response.json()
            # Endpoint returns {items: [...]} — normalize to a list.
            if isinstance(data, dict):
                return data.get("items", data.get("data", []))
            return data or []

    def push_device(self, device_data: dict) -> dict:
        """Push a single device to FreeSDN."""
        with self._get_client() as client:
            response = client.post("/api/v1/devices", json=device_data, headers=self._get_headers())
            response.raise_for_status()
            return response.json()
    
    def create_device(self, site_id: str, device: dict) -> dict:
        """
        Create a device in FreeSDN.
        
        Args:
            site_id: The site UUID to add the device to
            device: Device data from scan result (ip_address, mac_address, vendor, etc.)
        
        Returns:
            Created device data from API
        """
        # Map device type from scan result to API enum
        type_mapping = {
            "switch": "switch",
            "router": "router",
            "access_point": "ap",
            "ap": "ap",
            "camera": "camera",
            "nvr": "nvr",
            "voip": "voip",
            "voip_phone": "voip",
            "unknown": "unknown",
        }
        
        device_type = device.get("device_type", "unknown")
        mapped_type = type_mapping.get(device_type.lower(), "unknown") if device_type else "unknown"
        
        # Normalize MAC address to XX:XX:XX:XX:XX:XX format
        mac_address = device.get("mac_address")
        if mac_address:
            # Remove any existing separators and convert to uppercase
            mac_clean = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
            if len(mac_clean) == 12:
                # Format as XX:XX:XX:XX:XX:XX
                mac_address = ":".join([mac_clean[i:i+2] for i in range(0, 12, 2)])
            else:
                mac_address = None  # Invalid MAC, don't send it
        
        # Build the device payload for API
        # Note: Field names match the Device model in backend
        payload = {
            "site_id": site_id,
            "name": device.get("hostname") or device.get("ip_address", "Unknown Device"),
            "vendor": device.get("vendor") or "Unknown",
            "device_type": mapped_type,
            "capabilities": [],  # List of capability strings
            "vendor_data": {
                "discovery_source": "freesdn-agent",
                "protocols": device.get("protocols", []),
            },
        }
        
        # Only include optional fields if they have values
        # Backend uses ip_address and mac_address (not ip/mac)
        ip_address = device.get("ip_address")
        if ip_address:
            payload["ip_address"] = ip_address
        
        if mac_address:
            payload["mac_address"] = mac_address
        
        hostname = device.get("hostname")
        if hostname:
            payload["hostname"] = hostname
        
        model = device.get("model")
        if model:
            payload["model"] = model
        
        logger.info(f"Creating device with payload: {payload}")
        
        with self._get_client() as client:
            response = client.post("/api/v1/devices", json=payload, headers=self._get_headers())
            if response.status_code >= 400:
                # Log the error response for debugging
                try:
                    error_body = response.json()
                    logger.error(f"API error response: {error_body}")
                except:
                    logger.error(f"API error response (raw): {response.text}")
            response.raise_for_status()
            return response.json()
    
    def push_topology_edges(self, edges: list[dict], site_id: str) -> dict:
        """Push LLDP/CDP edges captured during a GUI-mode brief sniff.

        Mirrors push_discovery_results but for the topology table.
        Edges are deduped server-side by
        (site_id, local_interface, neighbor_chassis_id, neighbor_port_id).
        """
        # Strip the internal _seen_at field; backend doesn't store it
        clean = [
            {k: v for k, v in e.items() if not k.startswith("_") and v is not None}
            for e in edges
        ]
        if not clean:
            return {"created": 0, "updated": 0, "skipped": 0}
        with self._get_client() as client:
            response = client.post(
                "/api/v1/discovery/topology-edges/batch",
                json={"site_id": site_id, "edges": clean},
                headers=self._get_headers(),
            )
            response.raise_for_status()
            return response.json()

    def push_discovery_results(self, results: list[dict], site_id: str) -> dict:
        """Push discovery results to FreeSDN's POST /api/v1/discovery/results.

        Pass-through: caller is expected to have already shaped each
        host dict via ``main_window._results_to_payload`` (or similar)
        so that ``discovered_via`` / ``open_ports`` / ``services`` /
        ``mdns_services`` / ``ssdp_info`` / ``lldp_*`` are populated.
        Backend Pydantic will silently drop any keys it doesn't know.

        Returns the upsert summary: ``{created, updated, skipped, site_id}``.
        """
        with self._get_client() as client:
            response = client.post(
                "/api/v1/discovery/results",
                json={"results": results, "site_id": site_id},
                headers=self._get_headers(),
            )
            response.raise_for_status()
            return response.json()

    def search_devices(self, search: str, site_id: Optional[str] = None) -> list[dict]:
        """
        Search devices by name, hostname, IP, or MAC address.
        
        Args:
            search: Search term (can be MAC address, IP, hostname, etc.)
            site_id: Optional site ID to restrict search
            
        Returns:
            List of matching devices
        """
        params = {"search": search}
        if site_id:
            params["site_id"] = site_id
        
        with self._get_client() as client:
            response = client.get("/api/v1/devices", params=params, headers=self._get_headers())
            response.raise_for_status()
            data = response.json()
            # Handle paginated response
            if isinstance(data, dict):
                return data.get("items", data.get("data", []))
            return data if data else []

    def check_devices_exist(self, mac_addresses: list[str], site_id: Optional[str] = None) -> dict[str, dict]:
        """
        Check which MAC addresses already exist in the database.
        
        Args:
            mac_addresses: List of MAC addresses to check
            site_id: Optional site ID to restrict search
            
        Returns:
            Dict mapping MAC addresses to device info (empty if not found)
        """
        result = {}
        
        # Normalize MACs for comparison
        def normalize_mac(mac: str) -> str:
            if not mac:
                return ""
            clean = mac.replace(":", "").replace("-", "").replace(".", "").upper()
            if len(clean) == 12:
                return ":".join([clean[i:i+2] for i in range(0, 12, 2)])
            return mac.upper()
        
        # Fetch all devices from the site (more efficient than individual lookups)
        devices = self.get_devices(site_id=site_id)
        
        # Handle paginated response
        if isinstance(devices, dict):
            devices = devices.get("items", devices.get("data", []))
        
        # Build a lookup by normalized MAC
        db_macs = {}
        for device in devices:
            mac = device.get("mac_address")
            if mac:
                db_macs[normalize_mac(mac)] = device
        
        # Check each MAC
        for mac in mac_addresses:
            normalized = normalize_mac(mac)
            if normalized in db_macs:
                result[mac] = db_macs[normalized]
        
        return result
