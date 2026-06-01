# FreeSDN Agent

A site-local network discovery + automation daemon that connects to a
FreeSDN control plane. Runs on Windows, Linux, and macOS as either a
GUI (one-off scans, manual adoption) or a background daemon (scheduled
scans, passive LLDP, auto-update).

## What it does

- **Active scans** - ARP, ICMP, port, ONVIF, SADP, NetBIOS/SMB, SIP,
  mDNS, SSDP across configured subnets.
- **Discovery push** - found hosts upserted into
  `devices.discovered_hosts` on the backend, deduped by site + MAC
  (or site + IP when MAC unknown), routed to the correct site by
  `Site.subnets` CIDR match.
- **Adoption** - operator promotes a discovered host into a managed
  `Device` row with auto-matched driver (or per-row override).
- **Scheduled scans** - cron-based, managed from the web UI or CLI,
  pushed to the agent via WS on change.
- **Run history + alerts** - every scheduled run records to
  `agent_schedule_runs` and can fire Slack / email notifications on
  failure or when N+ new devices are found.
- **L2 topology** - passive LLDP listener (daemon mode) and active
  30-second sniff (GUI Full Scan) push edges to
  `devices.topology_edges`.
- **Auto-update** - agent checks the backend for new releases on a
  configurable interval, downloads + verifies SHA-256 + verifies
  ECDSA-P256 signature, stages, and restarts with rollback marker.
- **Offline detection** - backend periodic task alerts via the
  configured notification channels when an agent's heartbeat goes
  stale.

## End-to-end lifecycle

```
┌─────────────┐     register     ┌─────────────┐
│   Operator  │ ───────────────▶ │  FreeSDN BE │
└─────────────┘                  └──────┬──────┘
                                        │
                                        │ stores agent + key
                                        ▼
┌─────────────┐    WS connect    ┌─────────────┐
│  Agent host │ ───────────────▶ │  WS handler │ ──┐
└──────┬──────┘    (handshake)   └─────────────┘   │
       │                                            │
       │ ◀──── bootstrap-push schedules ────────────┘
       │
       │ heartbeat every 30s
       │
       │ cron fires
       │   ┌─────────────┐
       │   │ Run scan    │
       │   │ Find hosts  │
       │   │ Push via WS │ ────▶  discovered_hosts (auto-routed)
       │   │ Record run  │ ────▶  agent_schedule_runs
       │   │ Maybe alert │ ────▶  Slack / email
       │   └─────────────┘
       │
       │ Full scan (GUI) → LLDP sniff (30s) → POST /discovery/topology-edges/batch
       │
       │ Auto-update tick
       │   ├─ GET /agents/updates/check (with X-Agent-Key)
       │   ├─ Download binary (with X-Agent-Key)
       │   ├─ Verify SHA-256 + ECDSA-P256 signature
       │   ├─ Stage + write rollback marker
       │   └─ Restart
       │
       │ Heartbeat lapses >threshold
       ▼
  ┌────────────────┐
  │  Backend task  │  Mark offline + dispatch alert (once per transition)
  └────────────────┘
```

## Installation

### Linux

```bash
# After downloading the package
sudo dpkg -i freesdn-agent_*.deb
sudo freesdn-agent register --server https://freesdn.example.com --site-id <uuid>
sudo systemctl enable --now freesdn-agent
journalctl -u freesdn-agent -f
```

### Windows

```powershell
# After running the MSI installer
freesdn-agent register --server https://freesdn.example.com --site-id <uuid>
# Run as a Windows service via NSSM (see DEPLOYMENT.md for the full recipe):
nssm install FreeSDN-Agent "C:\Program Files\FreeSDN Agent\freesdn-agent.exe" daemon
nssm start FreeSDN-Agent
```

### macOS

```bash
sudo installer -pkg freesdn-agent-*.pkg -target /
sudo freesdn-agent register --server https://freesdn.example.com --site-id <uuid>
sudo launchctl load -w /Library/LaunchDaemons/com.freesdn.agent.plist
```

## Configuration

Config lives at:
- Linux: `~/.config/FreeSDN Agent/config.json`
- macOS: `~/Library/Application Support/FreeSDN Agent/config.json`
- Windows: `%LOCALAPPDATA%\FreeSDN\FreeSDN Agent\config.json`

Key sections:

```jsonc
{
  "freesdn": { "url": "https://...", "site_id": "..." },
  "daemon": {
    "agent_id": "...",            // populated by `register`
    "websocket_url": "ws://...",
    "heartbeat_interval": 30,     // seconds
    "auto_update_enabled": true,
    "auto_update_interval": 300,  // 5 min minimum
    "auto_update_channel": "stable"
  },
  "schedules": [],                // local schedules; backend-managed
                                  // schedules arrive via WS bootstrap
  "passive": {
    "enable_lldp": false,         // daemon mode only; needs raw socket
    "enable_cdp": false,
    "enable_snmp_traps": false
  }
}
```

The agent's API key is stored in the OS keyring (Windows Credential
Manager / macOS Keychain / Linux Secret Service), never in the JSON
config.

## CLI reference

```bash
# Lifecycle
freesdn-agent register --server URL --site-id UUID
freesdn-agent unregister
freesdn-agent status
freesdn-agent daemon                # run in foreground (or under systemd/NSSM/launchd)

# Scans
freesdn-agent scan --type quick --targets 192.168.1.0/24
freesdn-agent list-discovered       # show unadopted hosts
freesdn-agent adopt 192.168.1.150    # adopt single
freesdn-agent adopt all             # adopt every unadopted host

# Schedules (backend-managed; agent auto-syncs on WS connect)
freesdn-agent schedule list
freesdn-agent schedule add --name nightly --cron "0 2 * * *" --targets 192.168.1.0/24
freesdn-agent schedule remove <id>
```

## Backend endpoints used

| Verb | Path | Purpose |
|------|------|---------|
| POST | `/api/v1/auth/login` | initial register-time auth |
| POST | `/api/v1/agents/register` | register a new agent row |
| POST | `/api/v1/agents/{id}/approve` | admin approves the agent |
| WS   | `/api/v1/agents/ws/{id}` | persistent control channel |
| POST | `/api/v1/agents/{id}/heartbeat` | non-WS heartbeat fallback |
| POST | `/api/v1/discovery/results` | push found hosts |
| POST | `/api/v1/discovery/topology-edges/batch` | push LLDP edges (GUI) |
| GET  | `/api/v1/agents/updates/check` | self-update check (X-Agent-Key) |
| GET  | `/api/v1/agents/releases/public-key` | ECDSA verify key |
| GET  | `/api/v1/agents/releases/{id}/binary` | download (X-Agent-Key) |
| GET  | `/api/v1/agents/schedules?site_id=X` | list schedules (operator) |
| POST | `/api/v1/agents/schedules?site_id=X` | create schedule (operator) |

## Security model

- **Agent auth** is hash-based: the agent_key (random base64 url-safe
  string) is stored in the keyring; the backend stores SHA-256 of the
  key. Every authenticated request sends `X-Agent-ID` +
  `X-Agent-Key` and the backend compares hashes.
- **Release downloads** require the same X-Agent-Key headers.
  Unguessable UUIDs are no longer the only defense.
- **Release signing** uses backend-generated ECDSA-P256. Agents
  fetch the public key once + verify each download. A compromised
  backend that swapped both binary AND checksum would also need the
  private signing key.
- **Multi-tenant**: releases are scoped by `organization_id` (NULL
  rows are legacy globals visible to everyone but only mutable by
  super_admin).
- **WS connections** use the agent_key to authenticate at the
  handshake. Site_id spoofing is rejected.

## Observability

- **Web UI Agents page** (`/agents`) - fleet dashboard: connection
  state, recent runs, discovered hosts, last fired.
- **Per-agent drilldown** (`/agents/{id}`) - schedules, runs,
  discoveries, topology edges, configure-alerts dialog.
- **Prometheus** - `GET /api/v1/agents/{id}/metrics` returns
  text-format metrics (`freesdn_agent_up`,
  `freesdn_agent_heartbeat_age_seconds`, `freesdn_agent_runs_24h_*`,
  `freesdn_agent_discovered_hosts_total`).
- **Notifications** - per-schedule (failure / N+ new) and per-agent
  (offline) channels via the existing dispatch_notifications
  pipeline (email / Slack / Teams / webhook).

## Troubleshooting

See `agent/DEPLOYMENT.md` for the troubleshooting runbook covering
five common operational scenarios (keyring missing, schedule never
fires, results don't appear, multi-agent racing, uninstall).
