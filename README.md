# FreeSDN Agent

Site-local discovery daemon for the [FreeSDN](https://freesdn.org) platform.

**License:** MIT &nbsp;|&nbsp; **Releases:** [GitHub Releases](https://github.com/freesdn/freesdn-agent/releases) (signed) &nbsp;|&nbsp; **Core:** [github.com/freesdn/freesdn](https://github.com/freesdn/freesdn)

---

## What it does

The agent runs on a host inside your network and handles the discovery work
that a containerized backend cannot: Layer 2 scans, raw-socket protocols, and
passive traffic listeners that need access to the actual wire.

- **Active scanning** - ARP, ICMP, TCP port, ONVIF WS-Discovery (cameras),
  Hikvision SADP, NetBIOS/SMB, SIP, mDNS, SSDP
- **Discovery push** - found hosts upserted into the FreeSDN backend,
  de-duplicated by site + MAC, auto-routed to the correct site by subnet match
- **Adoption** - operators promote a discovered host into a managed device row
  from the web UI or CLI; the agent suggests the driver
- **Scheduled scans** - cron-based, managed from the web UI, delivered to the
  agent over WebSocket on change
- **Passive topology** - LLDP listener (daemon mode) pushes Layer 2 edges to
  the topology view
- **Auto-update** - the agent checks for new releases on a configurable
  interval, downloads the binary, verifies SHA-256 and an ECDSA-P256
  signature from the server, stages, and restarts with a rollback marker

All of this is reflected in the FreeSDN web UI: the Agents page shows
connection state, recent runs, discovered hosts, and topology edges per
agent. Per-agent Prometheus metrics are also available.

## Install

Download the installer for your platform from the
[Releases page](https://github.com/freesdn/freesdn-agent/releases).
Every release is signed - see [Signed releases](#signed-releases) below.

**Linux (deb)**

```bash
sudo dpkg -i freesdn-agent_*.deb
sudo freesdn-agent register --server https://freesdn.example.com --site-id <uuid>
sudo systemctl enable --now freesdn-agent
```

**Windows (MSI)**

```powershell
# Run the MSI installer, then register:
freesdn-agent register --server https://freesdn.example.com --site-id <uuid>
# Run in the foreground to verify, or install it as a Windows service - see DEPLOYMENT.md.
freesdn-agent daemon
```

**macOS (pkg)**

```bash
sudo installer -pkg freesdn-agent-*.pkg -target /
sudo freesdn-agent register --server https://freesdn.example.com --site-id <uuid>
sudo launchctl load -w /Library/LaunchDaemons/com.freesdn.agent.plist
```

The `register` command prompts for your FreeSDN admin credentials, creates the
agent row in the backend, and stores the API key in the OS keyring (Windows
Credential Manager, macOS Keychain, Linux Secret Service). The key is never
written to the config file on disk.

After registering, approve the agent in the web UI under Site - Agent tab.

## Signed releases

Every release binary is signed with ECDSA-P256. The agent verifies the
signature on every auto-update before staging the new binary. The public
verification key is served by your FreeSDN instance at
`GET /api/v1/agents/releases/public-key` and is independent of the download
itself, so a compromised download source cannot swap binary and signature
together without also controlling the signing key.

## CLI quick reference

```
freesdn-agent register   --server URL --site-id UUID
freesdn-agent status
freesdn-agent daemon                  # run in foreground (or under a service manager)
freesdn-agent unregister

freesdn-agent scan --type quick --targets 192.168.1.0/24
freesdn-agent list-discovered
freesdn-agent adopt 192.168.1.50
freesdn-agent adopt all

freesdn-agent schedule list
freesdn-agent schedule add --name nightly --cron "0 2 * * *" --targets 10.0.0.0/24
```

Schedules created here sync to the FreeSDN backend. Schedules created in
the web UI are pushed to the agent over WebSocket.

## Platforms

| Platform | Status |
|---|---|
| Windows 10 / 11 | Primary |
| Ubuntu 22.04+ | Supported (root needed for raw-socket scans) |
| macOS 12+ | Supported |

Raw-socket scans (LLDP, some ARP variants) need Administrator on Windows or
root on Linux/macOS. Plain ping and TCP-connect scans work without elevated
privileges.

## Documentation

Full deployment runbook, troubleshooting guide, and config reference:
[AGENT.md](AGENT.md) and [DEPLOYMENT.md](DEPLOYMENT.md) in this repo.

## Contributing

FreeSDN is developed in-house by the small team that runs it in production
and does not accept external code contributions; this repo follows the same
policy. Bug reports and real-hardware field reports are welcome via GitHub
Issues. Two optional ways to support development: donate hardware
(`hardware@freesdn.org`), or fuel the build - the team builds and reviews with
AI tooling, so gifting a Claude or OpenAI Codex subscription
(`fuel@freesdn.org`) directly funds that work. See the
[core CONTRIBUTING guide](https://github.com/freesdn/freesdn/blob/main/CONTRIBUTING.md)
for the full reasoning.

## License

MIT. See [LICENSE](LICENSE). The FreeSDN core that this agent connects to is
[AGPL-3.0-only](https://github.com/freesdn/freesdn/blob/main/LICENSE).
