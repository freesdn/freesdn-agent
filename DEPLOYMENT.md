# FreeSDN Agent - Deployment runbook

This runbook covers running the agent as a background daemon against a
FreeSDN control plane. The agent does two things:

- Continuously listens for server commands over WebSocket (heartbeats,
  manual scans, schedule updates, restart).
- Fires scheduled scans (cron-based) and pushes results back to the
  control plane.

The GUI (`run.py` / FreeSDN Agent.exe) and the daemon
(`freesdn-agent daemon`) share the same code and config. Use the GUI
for one-off scans + initial registration. Use the daemon for ongoing
unattended operation.

## Prerequisites

- The agent's host must reach the FreeSDN control plane on TCP 8000
  (or whatever port your `server_url` uses).
- Raw-socket scans (LLDP, CDP, some ARP variants) need root on Linux
  or Administrator on Windows. Plain ping + TCP-connect scans work
  unprivileged.
- The control plane must have a `RemoteAgent` row pre-registered for
  this host. Register either via the web UI (Site detail → Agent tab
  → Register agent) or via the CLI `freesdn-agent register`.

## 1. Register the agent

From the host that will run the daemon:

```bash
freesdn-agent register \
    --server http://controlplane.example.com:8000 \
    --site-id <site-uuid>
```

Prompts for an admin login (your FreeSDN account email + password).
On success it:

1. Calls `POST /api/v1/agents/register` with the host's name + site.
2. Stores `agent_id`, `server_url`, `websocket_url`, `site_id` in
   `~/.config/FreeSDN Agent/config.json` (Linux/macOS) or
   `%LOCALAPPDATA%\FreeSDN\FreeSDN Agent\config.json` (Windows).
3. Saves the agent's API key to the OS keyring (Windows Credential
   Manager / macOS Keychain / Linux Secret Service).

Verify with `freesdn-agent status`.

## 2. Run in foreground (smoke test)

```bash
freesdn-agent daemon
```

You should see:

```
FreeSDN Agent Daemon v1.0.0 starting (agent_id=…, server=…)
Connecting to ws://…/api/v1/agents/ws/<agent_id>
Authenticated: Connected as <agent-name>
Reloading 1 schedule(s)
Loaded schedule '<name>': '<cron>'
Heartbeat service started (every 30s)
```

The schedule list comes from the backend's bootstrap-push on WS
connect - it does NOT need to be in the local config.json. Any
schedule created via the web UI or `freesdn-agent schedule add`
arrives via the same channel and the scheduler hot-reloads.

When a schedule's cron matches, the agent runs the scan and pushes
results to the control plane:

```
Scheduled scan firing: '<name>' (<cron>)
Scan completed: N devices found
Scheduled scan '<name>' completed in <N>s: N device(s)
```

Backend logs (`docker logs freesdn-api | grep schedule`):

```
Persisted scan_result from agent <id>: {'created': X, 'updated': Y, ...}
Recorded schedule run: <name> (status=completed, devices=N)
```

You can verify via the web UI:

- Agents page → Recent Activity panel shows the latest run.
- Sites → Site detail → Agent tab → Scheduled Scans → "Last fired"
  column shows relative time; History icon opens the run dialog.
- Discovery → Discovered Hosts → new IPs appear here.

## 3. Run as a system service

### Linux (systemd)

```bash
# The .deb ships the systemd unit; enable and start it:
sudo systemctl daemon-reload
sudo systemctl enable --now freesdn-agent.service
sudo systemctl status freesdn-agent.service
journalctl -u freesdn-agent.service -f
```

The unit file lives at `/etc/systemd/system/freesdn-agent.service` and
runs the daemon under `root` with `CAP_NET_RAW`. Edit the unit to
drop those caps if you only need ICMP/TCP scans.

### Windows (NSSM)

Register the daemon as a Windows service with [NSSM](https://nssm.cc).
From an elevated PowerShell:

```powershell
nssm install FreeSDN-Agent "C:\Path\To\freesdn-agent.exe" daemon
nssm set FreeSDN-Agent AppStdout "C:\ProgramData\FreeSDN\agent.log"
nssm set FreeSDN-Agent AppStderr "C:\ProgramData\FreeSDN\agent.log"
nssm start FreeSDN-Agent
```

### macOS (launchd)

```bash
# The .pkg ships the launchd plist; load and start it:
sudo launchctl bootstrap system /Library/LaunchDaemons/com.freesdn.agent.plist
sudo launchctl start com.freesdn.agent
```

## 4. Managing schedules

CLI:

```bash
# List existing schedules at this site
freesdn-agent schedule list

# Add one
freesdn-agent schedule add \
    --name lab-quick-4h \
    --cron "0 */4 * * *" \
    --scan-type quick \
    --targets 192.168.1.0/24

# Remove
freesdn-agent schedule remove <schedule-uuid>
```

Web UI: Site detail → Agent tab → Scheduled Scans → "New schedule".

Cron format: standard 5-field (minute hour day month weekday). Minimum
fire interval is 5 minutes - sub-minute crons are loaded but skipped
by the agent's safety check.

## 5. Common issues

### "Agent key not found in keyring"

The agent stored its key in the OS keyring during registration but a
different user is now running the daemon (or the keyring backend
changed). Re-register:

```bash
freesdn-agent unregister
freesdn-agent register --server ... --site-id ...
```

### Schedule loaded but never fires

- Check that the cron expression matches more than once per 5 minutes
  in calendar terms (e.g. `* * * * *` fires too often and gets
  silently dropped).
- The scheduler only ticks every 60 seconds - a one-off fire scheduled
  for a past minute won't catch up.
- Check `journalctl -u freesdn-agent.service` for "Schedule … fires
  too frequently" warnings.

### Schedule fires but results don't appear in the web UI

- Confirm the agent's WS connection stayed up through the scan. Look
  for "Reconnecting in Ns" lines in the daemon log - if the WS
  dropped during the scan, the `scan_result` send goes to a stale
  queue.
- Backend log: `docker logs freesdn-api | grep scan_result` should
  show a "Persisted scan_result" line for each run.
- Schedule names are case-sensitive when matching to record the run.
  If you renamed a schedule mid-fire, the run will persist devices
  but skip the schedule-run insert.

### Multiple agents at the same site

The backend's `push_schedules_to_agents` fans schedule changes out to
every connected agent at the site. To pin a schedule to one specific
agent, set `agent_id` when creating it (via API or "Agent" dropdown
on the new-schedule dialog when it ships). Pinned schedules only
reach that agent; site-wide schedules reach every connected agent at
the site.

## 6. Uninstall

```bash
sudo systemctl disable --now freesdn-agent.service
sudo rm /etc/systemd/system/freesdn-agent.service
freesdn-agent unregister  # removes keyring entry + clears config
```

Web UI: Agents page → row's "..." menu → Delete (soft-deletes the
`RemoteAgent` row; existing discovered_hosts + schedule_runs stay).
