"""
CLI interface for FreeSDN Agent.

Commands:
  freesdn-agent register  --server URL --name NAME [--site-id UUID]
  freesdn-agent daemon    [--foreground]
  freesdn-agent status
  freesdn-agent scan      --type quick --targets 192.168.1.0/24
  freesdn-agent version
"""

import argparse
import asyncio
import getpass
import logging
import platform
import socket
import sys

from freesdn_agent import __version__, __app_name__
from freesdn_agent.core.config import Config, get_config

logger = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="freesdn-agent",
        description="FreeSDN Agent — network discovery daemon & toolkit",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    sub = parser.add_subparsers(dest="command")

    # ---- register ----
    reg = sub.add_parser("register", help="Register this agent with a FreeSDN server")
    reg.add_argument("--server", required=True, help="FreeSDN server URL")
    reg.add_argument("--name", default=None, help="Agent display name (default: hostname)")
    reg.add_argument("--site-id", default=None, help="Site UUID to assign to")
    reg.add_argument("--agent-type", default="site", help="Agent type (site, scanner, collector)")
    reg.add_argument("--description", default="", help="Agent description")

    # ---- daemon ----
    dm = sub.add_parser("daemon", help="Run the agent daemon")
    dm.add_argument("--foreground", action="store_true", help="Run in foreground (default)")

    # ---- status ----
    sub.add_parser("status", help="Show agent status and configuration")

    # ---- scan ----
    sc = sub.add_parser("scan", help="Run an ad-hoc scan")
    sc.add_argument("--type", default="quick", help="Scan type (quick, camera, voip, iot, port, windows, full)")
    sc.add_argument("--targets", nargs="*", default=[], help="Target CIDRs or IPs")
    sc.add_argument("--interface", default="", help="Network interface")

    # ---- unregister ----
    sub.add_parser("unregister", help="Remove agent registration")

    # ---- list-discovered ----
    ld = sub.add_parser(
        "list-discovered",
        help="List unadopted discovered hosts for the configured site",
    )
    ld.add_argument("--site-id", default=None, help="Override config site id")
    ld.add_argument("--limit", type=int, default=200, help="Max rows (default 200)")
    ld.add_argument("--show-adopted", action="store_true", help="Include adopted rows")

    # ---- schedule ----
    sched = sub.add_parser(
        "schedule",
        help="Manage scan schedules at the configured site",
    )
    sched_sub = sched.add_subparsers(dest="schedule_cmd")
    sched_sub.add_parser("list", help="List schedules at this site")
    sa = sched_sub.add_parser("add", help="Create a schedule")
    sa.add_argument("--name", required=True, help="Schedule name (unique per site)")
    sa.add_argument("--cron", required=True, help="5-field cron expression, e.g. '0 */4 * * *'")
    sa.add_argument("--scan-type", default="quick",
                    help="quick|camera|voip|iot|port|windows|full (default: quick)")
    sa.add_argument("--targets", nargs="*", default=[],
                    help="CIDRs/IPs to scan (defaults to checked interfaces' subnets if empty)")
    sa.add_argument("--interface", default=None, help="Optional interface override")
    sa.add_argument("--disabled", action="store_true", help="Create disabled (default: enabled)")
    sa.add_argument("--agent-id", default=None,
                    help="Bind to a specific agent (defaults to all agents at the site)")
    sr = sched_sub.add_parser("remove", help="Delete a schedule")
    sr.add_argument("schedule_id", help="UUID of the schedule to delete")

    # ---- adopt ----
    ad = sub.add_parser(
        "adopt",
        help="Adopt one or more discovered hosts (auto-matches driver by default)",
    )
    ad.add_argument(
        "ips",
        nargs="+",
        help="IP address(es) of hosts to adopt (or 'all' to adopt every unadopted host at the site)",
    )
    ad.add_argument("--site-id", default=None, help="Override config site id")
    ad.add_argument(
        "--driver",
        default=None,
        help="Override driver_id for ALL hosts (e.g. mikrotik_routeros). Omit to let the server auto-match per host.",
    )
    ad.add_argument(
        "--name-prefix",
        default="",
        help="Prepend this string to each generated device name (default: 'discovered-')",
    )
    ad.add_argument("--dry-run", action="store_true", help="Print payload + skip submit")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    handlers = {
        "register": _cmd_register,
        "daemon": _cmd_daemon,
        "status": _cmd_status,
        "scan": _cmd_scan,
        "unregister": _cmd_unregister,
        "list-discovered": _cmd_list_discovered,
        "adopt": _cmd_adopt,
        "schedule": _cmd_schedule,
    }
    return handlers[args.command](args)


# -----------------------------------------------------------------
# register
# -----------------------------------------------------------------

def _cmd_register(args: argparse.Namespace) -> int:
    """Register this agent with the FreeSDN control plane."""
    import httpx

    server = args.server.rstrip("/")
    name = args.name or socket.gethostname()

    print(f"Registering agent '{name}' with {server} …")

    payload = {
        "name": name,
        "agent_type": args.agent_type,
        "description": args.description or f"Agent on {platform.node()} ({platform.system()})",
    }
    if args.site_id:
        payload["site_id"] = args.site_id

    try:
        # We need admin auth to register.  Ask for credentials interactively.
        email = input("Admin email: ").strip()
        password = getpass.getpass("Admin password: ").strip()

        with httpx.Client(base_url=server, timeout=30) as client:
            # Login first
            login_resp = client.post("/api/v1/auth/login", json={"login": email, "password": password})
            if login_resp.status_code != 200:
                print(f"Login failed: {login_resp.status_code} — {login_resp.text}")
                return 1

            tokens = login_resp.json().get("tokens", login_resp.json())
            headers = {"Authorization": f"Bearer {tokens['access_token']}"}

            # Register agent
            resp = client.post("/api/v1/agents/register", json=payload, headers=headers)
            if resp.status_code not in (200, 201):
                print(f"Registration failed: {resp.status_code} — {resp.text}")
                return 1

            data = resp.json()

        agent_id = data["agent_id"]
        agent_key = data["agent_key"]
        ws_url = data.get("websocket_url", "")

        # Save to config
        config = get_config()
        config.daemon.agent_id = agent_id
        config.daemon.server_url = server
        config.daemon.websocket_url = ws_url
        if args.site_id:
            config.daemon.site_id = args.site_id
        config.save()

        # Save agent key to keyring
        try:
            import keyring
            keyring.set_password("FreeSDN Agent", f"agent_key:{agent_id}", agent_key)
            print("Agent key stored in system keyring.")
        except Exception as e:
            print(f"WARNING: Could not store key in keyring ({e}).")
            print(f"Agent key (save this!): {agent_key}")

        print()
        print("Registration successful!")
        print(f"  Agent ID:  {agent_id}")
        print(f"  Server:    {server}")
        print(f"  WebSocket: {ws_url}")
        print()
        print("Next steps:")
        print("  1. Ask your admin to approve this agent in the FreeSDN UI")
        print("  2. Run:  freesdn-agent daemon")
        return 0

    except httpx.RequestError as e:
        print(f"Connection error: {e}")
        return 1


# -----------------------------------------------------------------
# daemon
# -----------------------------------------------------------------

def _cmd_daemon(args: argparse.Namespace) -> int:
    """Run the daemon."""
    from freesdn_agent.daemon.main import run_daemon

    config = get_config()
    if not config.daemon.agent_id:
        print("Agent not registered. Run 'freesdn-agent register' first.")
        return 1

    print(f"Starting FreeSDN Agent Daemon v{__version__} …")
    print(f"  Agent ID: {config.daemon.agent_id}")
    print(f"  Server:   {config.daemon.server_url}")
    run_daemon(config)
    return 0


# -----------------------------------------------------------------
# status
# -----------------------------------------------------------------

def _cmd_status(args: argparse.Namespace) -> int:
    """Show agent configuration and connection status."""
    config = get_config()
    d = config.daemon

    print(f"FreeSDN Agent v{__version__}")
    print(f"  Config:    {Config.get_config_file()}")
    print()

    if not d.agent_id:
        print("  Status:    Not registered")
        print()
        print("  Run 'freesdn-agent register --server <URL>' to get started.")
        return 0

    print(f"  Agent ID:  {d.agent_id}")
    print(f"  Server:    {d.server_url}")
    print(f"  Site ID:   {d.site_id or '(not assigned)'}")
    print(f"  Heartbeat: every {d.heartbeat_interval}s")
    print(f"  Log level: {d.log_level}")

    # Check keyring
    try:
        import keyring
        key = keyring.get_password("FreeSDN Agent", f"agent_key:{d.agent_id}")
        print(f"  Key:       {'Stored in keyring' if key else 'NOT FOUND in keyring'}")
    except Exception:
        print("  Key:       keyring unavailable")

    # Show schedules
    if config.schedules:
        print()
        print("  Scheduled scans:")
        for sched in config.schedules:
            status = "enabled" if sched.enabled else "disabled"
            print(f"    - {sched.name}: {sched.scan_type} [{sched.cron}] ({status})")

    return 0


# -----------------------------------------------------------------
# scan
# -----------------------------------------------------------------

def _cmd_scan(args: argparse.Namespace) -> int:
    """Run an ad-hoc local scan."""
    from freesdn_agent.services.async_scan_manager import AsyncScanManager, ScanJob, ScanType

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    try:
        scan_type = ScanType(args.type)
    except ValueError:
        print(f"Unknown scan type: {args.type}")
        print(f"Available: {', '.join(t.value for t in ScanType)}")
        return 1

    # Auto-detect interfaces if not specified
    interfaces = []
    if args.interface:
        interfaces = [args.interface]
    else:
        try:
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                if any(not a.get("addr", "").startswith("127.") for a in addrs):
                    interfaces.append(iface)
        except ImportError:
            interfaces = ["eth0"]

    if not interfaces:
        print("No network interfaces detected.")
        return 1

    job = ScanJob(
        scan_type=scan_type,
        interfaces=interfaces,
        targets=args.targets or None,
    )

    manager = AsyncScanManager()

    def on_device(result):
        mac = result.mac_address or "N/A"
        host = result.hostname or ""
        vendor = result.vendor or ""
        print(f"  Found: {result.ip_address:16s}  {mac:18s}  {vendor:20s}  {host}")

    print(f"Running {scan_type.value} scan on {', '.join(interfaces)} …")
    print()

    results = asyncio.run(manager.run_scan(job, on_device=on_device))

    print()
    print(f"Scan complete: {len(results)} device(s) found.")
    manager.shutdown()
    return 0


# -----------------------------------------------------------------
# unregister
# -----------------------------------------------------------------

def _cmd_unregister(args: argparse.Namespace) -> int:
    """Remove agent registration."""
    config = get_config()
    d = config.daemon

    if not d.agent_id:
        print("Agent is not registered.")
        return 0

    agent_id = d.agent_id

    # Clear keyring
    try:
        import keyring
        keyring.delete_password("FreeSDN Agent", f"agent_key:{agent_id}")
        print("Agent key removed from keyring.")
    except Exception:
        pass

    # Clear config
    config.daemon.agent_id = ""
    config.daemon.server_url = ""
    config.daemon.websocket_url = ""
    config.daemon.site_id = ""
    config.save()

    print(f"Agent {agent_id} unregistered.")
    return 0


# -----------------------------------------------------------------
# Auth helpers — shared by list-discovered + adopt
# -----------------------------------------------------------------

def _login_interactive(server: str):
    """Login + return (httpx.Client, headers) for authenticated REST calls.

    Returns ``None`` on failure (caller exits 1). We don't reuse the
    sync ``FreeSDNClient`` from api/client.py here because its auth
    flow mutates persistent state on the keyring/config; the CLI is
    one-shot and should not change saved credentials.
    """
    import getpass
    import httpx

    email = input("FreeSDN email: ").strip()
    password = getpass.getpass("FreeSDN password: ").strip()

    # Use the OAuth2 password-grant endpoint (/auth/token) which returns raw
    # bearer tokens in the JSON body.  /auth/login is the browser endpoint and
    # no longer carries tokens in JSON (tokens are set as
    # httpOnly cookies for browsers; bearer header for API / agent callers).
    client = httpx.Client(base_url=server.rstrip("/"), timeout=60)
    try:
        resp = client.post(
            "/api/v1/auth/token",
            data={"username": email, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except httpx.HTTPError as exc:
        client.close()
        print(f"Login transport error: {exc}")
        return None
    if resp.status_code != 200:
        client.close()
        print(f"Login failed: {resp.status_code} — {resp.text}")
        return None
    tokens = resp.json()
    return client, {"Authorization": f"Bearer {tokens['access_token']}"}


# -----------------------------------------------------------------
# list-discovered
# -----------------------------------------------------------------

def _cmd_list_discovered(args: argparse.Namespace) -> int:
    """Pretty-print the unadopted discovered hosts at the configured site."""
    config = get_config()
    server = (config.daemon.server_url or "").rstrip("/")
    site_id = args.site_id or config.daemon.site_id
    if not server:
        print("Not configured. Run `freesdn-agent register` first.")
        return 1
    if not site_id:
        print("No site id — pass --site-id or set one via register.")
        return 1

    login = _login_interactive(server)
    if not login:
        return 1
    client, headers = login
    try:
        params = {
            "site_id": site_id,
            "limit": args.limit,
            "show_adopted": "true" if args.show_adopted else "false",
        }
        resp = client.get(
            "/api/v1/discovery/discovered-hosts", params=params, headers=headers
        )
        if resp.status_code != 200:
            print(f"List failed: {resp.status_code} — {resp.text}")
            return 1
        rows = resp.json() or []
    finally:
        client.close()

    if not rows:
        print("(no discovered hosts)")
        return 0

    print(
        f"{'IP':<16} {'MAC':<18} {'VENDOR':<24} {'HOSTNAME':<28} ADOPTED"
    )
    print("-" * 100)
    for r in rows:
        mac = r.get("mac_address") or "—"
        vendor = (r.get("vendor") or "—")[:24]
        host = (r.get("hostname") or "")[:28]
        adopted = "yes" if r.get("is_adopted") else "no"
        print(f"{r.get('ip_address', ''):<16} {mac:<18} {vendor:<24} {host:<28} {adopted}")

    print(f"\n{len(rows)} row(s).")
    return 0


# -----------------------------------------------------------------
# adopt
# -----------------------------------------------------------------

def _cmd_adopt(args: argparse.Namespace) -> int:
    """Adopt one or more discovered hosts via /discovery/adopt/bulk.

    Usage forms:
        freesdn-agent adopt 192.168.1.1 192.168.1.150
        freesdn-agent adopt all
        freesdn-agent adopt 192.168.1.150 --driver mikrotik_routeros
    """
    config = get_config()
    server = (config.daemon.server_url or "").rstrip("/")
    site_id = args.site_id or config.daemon.site_id
    if not server:
        print("Not configured. Run `freesdn-agent register` first.")
        return 1
    if not site_id:
        print("No site id — pass --site-id or set one via register.")
        return 1

    login = _login_interactive(server)
    if not login:
        return 1
    client, headers = login

    try:
        # Pull the discovered-hosts list so we know hostname/mac/etc.
        # without asking the user to type them.
        resp = client.get(
            "/api/v1/discovery/discovered-hosts",
            params={"site_id": site_id, "limit": 1000, "show_adopted": "false"},
            headers=headers,
        )
        if resp.status_code != 200:
            print(f"Could not load discovered hosts: {resp.status_code} — {resp.text}")
            return 1
        all_rows = resp.json() or []

        target_ips = [ip.lower() for ip in args.ips]
        if target_ips == ["all"]:
            picked = all_rows
        else:
            ip_set = set(target_ips)
            picked = [r for r in all_rows if r.get("ip_address", "").lower() in ip_set]
            missing = ip_set - {r.get("ip_address", "").lower() for r in picked}
            if missing:
                print(f"Not in discovered list (skipping): {', '.join(sorted(missing))}")

        if not picked:
            print("Nothing to adopt.")
            return 0

        # Bulk endpoint caps at 100; split if needed.
        BATCH = 100
        prefix = args.name_prefix or "discovered-"
        all_results: list[dict] = []
        total_succ = 0
        total_fail = 0
        for start in range(0, len(picked), BATCH):
            chunk = picked[start : start + BATCH]
            payload = []
            for r in chunk:
                entry = {
                    "ip_address": r["ip_address"],
                    "name": r.get("hostname") or f"{prefix}{r['ip_address']}",
                    "site_id": site_id,
                    "device_type": r.get("device_type") or "other",
                }
                if r.get("mac_address"):
                    entry["mac_address"] = r["mac_address"]
                if args.driver:
                    entry["driver_id"] = args.driver
                payload.append(entry)

            if args.dry_run:
                import json as _json
                print(_json.dumps({"devices": payload}, indent=2))
                continue

            resp = client.post(
                "/api/v1/discovery/adopt/bulk",
                json={"devices": payload},
                headers=headers,
            )
            if resp.status_code != 200:
                print(f"Adopt batch failed: {resp.status_code} — {resp.text}")
                return 1
            data = resp.json()
            total_succ += data.get("succeeded", 0)
            total_fail += data.get("failed", 0)
            all_results.extend(data.get("results", []))

        if args.dry_run:
            print(f"(dry-run, no submit) {len(picked)} entries would be adopted.")
            return 0

        print()
        for r in all_results:
            if r.get("status") == "adopted":
                print(
                    f"  ✓ {r.get('ip_address'):<16}  →  "
                    f"{r.get('driver_id', '')}  device_id={r.get('device_id', '')}"
                )
            else:
                print(
                    f"  ✗ {r.get('ip_address'):<16}  {r.get('error', 'unknown error')}"
                )
        print()
        print(f"Adoption complete: {total_succ}/{len(picked)} succeeded, {total_fail} failed.")
        return 0 if total_fail == 0 else 2
    finally:
        client.close()


# -----------------------------------------------------------------
# schedule (list / add / remove)
# -----------------------------------------------------------------

def _cmd_schedule(args: argparse.Namespace) -> int:
    """Dispatch sub-action for `freesdn-agent schedule {list,add,remove}`."""
    sub_cmd = getattr(args, "schedule_cmd", None)
    if not sub_cmd:
        print("Usage: freesdn-agent schedule {list,add,remove} ...")
        return 1

    config = get_config()
    server = (config.daemon.server_url or "").rstrip("/")
    site_id = config.daemon.site_id
    if not server:
        print("Not configured. Run `freesdn-agent register` first.")
        return 1
    if not site_id:
        print("No site id in config — re-run register with --site-id.")
        return 1

    login = _login_interactive(server)
    if not login:
        return 1
    client, headers = login

    try:
        if sub_cmd == "list":
            resp = client.get(
                "/api/v1/agents/schedules",
                params={"site_id": site_id},
                headers=headers,
            )
            if resp.status_code != 200:
                print(f"List failed: {resp.status_code} — {resp.text}")
                return 1
            rows = resp.json() or []
            if not rows:
                print("(no schedules)")
                return 0
            print(f"{'NAME':<24} {'CRON':<20} {'TYPE':<10} {'TARGETS'}")
            print("-" * 100)
            for r in rows:
                tgt = ",".join(r.get("targets") or [])[:40]
                enabled = "" if r.get("enabled") else " (disabled)"
                print(
                    f"{r['name']:<24} {r['cron']:<20} {r['scan_type']:<10} {tgt}{enabled}"
                )
                print(f"  id={r['id']}")
            return 0

        elif sub_cmd == "add":
            body = {
                "name": args.name,
                "cron": args.cron,
                "scan_type": args.scan_type,
                "targets": args.targets,
                "interface": args.interface,
                "enabled": not args.disabled,
            }
            if args.agent_id:
                body["agent_id"] = args.agent_id
            resp = client.post(
                "/api/v1/agents/schedules",
                params={"site_id": site_id},
                json=body,
                headers=headers,
            )
            if resp.status_code not in (200, 201):
                print(f"Create failed: {resp.status_code} — {resp.text}")
                return 1
            data = resp.json()
            print(f"Created schedule {data['id']}")
            print(f"  name: {data['name']}  cron: {data['cron']}  type: {data['scan_type']}")
            return 0

        elif sub_cmd == "remove":
            resp = client.delete(
                f"/api/v1/agents/schedules/{args.schedule_id}",
                headers=headers,
            )
            if resp.status_code not in (200, 204):
                print(f"Delete failed: {resp.status_code} — {resp.text}")
                return 1
            print(f"Schedule {args.schedule_id} deleted")
            return 0

        else:
            print(f"Unknown schedule sub-command: {sub_cmd}")
            return 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
