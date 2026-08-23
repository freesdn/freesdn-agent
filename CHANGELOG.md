# Changelog

All notable changes to the FreeSDN Agent are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-08-23

Windows. Found by looking at a screenshot of the running GUI rather than at the
code, which is the only way this one surfaces: on Linux the same code is right.

### Fixed

- **The interface list showed adapter GUIDs.** ``netifaces`` returns
  ``{37217669-42DA-4657-A55B-0D995D328250}`` on Windows, and the GUI printed it.
  The daemon already had a registry lookup that turns those into ``Ethernet`` /
  ``Tailscale``, but it was private to the capability advertiser, where the GUI
  -- the only place an operator actually reads these -- could not reach it.

- **Hyper-V and WSL switches were scanned by default.** The filter that keeps
  virtual adapters out of a scan matched against that same GUID, so on Windows
  it never fired once. Measured on a real host: a default Quick Scan covered
  8,443 addresses, of which 254 were the operator's actual LAN and 8,188 were
  two ``vEthernet`` /20s with nothing behind them. Now 254, and the virtual
  adapters arrive unchecked and labelled.

- **A scan that named an interface and gave no targets scanned nothing.** This
  one was never Windows-specific. ``targets = job.targets or [interface]`` handed
  the scanner the interface NAME, and a name parses to zero addresses -- so the
  scan logged "No valid IPs to scan", reported success, and found nothing. Every
  scheduled scan without explicit targets did exactly this. The comment on the
  line already said "default to interface subnet"; now the code does.

### Changed

- The three jobs an interface name was doing -- label, virtual-adapter hint,
  and stand-in for a subnet -- are one implementation in ``utils/netiface.py``,
  and the GUI keeps the identifier and the label as separate fields, because the
  scanners need the first and people need the second. A test fails if the
  registry lookup is ever copied back out.

- 30 more tests (187 to 217). Each fix was verified by reintroducing it.

## [1.0.1] - 2026-08-23

Fix release. Every fault below is present in the shipped v1.0.0 binaries.

Most of these were found by RUNNING the agent against a live controller
rather than by reading it, which is why several had survived a release: they
are not visible in the source, only in what the server answers.

### Fixed

- **Every authenticated CLI command returned 403.** `register`, `list-discovered`,
  `adopt` and `schedule` all failed against any current controller. The OAuth2
  token endpoint returns bearer tokens in the body AND sets the browser session
  cookies; httpx stored them, so each following request carried a bearer header
  *and* a session cookie, which the server refuses on purpose (an attacker able
  to send `Authorization: Bearer garbage` alongside a victim's cookie would
  otherwise bypass CSRF). The agent is not a browser and now drops those cookies.
  `register` had never once completed successfully in any released build.

- **Registration could not be automated.** `getpass` reads the terminal rather
  than stdin, so piping a password did not fail -- it hung, with no output and no
  timeout, which is the worst possible behaviour for the `.deb` postinst that
  prints this command. Credentials are now read from `FREESDN_EMAIL` /
  `FREESDN_PASSWORD` first; prompts remain for interactive use, and a headless
  run with neither set exits with a message instead of blocking.

- **The agent reported its own packaged deployment as unprivileged.** The shipped
  unit runs as `User=freesdn-agent` with `AmbientCapabilities=CAP_NET_RAW` --
  the correct way to run a scanner -- and three separate modules asked
  `os.geteuid() == 0`, which is false for it. The result on a `.deb` install: the
  ARP scanner was never advertised to the control plane and every `REQUIRES_ROOT`
  listener was skipped, including passive LLDP, the daemon's topology source.
  There is now one implementation that reads `CapEff` from `/proc/self/status`.

- **The daemon could not shut down.** Five long-lived loops run under one
  `asyncio.gather` and `stop()` only set a flag, which a loop inside
  `asyncio.sleep(interval)` cannot see. The updater's interval defaults to 3000s
  and permits 86400s, so in practice systemd's `TimeoutStopSec` fired and the
  daemon was SIGKILLed on every restart -- losing the clean WebSocket close,
  killing in-flight work, and blocking `systemctl restart` for the full timeout.
  Measured: stop at 0.3s, exit at 6.0s (heartbeat) and never (updater). Now 0.30s
  and 0.31s.

- **Scheduled scans ran on the wrong days.** The cron parser AND-ed day-of-month
  and day-of-week; POSIX cron ORs them when both are restricted. `0 0 1 * 1`,
  which every operator reads as "the 1st and every Monday", fired only on a 1st
  that was also a Monday -- roughly once every seven months instead of five times
  a month.

- **The minimum-interval guard measured the wrong thing.** It counted firings per
  hour, so `0,1,2,3,4 * * * *` passed a twelve-an-hour limit while running five
  scans in five consecutive minutes. It now measures the actual gap, including
  across the hour boundary.

- **"Export Results..." did nothing.** The menu item carries a Ctrl+E shortcut
  and enables itself after any successful scan; its handler was `pass`. It now
  writes a CSV.


- **`freesdn-agent register` failed against any current controller.** The command
  posted to `/api/v1/auth/login` and read `access_token` from the response, but
  that endpoint returns `BrowserAuthResponse`, which deliberately omits both
  tokens because browsers receive them as httpOnly cookies. The lookup raised an
  uncaught `KeyError`, so the first command an operator runs, the one printed by
  the `.deb` postinst and every doc, ended in a traceback. It now uses the OAuth2
  form-POST at `/api/v1/auth/token`, the same endpoint the interactive login path
  was already migrated to.

- **The self-updater could overwrite a source install's Python interpreter.** The
  update path replaces the file at `sys.executable`, which is the agent binary in
  a PyInstaller build but the user's interpreter under
  `pip install freesdn-agent[daemon]`. Since `auto_update_enabled` defaults to
  true, this needed to fail closed rather than depend on configuration. Both
  `UpdaterService.run()` and `_stage_binary()` now refuse to proceed unless the
  process is a frozen build.

### Security

- **The edge-bridge HTTP proxy followed redirects chosen by the target.**
  `proxy_http` exists because the controller cannot reach an appliance LAN: it
  sends a request spec and the agent executes it there. The controller choosing
  the URL is the entire trust argument -- but a redirect is chosen by the device,
  so "fetch this camera's status page" became "fetch whatever that camera names",
  anywhere on the agent's LAN or a cloud metadata endpoint. Redirects are no
  longer followed; the 3xx and its `Location` are returned to the controller,
  which can decide. The backend's own HTTP clients already refuse redirects for
  exactly this reason.

- **Unbounded values from the wire.** `timeout_seconds: null` satisfied the
  default lookup and reached `asyncio.wait_for(timeout=None)`, which waits for
  ever -- one message pinned a task slot for the life of the process, and the
  agent reports health by counting slots, so it looked progressively busier and
  never recovered. `proxy_http`'s `timeout` and `max_bytes` had no ceiling
  either; `max_bytes` sizes a read into memory. All three are now bounded.


- `pyasn1` 0.6.3 to 0.6.4, closing three high-severity BER/DER decoder
  denial-of-service advisories. `pysnmp` only floors this dependency at
  `>=0.6.3`, so it is now pinned explicitly rather than left to resolution.
- `pysnmp` 7.1.27 to 7.1.28.
- `cryptography` 49.0.0 to 50.0.0 (PKCS#7 `EnvelopedData` Bleichenbacher oracle).
- `aiohttp` 3.14.1 to 3.14.3 (out-of-bounds heap read in the C HTTP parser).

The SNMP trap listener is the only shipped consumer of the `pyasn1` decoder, and
all five passive listeners are disabled by default, so reaching the affected code
required an explicit opt-in plus running as root.

### Changed

- Registration now reports an unexpected server response as a message instead of
  a traceback, and catches `httpx.HTTPError` rather than only
  `httpx.RequestError`.

- The async `FreeSDNClient` drops its session cookies after login, for the same
  reason the CLI does. Its reads were unaffected (CSRF applies to unsafe methods
  only), so every write failed 403 while a connection test and a site list both
  looked healthy. `SyncFreeSDNClient`, which the GUI uses, was never affected --
  it builds a fresh client per call.

- CSV export lives in `utils/export.py` rather than behind the Qt import, so it
  is testable and reusable; PySide6 is an optional extra that CI does not install.

- The test suite grew from 81 to 187 tests, and CI now lints `tests/` as well as
  `src/`. Every fix above was verified by reintroducing it and confirming a test
  catches it.

## [1.0.0] - 2026-07-02

Initial public release: Windows, Linux and macOS daemons, Windows and Linux GUI
builds, a Debian package, and an SBOM, published at
<https://github.com/freesdn/freesdn-agent>.
