"""
Auto-update service for FreeSDN Agent.

Periodically checks the control plane for new agent versions.
If an update is available, downloads the binary, verifies its
SHA-256 checksum, stages it, writes a rollback marker, and
triggers a platform-specific restart.

Security:
  - HTTPS-only downloads enforced (http:// rejected)
  - Download URL validated against configured server hostname (SSRF protection)
  - SHA-256 checksum verification is mandatory; mismatch aborts
  - Maximum download size enforced (500 MB)
  - asyncio.Lock serializes concurrent update attempts
  - Rollback marker enables recovery if the new binary fails
  - Temp files written to same filesystem as target for atomic rename
"""

import asyncio
import hashlib
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from freesdn_agent.services.rollback import (
    _binary_path,
    _sha256_file,
    write_rollback_marker,
)

logger = logging.getLogger(__name__)

# Maximum download size: 500 MB
_MAX_DOWNLOAD_BYTES = 500 * 1024 * 1024


class UpdaterService:
    """Periodically checks for and applies agent updates."""

    def __init__(
        self,
        ws_client,
        config,
        agent_version: str,
    ):
        """
        Args:
            ws_client: AgentWSClient for reporting status and deriving server URL.
            config: DaemonConfig with auto_update_* fields.
            agent_version: Current agent version string (e.g. "2.5.0").
        """
        self._ws = ws_client
        self._config = config
        self._agent_version = agent_version
        self._running = False
        self._update_lock = asyncio.Lock()

    async def run(self) -> None:
        """Main loop — check for updates at configured interval."""
        if not self._config.auto_update_enabled:
            logger.info("Auto-update disabled in config")
            return

        self._running = True
        interval = self._config.auto_update_interval

        logger.info(
            "Updater service started (interval=%ds, channel=%s)",
            interval,
            self._config.auto_update_channel,
        )

        while self._running:
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break

            if not self._running:
                break

            try:
                updated = await self.check_and_apply()
                if updated:
                    break
            except Exception:
                logger.exception("Update check failed")

    async def check_and_apply(self) -> bool:
        """
        Check the server for a new version and apply it if available.

        Serialized via asyncio.Lock to prevent concurrent staging races.
        Returns True if an update was applied and restart triggered.
        """
        if self._update_lock.locked():
            logger.debug("Update already in progress — skipping")
            return False

        async with self._update_lock:
            return await self._do_check_and_apply()

    async def _do_check_and_apply(self) -> bool:
        """Inner update logic (runs under lock)."""
        import httpx

        server_url = self._config.server_url.rstrip("/")
        platform = _detect_platform()
        channel = self._config.auto_update_channel

        check_url = (
            f"{server_url}/api/v1/agents/updates/check"
            f"?current_version={self._agent_version}"
            f"&platform={platform}"
            f"&agent_type=daemon"
            f"&channel={channel}"
        )

        logger.debug("Checking for updates: %s", check_url)

        # /updates/check requires X-Agent-ID + X-Agent-Key (information-
        # disclosure mitigation from the prior audit wave). Without
        # these headers the endpoint 401s silently and the agent thinks
        # there's never an update available. Load the same key the WS
        # client uses from the OS keyring + agent_id from config.
        agent_id = self._config.agent_id
        try:
            import keyring
            agent_key = keyring.get_password(
                "FreeSDN Agent", f"agent_key:{agent_id}",
            )
        except Exception:
            agent_key = None

        headers: dict[str, str] = {}
        if agent_id and agent_key:
            headers["X-Agent-ID"] = agent_id
            headers["X-Agent-Key"] = agent_key
        else:
            logger.warning(
                "Update check: agent_id=%r key_present=%s — endpoint will 401",
                agent_id, bool(agent_key),
            )

        try:
            async with httpx.AsyncClient(timeout=30.0, verify=True) as client:
                resp = await client.get(check_url, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            logger.warning("Update check HTTP error: %s", exc)
            return False

        if not data.get("update_available"):
            logger.debug(
                "No update available (current=%s, latest=%s)",
                self._agent_version,
                data.get("latest_version", "?"),
            )
            return False

        new_version = data.get("latest_version")
        download_url = data.get("download_url")
        expected_sha = data.get("checksum_sha256", "")

        if not new_version or not download_url:
            logger.error("Server response missing latest_version or download_url")
            return False

        if not expected_sha:
            logger.error("Server did not provide SHA-256 checksum — aborting update")
            return False

        # Validate download URL: HTTPS only, must match server hostname
        resolved_url = self._validate_download_url(server_url, download_url)
        if resolved_url is None:
            return False

        logger.info("Update available: %s → %s", self._agent_version, new_version)

        # Download with streaming and size limit
        binary_data = await self._download(resolved_url)
        if binary_data is None:
            return False

        # Verify checksum
        actual_sha = hashlib.sha256(binary_data).hexdigest()
        if actual_sha != expected_sha:
            logger.error(
                "Checksum mismatch! expected=%s got=%s — aborting update",
                expected_sha[:16],
                actual_sha[:16],
            )
            await self._report_update_status(new_version, False, "checksum_mismatch")
            return False

        logger.info("Checksum verified for v%s", new_version)

        # Verify ECDSA-P256 signature. Defense in depth on top of the
        # checksum check: a compromised backend that swapped the
        # served binary + checksum would also need the backend's
        # private signing key. Empty signature is allowed for backward
        # compat with releases uploaded before the signing chapter.
        expected_sig = data.get("signature", "")
        if expected_sig:
            sig_ok = await self._verify_signature(server_url, actual_sha, expected_sig)
            if not sig_ok:
                logger.error(
                    "Signature verification FAILED for v%s — aborting update",
                    new_version,
                )
                await self._report_update_status(
                    new_version, False, "signature_mismatch",
                )
                return False
            logger.info("Signature verified for v%s", new_version)
        else:
            # fail CLOSED on a missing signature by default. A
            # compromised/MITM'd control plane can swap the served binary AND its
            # checksum together, so the checksum alone proves nothing — only the
            # ECDSA signature (which needs the backend's private key) does. Both
            # publish paths now sign, so an unsigned release is anomalous.
            require_sig = getattr(self._config, "auto_update_require_signature", True)
            if require_sig:
                logger.error(
                    "Release v%s has NO signature — refusing to install an unsigned "
                    "release. Set auto_update_require_signature=false only "
                    "for a fully-trusted/legacy server.",
                    new_version,
                )
                await self._report_update_status(new_version, False, "unsigned_release")
                return False
            logger.warning(
                "Release v%s has no signature — accepting on checksum alone "
                "(auto_update_require_signature disabled)",
                new_version,
            )

        # Stage and restart
        success = self._stage_binary(binary_data, new_version)
        if not success:
            await self._report_update_status(new_version, False, "staging_failed")
            return False

        await self._report_update_status(new_version, True, "restarting")
        self._trigger_restart()
        return True

    def _validate_download_url(self, server_url: str, download_url: str) -> str | None:
        """
        Validate and resolve the download URL.

        Security:
          - Relative paths are resolved against the server URL
          - Absolute URLs must be HTTPS and match the server hostname
          - http:// is rejected
          - Private/link-local IPs are not validated here (rely on httpx verify=True)
        """
        if download_url.startswith("/"):
            # Relative URL — resolve against server
            return f"{server_url}{download_url}"

        if download_url.startswith("http://"):
            logger.error("Refusing non-TLS download URL: %s", download_url)
            return None

        if download_url.startswith("https://"):
            # Validate hostname matches server
            server_host = urlparse(server_url).hostname
            download_host = urlparse(download_url).hostname
            if server_host != download_host:
                logger.error(
                    "Download URL hostname %r does not match server %r — SSRF blocked",
                    download_host,
                    server_host,
                )
                return None
            return download_url

        logger.error("Invalid download URL scheme: %s", download_url[:50])
        return None

    async def _download(self, url: str) -> bytes | None:
        """Download the update binary with streaming and size limit.

        Sends X-Agent-ID/X-Agent-Key headers (same as /updates/check)
        — audit HIGH #2 requires authenticated download.
        """
        import httpx

        logger.info("Downloading update from %s", url)

        # Same headers as the update check — reuses the keyring load
        agent_id = self._config.agent_id
        try:
            import keyring
            agent_key = keyring.get_password(
                "FreeSDN Agent", f"agent_key:{agent_id}",
            )
        except Exception:
            agent_key = None
        headers: dict[str, str] = {}
        if agent_id and agent_key:
            headers["X-Agent-ID"] = agent_id
            headers["X-Agent-Key"] = agent_key

        try:
            async with httpx.AsyncClient(timeout=300.0, verify=True, headers=headers) as client:
                async with client.stream("GET", url) as resp:
                    resp.raise_for_status()

                    # Check Content-Length if provided
                    content_length = resp.headers.get("content-length")
                    if content_length and int(content_length) > _MAX_DOWNLOAD_BYTES:
                        logger.error(
                            "Download too large: %s bytes (max %d)",
                            content_length,
                            _MAX_DOWNLOAD_BYTES,
                        )
                        return None

                    # Stream with size enforcement
                    chunks: list[bytes] = []
                    total = 0
                    async for chunk in resp.aiter_bytes(chunk_size=65536):
                        total += len(chunk)
                        if total > _MAX_DOWNLOAD_BYTES:
                            logger.error(
                                "Download exceeded max size (%d bytes) — aborting",
                                _MAX_DOWNLOAD_BYTES,
                            )
                            return None
                        chunks.append(chunk)

            data = b"".join(chunks)
            logger.info("Downloaded %d bytes", len(data))
            return data

        except httpx.HTTPError:
            logger.exception("Download failed")
            return None

    def _stage_binary(self, data: bytes, new_version: str) -> bool:
        """
        Write the new binary to disk using atomic rename.

        Steps:
          1. Write to temp file on same filesystem
          2. Back up current binary as <name>.bak
          3. Atomic rename temp → target (os.replace)
          4. Write rollback marker after successful replace
        """
        target = _binary_path()
        target_dir = target.parent

        try:
            fd, tmp_path = tempfile.mkstemp(
                dir=str(target_dir),
                prefix=".freesdn-update-",
                suffix=".tmp",
            )
            tmp = Path(tmp_path)
            try:
                with open(fd, "wb") as f:
                    f.write(data)

                # Make executable on Unix
                if sys.platform != "win32":
                    import stat
                    tmp.chmod(tmp.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

                # Back up current binary
                backup = target.with_suffix(target.suffix + ".bak")
                if target.exists():
                    shutil.copy2(str(target), str(backup))
                    # Hash the backup, not the original (post-copy verification)
                    backup_hash = _sha256_file(backup)
                    logger.info("Backed up current binary to %s", backup)
                else:
                    backup_hash = ""

                # Atomic replace (os.replace works on both Unix and Windows/NTFS)
                os.replace(str(tmp), str(target))

                # Write rollback marker AFTER successful replace
                write_rollback_marker(
                    prev_version=self._agent_version,
                    prev_hash=backup_hash,
                )

                logger.info("Staged v%s binary at %s", new_version, target)
                return True

            except Exception:
                # Clean up temp file on failure
                try:
                    if tmp.exists():
                        tmp.unlink()
                except OSError:
                    pass
                raise

        except OSError:
            logger.exception("Failed to stage update binary")
            return False

    def _trigger_restart(self) -> None:
        """Platform-specific daemon restart."""
        logger.info("Triggering daemon restart for update …")

        if sys.platform == "linux":
            try:
                subprocess.Popen(
                    ["systemctl", "restart", "freesdn-agent"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except FileNotFoundError:
                logger.warning("systemctl not found — manual restart required")

        elif sys.platform == "darwin":
            try:
                subprocess.Popen(
                    ["launchctl", "kickstart", "-k", "system/com.freesdn.agent"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except FileNotFoundError:
                logger.warning("launchctl not found — manual restart required")

        elif sys.platform == "win32":
            try:
                subprocess.Popen(
                    ["sc", "stop", "FreeSDNAgent"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except FileNotFoundError:
                logger.warning("sc.exe not found — manual restart required")

        else:
            logger.warning("Unknown platform %s — manual restart required", sys.platform)

    async def _verify_signature(
        self, server_url: str, digest_hex: str, signature_b64: str,
    ) -> bool:
        """Fetch the backend's public key + verify the ECDSA signature.

        Cached in-memory after first fetch — the public key rarely
        changes and we want to avoid hammering the backend on every
        update check. A future chapter could pin the key to a
        configured fingerprint to defend against the public-key
        endpoint being attacker-controlled.
        """
        import base64

        import httpx
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        if not getattr(self, "_cached_public_key_pem", None):
            try:
                url = f"{server_url}/api/v1/agents/releases/public-key"
                async with httpx.AsyncClient(timeout=10.0, verify=True) as client:
                    resp = await client.get(url)
                    resp.raise_for_status()
                    self._cached_public_key_pem = resp.content
            except Exception:
                logger.exception("Could not fetch release public key from %s", server_url)
                return False

        # the fetched public key MUST match a trusted fingerprint —
        # otherwise a compromised public-key endpoint could swap in its own key to
        # sign a malicious release. Priority: (1) an install-time pin
        # (release_public_key_sha256); else (2) a PERSISTED trust-on-first-use
        # fingerprint, so once the agent has seen the real key, a later key-swap is
        # rejected even across restarts (the in-memory cache alone reset every boot).
        actual_fp = hashlib.sha256(self._cached_public_key_pem).hexdigest()
        pinned = getattr(self._config, "release_public_key_sha256", None)
        pin_source = "config"
        if not pinned:
            pinned = self._load_or_persist_release_key_fp(actual_fp)
            pin_source = "tofu"
        if pinned and actual_fp.lower() != pinned.strip().lower():
            logger.error(
                "Release public key fingerprint MISMATCH (%s pin=%s… got=%s…) — "
                "refusing update (possible key-swap / compromised server)",
                pin_source,
                pinned[:16],
                actual_fp[:16],
            )
            self._cached_public_key_pem = None  # let a later legit fetch retry
            return False

        try:
            pub = serialization.load_pem_public_key(self._cached_public_key_pem)
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                return False
            digest_bytes = bytes.fromhex(digest_hex)
            sig_der = base64.b64decode(signature_b64)
            pub.verify(sig_der, digest_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError, Exception):
            logger.warning("Signature verification raised", exc_info=True)
            return False

    def _load_or_persist_release_key_fp(self, actual_fp: str) -> str | None:
        """Trust-on-first-use pin for the release-signing public key.

        Persists the first key fingerprint we ever verify against to the agent
        config dir, then treats it as the pin on every later run — so a compromised
        public-key endpoint cannot swap in its own key after the agent has seen the
        real one. Returns the trusted fingerprint (== ``actual_fp`` on first use), or
        None if persistence is impossible (degrades to no-pin, best-effort).
        """
        try:
            from freesdn_agent.core.config import Config

            fp_file = Config.get_config_dir() / "release_signing_key.sha256"
            if fp_file.exists():
                return fp_file.read_text(encoding="utf-8").strip()
            fp_file.write_text(actual_fp, encoding="utf-8")
            logger.warning(
                "Pinned release-signing public key on first use (TOFU): %s… — a "
                "later key change will now be refused. Set release_public_key_sha256 "
                "at install for full protection against a first-contact compromise.",
                actual_fp[:16],
            )
            return actual_fp
        except Exception:
            logger.exception("Could not read/persist the TOFU release-key fingerprint")
            return None

    async def _report_update_status(
        self, version: str, success: bool, detail: str,
    ) -> None:
        """Report update progress/result to the control plane."""
        try:
            await self._ws.send_report("action_result", {
                "action": "auto_update",
                "version": version,
                "success": success,
                "detail": detail,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            logger.debug("Failed to report update status", exc_info=True)

    def stop(self) -> None:
        """Signal the updater to stop."""
        self._running = False


def _detect_platform() -> str:
    """Detect the current platform for update checks."""
    if sys.platform == "win32":
        return "windows"
    elif sys.platform == "darwin":
        return "macos"
    else:
        return "linux"
