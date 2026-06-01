"""
Rollback service for FreeSDN Agent auto-updates.

Writes a marker file before applying an update. On next daemon startup,
if the marker exists and the daemon crashes within 60 seconds, the previous
binary is restored automatically.

Marker format (JSON):
    {
        "previous_version": "2.4.0",
        "previous_binary_hash": "<sha256>",
        "staged_at": "2025-01-01T00:00:00Z",
        "binary_path": "/opt/freesdn-agent/bin/freesdn-agent",
        "rollback_count": 0
    }
"""

import hashlib
import json
import logging
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Marker lives next to the running binary
_MARKER_NAME = ".freesdn-rollback"

# If daemon starts and crashes within this window, trigger rollback
_ROLLBACK_WINDOW_SECONDS = 60

# Maximum rollback attempts before refusing to start
_MAX_ROLLBACK_ATTEMPTS = 3


def _binary_path() -> Path:
    """Path to the currently running binary."""
    return Path(sys.executable).resolve()


def _marker_path() -> Path:
    """Path to the rollback marker file."""
    return _binary_path().parent / _MARKER_NAME


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_rollback_marker(prev_version: str, prev_hash: str) -> None:
    """
    Write a rollback marker after staging a new binary.

    Args:
        prev_version: Version string of the current (soon-to-be-previous) binary.
        prev_hash: SHA-256 of the backup binary for verification after rollback.
    """
    marker = _marker_path()
    data = {
        "previous_version": prev_version,
        "previous_binary_hash": prev_hash,
        "staged_at": datetime.now(timezone.utc).isoformat(),
        "binary_path": str(_binary_path()),
        "rollback_count": 0,
    }
    try:
        marker.write_text(json.dumps(data, indent=2), encoding="utf-8")
        # Restrict marker permissions on Unix
        if sys.platform != "win32":
            marker.chmod(0o600)
        logger.info("Rollback marker written: %s", marker)
    except OSError:
        logger.warning("Failed to write rollback marker", exc_info=True)


def clear_rollback_marker() -> None:
    """
    Clear the rollback marker after a successful startup.

    Called once the daemon has sent its first heartbeat, confirming
    the new binary is healthy.
    """
    marker = _marker_path()
    try:
        marker.unlink(missing_ok=True)
        logger.info("Rollback marker cleared — update confirmed healthy")
    except OSError:
        logger.debug("Failed to clear rollback marker", exc_info=True)


def check_rollback_needed() -> bool:
    """
    Check if a rollback is needed at daemon startup.

    Returns True if a rollback was performed. Returns False if:
      - No marker exists
      - Marker is older than the rollback window (update is healthy)
      - Maximum rollback attempts exceeded (logs CRITICAL)
    """
    marker = _marker_path()
    if not marker.exists():
        return False

    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.warning("Corrupt rollback marker — removing")
        _safe_delete(marker)
        return False

    # Validate binary_path matches the actual running binary
    marker_binary = data.get("binary_path", "")
    actual_binary = str(_binary_path())
    if marker_binary and marker_binary != actual_binary:
        logger.warning(
            "Rollback marker binary_path %r does not match running binary %r — ignoring",
            marker_binary,
            actual_binary,
        )
        _safe_delete(marker)
        return False

    staged_at = data.get("staged_at", "")
    try:
        staged_time = datetime.fromisoformat(staged_at)
        # Ensure timezone-aware comparison
        if staged_time.tzinfo is None:
            staged_time = staged_time.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        logger.warning("Invalid timestamp in rollback marker — removing")
        _safe_delete(marker)
        return False

    elapsed = (datetime.now(timezone.utc) - staged_time).total_seconds()

    if elapsed > _ROLLBACK_WINDOW_SECONDS:
        # Previous startup survived long enough — update is healthy
        logger.info(
            "Rollback marker found but aged %.0fs (> %ds) — update OK, clearing",
            elapsed,
            _ROLLBACK_WINDOW_SECONDS,
        )
        _safe_delete(marker)
        return False

    # Check rollback attempt counter
    rollback_count = data.get("rollback_count", 0)
    if rollback_count >= _MAX_ROLLBACK_ATTEMPTS:
        logger.critical(
            "Maximum rollback attempts (%d) exceeded — refusing to roll back. "
            "Manual intervention required.",
            _MAX_ROLLBACK_ATTEMPTS,
        )
        _safe_delete(marker)
        return False

    # Within the crash window — attempt rollback
    logger.warning(
        "Rollback triggered! Daemon crashed within %ds of update "
        "(elapsed=%.0fs, attempt=%d/%d)",
        _ROLLBACK_WINDOW_SECONDS,
        elapsed,
        rollback_count + 1,
        _MAX_ROLLBACK_ATTEMPTS,
    )

    # Increment the counter before attempting rollback
    data["rollback_count"] = rollback_count + 1
    try:
        marker.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass

    return _perform_rollback(data)


def _perform_rollback(marker_data: dict) -> bool:
    """
    Restore the previous binary from the .bak file.

    The updater renames the old binary to <name>.bak before staging the new one.
    We reverse that: rename current → .failed, rename .bak → current.
    """
    binary = _binary_path()  # Always use actual binary, not marker data
    backup = binary.with_suffix(binary.suffix + ".bak")

    if not backup.exists():
        logger.error("Rollback failed — backup binary not found: %s", backup)
        _safe_delete(_marker_path())
        return False

    failed = binary.with_suffix(binary.suffix + ".failed")

    try:
        # Move broken new binary aside
        if binary.exists():
            shutil.move(str(binary), str(failed))

        # Restore previous binary
        shutil.move(str(backup), str(binary))

        # Verify hash if available
        expected_hash = marker_data.get("previous_binary_hash", "")
        if expected_hash:
            actual_hash = _sha256_file(binary)
            if actual_hash != expected_hash:
                logger.error(
                    "Rollback hash mismatch! expected=%s got=%s",
                    expected_hash[:16],
                    actual_hash[:16],
                )
                # Still keep the rollback — better to run mismatched than broken
            else:
                logger.info("Rollback hash verified OK")

        logger.info(
            "Rollback complete: restored v%s",
            marker_data.get("previous_version", "unknown"),
        )

        # Clean up marker
        _safe_delete(_marker_path())

        # Clean up the failed binary
        _safe_delete(failed)

        return True

    except OSError:
        logger.exception("Rollback failed during file operations")
        _safe_delete(_marker_path())
        return False


def _safe_delete(path: Path) -> None:
    """Delete a file without raising."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
