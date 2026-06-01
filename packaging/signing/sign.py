"""
FreeSDN Agent — Cross-platform code signing wrapper.

Usage:
    python sign.py --platform windows --file dist/freesdn-agent.exe
    python sign.py --platform macos   --file dist/freesdn-agent
    python sign.py --platform linux   --file dist/freesdn-agent

Signing is best-effort: if credentials/tools are unavailable the build
continues with a warning. SHA-256 checksums are always generated.
"""

import argparse
import hashlib
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sign_windows(filepath: Path) -> bool:
    """Sign with Authenticode via signtool (Windows SDK)."""
    signtool = shutil.which("signtool")
    if not signtool:
        logger.warning("signtool not found — skipping Windows code signing")
        return False

    try:
        result = subprocess.run(
            [
                signtool, "sign",
                "/tr", "http://timestamp.digicert.com",
                "/td", "sha256",
                "/fd", "sha256",
                "/a",
                str(filepath),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            logger.warning("signtool failed: %s", result.stderr.strip())
            return False
        logger.info("Windows signing successful")
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning("Windows signing error: %s", e)
        return False


def sign_macos(filepath: Path, identity: str = "") -> bool:
    """Sign with codesign. Uses CODESIGN_IDENTITY env var or ad-hoc signing."""
    identity = identity or os.environ.get("CODESIGN_IDENTITY", "")
    codesign = shutil.which("codesign")
    if not codesign:
        logger.warning("codesign not found — skipping macOS code signing")
        return False

    try:
        result = subprocess.run(
            [
                codesign,
                "--force",
                "--timestamp",
                "--sign", identity or "-",  # Use identity if provided, else ad-hoc
                str(filepath),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            logger.warning("codesign failed: %s", result.stderr.strip())
            return False
        logger.info("macOS signing successful")
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning("macOS signing error: %s", e)
        return False


def sign_linux(filepath: Path) -> bool:
    """Generate detached GPG signature."""
    gpg = shutil.which("gpg") or shutil.which("gpg2")
    if not gpg:
        logger.warning("gpg not found — skipping GPG signing")
        return False

    sig_path = filepath.with_suffix(filepath.suffix + ".sig")
    try:
        result = subprocess.run(
            [gpg, "--detach-sign", "--armor", "--output", str(sig_path), str(filepath)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            logger.warning("GPG signing failed: %s", result.stderr.strip())
            return False
        logger.info("GPG signature: %s", sig_path)
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning("GPG signing error: %s", e)
        return False


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(description="FreeSDN Agent code signing")
    parser.add_argument("--platform", required=True, choices=["windows", "macos", "linux"])
    parser.add_argument("--file", required=True, type=Path)
    args = parser.parse_args()

    filepath = args.file.resolve()
    if not filepath.exists():
        logger.error("File not found: %s", filepath)
        return 1

    # Always generate SHA-256 checksum
    digest = sha256_file(filepath)
    checksum_file = filepath.with_suffix(filepath.suffix + ".sha256")
    checksum_file.write_text(f"{digest}  {filepath.name}\n")
    logger.info("SHA-256: %s", digest)
    logger.info("Checksum: %s", checksum_file)

    # Attempt platform-specific signing
    signers = {
        "windows": sign_windows,
        "macos": sign_macos,
        "linux": sign_linux,
    }
    signed = signers[args.platform](filepath)
    if not signed:
        logger.warning("Code signing skipped — binary is unsigned")

    return 0


if __name__ == "__main__":
    sys.exit(main())
