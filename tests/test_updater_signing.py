# SPDX-License-Identifier: MIT
# Copyright (C) 2024-2026 FreeSDN
"""Regression tests for agent auto-update signing.

The updater now (a) fails closed on a missing signature by default and (b) pins the
release-signing public key to a configured SHA-256 fingerprint, so a compromised
public-key endpoint cannot swap in its own key.
"""

from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from freesdn_agent.services.updater import UpdaterService


def _keypair_and_sign(digest_hex: str) -> tuple[bytes, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    sig = base64.b64encode(
        priv.sign(bytes.fromhex(digest_hex), ec.ECDSA(hashes.SHA256()))
    ).decode()
    return pub_pem, sig


def _svc(**config_overrides) -> UpdaterService:
    fields = {
        "auto_update_require_signature": True,
        "release_public_key_sha256": None,
        "server_url": "https://example",
        "agent_id": "agent-1",
    }
    fields.update(config_overrides)
    config = SimpleNamespace(**fields)
    return UpdaterService(ws_client=None, config=config, agent_version="1.0.0")


DIGEST = "ab" * 32  # 32-byte digest, hex


class TestConfigDefaults:
    def test_require_signature_defaults_true(self) -> None:
        from freesdn_agent.core.config import DaemonConfig

        f = DaemonConfig.model_fields
        assert f["auto_update_require_signature"].default is True
        assert f["release_public_key_sha256"].default is None


class TestPublicKeyPinning:
    @pytest.mark.asyncio
    async def test_matching_fingerprint_verifies(self) -> None:
        pub_pem, sig = _keypair_and_sign(DIGEST)
        svc = _svc(release_public_key_sha256=hashlib.sha256(pub_pem).hexdigest())
        svc._cached_public_key_pem = pub_pem  # skip the network fetch
        assert await svc._verify_signature("https://example", DIGEST, sig) is True

    @pytest.mark.asyncio
    async def test_mismatched_fingerprint_rejected(self) -> None:
        """THE key-swap defense: a fetched key whose fingerprint != the pin is
        refused even if the signature it carries is otherwise valid."""
        pub_pem, sig = _keypair_and_sign(DIGEST)
        svc = _svc(release_public_key_sha256="00" * 32)  # wrong pin
        svc._cached_public_key_pem = pub_pem
        assert await svc._verify_signature("https://example", DIGEST, sig) is False

    @pytest.mark.asyncio
    async def test_no_pin_tofu_persists_and_verifies(self, tmp_path, monkeypatch) -> None:
        """No explicit pin → persistent TOFU: first use persists the key fingerprint
        to the config dir and verifies the signature."""
        import freesdn_agent.core.config as cfg

        monkeypatch.setattr(cfg.Config, "get_config_dir", classmethod(lambda cls: tmp_path))
        pub_pem, sig = _keypair_and_sign(DIGEST)
        svc = _svc(release_public_key_sha256=None)
        svc._cached_public_key_pem = pub_pem
        assert await svc._verify_signature("https://example", DIGEST, sig) is True
        # The fingerprint is now persisted (locked) for future runs.
        assert (tmp_path / "release_signing_key.sha256").read_text().strip()

    @pytest.mark.asyncio
    async def test_tofu_rejects_later_key_swap(self, tmp_path, monkeypatch) -> None:
        """THE key-swap defense without an install pin: once a key is TOFU-pinned,
        a different fetched key (compromised server) is refused."""
        import hashlib as _h

        import freesdn_agent.core.config as cfg

        monkeypatch.setattr(cfg.Config, "get_config_dir", classmethod(lambda cls: tmp_path))
        good_pem, _ = _keypair_and_sign(DIGEST)
        # Persist the GOOD key fingerprint as the TOFU pin.
        (tmp_path / "release_signing_key.sha256").write_text(
            _h.sha256(good_pem).hexdigest()
        )
        evil_pem, evil_sig = _keypair_and_sign(DIGEST)  # attacker key + its signature
        svc = _svc(release_public_key_sha256=None)
        svc._cached_public_key_pem = evil_pem
        assert await svc._verify_signature("https://example", DIGEST, evil_sig) is False

    @pytest.mark.asyncio
    async def test_bad_signature_rejected(self) -> None:
        pub_pem, _ = _keypair_and_sign(DIGEST)
        _, other_sig = _keypair_and_sign(DIGEST)  # signature from a different key
        svc = _svc(release_public_key_sha256=hashlib.sha256(pub_pem).hexdigest())
        svc._cached_public_key_pem = pub_pem
        assert await svc._verify_signature("https://example", DIGEST, other_sig) is False
