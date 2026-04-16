"""Tests for authentication modules — OAuth, API key, mTLS."""

from __future__ import annotations

import time
import tempfile
from pathlib import Path

import pytest

from agentshield_core.auth.oauth import (
    create_access_token,
    verify_access_token,
    _cleanup_expired_states,
    _oauth_states,
    _MAX_OAUTH_STATES,
)
from agentshield_core.auth.api_key import hash_api_key


class TestJWT:
    def test_create_and_verify_token(self):
        token = create_access_token(user_id="user-1", email="test@example.com", role="admin")
        payload = verify_access_token(token)
        assert payload["sub"] == "user-1"
        assert payload["email"] == "test@example.com"
        assert payload["role"] == "admin"
        assert payload["iss"] == "agentshield"

    def test_expired_token_rejected(self):
        from jose import jwt as jose_jwt
        from agentshield_core.auth.oauth import JWT_SECRET, JWT_ALGORITHM

        payload = {
            "sub": "user-1",
            "email": "test@example.com",
            "role": "viewer",
            "iat": int(time.time()) - 200000,
            "exp": int(time.time()) - 100000,  # Expired
            "iss": "agentshield",
        }
        token = jose_jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            verify_access_token(token)
        assert exc_info.value.status_code == 401

    def test_invalid_token_rejected(self):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            verify_access_token("completely.invalid.token")
        assert exc_info.value.status_code == 401

    def test_token_contains_timestamps(self):
        before = int(time.time())
        token = create_access_token("u1", "e@x.com", "viewer")
        payload = verify_access_token(token)
        assert payload["iat"] >= before
        assert payload["exp"] > payload["iat"]
        # 24 hour expiry
        assert payload["exp"] - payload["iat"] == 86400


class TestOAuthStateCleanup:
    def test_cleanup_removes_expired_states(self):
        _oauth_states.clear()
        _oauth_states["old-state"] = time.time() - 700  # Expired (>600s)
        _oauth_states["fresh-state"] = time.time()

        _cleanup_expired_states()

        assert "old-state" not in _oauth_states
        assert "fresh-state" in _oauth_states

    def test_cleanup_caps_at_max(self):
        _oauth_states.clear()
        now = time.time()
        for i in range(_MAX_OAUTH_STATES + 100):
            _oauth_states[f"state-{i}"] = now + i * 0.001

        _cleanup_expired_states()
        assert len(_oauth_states) <= _MAX_OAUTH_STATES

    def test_cleanup_empty_states(self):
        _oauth_states.clear()
        _cleanup_expired_states()  # Should not crash
        assert len(_oauth_states) == 0


class TestAPIKey:
    def test_hash_is_deterministic(self):
        h1 = hash_api_key("test-key-123")
        h2 = hash_api_key("test-key-123")
        assert h1 == h2

    def test_different_keys_different_hashes(self):
        h1 = hash_api_key("key-a")
        h2 = hash_api_key("key-b")
        assert h1 != h2

    def test_hash_is_sha256(self):
        h = hash_api_key("test")
        assert len(h) == 64  # SHA256 hex digest

    @pytest.mark.asyncio
    async def test_validate_missing_key_raises(self):
        from agentshield_core.auth.api_key import validate_api_key
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await validate_api_key(api_key=None)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_validate_valid_key_returns_prefix(self):
        from agentshield_core.auth.api_key import validate_api_key

        result = await validate_api_key(api_key="sk-test-key-12345678")
        assert result == "sk-test-"


class TestMTLS:
    def test_generate_self_signed_certs(self):
        """Test certificate generation for development."""
        try:
            from agentshield_core.auth.mtls import generate_self_signed_certs
        except ImportError:
            pytest.skip("cryptography not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_self_signed_certs(tmpdir)

            assert Path(paths["ca_cert"]).exists()
            assert Path(paths["ca_key"]).exists()
            assert Path(paths["server_cert"]).exists()
            assert Path(paths["server_key"]).exists()
            assert Path(paths["client_cert"]).exists()
            assert Path(paths["client_key"]).exists()

            # Verify PEM format
            ca_content = Path(paths["ca_cert"]).read_text()
            assert "BEGIN CERTIFICATE" in ca_content

    def test_create_server_ssl_context(self):
        """Test server SSL context creation."""
        try:
            from agentshield_core.auth.mtls import (
                generate_self_signed_certs,
                create_server_ssl_context,
            )
        except ImportError:
            pytest.skip("cryptography not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_self_signed_certs(tmpdir)
            ctx = create_server_ssl_context(
                cert_file=paths["server_cert"],
                key_file=paths["server_key"],
                ca_file=paths["ca_cert"],
            )
            import ssl

            assert ctx.verify_mode == ssl.CERT_REQUIRED
            assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3

    def test_create_client_ssl_context(self):
        """Test client SSL context creation."""
        try:
            from agentshield_core.auth.mtls import (
                generate_self_signed_certs,
                create_client_ssl_context,
            )
        except ImportError:
            pytest.skip("cryptography not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_self_signed_certs(tmpdir)
            ctx = create_client_ssl_context(
                cert_file=paths["client_cert"],
                key_file=paths["client_key"],
                ca_file=paths["ca_cert"],
            )
            import ssl

            assert ctx.verify_mode == ssl.CERT_REQUIRED
            assert ctx.check_hostname is True
