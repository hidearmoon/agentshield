"""Tests for OAuth 2.0 endpoints."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

from agentshield_core.auth.oauth import (
    router,
    _oauth_states,
    create_access_token,
    verify_access_token,
)


@pytest.fixture
def app():
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def client(app):
    return TestClient(app)


class TestOAuthLogin:
    def test_login_redirects_when_configured(self, client):
        with patch("agentshield_core.auth.oauth._get_oauth_config") as mock_config:
            mock_config.return_value = MagicMock(
                authorization_url="https://idp.example.com/authorize",
                client_id="test-client-id",
                redirect_uri="http://localhost:8080/auth/callback",
                scopes=["openid", "email", "profile"],
            )
            resp = client.get("/auth/login", follow_redirects=False)
            assert resp.status_code == 307
            location = resp.headers["location"]
            assert "idp.example.com/authorize" in location
            assert "client_id=test-client-id" in location
            assert "state=" in location

    def test_login_fails_when_not_configured(self, client):
        with patch("agentshield_core.auth.oauth._get_oauth_config") as mock_config:
            mock_config.return_value = MagicMock(authorization_url="")
            resp = client.get("/auth/login")
            assert resp.status_code == 501


class TestOAuthCallback:
    def test_callback_rejects_invalid_state(self, client):
        resp = client.get("/auth/callback?code=test-code&state=invalid-state")
        assert resp.status_code == 400
        assert "Invalid OAuth state" in resp.json()["detail"]

    def test_callback_rejects_expired_state(self, client):
        state = "test-expired-state"
        _oauth_states[state] = time.time() - 700  # 700s ago, > 600s expiry
        resp = client.get(f"/auth/callback?code=test-code&state={state}")
        assert resp.status_code == 400
        assert "expired" in resp.json()["detail"]

    def test_callback_exchanges_code_successfully(self, client):
        state = "valid-state"
        _oauth_states[state] = time.time()

        with (
            patch("agentshield_core.auth.oauth._get_oauth_config") as mock_config,
            patch("agentshield_core.auth.oauth.httpx.AsyncClient") as mock_http,
        ):
            mock_config.return_value = MagicMock(
                token_url="https://idp.example.com/token",
                userinfo_url="https://idp.example.com/userinfo",
                redirect_uri="http://localhost:8080/auth/callback",
                client_id="test-client",
                client_secret="test-secret",
            )

            # Mock token exchange
            token_resp = MagicMock()
            token_resp.status_code = 200
            token_resp.json.return_value = {"access_token": "idp-token-123"}

            # Mock userinfo
            userinfo_resp = MagicMock()
            userinfo_resp.status_code = 200
            userinfo_resp.json.return_value = {
                "sub": "user-123",
                "email": "user@example.com",
                "name": "Test User",
            }

            mock_client_instance = AsyncMock()
            mock_client_instance.post.return_value = token_resp
            mock_client_instance.get.return_value = userinfo_resp
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock(return_value=False)
            mock_http.return_value = mock_client_instance

            resp = client.get(f"/auth/callback?code=auth-code-xyz&state={state}")
            assert resp.status_code == 200
            data = resp.json()
            assert "access_token" in data
            assert data["user"]["email"] == "user@example.com"
            assert data["token_type"] == "bearer"

    def test_callback_handles_token_exchange_failure(self, client):
        state = "fail-state"
        _oauth_states[state] = time.time()

        with (
            patch("agentshield_core.auth.oauth._get_oauth_config") as mock_config,
            patch("agentshield_core.auth.oauth.httpx.AsyncClient") as mock_http,
        ):
            mock_config.return_value = MagicMock(
                token_url="https://idp.example.com/token",
                redirect_uri="http://localhost:8080/auth/callback",
                client_id="c",
                client_secret="s",
            )

            fail_resp = MagicMock()
            fail_resp.status_code = 400

            mock_instance = AsyncMock()
            mock_instance.post.return_value = fail_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_http.return_value = mock_instance

            resp = client.get(f"/auth/callback?code=bad-code&state={state}")
            assert resp.status_code == 502


class TestTokenRefresh:
    def test_refresh_valid_token(self, client):
        token = create_access_token("user-1", "test@example.com", "admin")
        resp = client.post(
            "/auth/token/refresh",
            headers={
                "Authorization": f"Bearer {token}",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        # Verify the refreshed token is valid
        refreshed_payload = verify_access_token(data["access_token"])
        assert refreshed_payload["sub"] == "user-1"
        assert refreshed_payload["email"] == "test@example.com"

    def test_refresh_without_bearer(self, client):
        resp = client.post(
            "/auth/token/refresh",
            headers={
                "Authorization": "Basic abc123",
            },
        )
        assert resp.status_code == 401

    def test_refresh_without_auth_header(self, client):
        resp = client.post("/auth/token/refresh")
        assert resp.status_code == 401

    def test_refresh_with_invalid_token(self, client):
        resp = client.post(
            "/auth/token/refresh",
            headers={
                "Authorization": "Bearer invalid.token.here",
            },
        )
        assert resp.status_code == 401

    def test_refresh_rejects_very_old_token(self, client):
        from jose import jwt as jose_jwt
        from agentshield_core.auth.oauth import JWT_SECRET, JWT_ALGORITHM

        old_payload = {
            "sub": "user-1",
            "email": "old@test.com",
            "role": "viewer",
            "iat": int(time.time()) - 200000,
            "exp": int(time.time()) - 100000,  # Expired 100000s ago (> 86400)
        }
        old_token = jose_jwt.encode(old_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        resp = client.post(
            "/auth/token/refresh",
            headers={
                "Authorization": f"Bearer {old_token}",
            },
        )
        assert resp.status_code == 401
        assert "too old" in resp.json()["detail"]
