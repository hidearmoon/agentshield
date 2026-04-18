"""Tests for the SecurityContextMiddleware."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
import httpx
from starlette.requests import Request
from starlette.types import Scope

from agentguard_proxy.middleware.security_context import SecurityContextMiddleware


def _make_request(path="/tools/test", body=b'{"key": "value"}'):
    scope: Scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "query_string": b"",
        "root_path": "",
        "headers": [(b"content-type", b"application/json")],
        "server": ("localhost", 8080),
    }
    return Request(scope, receive=AsyncMock(return_value={"type": "http.request", "body": body}))


class TestSecurityContextMiddleware:
    @pytest.mark.asyncio
    async def test_block_response_on_block_action(self):
        mock_resp = httpx.Response(
            200,
            json={"action": "BLOCK", "reason": "dangerous", "trace_id": "t1", "span_id": "s1"},
            request=httpx.Request("POST", "http://core/api/v1/check"),
        )
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        mw = SecurityContextMiddleware(http_client=mock_client)
        request = _make_request()
        result = await mw.process(request, {"passthrough_headers": {}})

        assert result.response is not None
        assert result.response.status_code == 403

    @pytest.mark.asyncio
    async def test_confirmation_response(self):
        mock_resp = httpx.Response(
            200,
            json={"action": "REQUIRE_CONFIRMATION", "reason": "needs approval", "trace_id": "t1", "span_id": "s1"},
            request=httpx.Request("POST", "http://core/api/v1/check"),
        )
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        mw = SecurityContextMiddleware(http_client=mock_client)
        result = await mw.process(_make_request(), {"passthrough_headers": {}})

        assert result.response is not None
        assert result.response.status_code == 428

    @pytest.mark.asyncio
    async def test_allow_passes_through(self):
        mock_resp = httpx.Response(
            200,
            json={"action": "ALLOW", "trace_id": "t1", "span_id": "s1"},
            request=httpx.Request("POST", "http://core/api/v1/check"),
        )
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        mw = SecurityContextMiddleware(http_client=mock_client)
        result = await mw.process(_make_request(), {"passthrough_headers": {}})

        assert result.response is None  # Passes through
        assert result.metadata["security_action"] == "ALLOW"

    @pytest.mark.asyncio
    async def test_core_engine_error_returns_502(self):
        mock_resp = httpx.Response(
            500,
            json={"error": "internal"},
            request=httpx.Request("POST", "http://core/api/v1/check"),
        )
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        mw = SecurityContextMiddleware(http_client=mock_client)
        result = await mw.process(_make_request(), {"passthrough_headers": {}})

        assert result.response is not None
        assert result.response.status_code == 502
