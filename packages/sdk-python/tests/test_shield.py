"""Tests for the Shield class and guard decorator."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest
import httpx

from agentshield import Shield, ToolCallBlocked, ConfirmationRejected


@pytest.fixture(autouse=True)
def set_api_key():
    """Set API key env var for all tests."""
    with patch.dict(os.environ, {"AGENTSHIELD_API_KEY": "test-key-123"}):
        yield


@pytest.fixture
def mock_check_response():
    """Create a mock HTTP response for /api/v1/check."""

    def _make(action="ALLOW", reason="", trace_id="t-123", span_id="s-456"):
        return httpx.Response(
            200,
            json={
                "action": action,
                "reason": reason,
                "trace_id": trace_id,
                "span_id": span_id,
            },
            request=httpx.Request("POST", "http://test/api/v1/check"),
        )

    return _make


class TestGuardDecorator:
    @pytest.mark.asyncio
    async def test_guard_allows_call(self, mock_check_response):
        shield = Shield(api_key="test-key")

        @shield.guard
        async def send_email(to: str, body: str) -> str:
            return f"sent to {to}"

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=mock_check_response("ALLOW"),
        ):
            result = await send_email(to="user@company.com", body="hello")
            assert result == "sent to user@company.com"

    @pytest.mark.asyncio
    async def test_guard_blocks_call(self, mock_check_response):
        shield = Shield(api_key="test-key")

        @shield.guard
        async def delete_all(scope: str) -> str:
            return "deleted"

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=mock_check_response("BLOCK", "dangerous operation"),
        ):
            with pytest.raises(ToolCallBlocked) as exc_info:
                await delete_all(scope="production")

            assert "delete_all" in str(exc_info.value)
            assert exc_info.value.reason == "dangerous operation"
            assert exc_info.value.trace_id == "t-123"

    @pytest.mark.asyncio
    async def test_guard_with_custom_name(self, mock_check_response):
        shield = Shield(api_key="test-key")

        @shield.guard(tool_name="custom_tool")
        async def my_function(x: int) -> int:
            return x * 2

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=mock_check_response("ALLOW"),
        ) as mock_post:
            result = await my_function(x=5)
            assert result == 10
            # Verify the custom tool name was sent
            call_kwargs = mock_post.call_args
            sent_json = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
            assert sent_json["tool_name"] == "custom_tool"

    @pytest.mark.asyncio
    async def test_guard_confirmation_with_callback(self, mock_check_response):
        confirmed = False

        async def confirm(tool_name: str, params: dict) -> bool:
            nonlocal confirmed
            confirmed = True
            return True

        shield = Shield(api_key="test-key", confirm_callback=confirm)

        @shield.guard
        async def transfer_funds(amount: float) -> str:
            return "transferred"

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=mock_check_response("REQUIRE_CONFIRMATION", "needs approval"),
        ):
            result = await transfer_funds(amount=1000.0)
            assert result == "transferred"
            assert confirmed

    @pytest.mark.asyncio
    async def test_guard_confirmation_rejected(self, mock_check_response):
        async def reject(tool_name: str, params: dict) -> bool:
            return False

        shield = Shield(api_key="test-key", confirm_callback=reject)

        @shield.guard
        async def risky_op() -> str:
            return "done"

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=mock_check_response("REQUIRE_CONFIRMATION"),
        ):
            with pytest.raises(ConfirmationRejected):
                await risky_op()

    @pytest.mark.asyncio
    async def test_guard_no_callback_raises_on_confirmation(self, mock_check_response):
        shield = Shield(api_key="test-key")  # No confirm_callback

        @shield.guard
        async def risky_op() -> str:
            return "done"

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=mock_check_response("REQUIRE_CONFIRMATION"),
        ):
            with pytest.raises(ConfirmationRejected):
                await risky_op()


class TestShieldConfig:
    def test_missing_api_key_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(Exception, match="API key"):
                Shield()

    def test_api_key_from_env(self):
        shield = Shield()
        assert shield._config.api_key == "test-key-123"

    def test_custom_base_url(self):
        shield = Shield(api_key="key", base_url="https://shield.example.com")
        assert shield._config.base_url == "https://shield.example.com"

    def test_base_url_trailing_slash_stripped(self):
        shield = Shield(api_key="key", base_url="https://shield.example.com/")
        assert not shield._config.base_url.endswith("/")


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_server_error_wrapped(self):
        """500 error should be wrapped as ServerError."""
        from agentshield import ServerError

        shield = Shield(api_key="test-key")

        error_response = httpx.Response(
            500,
            json={"detail": "internal server error"},
            request=httpx.Request("POST", "http://test/api/v1/check"),
        )

        @shield.guard
        async def my_tool() -> str:
            return "done"

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=error_response,
        ):
            with pytest.raises(ServerError) as exc_info:
                await my_tool()
            assert exc_info.value.status_code == 500

    @pytest.mark.asyncio
    async def test_connection_error_wrapped(self):
        """Connection failure should be wrapped as ServerError."""
        from agentshield import ServerError

        shield = Shield(api_key="test-key")

        @shield.guard
        async def my_tool() -> str:
            return "done"

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("refused"),
        ):
            with pytest.raises(ServerError, match="Cannot connect"):
                await my_tool()


class TestShieldLifecycle:
    @pytest.mark.asyncio
    async def test_close_releases_resources(self):
        shield = Shield(api_key="test-key")
        with patch.object(
            shield._client._http,
            "aclose",
            new_callable=AsyncMock,
        ) as mock_close:
            await shield.close()
            mock_close.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Shield can be used as async context manager."""
        with patch.object(
            Shield,
            "close",
            new_callable=AsyncMock,
        ):
            async with Shield(api_key="test-key") as shield:
                assert shield is not None


class TestManualCheck:
    @pytest.mark.asyncio
    async def test_check_returns_result(self, mock_check_response):
        shield = Shield(api_key="test-key")

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=mock_check_response("ALLOW"),
        ):
            result = await shield.check("summarize", {"text": "hello"})
            assert result.action.value == "ALLOW"

    @pytest.mark.asyncio
    async def test_check_with_blocked_tool(self, mock_check_response):
        shield = Shield(api_key="test-key")

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=mock_check_response("BLOCK", reason="dangerous"),
        ):
            result = await shield.check("delete_all")
            assert result.action.value == "BLOCK"
            assert result.reason == "dangerous"
