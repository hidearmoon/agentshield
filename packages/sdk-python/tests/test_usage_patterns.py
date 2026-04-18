"""Tests for common SDK usage patterns from user perspective."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest
import httpx

from agentguard import Shield, ToolCallBlocked, Decision


@pytest.fixture(autouse=True)
def set_api_key():
    with patch.dict(os.environ, {"AGENTGUARD_API_KEY": "test-key"}):
        yield


def _ok_response(**data):
    default = {"action": "ALLOW", "reason": "", "trace_id": "t1", "span_id": "s1"}
    default.update(data)
    return httpx.Response(200, json=default, request=httpx.Request("POST", "http://test/x"))


class TestCommonPatterns:
    """Test the most common SDK usage patterns."""

    @pytest.mark.asyncio
    async def test_pattern_guard_decorator(self):
        """Most basic pattern: @shield.guard decorator."""
        shield = Shield(api_key="key")

        @shield.guard
        async def summarize(text: str) -> str:
            return f"Summary of: {text[:20]}"

        with patch.object(shield._client._http, "request", new_callable=AsyncMock, return_value=_ok_response()):
            result = await summarize(text="This is a long document about AI safety")
            assert result.startswith("Summary of:")

    @pytest.mark.asyncio
    async def test_pattern_manual_check(self):
        """Manual check pattern for conditional execution."""
        shield = Shield(api_key="key")

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=_ok_response(action="BLOCK", reason="too dangerous"),
        ):
            result = await shield.check("delete_all", {"scope": "prod"})
            assert result.action == Decision.BLOCK
            # User can handle block gracefully
            assert result.reason == "too dangerous"

    @pytest.mark.asyncio
    async def test_pattern_context_manager(self):
        """Context manager pattern for auto-cleanup."""
        async with Shield(api_key="key") as shield:

            @shield.guard
            async def safe_op() -> str:
                return "done"

            with patch.object(
                shield._client._http,
                "request",
                new_callable=AsyncMock,
                return_value=_ok_response(),
            ):
                result = await safe_op()
                assert result == "done"

    @pytest.mark.asyncio
    async def test_pattern_custom_tool_name(self):
        """Override tool name for decorated function."""
        shield = Shield(api_key="key")

        @shield.guard(tool_name="custom_email_sender")
        async def my_internal_fn(to: str) -> str:
            return f"sent to {to}"

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=_ok_response(),
        ) as mock:
            await my_internal_fn(to="user@test.com")
            sent_json = mock.call_args.kwargs.get("json")
            assert sent_json["tool_name"] == "custom_email_sender"

    @pytest.mark.asyncio
    async def test_pattern_error_handling(self):
        """Proper error handling for blocked operations."""
        shield = Shield(api_key="key")

        @shield.guard
        async def risky() -> str:
            return "should not return"

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=_ok_response(action="BLOCK", reason="security policy"),
        ):
            blocked = False
            try:
                await risky()
            except ToolCallBlocked as e:
                blocked = True
                assert "risky" in str(e)
                assert e.reason == "security policy"
            assert blocked

    @pytest.mark.asyncio
    async def test_pattern_sanitize(self):
        """Sanitize external data before processing."""
        shield = Shield(api_key="key")
        san_response = httpx.Response(
            200,
            json={
                "content": "clean text",
                "trust_level": "EXTERNAL",
                "sanitization_chain": ["format_cleansing"],
            },
            request=httpx.Request("POST", "http://test/api/v1/sanitize"),
        )

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=san_response,
        ):
            result = await shield.sanitize("dirty <!-- evil -->", source="email/external")
            assert result.content == "clean text"
            assert result.trust_level == "EXTERNAL"
