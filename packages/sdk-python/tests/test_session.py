"""Tests for ShieldSession and GuardedExecutor."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest
import httpx

from agentshield import Shield, ToolCallBlocked


@pytest.fixture(autouse=True)
def set_api_key():
    with patch.dict(os.environ, {"AGENTSHIELD_API_KEY": "test-key-123"}):
        yield


def _mock_response(action="ALLOW", **kwargs):
    data = {"action": action, "reason": kwargs.get("reason", ""), "trace_id": "t1", "span_id": "s1"}
    data.update(kwargs)
    return httpx.Response(200, json=data, request=httpx.Request("POST", "http://test/api/v1/check"))


def _mock_session_response():
    return httpx.Response(
        200,
        json={"session_id": "sess-123", "trace_id": "trace-456"},
        request=httpx.Request("POST", "http://test/api/v1/sessions"),
    )


class TestShieldSession:
    @pytest.mark.asyncio
    async def test_session_creates_and_provides_executor(self):
        shield = Shield(api_key="test-key")

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=_mock_session_response(),
        ):
            async with shield.session("Summarize my emails") as s:
                assert s.session_id == "sess-123"
                assert s.trace_id == "trace-456"
                assert s.guarded_executor is not None

    @pytest.mark.asyncio
    async def test_executor_runs_function_on_allow(self):
        shield = Shield(api_key="test-key")

        call_count = 0

        async def my_tool(**kwargs):
            nonlocal call_count
            call_count += 1
            return "result"

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            side_effect=[_mock_session_response(), _mock_response("ALLOW")],
        ):
            async with shield.session("test") as s:
                result = await s.guarded_executor.execute("my_tool", {}, my_tool)
                assert result == "result"
                assert call_count == 1

    @pytest.mark.asyncio
    async def test_executor_blocks_on_block(self):
        shield = Shield(api_key="test-key")

        async def my_tool(**kwargs):
            return "should not run"

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            side_effect=[_mock_session_response(), _mock_response("BLOCK", reason="dangerous")],
        ):
            async with shield.session("test") as s:
                with pytest.raises(ToolCallBlocked) as exc_info:
                    await s.guarded_executor.execute("danger", {}, my_tool)
                assert "dangerous" in exc_info.value.reason

    @pytest.mark.asyncio
    async def test_executor_confirmation_callback(self):
        confirmed = False

        async def confirm(tool_name, params):
            nonlocal confirmed
            confirmed = True
            return True

        shield = Shield(api_key="test-key", confirm_callback=confirm)

        async def my_tool(**kwargs):
            return "ok"

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            side_effect=[_mock_session_response(), _mock_response("REQUIRE_CONFIRMATION")],
        ):
            async with shield.session("test") as s:
                result = await s.guarded_executor.execute("risky", {}, my_tool)
                assert result == "ok"
                assert confirmed

    @pytest.mark.asyncio
    async def test_session_outside_context_manager_raises(self):
        shield = Shield(api_key="test-key")
        session = shield.session("test")
        with pytest.raises(RuntimeError, match="async context manager"):
            _ = session.guarded_executor

    @pytest.mark.asyncio
    async def test_executor_passes_params_to_function(self):
        shield = Shield(api_key="test-key")
        received_params = {}

        async def my_tool(to: str, body: str):
            received_params["to"] = to
            received_params["body"] = body
            return "sent"

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            side_effect=[_mock_session_response(), _mock_response("ALLOW")],
        ):
            async with shield.session("test") as s:
                result = await s.guarded_executor.execute(
                    "send_email",
                    {"to": "user@test.com", "body": "hello"},
                    my_tool,
                )
                assert result == "sent"
                assert received_params["to"] == "user@test.com"
