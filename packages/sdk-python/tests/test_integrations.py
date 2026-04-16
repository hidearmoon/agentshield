"""Tests for framework integration patterns.

Tests that the integration wrappers correctly intercept tool calls
and forward them to the shield check.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from agentshield import Shield, ToolCallBlocked


@pytest.fixture(autouse=True)
def set_api_key():
    with patch.dict(os.environ, {"AGENTSHIELD_API_KEY": "test-key"}):
        yield


def _allow_response():
    return httpx.Response(
        200,
        json={"action": "ALLOW", "reason": "", "trace_id": "t1", "span_id": "s1"},
        request=httpx.Request("POST", "http://test/api/v1/check"),
    )


def _block_response(reason="blocked"):
    return httpx.Response(
        200,
        json={"action": "BLOCK", "reason": reason, "trace_id": "t1", "span_id": "s1"},
        request=httpx.Request("POST", "http://test/api/v1/check"),
    )


class TestLangChainIntegration:
    """Test LangChain integration pattern."""

    @pytest.mark.asyncio
    async def test_langchain_allows_on_check_pass(self):
        shield = Shield(api_key="test-key")

        # Create a simple object that behaves like a LangChain tool
        class FakeTool:
            name = "search"

            async def _arun(self, query: str = "") -> str:
                return f"results for {query}"

        tool = FakeTool()

        from agentshield.integrations.langchain import LangChainShield

        LangChainShield(shield)._patch_tool(tool)

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=_allow_response(),
        ):
            result = await tool._arun(query="test query")
            assert result == "results for test query"

    @pytest.mark.asyncio
    async def test_langchain_blocks_on_check_failure(self):
        shield = Shield(api_key="test-key")

        mock_tool = MagicMock()
        mock_tool.name = "dangerous_tool"
        original_arun = AsyncMock(return_value="should not run")
        mock_tool._arun = original_arun

        from agentshield.integrations.langchain import LangChainShield

        wrapper = LangChainShield(shield)
        wrapper._patch_tool(mock_tool)

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=_block_response("tool blocked"),
        ):
            with pytest.raises(ToolCallBlocked):
                await mock_tool._arun(query="test")


class TestClaudeAgentIntegration:
    """Test Claude Agent SDK integration pattern."""

    @pytest.mark.asyncio
    async def test_claude_agent_wraps_handler(self):
        shield = Shield(api_key="test-key")

        async def original_handler(tool_name: str, params: dict) -> str:
            return f"executed {tool_name}"

        from agentshield.integrations.claude_agent import ClaudeAgentShield

        guarded = ClaudeAgentShield(shield).wrap(original_handler)

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=_allow_response(),
        ):
            result = await guarded("summarize", {"text": "hello"})
            assert result == "executed summarize"

    @pytest.mark.asyncio
    async def test_claude_agent_blocks_dangerous(self):
        shield = Shield(api_key="test-key")

        async def original_handler(tool_name: str, params: dict) -> str:
            return "should not run"

        from agentshield.integrations.claude_agent import ClaudeAgentShield

        guarded = ClaudeAgentShield(shield).wrap(original_handler)

        with patch.object(
            shield._client._http,
            "request",
            new_callable=AsyncMock,
            return_value=_block_response("dangerous"),
        ):
            with pytest.raises(ToolCallBlocked):
                await guarded("delete_all", {})
