"""Tests for the Semantic Checker (Layer 3)."""

from __future__ import annotations

import json

import pytest

from agentguard_core.engine.intent.semantic import SemanticChecker
from agentguard_core.engine.intent.models import (
    DecisionAction,
    Intent,
    IntentContext,
    ToolCall,
)
from agentguard_core.engine.trust.levels import TrustLevel
from agentguard_core.llm.client import LLMClient, LLMResponse


class MockSemanticLLM(LLMClient):
    def __init__(self, response_json: dict):
        self._response = json.dumps(response_json)

    async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
        return LLMResponse(
            content=self._response,
            model="mock",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )


class TestSemanticChecker:
    @pytest.mark.asyncio
    async def test_consistent_tool_call_allowed(self):
        llm = MockSemanticLLM({"consistent": True, "confidence": 0.95, "reason": "matches intent"})
        checker = SemanticChecker(llm)

        tc = ToolCall(name="summarize", params={"text": "hello"})
        ctx = IntentContext(
            original_message="Summarize my emails",
            intent=Intent(intent="summarize emails", expected_tools=["summarize"]),
            current_data_trust_level=TrustLevel.VERIFIED,
        )

        decision = await checker.check(tc, ctx)
        assert decision.action == DecisionAction.ALLOW

    @pytest.mark.asyncio
    async def test_inconsistent_high_confidence_blocked(self):
        llm = MockSemanticLLM({"consistent": False, "confidence": 0.9, "reason": "intent drift detected"})
        checker = SemanticChecker(llm)

        tc = ToolCall(name="delete_all", params={})
        ctx = IntentContext(
            original_message="Read emails",
            intent=Intent(intent="read emails"),
            current_data_trust_level=TrustLevel.EXTERNAL,
        )

        decision = await checker.check(tc, ctx)
        assert decision.action == DecisionAction.BLOCK
        assert decision.engine == "semantic"

    @pytest.mark.asyncio
    async def test_inconsistent_low_confidence_requires_confirmation(self):
        llm = MockSemanticLLM({"consistent": False, "confidence": 0.4, "reason": "maybe off-track"})
        checker = SemanticChecker(llm)

        tc = ToolCall(name="send_email", params={"to": "someone"})
        ctx = IntentContext(
            original_message="Process data",
            intent=Intent(intent="process"),
            current_data_trust_level=TrustLevel.VERIFIED,
        )

        decision = await checker.check(tc, ctx)
        assert decision.action == DecisionAction.REQUIRE_CONFIRMATION

    @pytest.mark.asyncio
    async def test_build_prompt_includes_context(self):
        """The prompt should include intent, tool info, and trust level."""
        captured = []

        class CaptureLLM(LLMClient):
            async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
                captured.extend(messages)
                return LLMResponse(
                    content='{"consistent": true, "confidence": 1.0, "reason": "ok"}',
                    model="m",
                    usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                )

        checker = SemanticChecker(CaptureLLM())
        tc = ToolCall(name="test_tool", params={"key": "value"})
        ctx = IntentContext(
            original_message="Do something",
            intent=Intent(intent="do task"),
            current_data_trust_level=TrustLevel.EXTERNAL,
            tool_call_history=[ToolCall(name="prev_tool")],
        )

        await checker.check(tc, ctx)

        user_msg = next(m for m in captured if m.role == "user")
        assert "test_tool" in user_msg.content
        assert "do task" in user_msg.content
        assert "EXTERNAL" in user_msg.content or "2" in user_msg.content

    @pytest.mark.asyncio
    async def test_invalid_llm_response_allows(self):
        """If LLM returns garbage, fail open (ALLOW)."""
        llm = MockSemanticLLM.__new__(MockSemanticLLM)
        llm._response = "not json at all"

        class BadLLM(LLMClient):
            async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
                return LLMResponse(
                    content="not json",
                    model="m",
                    usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                )

        checker = SemanticChecker(BadLLM())
        tc = ToolCall(name="test", params={})
        ctx = IntentContext(original_message="x", intent=Intent(intent="x"))

        decision = await checker.check(tc, ctx)
        assert decision.action == DecisionAction.ALLOW
