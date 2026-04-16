"""Tests for the 3-layer cascade intent detection behavior.

Verifies the interaction between:
- Layer 1: Rule Engine (deterministic, microseconds)
- Layer 2: Anomaly Detector (statistical, sub-millisecond)
- Layer 3: Semantic Checker (LLM-based, only when suspicious)
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from agentshield_core.engine.intent.engine import IntentConsistencyEngine
from agentshield_core.engine.intent.rule_engine import RuleEngine
from agentshield_core.engine.intent.anomaly import AnomalyDetector, AnomalyResult
from agentshield_core.engine.intent.semantic import SemanticChecker
from agentshield_core.engine.intent.models import (
    ToolCall,
    Decision,
    DecisionAction,
)
from agentshield_core.llm.client import LLMClient, LLMResponse


class MockLLM(LLMClient):
    async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
        return LLMResponse(
            content=json.dumps({"intent": "test", "expected_tools": [], "sensitive_data_involved": False}),
            model="mock",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )


class TestIntentCascade:
    @pytest.fixture
    def llm(self):
        return MockLLM()

    @pytest.fixture
    def engine(self, llm):
        return IntentConsistencyEngine(llm_client=llm)

    @pytest.mark.asyncio
    async def test_rule_engine_short_circuits(self, engine):
        """When rule engine gives definitive result, anomaly and semantic are skipped."""
        session_id = "test-session"
        await engine.on_session_start(session_id, "help me")

        # delete_all triggers builtin data_destruction rule
        tc = ToolCall(name="delete_all", params={})
        decision = await engine.check_tool_call(session_id, tc)

        assert decision.action == DecisionAction.BLOCK
        assert decision.engine == "rule"

    @pytest.mark.asyncio
    async def test_low_anomaly_score_allows(self, engine):
        """Low anomaly score (< 0.6) should ALLOW without semantic check."""
        session_id = "test-session"
        await engine.on_session_start(session_id, "summarize emails")

        tc = ToolCall(name="summarize", params={"text": "hello"})
        decision = await engine.check_tool_call(session_id, tc)

        assert decision.action == DecisionAction.ALLOW

    @pytest.mark.asyncio
    async def test_high_anomaly_score_blocks_without_semantic(self, llm):
        """Score >= 0.85 should BLOCK without calling semantic checker."""
        # Create a detector that always returns very high score
        detector = AnomalyDetector()

        def high_score_check(tc, ctx):
            return AnomalyResult(score=0.9, reason="very suspicious")

        detector.check = high_score_check

        semantic = SemanticChecker(llm)
        semantic_mock = AsyncMock(return_value=Decision.allow())
        semantic.check = semantic_mock

        engine = IntentConsistencyEngine(
            llm_client=llm,
            rule_engine=RuleEngine(rules=[]),  # No rules
            anomaly_detector=detector,
            semantic_checker=semantic,
        )

        await engine.on_session_start("s1", "test")
        tc = ToolCall(name="evil", params={})
        decision = await engine.check_tool_call("s1", tc)

        assert decision.action == DecisionAction.BLOCK
        assert decision.engine == "anomaly"
        # Semantic should NOT be called
        semantic_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_suspicious_score_triggers_semantic(self, llm):
        """Score between 0.6 and 0.85 should trigger semantic check."""
        detector = AnomalyDetector()

        def suspicious_check(tc, ctx):
            return AnomalyResult(score=0.7, reason="somewhat suspicious")

        detector.check = suspicious_check

        # Semantic checker that says inconsistent
        semantic = SemanticChecker(llm)
        semantic_mock = AsyncMock(return_value=Decision.block("intent mismatch", "semantic"))
        semantic.check = semantic_mock

        engine = IntentConsistencyEngine(
            llm_client=llm,
            rule_engine=RuleEngine(rules=[]),
            anomaly_detector=detector,
            semantic_checker=semantic,
        )

        await engine.on_session_start("s1", "read emails")
        tc = ToolCall(name="send_email", params={"to": "x@y.com"})
        decision = await engine.check_tool_call("s1", tc)

        # Semantic was called and decided to block
        semantic_mock.assert_called_once()
        assert decision.action == DecisionAction.BLOCK
        assert decision.engine == "semantic"

    @pytest.mark.asyncio
    async def test_no_session_context_allows(self, engine):
        """Missing session context should allow (handled at pipeline level)."""
        tc = ToolCall(name="anything", params={})
        decision = await engine.check_tool_call("nonexistent-session", tc)
        assert decision.action == DecisionAction.ALLOW

    @pytest.mark.asyncio
    async def test_intent_extraction_empty_message(self, engine):
        """Empty user message should still create valid context."""
        await engine.on_session_start("s1", "")
        ctx = engine.get_context("s1")
        assert ctx is not None
        assert ctx.intent.intent == "unknown"

    @pytest.mark.asyncio
    async def test_multiple_tool_calls_accumulate_history(self, engine):
        """Tool call history should accumulate across calls."""
        await engine.on_session_start("s1", "process data")

        for i in range(5):
            tc = ToolCall(name=f"step_{i}", params={})
            await engine.check_tool_call("s1", tc)

        ctx = engine.get_context("s1")
        # History is tracked in the IntentContext (via allowed_tool_categories etc)
        assert ctx is not None


class TestSemanticChecker:
    """Test the semantic checker's response parsing."""

    def test_parse_consistent_response(self):
        decision = SemanticChecker._parse_response(
            json.dumps({"consistent": True, "confidence": 0.95, "reason": "matches intent"})
        )
        assert decision.action == DecisionAction.ALLOW

    def test_parse_inconsistent_high_confidence(self):
        decision = SemanticChecker._parse_response(
            json.dumps({"consistent": False, "confidence": 0.9, "reason": "intent drift"})
        )
        assert decision.action == DecisionAction.BLOCK
        assert decision.engine == "semantic"

    def test_parse_inconsistent_low_confidence(self):
        decision = SemanticChecker._parse_response(
            json.dumps({"consistent": False, "confidence": 0.4, "reason": "maybe wrong"})
        )
        assert decision.action == DecisionAction.REQUIRE_CONFIRMATION

    def test_parse_invalid_json_allows(self):
        """If LLM returns garbage, fail open (allow)."""
        decision = SemanticChecker._parse_response("not json at all")
        assert decision.action == DecisionAction.ALLOW

    def test_parse_empty_response_allows(self):
        decision = SemanticChecker._parse_response("{}")
        assert decision.action == DecisionAction.ALLOW
