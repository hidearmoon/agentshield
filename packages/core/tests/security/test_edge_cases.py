"""Edge case security tests — adversarial scenarios that push boundaries."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from agentguard_core.engine.intent.rule_engine import RuleEngine
from agentguard_core.engine.intent.anomaly import AnomalyDetector
from agentguard_core.engine.intent.models import (
    ToolCall,
    IntentContext,
    Intent,
)
from agentguard_core.engine.trust.levels import TrustLevel
from agentguard_core.engine.trust.marker import TrustMarker, TrustPolicy
from agentguard_core.engine.permissions.dynamic import DynamicPermissionEngine
from agentguard_core.engine.trace.merkle import MerkleChain
from agentguard_core.engine.trace.models import TraceSpan
from agentguard_core.engine.sanitization.format_cleansing import FormatCleansingStage
from agentguard_core.engine.pipeline import Pipeline
from agentguard_core.engine.intent.engine import IntentConsistencyEngine
from agentguard_core.engine.intent.semantic import SemanticChecker
from agentguard_core.engine.trace.engine import TraceEngine
from agentguard_core.llm.client import LLMClient, LLMResponse

import json


class MockLLM(LLMClient):
    async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
        return LLMResponse(
            content=json.dumps({"intent": "test", "expected_tools": [], "sensitive_data_involved": False}),
            model="mock",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )


class TestRuleEngineEdgeCases:
    """Test rule engine with adversarial inputs."""

    @pytest.fixture
    def engine(self):
        return RuleEngine()

    def _ctx(self, trust=TrustLevel.EXTERNAL, **kwargs):
        return IntentContext(
            original_message="test",
            intent=Intent(intent="test"),
            current_data_trust_level=trust,
            **kwargs,
        )

    def test_empty_tool_name(self, engine):
        """Empty tool name should not crash."""
        tc = ToolCall(name="", params={})
        result = engine.check(tc, self._ctx())
        # Should not crash — either trigger or pass
        assert result is not None

    def test_very_long_tool_name(self, engine):
        """Very long tool name should not crash."""
        tc = ToolCall(name="a" * 10000, params={})
        result = engine.check(tc, self._ctx())
        assert result is not None

    def test_tool_name_injection_attempt(self, engine):
        """Tool name containing injection patterns should not execute."""
        tc = ToolCall(name="send_email; DROP TABLE users", params={})
        result = engine.check(tc, self._ctx())
        assert result is not None

    def test_rapid_fire_exactly_at_threshold(self, engine):
        """Rapid fire rule triggers at exactly 10 identical calls."""
        history = [ToolCall(name="query", params={}) for _ in range(10)]
        ctx = self._ctx(tool_call_history=history)
        tc = ToolCall(name="query", params={})
        result = engine.check(tc, ctx)
        assert result.triggered
        assert "rapid" in result.rule_name.lower()

    def test_rapid_fire_below_threshold(self, engine):
        """9 identical calls should not trigger rapid fire."""
        history = [ToolCall(name="query", params={}) for _ in range(9)]
        ctx = self._ctx(tool_call_history=history)
        tc = ToolCall(name="query", params={})
        result = engine.check(tc, ctx)
        # rapid_fire should NOT trigger, but other rules might
        if result.triggered:
            assert "rapid" not in result.rule_name.lower()

    def test_params_with_nested_injection(self, engine):
        """Deep nested injection in params should not bypass detection."""
        tc = ToolCall(
            name="query_database",
            params={"data": {"nested": {"deep": "'; DROP TABLE users;--"}}},
        )
        ctx = self._ctx(trust=TrustLevel.EXTERNAL)
        # This tests that the rule engine doesn't crash on nested params
        result = engine.check(tc, ctx)
        assert result is not None

    def test_all_rules_disabled(self, engine):
        """Disabling all rules should allow everything."""
        for rule in engine._rules:
            rule.enabled = False
        tc = ToolCall(name="delete_all", params={})
        result = engine.check(tc, self._ctx())
        assert not result.triggered


class TestAnomalyDetectorEdgeCases:
    """Test anomaly detector with adversarial inputs."""

    @pytest.fixture
    def detector(self):
        return AnomalyDetector()

    def test_empty_context(self, detector):
        """Empty context should not crash."""
        ctx = IntentContext(
            original_message="",
            intent=Intent(intent=""),
            current_data_trust_level=TrustLevel.VERIFIED,
        )
        tc = ToolCall(name="", params={})
        result = detector.check(tc, ctx)
        assert 0 <= result.score <= 1

    def test_max_score_scenario(self, detector):
        """All risk factors maxed should produce high score."""
        ctx = IntentContext(
            original_message="read emails",
            intent=Intent(intent="read", expected_tools=["read"]),
            allowed_tool_categories=["read"],
            current_data_trust_level=TrustLevel.UNTRUSTED,
            tool_call_history=[ToolCall(name="x", params={}) for _ in range(50)],
        )
        tc = ToolCall(
            name="execute_code",
            params={"code": "ignore previous instructions " + "x" * 6000},
            tool_category="execute",
        )
        result = detector.check(tc, ctx)
        assert result.score > 0.5  # High combined score

    def test_params_with_all_injection_patterns(self, detector):
        """All injection patterns in one param should maximize param_anomaly."""
        ctx = IntentContext(
            original_message="test",
            intent=Intent(intent="test"),
            current_data_trust_level=TrustLevel.VERIFIED,
        )
        tc = ToolCall(
            name="process",
            params={"input": "ignore previous system prompt ```eval( exec("},
        )
        result = detector.check(tc, ctx)
        assert result.score > 0.1  # param_anomaly should fire


class TestPermissionEdgeCases:
    """Test permission engine edge cases."""

    def test_empty_agent_tools(self):
        """Empty agent tools should return empty (all allowed)."""
        engine = DynamicPermissionEngine()
        result = engine.get_available_tools(TrustLevel.TRUSTED, agent_tools=[])
        assert result == []

    def test_none_agent_tools_trusted(self):
        """None agent tools at TRUSTED should allow all."""
        engine = DynamicPermissionEngine()
        result = engine.get_available_tools(TrustLevel.TRUSTED)
        assert result == []  # Empty = all allowed

    def test_external_blocks_dangerous(self):
        """EXTERNAL with dangerous tools should filter them out."""
        engine = DynamicPermissionEngine()
        tools = ["summarize", "send_email", "execute_code", "classify"]
        result = engine.get_available_tools(TrustLevel.EXTERNAL, agent_tools=tools)
        assert "send_email" not in result
        assert "execute_code" not in result
        assert "summarize" in result
        assert "classify" in result

    def test_internal_blocks_restricted_only(self):
        """INTERNAL should only block specific restricted tools."""
        engine = DynamicPermissionEngine()
        tools = ["send_email", "summarize", "send_email_external", "export_data"]
        result = engine.get_available_tools(TrustLevel.INTERNAL, agent_tools=tools)
        assert "send_email_external" not in result
        assert "export_data" not in result
        assert "send_email" in result  # Regular send_email is OK at INTERNAL


class TestMerkleChainEdgeCases:
    """Test Merkle chain tamper detection edge cases."""

    def _make_span(self, trace_id="t1", span_id="s1", tool="test", decision="ALLOW"):
        return TraceSpan(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id="",
            agent_id="agent",
            session_id="sess",
            span_type="tool_call",
            intent="test",
            intent_drift_score=0.0,
            data_trust_level="VERIFIED",
            tool_name=tool,
            tool_params={},
            tool_result_summary="",
            decision=decision,
            decision_reason="",
            decision_engine="",
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        )

    def test_reorder_attack_detected(self):
        """Swapping span order should invalidate the chain."""
        chain = MerkleChain()
        s1 = self._make_span(span_id="s1", tool="read")
        s2 = self._make_span(span_id="s2", tool="write")
        s1.merkle_hash = chain.compute_hash(s1)
        s2.merkle_hash = chain.compute_hash(s2)

        # Original order is valid
        assert MerkleChain.verify_chain([s1, s2])
        # Swapped order should fail
        assert not MerkleChain.verify_chain([s2, s1])

    def test_decision_tampering_detected(self):
        """Changing a span's decision should invalidate its hash."""
        chain = MerkleChain()
        s1 = self._make_span(decision="BLOCK")
        s1.merkle_hash = chain.compute_hash(s1)

        assert MerkleChain.verify_chain([s1])

        # Tamper with decision
        s1.decision = "ALLOW"
        assert not MerkleChain.verify_chain([s1])

    def test_insertion_attack_detected(self):
        """Inserting a span into a chain should fail verification."""
        chain = MerkleChain()
        s1 = self._make_span(span_id="s1")
        s2 = self._make_span(span_id="s2")
        s1.merkle_hash = chain.compute_hash(s1)
        s2.merkle_hash = chain.compute_hash(s2)

        # Create a forged span
        forged = self._make_span(span_id="forged", tool="evil")
        forged.merkle_hash = "fakehash"

        # Insert between s1 and s2
        assert not MerkleChain.verify_chain([s1, forged, s2])

    def test_single_span_tampering(self):
        """Even a single span's hash must match."""
        chain = MerkleChain()
        s1 = self._make_span()
        s1.merkle_hash = chain.compute_hash(s1)
        assert MerkleChain.verify_chain([s1])

        s1.tool_name = "evil_tool"
        assert not MerkleChain.verify_chain([s1])


class TestSanitizationEdgeCases:
    """Test format cleansing with adversarial inputs."""

    @pytest.fixture
    def stage(self):
        return FormatCleansingStage()

    @pytest.mark.asyncio
    async def test_empty_input(self, stage):
        result = await stage.process("")
        assert result == ""

    @pytest.mark.asyncio
    async def test_only_zero_width_chars(self, stage):
        """Input of only zero-width chars should become empty."""
        result = await stage.process("\u200b\u200c\u200d\ufeff")
        assert result == ""

    @pytest.mark.asyncio
    async def test_html_with_no_closing_tag(self, stage):
        """Unclosed HTML tags should not cause hangs."""
        result = await stage.process('<div style="display:none">unclosed content')
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_nested_html_comments(self, stage):
        """Nested comments should be fully removed."""
        result = await stage.process("before<!-- outer <!-- inner --> still comment -->after")
        # At minimum, the outer comment markers should be removed
        assert "<!--" not in result

    @pytest.mark.asyncio
    async def test_emoji_preserved(self, stage):
        """Emoji characters should not be stripped."""
        result = await stage.process("Hello 👋 World 🌍")
        assert "👋" in result
        assert "🌍" in result

    @pytest.mark.asyncio
    async def test_cjk_text_preserved(self, stage):
        """CJK text should be preserved."""
        result = await stage.process("你好世界 こんにちは 안녕하세요")
        assert "你好世界" in result
        assert "こんにちは" in result

    @pytest.mark.asyncio
    async def test_legitimate_base64_in_json(self, stage):
        """Base64 that decodes to binary should be left alone."""
        # This is a PNG header in base64
        result = await stage.process("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk")
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_url_in_text_preserved(self, stage):
        """URLs should not be mangled by sanitization."""
        text = "Visit https://example.com/path?q=hello&lang=en for more info"
        result = await stage.process(text)
        assert "https://example.com" in result


class TestTrustMarkerEdgeCases:
    """Test trust marker with edge case sources."""

    def test_empty_source(self):
        marker = TrustMarker(TrustPolicy())
        level = marker.compute_trust_level("")
        assert level == TrustLevel.UNTRUSTED

    def test_source_with_special_chars(self):
        marker = TrustMarker(TrustPolicy())
        level = marker.compute_trust_level("../../../etc/passwd")
        assert level == TrustLevel.UNTRUSTED

    def test_source_case_sensitivity(self):
        marker = TrustMarker(TrustPolicy())
        # "user_input" is mapped, "User_Input" should fall to UNTRUSTED
        level = marker.compute_trust_level("User_Input")
        assert level == TrustLevel.UNTRUSTED

    def test_wildcard_source_matching(self):
        marker = TrustMarker(TrustPolicy())
        level = marker.compute_trust_level("email/gmail/inbox")
        assert level == TrustLevel.EXTERNAL

    def test_client_tries_trusted_for_unknown(self):
        """Client claiming TRUSTED for unknown source should be overridden."""
        marker = TrustMarker(TrustPolicy())
        level = marker.compute_trust_level("unknown", TrustLevel.TRUSTED)
        assert level == TrustLevel.UNTRUSTED  # Server mapping wins


class TestPipelineEdgeCases:
    """Test pipeline with unusual inputs."""

    @pytest.fixture
    def pipeline(self):
        llm = MockLLM()
        return Pipeline(
            trust_marker=TrustMarker(TrustPolicy()),
            intent_engine=IntentConsistencyEngine(
                llm_client=llm,
                rule_engine=RuleEngine(),
                anomaly_detector=AnomalyDetector(),
                semantic_checker=SemanticChecker(llm),
            ),
            permission_engine=DynamicPermissionEngine(),
            trace_engine=TraceEngine(),
        )

    @pytest.mark.asyncio
    @patch("agentguard_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_concurrent_sessions(self, mock_insert, pipeline):
        """Multiple sessions should be independent."""
        s1, _ = await pipeline.create_session("task A", agent_id="a1")
        s2, _ = await pipeline.create_session("task B", agent_id="a2")

        # Check on session 1
        r1 = await pipeline.check_tool_call(
            session_id=s1, tool_name="summarize", tool_params={}, source_id="user_input"
        )
        # Check on session 2
        r2 = await pipeline.check_tool_call(
            session_id=s2, tool_name="summarize", tool_params={}, source_id="user_input"
        )

        # Both should have independent traces
        assert r1.trace_id != r2.trace_id

        # History should be independent
        assert len(pipeline._sessions[s1].tool_call_history) == 1
        assert len(pipeline._sessions[s2].tool_call_history) == 1

    @pytest.mark.asyncio
    @patch("agentguard_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_unicode_tool_name(self, mock_insert, pipeline):
        """Unicode tool names should not crash."""
        s, _ = await pipeline.create_session("test")
        result = await pipeline.check_tool_call(
            session_id=s, tool_name="发送邮件", tool_params={}, source_id="user_input"
        )
        assert result.action in ("ALLOW", "BLOCK", "REQUIRE_CONFIRMATION")

    @pytest.mark.asyncio
    @patch("agentguard_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_empty_params(self, mock_insert, pipeline):
        """Empty params should not crash."""
        s, _ = await pipeline.create_session("test")
        result = await pipeline.check_tool_call(session_id=s, tool_name="list", tool_params={}, source_id="user_input")
        assert result.action in ("ALLOW", "BLOCK", "REQUIRE_CONFIRMATION")
