"""Performance benchmarks for core engine components.

These tests verify that key operations meet performance targets:
- Pipeline check: < 1ms (P99)
- Rule engine: < 100μs per check
- Sanitization: < 5ms for typical inputs
- Merkle verification: < 1ms for 100 spans
"""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, patch

import pytest

from agentshield_core.engine.pipeline import Pipeline
from agentshield_core.engine.trust.marker import TrustMarker, TrustPolicy
from agentshield_core.engine.trust.levels import TrustLevel
from agentshield_core.engine.intent.engine import IntentConsistencyEngine
from agentshield_core.engine.intent.rule_engine import RuleEngine
from agentshield_core.engine.intent.anomaly import AnomalyDetector
from agentshield_core.engine.intent.semantic import SemanticChecker
from agentshield_core.engine.intent.models import ToolCall, IntentContext, Intent
from agentshield_core.engine.permissions.dynamic import DynamicPermissionEngine
from agentshield_core.engine.trace.engine import TraceEngine
from agentshield_core.engine.trace.merkle import MerkleChain
from agentshield_core.engine.trace.models import TraceSpan
from agentshield_core.engine.sanitization.format_cleansing import FormatCleansingStage
from agentshield_core.llm.client import LLMClient, LLMResponse
from datetime import datetime, timedelta, timezone


class MockLLM(LLMClient):
    async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
        return LLMResponse(
            content=json.dumps({"intent": "t", "expected_tools": [], "sensitive_data_involved": False}),
            model="m",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )


class TestPipelinePerformance:
    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_check_latency_under_1ms(self, mock_insert):
        """Pipeline check should complete in under 1ms for typical calls."""
        llm = MockLLM()
        pipeline = Pipeline(
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

        sid, _ = await pipeline.create_session("test")

        # Warm up
        for _ in range(10):
            await pipeline.check_tool_call(sid, "summarize", {"text": "hi"}, source_id="user_input")

        # Benchmark
        n = 100
        start = time.perf_counter()
        for _ in range(n):
            await pipeline.check_tool_call(
                session_id=sid,
                tool_name="summarize",
                tool_params={"text": "benchmark"},
                source_id="user_input",
            )
        elapsed = time.perf_counter() - start
        avg_ms = elapsed / n * 1000

        assert avg_ms < 1.0, f"Average {avg_ms:.3f}ms exceeds 1ms target"


class TestRuleEnginePerformance:
    def test_rule_check_under_100us(self):
        """Rule engine check should complete in under 100μs."""
        engine = RuleEngine()
        tc = ToolCall(name="summarize", params={"text": "hello"})
        ctx = IntentContext(
            original_message="test",
            intent=Intent(intent="test"),
            current_data_trust_level=TrustLevel.VERIFIED,
        )

        # Warm up
        for _ in range(100):
            engine.check(tc, ctx)

        n = 1000
        start = time.perf_counter()
        for _ in range(n):
            engine.check(tc, ctx)
        elapsed = time.perf_counter() - start
        avg_us = elapsed / n * 1_000_000

        assert avg_us < 100, f"Average {avg_us:.1f}μs exceeds 100μs target"


class TestSanitizationPerformance:
    @pytest.mark.asyncio
    async def test_sanitize_typical_input_under_5ms(self):
        """Format cleansing should handle typical inputs in under 5ms."""
        stage = FormatCleansingStage()
        typical_email = (
            "Hi team,\n\n"
            "Please review the Q4 report attached.\n"
            "Key findings:\n"
            "- Revenue: $10M (up 25%)\n"
            "- Customer growth: 15%\n"
            "- Churn: 2.1%\n\n"
            "Best regards,\nJohn\n\n"
            '<div style="display:none">hidden injection</div>'
            "<!-- comment injection -->"
            "\u200b\u200c\u200d"
        )

        # Warm up
        for _ in range(10):
            await stage.process(typical_email)

        n = 100
        start = time.perf_counter()
        for _ in range(n):
            await stage.process(typical_email)
        elapsed = time.perf_counter() - start
        avg_ms = elapsed / n * 1000

        assert avg_ms < 5.0, f"Average {avg_ms:.3f}ms exceeds 5ms target"


class TestMerklePerformance:
    def test_verify_100_spans_under_1ms(self):
        """Merkle chain verification of 100 spans should complete in under 1ms."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        chain = MerkleChain()
        spans = []

        for i in range(100):
            span = TraceSpan(
                trace_id="t1",
                span_id=f"s-{i}",
                parent_span_id="",
                agent_id="a1",
                session_id="s1",
                span_type="tool_call",
                intent="test",
                intent_drift_score=0.0,
                data_trust_level="VERIFIED",
                tool_name=f"tool_{i}",
                tool_params={},
                tool_result_summary="",
                decision="ALLOW",
                decision_reason="",
                decision_engine="",
                start_time=base + timedelta(seconds=i),
                end_time=base + timedelta(seconds=i + 1),
            )
            span.merkle_hash = chain.compute_hash(span)
            spans.append(span)

        # Warm up
        for _ in range(10):
            MerkleChain.verify_chain(spans)

        n = 100
        start = time.perf_counter()
        for _ in range(n):
            MerkleChain.verify_chain(spans)
        elapsed = time.perf_counter() - start
        avg_ms = elapsed / n * 1000

        assert avg_ms < 1.0, f"Average {avg_ms:.3f}ms exceeds 1ms target"
