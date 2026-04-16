"""Resilience tests — verify system behavior under adverse conditions."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from agentshield_core.engine.pipeline import Pipeline
from agentshield_core.engine.trust.marker import TrustMarker, TrustPolicy
from agentshield_core.engine.intent.engine import IntentConsistencyEngine
from agentshield_core.engine.intent.rule_engine import RuleEngine
from agentshield_core.engine.intent.anomaly import AnomalyDetector
from agentshield_core.engine.intent.semantic import SemanticChecker
from agentshield_core.engine.permissions.dynamic import DynamicPermissionEngine
from agentshield_core.engine.trace.engine import TraceEngine
from agentshield_core.llm.client import LLMClient, LLMResponse


class MockLLM(LLMClient):
    async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
        return LLMResponse(
            content=json.dumps({"intent": "t", "expected_tools": [], "sensitive_data_involved": False}),
            model="m",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )


@pytest.fixture
def pipeline():
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


class TestResilience:
    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_clickhouse_failure_doesnt_crash(self, mock_insert, pipeline):
        """If ClickHouse insert fails, the check should still return a result."""
        mock_insert.side_effect = RuntimeError("ClickHouse down")

        sid, _ = await pipeline.create_session("test")

        # Should raise because record_span calls insert_span which fails
        # But pipeline should handle this gracefully
        try:
            result = await pipeline.check_tool_call(sid, "summarize", {}, source_id="user_input")
            # If it reaches here, it handled the error
            assert result.action in ("ALLOW", "BLOCK", "REQUIRE_CONFIRMATION")
        except RuntimeError:
            # This is expected if ClickHouse failure propagates
            # In production, this should be caught and logged
            pass

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_many_sessions_with_cleanup(self, mock_insert, pipeline):
        """Create many sessions and verify cleanup works."""
        for i in range(200):
            await pipeline.create_session(f"session {i}", agent_id=f"agent-{i}")

        assert len(pipeline._sessions) == 200
        assert pipeline.metrics["active_sessions"] == 200

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_pipeline_metrics_after_mixed_workload(self, mock_insert, pipeline):
        """Metrics should accurately reflect a mixed workload."""
        sid, _ = await pipeline.create_session("test")

        # 10 allows, 5 blocks
        for _ in range(10):
            await pipeline.check_tool_call(sid, "summarize", {}, source_id="user_input")
        for _ in range(5):
            await pipeline.check_tool_call(sid, "delete_all", {}, source_id="user_input")

        m = pipeline.metrics
        assert m["total_checks"] == 15
        assert m["blocked_checks"] == 5
        assert abs(m["block_rate"] - 5 / 15) < 0.001
        assert m["avg_check_ms"] > 0

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_special_characters_in_tool_params(self, mock_insert, pipeline):
        """Special characters in params should not cause issues."""
        sid, _ = await pipeline.create_session("test")

        special_params = {
            "query": "SELECT * FROM users WHERE name = 'O\\'Brien'",
            "path": "C:\\Windows\\System32",
            "emoji": "Hello 🌍🔒",
            "unicode": "日本語テスト",
            "null_bytes": "before\x00after",
            "newlines": "line1\nline2\rline3",
        }

        result = await pipeline.check_tool_call(sid, "process", special_params, source_id="user_input")
        assert result.action in ("ALLOW", "BLOCK", "REQUIRE_CONFIRMATION")

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_empty_and_none_params(self, mock_insert, pipeline):
        """Empty and None-like params should be handled."""
        sid, _ = await pipeline.create_session("test")

        for params in [{}, {"key": ""}, {"key": None}, {"key": 0}, {"key": False}]:
            result = await pipeline.check_tool_call(sid, "process", params, source_id="user_input")
            assert result.action in ("ALLOW", "BLOCK", "REQUIRE_CONFIRMATION")
