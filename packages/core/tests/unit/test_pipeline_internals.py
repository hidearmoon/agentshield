"""Tests for Pipeline internal components."""

from __future__ import annotations

import json
import time as time_mod
from unittest.mock import AsyncMock, patch

import pytest

from agentguard_core.engine.pipeline import Pipeline, SessionContext
from agentguard_core.engine.trust.levels import TrustLevel
from agentguard_core.engine.trust.marker import TrustMarker, TrustPolicy
from agentguard_core.engine.intent.engine import IntentConsistencyEngine
from agentguard_core.engine.intent.models import Intent
from agentguard_core.engine.intent.rule_engine import RuleEngine
from agentguard_core.engine.intent.anomaly import AnomalyDetector
from agentguard_core.engine.intent.semantic import SemanticChecker
from agentguard_core.engine.permissions.dynamic import DynamicPermissionEngine
from agentguard_core.engine.trace.engine import TraceEngine
from agentguard_core.llm.client import LLMClient, LLMResponse


class MockLLM(LLMClient):
    async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
        return LLMResponse(
            content=json.dumps({"intent": "t", "expected_tools": [], "sensitive_data_involved": False}),
            model="m",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )


class TestSessionContext:
    def test_current_trust_level_default(self):
        ctx = SessionContext(
            session_id="s1",
            trace_id="t1",
            agent_id="a1",
            user_message="test",
            intent=Intent(intent="test"),
        )
        assert ctx.current_trust_level == TrustLevel.VERIFIED

    def test_current_trust_level_with_scopes(self):
        ctx = SessionContext(
            session_id="s1",
            trace_id="t1",
            agent_id="a1",
            user_message="test",
            intent=Intent(intent="test"),
            trust_scopes=[TrustLevel.EXTERNAL, TrustLevel.INTERNAL],
        )
        assert ctx.current_trust_level == TrustLevel.EXTERNAL  # min


class TestPipelineMetrics:
    @pytest.mark.asyncio
    @patch("agentguard_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_reset_metrics(self, mock_insert):
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
        await pipeline.check_tool_call(sid, "summarize", {}, source_id="user_input")
        await pipeline.check_tool_call(sid, "delete_all", {}, source_id="user_input")

        assert pipeline.metrics["total_checks"] == 2
        assert pipeline.metrics["blocked_checks"] == 1

        pipeline.reset_metrics()
        assert pipeline.metrics["total_checks"] == 0
        assert pipeline.metrics["blocked_checks"] == 0
        assert pipeline.metrics["avg_check_ms"] == 0


class TestSessionEviction:
    @pytest.mark.asyncio
    @patch("agentguard_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_expired_sessions_evicted(self, mock_insert):
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

        # Create a session and make it expired
        s1, _ = await pipeline.create_session("old session")
        pipeline._sessions[s1].created_at = time_mod.time() - 7200  # 2h ago

        # Creating a new session triggers eviction
        s2, _ = await pipeline.create_session("new session")
        assert s1 not in pipeline._sessions
        assert s2 in pipeline._sessions
