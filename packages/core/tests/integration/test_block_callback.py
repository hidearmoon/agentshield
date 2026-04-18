"""Tests for the on_block callback mechanism."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from agentguard_core.engine.pipeline import Pipeline
from agentguard_core.engine.trust.marker import TrustMarker, TrustPolicy
from agentguard_core.engine.intent.engine import IntentConsistencyEngine
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


class TestOnBlockCallback:
    @pytest.mark.asyncio
    @patch("agentguard_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_callback_invoked_on_block(self, mock_insert):
        """on_block callback should be called when a tool is blocked."""
        callback = AsyncMock()
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
            on_block=callback,
        )

        sid, _ = await pipeline.create_session("test")
        await pipeline.check_tool_call(sid, "delete_all", {}, source_id="user_input")

        callback.assert_called_once()
        args = callback.call_args[0]
        assert args[0] == "delete_all"  # tool name

    @pytest.mark.asyncio
    @patch("agentguard_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_callback_not_invoked_on_allow(self, mock_insert):
        """on_block callback should NOT be called for allowed operations."""
        callback = AsyncMock()
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
            on_block=callback,
        )

        sid, _ = await pipeline.create_session("test")
        await pipeline.check_tool_call(sid, "summarize", {"text": "hi"}, source_id="user_input")

        callback.assert_not_called()

    @pytest.mark.asyncio
    @patch("agentguard_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_callback_failure_doesnt_crash_pipeline(self, mock_insert):
        """If the callback raises, the pipeline should continue working."""

        async def failing_callback(*args):
            raise RuntimeError("webhook down")

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
            on_block=failing_callback,
        )

        sid, _ = await pipeline.create_session("test")
        # Should not crash even though callback fails
        result = await pipeline.check_tool_call(sid, "delete_all", {}, source_id="user_input")
        assert result.action == "BLOCK"
