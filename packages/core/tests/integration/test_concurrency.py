"""Concurrency tests — verify thread safety under concurrent access."""

from __future__ import annotations

import asyncio
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
            content=json.dumps({"intent": "test", "expected_tools": [], "sensitive_data_involved": False}),
            model="mock",
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


class TestConcurrentAccess:
    @pytest.mark.asyncio
    @patch("agentguard_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_concurrent_sessions_dont_interfere(self, mock_insert, pipeline):
        """50 concurrent sessions should not interfere with each other."""
        sessions = []
        for i in range(50):
            sid, tid = await pipeline.create_session(f"task {i}", agent_id=f"agent-{i}")
            sessions.append((sid, tid))

        # Concurrent checks across different sessions
        async def check_session(sid, i):
            tool = "summarize" if i % 2 == 0 else "delete_all"
            r = await pipeline.check_tool_call(
                session_id=sid,
                tool_name=tool,
                tool_params={"i": i},
                source_id="user_input",
            )
            return r

        results = await asyncio.gather(*[check_session(sid, i) for i, (sid, tid) in enumerate(sessions)])

        # Verify results are correct
        for i, result in enumerate(results):
            if i % 2 == 0:
                assert result.action == "ALLOW", f"Session {i} summarize should be ALLOW"
            else:
                assert result.action == "BLOCK", f"Session {i} delete_all should be BLOCK"

    @pytest.mark.asyncio
    @patch("agentguard_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_concurrent_checks_same_session(self, mock_insert, pipeline):
        """Multiple concurrent checks on the same session should all work."""
        sid, _ = await pipeline.create_session("multi-check", agent_id="agent-1")

        async def check(tool_name):
            return await pipeline.check_tool_call(
                session_id=sid,
                tool_name=tool_name,
                tool_params={},
                source_id="user_input",
            )

        results = await asyncio.gather(
            check("summarize"),
            check("classify"),
            check("read_email"),
            check("delete_all"),  # Should be blocked
            check("summarize"),
        )

        # All summarize/classify/read should be ALLOW, delete_all should be BLOCK
        assert results[0].action == "ALLOW"
        assert results[1].action == "ALLOW"
        assert results[3].action == "BLOCK"

    @pytest.mark.asyncio
    @patch("agentguard_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_session_creation_under_load(self, mock_insert, pipeline):
        """Creating many sessions concurrently should not crash."""
        tasks = [pipeline.create_session(f"session {i}", agent_id=f"agent-{i}") for i in range(100)]
        results = await asyncio.gather(*tasks)
        session_ids = {sid for sid, tid in results}
        # All session IDs should be unique
        assert len(session_ids) == 100
