"""End-to-end test with real PostgreSQL and ClickHouse.

This test exercises the complete flow:
1. Initialize databases
2. Create a pipeline with real trace storage
3. Run security checks
4. Verify traces are stored in ClickHouse
5. Verify Merkle chain integrity from stored data

Requires:
  - PostgreSQL on localhost:5433
  - ClickHouse on localhost:8125
"""

from __future__ import annotations

import json
import os

import pytest

CH_PORT = os.environ.get("AGENTSHIELD_CLICKHOUSE_PORT", "8125")
PG_URL = os.environ.get(
    "AGENTSHIELD_DATABASE_URL",
    "postgresql+asyncpg://agentshield:test-password@localhost:5433/agentshield_test",
)

try:
    import clickhouse_connect

    _ch = clickhouse_connect.get_client(host="localhost", port=int(CH_PORT), database="agentshield")
    _ch.command("SELECT 1")
    DB_AVAILABLE = True
except Exception:
    DB_AVAILABLE = False

pytestmark = pytest.mark.skipif(not DB_AVAILABLE, reason="Databases not available")


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_CLICKHOUSE_PORT", CH_PORT)
    monkeypatch.setenv("AGENTSHIELD_DATABASE_URL", PG_URL)
    from agentshield_core.config import settings

    monkeypatch.setattr(settings, "clickhouse_port", int(CH_PORT))


class TestEndToEndWithDB:
    @pytest.mark.asyncio
    async def test_full_pipeline_with_real_storage(self):
        """Complete flow: session → check → trace stored → Merkle valid."""
        from agentshield_core.engine.pipeline import Pipeline
        from agentshield_core.engine.trust.marker import TrustMarker, TrustPolicy
        from agentshield_core.engine.intent.engine import IntentConsistencyEngine
        from agentshield_core.engine.intent.rule_engine import RuleEngine
        from agentshield_core.engine.intent.anomaly import AnomalyDetector
        from agentshield_core.engine.intent.semantic import SemanticChecker
        from agentshield_core.engine.permissions.dynamic import DynamicPermissionEngine
        from agentshield_core.engine.trace.engine import TraceEngine
        from agentshield_core.engine.trace.merkle import MerkleChain
        from agentshield_core.storage.clickhouse import (
            init_clickhouse,
            close_clickhouse,
            query_spans_by_trace,
        )
        from agentshield_core.llm.client import LLMClient, LLMResponse

        class MockLLM(LLMClient):
            async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
                return LLMResponse(
                    content=json.dumps({"intent": "e2e test", "expected_tools": [], "sensitive_data_involved": False}),
                    model="mock",
                    usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                )

        await init_clickhouse()

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

        # Create session and make tool calls
        session_id, trace_id = await pipeline.create_session("E2E test session", agent_id="e2e-agent")

        r1 = await pipeline.check_tool_call(session_id, "summarize", {"text": "hello"}, source_id="user_input")
        assert r1.action == "ALLOW"

        r2 = await pipeline.check_tool_call(session_id, "delete_all", {}, source_id="user_input")
        assert r2.action == "BLOCK"

        r3 = await pipeline.check_tool_call(
            session_id, "send_email", {"to": "evil@bad.com"}, source_id="email/external"
        )
        assert r3.action == "BLOCK"

        # Verify spans stored in ClickHouse
        spans = await query_spans_by_trace(trace_id)
        assert len(spans) == 3

        decisions = [s["decision"] for s in spans]
        assert "ALLOW" in decisions
        assert "BLOCK" in decisions

        # Verify Merkle chain from in-memory trace
        trace = pipeline._trace_engine.get_trace(trace_id)
        assert MerkleChain.verify_chain(trace.spans)

        # Verify metrics
        m = pipeline.metrics
        assert m["total_checks"] == 3
        assert m["blocked_checks"] == 2

        await close_clickhouse()
