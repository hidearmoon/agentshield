"""Integration tests for ClickHouse storage layer.

Requires a running ClickHouse instance on localhost:8125.
Skip these tests if ClickHouse is not available.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone, timedelta

import pytest

# Skip entire module if CH is not available
CH_PORT = os.environ.get("AGENTGUARD_CLICKHOUSE_PORT", "8125")

try:
    import clickhouse_connect

    _client = clickhouse_connect.get_client(host="localhost", port=int(CH_PORT), database="agentguard")
    _client.command("SELECT 1")
    CH_AVAILABLE = True
except Exception:
    CH_AVAILABLE = False

pytestmark = pytest.mark.skipif(not CH_AVAILABLE, reason="ClickHouse not available")


@pytest.fixture(autouse=True)
def set_ch_port(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_CLICKHOUSE_PORT", CH_PORT)
    # Also patch the settings object directly since it's already loaded
    from agentguard_core.config import settings

    monkeypatch.setattr(settings, "clickhouse_port", int(CH_PORT))


@pytest.fixture
async def ch_client():
    """Initialize and yield the async ClickHouse client."""
    from agentguard_core.storage import clickhouse as ch

    await ch.init_clickhouse()
    yield ch
    await ch.close_clickhouse()


def _make_span(trace_id: str = None, decision: str = "ALLOW", tool: str = "summarize", drift: float = 0.0):
    now = datetime.now(timezone.utc)
    return {
        "trace_id": trace_id or str(uuid.uuid4()),
        "span_id": str(uuid.uuid4()),
        "parent_span_id": "",
        "agent_id": "test-agent",
        "session_id": "test-session",
        "span_type": "tool_call",
        "intent": "test intent",
        "intent_drift_score": drift,
        "data_trust_level": "VERIFIED",
        "tool_name": tool,
        "tool_params": '{"key": "value"}',
        "tool_result_summary": "ok",
        "decision": decision,
        "decision_reason": "test" if decision == "BLOCK" else "",
        "decision_engine": "rule" if decision == "BLOCK" else "",
        "merkle_hash": str(uuid.uuid4()),
        "start_time": now,
        "end_time": now + timedelta(milliseconds=5),
    }


class TestClickHouseInsertAndQuery:
    @pytest.mark.asyncio
    async def test_insert_and_query_span(self, ch_client):
        trace_id = f"test-{uuid.uuid4()}"
        span = _make_span(trace_id=trace_id)
        await ch_client.insert_span(span)

        spans = await ch_client.query_spans_by_trace(trace_id)
        assert len(spans) >= 1
        found = [s for s in spans if s["span_id"] == span["span_id"]]
        assert len(found) == 1
        assert found[0]["tool_name"] == "summarize"

    @pytest.mark.asyncio
    async def test_query_spans_with_filters(self, ch_client):
        trace_id = f"filter-{uuid.uuid4()}"
        await ch_client.insert_span(_make_span(trace_id=trace_id, decision="ALLOW", tool="read"))
        await ch_client.insert_span(_make_span(trace_id=trace_id, decision="BLOCK", tool="delete"))

        # Filter by decision
        blocked = await ch_client.query_spans(decision="BLOCK", limit=100)
        # Should have at least one BLOCK span
        assert any(s["decision"] == "BLOCK" for s in blocked)

    @pytest.mark.asyncio
    async def test_dashboard_stats(self, ch_client):
        # Insert some test data
        for _ in range(3):
            await ch_client.insert_span(_make_span(decision="ALLOW"))
        await ch_client.insert_span(_make_span(decision="BLOCK"))

        stats = await ch_client.get_dashboard_stats(hours=1)
        assert isinstance(stats, list)
        # Stats should have entries
        assert len(stats) > 0

    @pytest.mark.asyncio
    async def test_query_with_agent_filter(self, ch_client):
        unique_agent = f"agent-{uuid.uuid4().hex[:8]}"
        span = _make_span(decision="BLOCK", tool="evil")
        span["agent_id"] = unique_agent
        await ch_client.insert_span(span)

        results = await ch_client.query_spans(agent_id=unique_agent, limit=10)
        assert len(results) >= 1
        assert all(r["agent_id"] == unique_agent for r in results)

    @pytest.mark.asyncio
    async def test_query_with_time_filter(self, ch_client):
        from datetime import timedelta

        now = datetime.now(timezone.utc)
        await ch_client.insert_span(_make_span())

        results = await ch_client.query_spans(
            start_time=now - timedelta(minutes=5),
            end_time=now + timedelta(minutes=5),
            limit=100,
        )
        assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_query_with_pagination(self, ch_client):
        for i in range(5):
            await ch_client.insert_span(_make_span(tool=f"page_tool_{i}"))

        page1 = await ch_client.query_spans(limit=2, offset=0)
        page2 = await ch_client.query_spans(limit=2, offset=2)
        # Both pages should have results
        assert len(page1) >= 1
        assert len(page2) >= 1


class TestClickHouseAuditLog:
    @pytest.mark.asyncio
    async def test_insert_and_query_audit_event(self, ch_client):
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": "policy.created",
            "actor_id": "admin-user",
            "actor_type": "user",
            "resource_type": "policy",
            "resource_id": str(uuid.uuid4()),
            "action": "create",
            "details": "Created test policy",
            "merkle_hash": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc),
        }
        await ch_client.insert_audit_event(event)

        logs = await ch_client.query_audit_log(event_type="policy.created", limit=10)
        assert len(logs) >= 1
        assert any(e["event_id"] == event["event_id"] for e in logs)
