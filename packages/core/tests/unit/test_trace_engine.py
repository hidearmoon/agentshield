"""Tests for the Trace Engine — lifecycle, propagation, and Merkle integrity."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from agentshield_core.engine.trace.engine import TraceEngine
from agentshield_core.engine.trace.models import TraceSpan
from agentshield_core.engine.trace.merkle import MerkleChain


class TestTraceEngine:
    @pytest.fixture
    def engine(self):
        return TraceEngine()

    def test_create_trace(self, engine):
        trace_id = engine.create_trace("session-1", "Test message")
        assert trace_id
        trace = engine.get_trace(trace_id)
        assert trace is not None
        assert trace.original_user_intent == "Test message"
        assert trace.spans == []

    def test_get_nonexistent_trace(self, engine):
        assert engine.get_trace("nonexistent") is None

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_record_span_adds_to_trace(self, mock_insert, engine):
        trace_id = engine.create_trace("s1", "Test")
        span = TraceSpan(
            trace_id=trace_id,
            span_id="span-1",
            parent_span_id="",
            agent_id="agent-1",
            session_id="s1",
            span_type="tool_call",
            intent="test",
            intent_drift_score=0.0,
            data_trust_level="VERIFIED",
            tool_name="summarize",
            tool_params={},
            tool_result_summary="",
            decision="ALLOW",
            decision_reason="",
            decision_engine="",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
        )
        await engine.record_span(span)

        trace = engine.get_trace(trace_id)
        assert len(trace.spans) == 1
        assert trace.spans[0].merkle_hash != ""  # Hash was computed

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_record_span_computes_merkle_hash(self, mock_insert, engine):
        trace_id = engine.create_trace("s1", "Test")
        span1 = TraceSpan(
            trace_id=trace_id,
            span_id="span-1",
            parent_span_id="",
            agent_id="a1",
            session_id="s1",
            span_type="tool_call",
            intent="test",
            intent_drift_score=0.0,
            data_trust_level="V",
            tool_name="tool1",
            tool_params={},
            tool_result_summary="",
            decision="ALLOW",
            decision_reason="",
            decision_engine="",
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        )
        span2 = TraceSpan(
            trace_id=trace_id,
            span_id="span-2",
            parent_span_id="span-1",
            agent_id="a1",
            session_id="s1",
            span_type="tool_call",
            intent="test",
            intent_drift_score=0.0,
            data_trust_level="V",
            tool_name="tool2",
            tool_params={},
            tool_result_summary="",
            decision="BLOCK",
            decision_reason="blocked",
            decision_engine="rule",
            start_time=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
            end_time=datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc),
        )
        await engine.record_span(span1)
        await engine.record_span(span2)

        trace = engine.get_trace(trace_id)
        # Merkle chain should be valid
        assert MerkleChain.verify_chain(trace.spans)

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_record_span_persists_to_clickhouse(self, mock_insert, engine):
        trace_id = engine.create_trace("s1", "Test")
        span = TraceSpan(
            trace_id=trace_id,
            span_id="span-1",
            parent_span_id="",
            agent_id="a1",
            session_id="s1",
            span_type="tool_call",
            intent="test",
            intent_drift_score=0.1,
            data_trust_level="EXTERNAL",
            tool_name="read",
            tool_params={"key": "value"},
            tool_result_summary="ok",
            decision="ALLOW",
            decision_reason="",
            decision_engine="",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
        )
        await engine.record_span(span)

        mock_insert.assert_called_once()
        span_data = mock_insert.call_args[0][0]
        assert span_data["trace_id"] == trace_id
        assert span_data["tool_name"] == "read"
        assert span_data["decision"] == "ALLOW"

    def test_propagate_context_downgrades_to_internal(self, engine):
        """Cross-agent propagation should force trust to INTERNAL."""
        trace_id = engine.create_trace("s1", "Orchestrate task")

        ctx = engine.propagate_context(
            source_agent="agent-A",
            target_agent="agent-B",
            trace_id=trace_id,
            parent_span_id="span-1",
        )

        assert ctx["data_trust_level"] == "INTERNAL"
        assert ctx["trace_id"] == trace_id
        assert ctx["parent_span_id"] == "span-1"
        assert ctx["original_intent"] == "Orchestrate task"

    def test_propagate_context_nonexistent_trace(self, engine):
        """Propagation for unknown trace should still work."""
        ctx = engine.propagate_context(
            source_agent="A",
            target_agent="B",
            trace_id="nonexistent",
            parent_span_id="sp-1",
        )
        assert ctx["data_trust_level"] == "INTERNAL"
        assert ctx["original_intent"] == ""

    @pytest.mark.asyncio
    @patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock)
    async def test_record_span_creates_chain_for_unknown_trace(self, mock_insert, engine):
        """Recording a span for an unknown trace should auto-create the chain."""
        span = TraceSpan(
            trace_id="orphan-trace",
            span_id="span-1",
            parent_span_id="",
            agent_id="a1",
            session_id="s1",
            span_type="tool_call",
            intent="test",
            intent_drift_score=0.0,
            data_trust_level="V",
            tool_name="test",
            tool_params={},
            tool_result_summary="",
            decision="ALLOW",
            decision_reason="",
            decision_engine="",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
        )
        await engine.record_span(span)
        assert span.merkle_hash != ""
