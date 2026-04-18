"""Trace engine — records and manages trace spans with Merkle chain integrity."""

from __future__ import annotations

import json
import uuid
from typing import Any

from agentguard_core.engine.trace.models import TraceSpan, Trace
from agentguard_core.engine.trace.merkle import MerkleChain
from agentguard_core.storage import clickhouse


class TraceEngine:
    """
    Manages trace lifecycle: create, record spans (append-only),
    cross-agent context propagation, and post-hoc analysis.
    """

    def __init__(self) -> None:
        self._traces: dict[str, Trace] = {}
        self._merkle_chains: dict[str, MerkleChain] = {}

    def create_trace(self, session_id: str, user_message: str) -> str:
        trace_id = str(uuid.uuid4())
        self._traces[trace_id] = Trace(
            trace_id=trace_id,
            original_user_intent=user_message,
        )
        self._merkle_chains[trace_id] = MerkleChain()
        return trace_id

    async def record_span(self, span: TraceSpan) -> None:
        # Compute Merkle hash
        chain = self._merkle_chains.get(span.trace_id)
        if chain is None:
            chain = MerkleChain()
            self._merkle_chains[span.trace_id] = chain
        span.merkle_hash = chain.compute_hash(span)

        # Track in memory
        trace = self._traces.get(span.trace_id)
        if trace:
            trace.spans.append(span)

        # Persist to ClickHouse (append-only)
        span_data = self._span_to_dict(span)
        await clickhouse.insert_span(span_data)

    def propagate_context(
        self,
        source_agent: str,
        target_agent: str,
        trace_id: str,
        parent_span_id: str,
    ) -> dict[str, Any]:
        """
        Cross-agent call context propagation.
        Key: trust level is ALWAYS downgraded to INTERNAL.
        """
        trace = self._traces.get(trace_id)
        return {
            "trace_id": trace_id,
            "parent_span_id": parent_span_id,
            "source_agent": source_agent,
            "data_trust_level": "INTERNAL",  # Forced downgrade
            "original_intent": trace.original_user_intent if trace else "",
        }

    def get_trace(self, trace_id: str) -> Trace | None:
        return self._traces.get(trace_id)

    @staticmethod
    def _span_to_dict(span: TraceSpan) -> dict[str, Any]:
        return {
            "trace_id": span.trace_id,
            "span_id": span.span_id,
            "parent_span_id": span.parent_span_id,
            "agent_id": span.agent_id,
            "session_id": span.session_id,
            "span_type": span.span_type,
            "intent": span.intent,
            "intent_drift_score": span.intent_drift_score,
            "data_trust_level": span.data_trust_level,
            "tool_name": span.tool_name,
            "tool_params": json.dumps(span.tool_params),
            "tool_result_summary": span.tool_result_summary,
            "decision": span.decision,
            "decision_reason": span.decision_reason,
            "decision_engine": span.decision_engine,
            "merkle_hash": span.merkle_hash,
            "start_time": span.start_time,
            "end_time": span.end_time,
        }
