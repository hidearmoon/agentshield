"""Trace data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class TraceSpan:
    trace_id: str
    span_id: str
    parent_span_id: str
    agent_id: str
    session_id: str
    span_type: str  # user_input | llm_call | tool_call | agent_call | data_ingest
    intent: str
    intent_drift_score: float
    data_trust_level: str
    tool_name: str
    tool_params: dict
    tool_result_summary: str
    decision: str  # ALLOW | BLOCK | REQUIRE_CONFIRMATION
    decision_reason: str
    decision_engine: str  # rule | anomaly | semantic | permission
    start_time: datetime
    end_time: datetime
    merkle_hash: str = ""


@dataclass
class Trace:
    trace_id: str
    original_user_intent: str
    spans: list[TraceSpan] = field(default_factory=list)
    alert_level: str = "NORMAL"  # NORMAL | SUSPICIOUS | CRITICAL
    summary: str = ""
