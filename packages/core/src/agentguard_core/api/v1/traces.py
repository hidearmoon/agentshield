"""Trace query endpoints."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel
from fastapi import APIRouter, Query

from agentguard_core.storage.clickhouse import query_spans_by_trace, query_spans

router = APIRouter()


class SpanResponse(BaseModel):
    trace_id: str
    span_id: str
    parent_span_id: str
    agent_id: str
    span_type: str
    tool_name: str
    decision: str
    decision_reason: str
    intent_drift_score: float
    start_time: datetime
    end_time: datetime


class TraceResponse(BaseModel):
    trace_id: str
    spans: list[SpanResponse]


@router.get("/traces/{trace_id}", response_model=TraceResponse)
async def get_trace(trace_id: str) -> TraceResponse:
    rows = await query_spans_by_trace(trace_id)
    spans = [SpanResponse(**row) for row in rows]
    return TraceResponse(trace_id=trace_id, spans=spans)


@router.get("/traces")
async def list_traces(
    agent_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    decision: str | None = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    return await query_spans(
        agent_id=agent_id,
        start_time=start_time,
        end_time=end_time,
        decision=decision,
        limit=limit,
        offset=offset,
    )
