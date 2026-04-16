"""Trace search and detail service."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agentshield_console.storage import clickhouse as ch


async def search_traces(
    query: str | None = None,
    agent_id: str | None = None,
    decision: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    min_drift: float | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    rows = await ch.search_traces(
        query=query,
        agent_id=agent_id,
        decision=decision,
        start_time=start_time,
        end_time=end_time,
        min_drift=min_drift,
        limit=limit,
        offset=offset,
    )
    return _serialize_rows(rows)


async def get_trace(trace_id: str) -> dict[str, Any]:
    spans = await ch.get_trace_detail(trace_id)
    serialized = _serialize_rows(spans)

    if not serialized:
        return {"trace_id": trace_id, "spans": [], "summary": None}

    # Build summary
    start_times = [s.get("start_time") for s in serialized if s.get("start_time")]
    end_times = [s.get("end_time") for s in serialized if s.get("end_time")]
    agents = list({s.get("agent_id", "") for s in serialized if s.get("agent_id")})
    decisions = list({s.get("decision", "") for s in serialized if s.get("decision")})
    max_drift = max((s.get("intent_drift_score", 0) for s in serialized), default=0)

    return {
        "trace_id": trace_id,
        "spans": serialized,
        "summary": {
            "span_count": len(serialized),
            "agents": agents,
            "decisions": decisions,
            "max_drift": max_drift,
            "start_time": min(start_times) if start_times else None,
            "end_time": max(end_times) if end_times else None,
        },
    }


def _serialize_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        entry = {}
        for k, v in row.items():
            if hasattr(v, "isoformat"):
                entry[k] = v.isoformat()
            elif isinstance(v, bytes):
                entry[k] = v.hex()
            else:
                entry[k] = v
        out.append(entry)
    return out
