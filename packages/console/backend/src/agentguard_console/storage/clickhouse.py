"""ClickHouse query helpers for dashboard stats, trace search, and audit log."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import clickhouse_connect
from clickhouse_connect.driver.asyncclient import AsyncClient

from agentguard_console.config import settings

_client: AsyncClient | None = None


async def init_clickhouse() -> None:
    global _client
    _client = await clickhouse_connect.get_async_client(
        host=settings.clickhouse_host,
        port=settings.clickhouse_port,
        database=settings.clickhouse_database,
    )


async def close_clickhouse() -> None:
    global _client
    if _client:
        await _client.close()
        _client = None


def get_clickhouse() -> AsyncClient:
    if _client is None:
        raise RuntimeError("ClickHouse client not initialized")
    return _client


def _rows_to_dicts(result: Any) -> list[dict[str, Any]]:
    columns = result.column_names
    return [dict(zip(columns, row)) for row in result.result_rows]


# ─── Dashboard ──────────────────────────────────────────────────────────────


async def get_dashboard_stats(hours: int = 24) -> dict[str, Any]:
    client = get_clickhouse()

    total_res = await client.query(
        """
        SELECT
            count() AS total_calls,
            countIf(decision = 'BLOCK') AS blocked_calls,
            countIf(decision = 'ALLOW') AS allowed_calls,
            countIf(decision = 'REQUIRE_CONFIRMATION') AS confirm_calls,
            avg(intent_drift_score) AS avg_drift,
            uniq(agent_id) AS active_agents,
            uniq(trace_id) AS total_traces
        FROM trace_spans
        WHERE start_time >= now() - INTERVAL {hours:UInt32} HOUR
        """,
        parameters={"hours": hours},
    )
    row = total_res.result_rows[0] if total_res.result_rows else (0, 0, 0, 0, 0.0, 0, 0)

    return {
        "total_calls": row[0],
        "blocked_calls": row[1],
        "allowed_calls": row[2],
        "confirm_calls": row[3],
        "avg_drift_score": round(float(row[4]), 4) if row[4] else 0.0,
        "active_agents": row[5],
        "total_traces": row[6],
    }


async def get_traffic_timeseries(hours: int = 24, granularity: str = "hour") -> list[dict[str, Any]]:
    client = get_clickhouse()
    bucket_fn = {
        "minute": "toStartOfMinute",
        "hour": "toStartOfHour",
        "day": "toStartOfDay",
    }.get(granularity, "toStartOfHour")

    result = await client.query(
        f"""
        SELECT
            {bucket_fn}(start_time) AS bucket,
            count() AS total,
            countIf(decision = 'BLOCK') AS blocked,
            countIf(decision = 'ALLOW') AS allowed,
            countIf(decision = 'REQUIRE_CONFIRMATION') AS confirm
        FROM trace_spans
        WHERE start_time >= now() - INTERVAL {{hours:UInt32}} HOUR
        GROUP BY bucket
        ORDER BY bucket
        """,
        parameters={"hours": hours},
    )
    return _rows_to_dicts(result)


async def get_intent_drift_timeseries(hours: int = 24) -> list[dict[str, Any]]:
    client = get_clickhouse()
    result = await client.query(
        """
        SELECT
            toStartOfHour(start_time) AS bucket,
            avg(intent_drift_score) AS avg_drift,
            max(intent_drift_score) AS max_drift,
            count() AS sample_count
        FROM trace_spans
        WHERE start_time >= now() - INTERVAL {hours:UInt32} HOUR
            AND intent_drift_score > 0
        GROUP BY bucket
        ORDER BY bucket
        """,
        parameters={"hours": hours},
    )
    return _rows_to_dicts(result)


async def get_risk_ranking(hours: int = 24, limit: int = 10) -> list[dict[str, Any]]:
    client = get_clickhouse()
    result = await client.query(
        """
        SELECT
            agent_id,
            count() AS total_calls,
            countIf(decision = 'BLOCK') AS blocked,
            avg(intent_drift_score) AS avg_drift,
            max(intent_drift_score) AS max_drift
        FROM trace_spans
        WHERE start_time >= now() - INTERVAL {hours:UInt32} HOUR
        GROUP BY agent_id
        ORDER BY blocked DESC, avg_drift DESC
        LIMIT {limit:UInt32}
        """,
        parameters={"hours": hours, "limit": limit},
    )
    return _rows_to_dicts(result)


# ─── Traces ─────────────────────────────────────────────────────────────────


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
    client = get_clickhouse()
    conditions: list[str] = []
    params: dict[str, Any] = {}

    if agent_id:
        conditions.append("agent_id = {agent_id:String}")
        params["agent_id"] = agent_id
    if decision:
        conditions.append("decision = {decision:String}")
        params["decision"] = decision
    if start_time:
        conditions.append("start_time >= {start_time:DateTime64(3)}")
        params["start_time"] = start_time
    if end_time:
        conditions.append("start_time <= {end_time:DateTime64(3)}")
        params["end_time"] = end_time
    if min_drift is not None:
        conditions.append("intent_drift_score >= {min_drift:Float32}")
        params["min_drift"] = min_drift
    if query:
        conditions.append("(intent ILIKE {q:String} OR tool_name ILIKE {q:String})")
        params["q"] = f"%{query}%"

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    # Return distinct traces (grouped by trace_id)
    result = await client.query(
        f"""
        SELECT
            trace_id,
            min(start_time) AS trace_start,
            max(end_time) AS trace_end,
            groupArray(DISTINCT agent_id) AS agents,
            count() AS span_count,
            max(intent_drift_score) AS max_drift,
            groupArray(DISTINCT decision) AS decisions,
            any(intent) AS root_intent
        FROM trace_spans
        {where}
        GROUP BY trace_id
        ORDER BY trace_start DESC
        LIMIT {{_limit:UInt32}} OFFSET {{_offset:UInt32}}
        """,
        parameters={**params, "_limit": limit, "_offset": offset},
    )
    return _rows_to_dicts(result)


async def get_trace_detail(trace_id: str) -> list[dict[str, Any]]:
    client = get_clickhouse()
    result = await client.query(
        """
        SELECT * FROM trace_spans
        WHERE trace_id = {trace_id:String}
        ORDER BY start_time ASC
        """,
        parameters={"trace_id": trace_id},
    )
    return _rows_to_dicts(result)


# ─── Audit Log ──────────────────────────────────────────────────────────────


async def query_audit_log(
    event_type: str | None = None,
    actor_id: str | None = None,
    resource_type: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    client = get_clickhouse()
    conditions: list[str] = []
    params: dict[str, Any] = {}

    if event_type:
        conditions.append("event_type = {event_type:String}")
        params["event_type"] = event_type
    if actor_id:
        conditions.append("actor_id = {actor_id:String}")
        params["actor_id"] = actor_id
    if resource_type:
        conditions.append("resource_type = {resource_type:String}")
        params["resource_type"] = resource_type
    if start_time:
        conditions.append("timestamp >= {start_time:DateTime64(3)}")
        params["start_time"] = start_time
    if end_time:
        conditions.append("timestamp <= {end_time:DateTime64(3)}")
        params["end_time"] = end_time

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params["_limit"] = limit
    params["_offset"] = offset
    sql = f"SELECT * FROM audit_log {where} ORDER BY timestamp DESC LIMIT {{_limit:UInt32}} OFFSET {{_offset:UInt32}}"

    result = await client.query(sql, parameters=params)
    return _rows_to_dicts(result)
