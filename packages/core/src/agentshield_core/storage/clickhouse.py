"""ClickHouse storage layer for traces and audit logs."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import clickhouse_connect
from clickhouse_connect.driver.asyncclient import AsyncClient

from agentshield_core.config import settings

_client: AsyncClient | None = None

# ─── Schema DDL ──────────────────────────────────────────────────────────────

TRACE_SPANS_DDL = """
CREATE TABLE IF NOT EXISTS trace_spans (
    trace_id String,
    span_id String,
    parent_span_id String,
    agent_id String,
    session_id String,
    span_type Enum8(
        'user_input'=1, 'llm_call'=2, 'tool_call'=3,
        'agent_call'=4, 'data_ingest'=5
    ),
    intent String,
    intent_drift_score Float32,
    data_trust_level LowCardinality(String),
    tool_name LowCardinality(String),
    tool_params String,
    tool_result_summary String,
    decision LowCardinality(String),
    decision_reason String,
    decision_engine LowCardinality(String),
    merkle_hash String,
    start_time DateTime64(3),
    end_time DateTime64(3),
    inserted_at DateTime64(3) DEFAULT now64(3)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(start_time)
ORDER BY (trace_id, start_time, span_id)
TTL toDate(start_time) + INTERVAL 90 DAY
"""

AUDIT_LOG_DDL = """
CREATE TABLE IF NOT EXISTS audit_log (
    event_id String,
    event_type LowCardinality(String),
    actor_id String,
    actor_type LowCardinality(String),
    resource_type LowCardinality(String),
    resource_id String,
    action LowCardinality(String),
    details String,
    merkle_hash String,
    timestamp DateTime64(3),
    inserted_at DateTime64(3) DEFAULT now64(3)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, event_id)
"""

DASHBOARD_STATS_DDL = """
CREATE MATERIALIZED VIEW IF NOT EXISTS dashboard_hourly_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, agent_id, decision)
AS SELECT
    toStartOfHour(start_time) AS hour,
    agent_id,
    decision,
    count() AS call_count,
    avg(intent_drift_score) AS avg_drift_score
FROM trace_spans
GROUP BY hour, agent_id, decision
"""


# ─── Client Management ──────────────────────────────────────────────────────


async def init_clickhouse() -> None:
    global _client
    _client = await clickhouse_connect.get_async_client(
        host=settings.clickhouse_host,
        port=settings.clickhouse_port,
        database=settings.clickhouse_database,
    )
    # Create tables
    await _client.command(TRACE_SPANS_DDL)
    await _client.command(AUDIT_LOG_DDL)
    await _client.command(DASHBOARD_STATS_DDL)


async def close_clickhouse() -> None:
    global _client
    if _client:
        await _client.close()
        _client = None


def get_clickhouse() -> AsyncClient:
    if _client is None:
        raise RuntimeError("ClickHouse client not initialized")
    return _client


# ─── Trace Operations ────────────────────────────────────────────────────────


async def insert_span(span_data: dict[str, Any]) -> None:
    client = get_clickhouse()
    columns = list(span_data.keys())
    values = [list(span_data.values())]
    await client.insert("trace_spans", values, column_names=columns)


async def query_spans_by_trace(trace_id: str) -> list[dict[str, Any]]:
    client = get_clickhouse()
    result = await client.query(
        "SELECT * FROM trace_spans WHERE trace_id = {trace_id:String} ORDER BY start_time",
        parameters={"trace_id": trace_id},
    )
    columns = result.column_names
    return [dict(zip(columns, row)) for row in result.result_rows]


async def query_spans(
    agent_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    decision: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    client = get_clickhouse()
    conditions = []
    params: dict[str, Any] = {}

    if agent_id:
        conditions.append("agent_id = {agent_id:String}")
        params["agent_id"] = agent_id
    if start_time:
        conditions.append("start_time >= {start_time:DateTime64(3)}")
        params["start_time"] = start_time
    if end_time:
        conditions.append("start_time <= {end_time:DateTime64(3)}")
        params["end_time"] = end_time
    if decision:
        conditions.append("decision = {decision:String}")
        params["decision"] = decision

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params["_limit"] = limit
    params["_offset"] = offset
    query = (
        f"SELECT * FROM trace_spans {where} ORDER BY start_time DESC LIMIT {{_limit:UInt32}} OFFSET {{_offset:UInt32}}"
    )

    result = await client.query(query, parameters=params)
    columns = result.column_names
    return [dict(zip(columns, row)) for row in result.result_rows]


async def get_dashboard_stats(hours: int = 24) -> list[dict[str, Any]]:
    client = get_clickhouse()
    result = await client.query(
        """
        SELECT hour, agent_id, decision, call_count, avg_drift_score
        FROM dashboard_hourly_stats
        WHERE hour >= now() - INTERVAL {hours:UInt32} HOUR
        ORDER BY hour DESC
        """,
        parameters={"hours": hours},
    )
    columns = result.column_names
    return [dict(zip(columns, row)) for row in result.result_rows]


# ─── Audit Log Operations ────────────────────────────────────────────────────


async def insert_audit_event(event_data: dict[str, Any]) -> None:
    client = get_clickhouse()
    columns = list(event_data.keys())
    values = [list(event_data.values())]
    await client.insert("audit_log", values, column_names=columns)


async def query_audit_log(
    event_type: str | None = None,
    resource_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    client = get_clickhouse()
    conditions = []
    params: dict[str, Any] = {}

    if event_type:
        conditions.append("event_type = {event_type:String}")
        params["event_type"] = event_type
    if resource_type:
        conditions.append("resource_type = {resource_type:String}")
        params["resource_type"] = resource_type

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params["_limit"] = limit
    params["_offset"] = offset
    query = f"SELECT * FROM audit_log {where} ORDER BY timestamp DESC LIMIT {{_limit:UInt32}} OFFSET {{_offset:UInt32}}"

    result = await client.query(query, parameters=params)
    columns = result.column_names
    return [dict(zip(columns, row)) for row in result.result_rows]
