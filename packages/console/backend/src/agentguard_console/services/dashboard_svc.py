"""Dashboard aggregation service."""

from __future__ import annotations

from typing import Any

from agentguard_console.storage import clickhouse as ch


async def get_overview(hours: int = 24) -> dict[str, Any]:
    stats = await ch.get_dashboard_stats(hours)
    traffic = await ch.get_traffic_timeseries(hours)
    drift = await ch.get_intent_drift_timeseries(hours)
    risk = await ch.get_risk_ranking(hours, limit=10)

    block_rate = 0.0
    if stats["total_calls"] > 0:
        block_rate = round(stats["blocked_calls"] / stats["total_calls"] * 100, 2)

    return {
        "summary": {
            **stats,
            "block_rate_pct": block_rate,
            "time_range_hours": hours,
        },
        "traffic": _serialize_timeseries(traffic),
        "intent_drift": _serialize_timeseries(drift),
        "risk_ranking": risk,
    }


def _serialize_timeseries(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ensure datetime objects are ISO-formatted strings for JSON."""
    out: list[dict[str, Any]] = []
    for row in rows:
        entry = {}
        for k, v in row.items():
            if hasattr(v, "isoformat"):
                entry[k] = v.isoformat()
            else:
                entry[k] = v
        out.append(entry)
    return out
