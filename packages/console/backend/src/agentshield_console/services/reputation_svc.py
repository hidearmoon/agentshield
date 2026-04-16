"""Data source reputation scoring service."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield_console.storage.postgres import DataSource
from agentshield_console.storage import clickhouse as ch


async def list_sources(
    db: AsyncSession,
    trust_level: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    stmt = select(DataSource).order_by(DataSource.created_at.desc())
    if trust_level:
        stmt = stmt.where(DataSource.trust_level == trust_level)
    stmt = stmt.limit(limit).offset(offset)
    result = await db.execute(stmt)
    return [_source_to_dict(s) for s in result.scalars().all()]


async def get_source(db: AsyncSession, source_id: uuid.UUID) -> dict[str, Any] | None:
    result = await db.execute(select(DataSource).where(DataSource.id == source_id))
    source = result.scalar_one_or_none()
    return _source_to_dict(source) if source else None


async def create_source(
    db: AsyncSession,
    source_id: str,
    trust_level: str,
    description: str | None = None,
    metadata: dict | None = None,
) -> dict[str, Any]:
    source = DataSource(
        source_id=source_id,
        trust_level=trust_level,
        reputation_score=_initial_reputation(trust_level),
        description=description,
        metadata_=metadata or {},
    )
    db.add(source)
    await db.commit()
    await db.refresh(source)
    return _source_to_dict(source)


async def update_source(
    db: AsyncSession,
    pk: uuid.UUID,
    updates: dict[str, Any],
) -> dict[str, Any] | None:
    result = await db.execute(select(DataSource).where(DataSource.id == pk))
    source = result.scalar_one_or_none()
    if not source:
        return None

    for field in ("trust_level", "description", "reputation_score"):
        if field in updates:
            setattr(source, field, updates[field])
    if "metadata" in updates:
        source.metadata_ = updates["metadata"]

    await db.commit()
    await db.refresh(source)
    return _source_to_dict(source)


async def delete_source(db: AsyncSession, pk: uuid.UUID) -> bool:
    result = await db.execute(select(DataSource).where(DataSource.id == pk))
    source = result.scalar_one_or_none()
    if not source:
        return False
    await db.delete(source)
    await db.commit()
    return True


async def recalculate_reputation(db: AsyncSession, pk: uuid.UUID) -> dict[str, Any] | None:
    """Recalculate reputation based on historical trace data."""
    result = await db.execute(select(DataSource).where(DataSource.id == pk))
    source = result.scalar_one_or_none()
    if not source:
        return None

    # Query ClickHouse for data trust signals
    client = ch.get_clickhouse()
    stats = await client.query(
        """
        SELECT
            countIf(decision = 'BLOCK') AS blocked,
            countIf(decision = 'ALLOW') AS allowed,
            avg(intent_drift_score) AS avg_drift
        FROM trace_spans
        WHERE data_trust_level = {trust:String}
            AND start_time >= now() - INTERVAL 30 DAY
        """,
        parameters={"trust": source.trust_level},
    )

    row = stats.result_rows[0] if stats.result_rows else (0, 0, 0.0)
    blocked, allowed, avg_drift = row[0], row[1], float(row[2]) if row[2] else 0.0
    total = blocked + allowed

    if total > 0:
        block_ratio = blocked / total
        drift_penalty = min(avg_drift, 1.0) * 0.3
        new_score = max(0.0, min(1.0, 1.0 - block_ratio * 0.5 - drift_penalty))
    else:
        new_score = _initial_reputation(source.trust_level)

    source.reputation_score = round(new_score, 4)
    await db.commit()
    await db.refresh(source)
    return _source_to_dict(source)


def _initial_reputation(trust_level: str) -> float:
    return {
        "TRUSTED": 1.0,
        "VERIFIED": 0.9,
        "INTERNAL": 0.7,
        "EXTERNAL": 0.5,
        "UNTRUSTED": 0.3,
    }.get(trust_level.upper(), 0.5)


def _source_to_dict(source: DataSource) -> dict[str, Any]:
    return {
        "id": str(source.id),
        "source_id": source.source_id,
        "trust_level": source.trust_level,
        "reputation_score": source.reputation_score,
        "description": source.description,
        "metadata": source.metadata_,
        "created_at": source.created_at.isoformat() if source.created_at else None,
    }
