"""Alert management service."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield_console.storage.postgres import Alert


async def list_alerts(
    db: AsyncSession,
    status: str | None = None,
    severity: str | None = None,
    agent_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    stmt = select(Alert).order_by(Alert.created_at.desc())

    if status:
        stmt = stmt.where(Alert.status == status)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if agent_id:
        stmt = stmt.where(Alert.agent_id == agent_id)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    stmt = stmt.limit(limit).offset(offset)
    result = await db.execute(stmt)
    alerts = result.scalars().all()

    return {
        "total": total,
        "items": [_alert_to_dict(a) for a in alerts],
    }


async def get_alert(db: AsyncSession, alert_id: uuid.UUID) -> dict[str, Any] | None:
    stmt = select(Alert).where(Alert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    return _alert_to_dict(alert) if alert else None


async def acknowledge_alert(
    db: AsyncSession,
    alert_id: uuid.UUID,
    user_id: uuid.UUID,
) -> dict[str, Any] | None:
    stmt = select(Alert).where(Alert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    if not alert:
        return None

    alert.status = "acknowledged"
    alert.acknowledged_by = user_id
    alert.acknowledged_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(alert)
    return _alert_to_dict(alert)


async def resolve_alert(
    db: AsyncSession,
    alert_id: uuid.UUID,
) -> dict[str, Any] | None:
    stmt = select(Alert).where(Alert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    if not alert:
        return None

    alert.status = "resolved"
    await db.commit()
    await db.refresh(alert)
    return _alert_to_dict(alert)


def _alert_to_dict(alert: Alert) -> dict[str, Any]:
    return {
        "id": str(alert.id),
        "rule_id": str(alert.rule_id) if alert.rule_id else None,
        "severity": alert.severity,
        "title": alert.title,
        "description": alert.description,
        "agent_id": alert.agent_id,
        "trace_id": alert.trace_id,
        "status": alert.status,
        "acknowledged_by": str(alert.acknowledged_by) if alert.acknowledged_by else None,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "metadata": alert.metadata_,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }
