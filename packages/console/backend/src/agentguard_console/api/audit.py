"""Audit log endpoint — read-only access to immutable audit trail."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from agentguard_console.auth.middleware import CurrentUser, get_current_user
from agentguard_console.storage import clickhouse as ch

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def get_audit_log(
    _user: Annotated[CurrentUser, Depends(get_current_user)],
    event_type: str | None = None,
    actor_id: str | None = None,
    resource_type: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Read-only audit log from ClickHouse."""
    rows = await ch.query_audit_log(
        event_type=event_type,
        actor_id=actor_id,
        resource_type=resource_type,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )

    # Serialize datetime objects
    serialized = []
    for row in rows:
        entry = {}
        for k, v in row.items():
            entry[k] = v.isoformat() if hasattr(v, "isoformat") else v
        serialized.append(entry)

    return serialized
