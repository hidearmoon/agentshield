"""Alert listing and acknowledgement endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard_console.auth.middleware import CurrentUser, get_current_user
from agentguard_console.auth.permissions import Permission, require_role
from agentguard_console.storage.postgres import get_db
from agentguard_console.services import alert_svc

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(
    _user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    status: str | None = None,
    severity: str | None = None,
    agent_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    return await alert_svc.list_alerts(
        db,
        status=status,
        severity=severity,
        agent_id=agent_id,
        limit=limit,
        offset=offset,
    )


@router.get("/{alert_id}")
async def get_alert(
    alert_id: uuid.UUID,
    _user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await alert_svc.get_alert(db, alert_id)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: uuid.UUID,
    user: Annotated[CurrentUser, Depends(require_role(Permission.WRITE))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await alert_svc.acknowledge_alert(db, alert_id, user.user_id)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@router.post("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: uuid.UUID,
    _user: Annotated[CurrentUser, Depends(require_role(Permission.WRITE))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await alert_svc.resolve_alert(db, alert_id)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result
