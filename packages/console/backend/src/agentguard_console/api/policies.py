"""Policy CRUD with version history and simulation."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard_console.auth.middleware import CurrentUser, get_current_user
from agentguard_console.auth.permissions import Permission, require_role
from agentguard_console.storage.postgres import get_db
from agentguard_console.services import policy_svc

router = APIRouter(prefix="/policies", tags=["policies"])


class RuleCreate(BaseModel):
    rule_name: str
    rule_type: str = "custom"
    condition: dict[str, Any]
    action: str
    priority: int = 0
    enabled: bool = True


class PolicyCreate(BaseModel):
    name: str
    content: dict[str, Any]
    rules: list[RuleCreate]


class PolicyUpdate(BaseModel):
    content: dict[str, Any] | None = None
    is_active: bool | None = None
    rollout_percentage: int | None = None
    rules: list[RuleCreate] | None = None


class SimulateRequest(BaseModel):
    content: dict[str, Any]
    rules: list[RuleCreate]
    test_input: dict[str, Any]


@router.get("")
async def list_policies(
    _user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    active_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    return await policy_svc.list_policies(db, active_only=active_only, limit=limit, offset=offset)


@router.get("/{policy_id}")
async def get_policy(
    policy_id: uuid.UUID,
    _user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await policy_svc.get_policy(db, policy_id)
    if not result:
        raise HTTPException(status_code=404, detail="Policy not found")
    return result


@router.get("/name/{name}/versions")
async def get_policy_versions(
    name: str,
    _user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    return await policy_svc.get_policy_versions(db, name)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_policy(
    body: PolicyCreate,
    user: Annotated[CurrentUser, Depends(require_role(Permission.WRITE))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    return await policy_svc.create_policy(
        db,
        name=body.name,
        content=body.content,
        rules=[r.model_dump() for r in body.rules],
        created_by=user.user_id,
    )


@router.patch("/{policy_id}")
async def update_policy(
    policy_id: uuid.UUID,
    body: PolicyUpdate,
    _user: Annotated[CurrentUser, Depends(require_role(Permission.WRITE))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    updates = body.model_dump(exclude_none=True)
    if "rules" in updates:
        updates["rules"] = [r.model_dump() for r in body.rules]  # type: ignore[union-attr]
    result = await policy_svc.update_policy(db, policy_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail="Policy not found")
    return result


@router.post("/{policy_id}/activate")
async def activate_policy(
    policy_id: uuid.UUID,
    _user: Annotated[CurrentUser, Depends(require_role(Permission.WRITE))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await policy_svc.activate_policy(db, policy_id)
    if not result:
        raise HTTPException(status_code=404, detail="Policy not found")
    return result


@router.post("/simulate")
async def simulate_policy(
    body: SimulateRequest,
    _user: Annotated[CurrentUser, Depends(get_current_user)],
):
    return await policy_svc.simulate_policy(
        content=body.content,
        rules=[r.model_dump() for r in body.rules],
        test_input=body.test_input,
    )
