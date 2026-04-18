"""Data source CRUD with reputation scoring."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard_console.auth.middleware import CurrentUser, get_current_user
from agentguard_console.auth.permissions import Permission, require_role
from agentguard_console.storage.postgres import get_db
from agentguard_console.services import reputation_svc

router = APIRouter(prefix="/sources", tags=["sources"])


class SourceCreate(BaseModel):
    source_id: str
    trust_level: str  # TRUSTED | VERIFIED | INTERNAL | EXTERNAL | UNTRUSTED
    description: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SourceUpdate(BaseModel):
    trust_level: str | None = None
    description: str | None = None
    reputation_score: float | None = None
    metadata: dict[str, Any] | None = None


@router.get("")
async def list_sources(
    _user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    trust_level: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    return await reputation_svc.list_sources(db, trust_level=trust_level, limit=limit, offset=offset)


@router.get("/{source_pk}")
async def get_source(
    source_pk: uuid.UUID,
    _user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await reputation_svc.get_source(db, source_pk)
    if not result:
        raise HTTPException(status_code=404, detail="Source not found")
    return result


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_source(
    body: SourceCreate,
    _user: Annotated[CurrentUser, Depends(require_role(Permission.WRITE))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    return await reputation_svc.create_source(
        db,
        source_id=body.source_id,
        trust_level=body.trust_level,
        description=body.description,
        metadata=body.metadata,
    )


@router.patch("/{source_pk}")
async def update_source(
    source_pk: uuid.UUID,
    body: SourceUpdate,
    _user: Annotated[CurrentUser, Depends(require_role(Permission.WRITE))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    updates = body.model_dump(exclude_none=True)
    result = await reputation_svc.update_source(db, source_pk, updates)
    if not result:
        raise HTTPException(status_code=404, detail="Source not found")
    return result


@router.delete("/{source_pk}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(
    source_pk: uuid.UUID,
    _user: Annotated[CurrentUser, Depends(require_role(Permission.ADMIN))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    deleted = await reputation_svc.delete_source(db, source_pk)
    if not deleted:
        raise HTTPException(status_code=404, detail="Source not found")


@router.post("/{source_pk}/recalculate")
async def recalculate_reputation(
    source_pk: uuid.UUID,
    _user: Annotated[CurrentUser, Depends(require_role(Permission.WRITE))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await reputation_svc.recalculate_reputation(db, source_pk)
    if not result:
        raise HTTPException(status_code=404, detail="Source not found")
    return result
