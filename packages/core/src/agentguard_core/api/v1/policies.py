"""Policy management endpoints with signature verification."""

from __future__ import annotations

from pydantic import BaseModel
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard_core.storage.postgres import get_db, Policy

router = APIRouter()


class PolicyResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    name: str
    version: int
    content: dict
    is_active: bool
    rollout_percentage: int


@router.get("/policies", response_model=list[PolicyResponse])
async def list_policies(db: AsyncSession = Depends(get_db)) -> list[PolicyResponse]:
    result = await db.execute(select(Policy).where(Policy.is_active.is_(True)))
    policies = result.scalars().all()
    return [
        PolicyResponse(
            id=str(p.id),
            name=p.name,
            version=p.version,
            content=p.content,
            is_active=p.is_active,
            rollout_percentage=p.rollout_percentage,
        )
        for p in policies
    ]
