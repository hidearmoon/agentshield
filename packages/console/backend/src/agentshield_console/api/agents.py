"""Agent registry CRUD and topology endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield_console.auth.middleware import CurrentUser, get_current_user
from agentshield_console.auth.permissions import Permission, require_role
from agentshield_console.storage.postgres import Agent, get_db
from agentshield_console.storage import clickhouse as ch

router = APIRouter(prefix="/agents", tags=["agents"])


class AgentCreate(BaseModel):
    agent_id: str
    name: str
    description: str | None = None
    allowed_tools: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    allowed_tools: list[str] | None = None
    metadata: dict[str, Any] | None = None


def _agent_to_dict(agent: Agent) -> dict[str, Any]:
    return {
        "id": str(agent.id),
        "agent_id": agent.agent_id,
        "name": agent.name,
        "description": agent.description,
        "allowed_tools": agent.allowed_tools,
        "metadata": agent.metadata_,
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
        "updated_at": agent.updated_at.isoformat() if agent.updated_at else None,
    }


@router.get("")
async def list_agents(
    _user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    stmt = select(Agent).order_by(Agent.name).limit(limit).offset(offset)
    result = await db.execute(stmt)
    return [_agent_to_dict(a) for a in result.scalars().all()]


@router.get("/topology")
async def get_agent_topology(
    _user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    hours: Annotated[int, Query(ge=1, le=720)] = 24,
):
    """Return nodes (agents) and edges (inter-agent calls) for a network graph."""
    # Nodes from the registry
    agents_result = await db.execute(select(Agent))
    agents = agents_result.scalars().all()
    nodes = [{"id": a.agent_id, "name": a.name, "tools": a.allowed_tools} for a in agents]

    # Edges from ClickHouse trace data (parent-child agent relationships)
    client = ch.get_clickhouse()
    edges_result = await client.query(
        """
        SELECT
            parent.agent_id AS source,
            child.agent_id AS target,
            count() AS call_count
        FROM trace_spans AS child
        INNER JOIN trace_spans AS parent
            ON child.trace_id = parent.trace_id
            AND child.parent_span_id = parent.span_id
        WHERE child.start_time >= now() - INTERVAL {hours:UInt32} HOUR
            AND parent.agent_id != child.agent_id
        GROUP BY source, target
        ORDER BY call_count DESC
        """,
        parameters={"hours": hours},
    )
    edges = [{"source": row[0], "target": row[1], "weight": row[2]} for row in edges_result.result_rows]

    return {"nodes": nodes, "edges": edges}


@router.get("/{agent_pk}")
async def get_agent(
    agent_pk: uuid.UUID,
    _user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(select(Agent).where(Agent.id == agent_pk))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _agent_to_dict(agent)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_agent(
    body: AgentCreate,
    _user: Annotated[CurrentUser, Depends(require_role(Permission.WRITE))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    agent = Agent(
        agent_id=body.agent_id,
        name=body.name,
        description=body.description,
        allowed_tools=body.allowed_tools,
        metadata_=body.metadata,
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    return _agent_to_dict(agent)


@router.patch("/{agent_pk}")
async def update_agent(
    agent_pk: uuid.UUID,
    body: AgentUpdate,
    _user: Annotated[CurrentUser, Depends(require_role(Permission.WRITE))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(select(Agent).where(Agent.id == agent_pk))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if body.name is not None:
        agent.name = body.name
    if body.description is not None:
        agent.description = body.description
    if body.allowed_tools is not None:
        agent.allowed_tools = body.allowed_tools
    if body.metadata is not None:
        agent.metadata_ = body.metadata

    await db.commit()
    await db.refresh(agent)
    return _agent_to_dict(agent)


@router.delete("/{agent_pk}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent(
    agent_pk: uuid.UUID,
    _user: Annotated[CurrentUser, Depends(require_role(Permission.ADMIN))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(select(Agent).where(Agent.id == agent_pk))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    await db.delete(agent)
    await db.commit()
