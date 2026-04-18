"""Session management endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends

from agentguard_core.dependencies import get_pipeline
from agentguard_core.engine.pipeline import Pipeline

router = APIRouter()


class CreateSessionRequest(BaseModel):
    user_message: str
    agent_id: str = ""
    metadata: dict = Field(default_factory=dict)


class SessionResponse(BaseModel):
    session_id: str
    trace_id: str


@router.post("/sessions", response_model=SessionResponse)
async def create_session(
    request: CreateSessionRequest,
    pipeline: Pipeline = Depends(get_pipeline),
) -> SessionResponse:
    session_id, trace_id = await pipeline.create_session(
        user_message=request.user_message,
        agent_id=request.agent_id,
        metadata=request.metadata,
    )
    return SessionResponse(session_id=session_id, trace_id=trace_id)
