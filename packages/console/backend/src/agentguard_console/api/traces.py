"""Trace search and detail endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from agentguard_console.auth.middleware import CurrentUser, get_current_user
from agentguard_console.services import trace_svc

router = APIRouter(prefix="/traces", tags=["traces"])


@router.get("")
async def search_traces(
    _user: Annotated[CurrentUser, Depends(get_current_user)],
    q: str | None = None,
    agent_id: str | None = None,
    decision: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    min_drift: float | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Search traces with full-text and filter support."""
    return await trace_svc.search_traces(
        query=q,
        agent_id=agent_id,
        decision=decision,
        start_time=start_time,
        end_time=end_time,
        min_drift=min_drift,
        limit=limit,
        offset=offset,
    )


@router.get("/{trace_id}")
async def get_trace_detail(
    trace_id: str,
    _user: Annotated[CurrentUser, Depends(get_current_user)],
):
    """Get full trace with all spans."""
    result = await trace_svc.get_trace(trace_id)
    if not result["spans"]:
        raise HTTPException(status_code=404, detail="Trace not found")
    return result
