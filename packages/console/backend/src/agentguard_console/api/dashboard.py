"""Dashboard statistics endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from agentguard_console.auth.middleware import CurrentUser, get_current_user
from agentguard_console.services import dashboard_svc

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
async def get_dashboard_stats(
    _user: Annotated[CurrentUser, Depends(get_current_user)],
    hours: Annotated[int, Query(ge=1, le=720)] = 24,
):
    """Aggregate dashboard metrics from ClickHouse."""
    return await dashboard_svc.get_overview(hours)
