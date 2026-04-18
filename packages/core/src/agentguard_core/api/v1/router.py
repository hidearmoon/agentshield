"""V1 API router aggregator."""

from fastapi import APIRouter

from agentguard_core.api.v1.check import router as check_router
from agentguard_core.api.v1.sanitize import router as sanitize_router
from agentguard_core.api.v1.extract import router as extract_router
from agentguard_core.api.v1.sessions import router as sessions_router
from agentguard_core.api.v1.traces import router as traces_router
from agentguard_core.api.v1.policies import router as policies_router
from agentguard_core.api.v1.rules import router as rules_router

v1_router = APIRouter()

v1_router.include_router(check_router, tags=["check"])
v1_router.include_router(sanitize_router, tags=["sanitize"])
v1_router.include_router(extract_router, tags=["extract"])
v1_router.include_router(sessions_router, tags=["sessions"])
v1_router.include_router(traces_router, tags=["traces"])
v1_router.include_router(policies_router, tags=["policies"])
v1_router.include_router(rules_router, tags=["rules"])
