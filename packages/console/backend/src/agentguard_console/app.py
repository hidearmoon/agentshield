"""FastAPI application for the AgentGuard Management Console."""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agentguard_console.config import settings
from agentguard_console.storage.postgres import init_db, close_db
from agentguard_console.storage.clickhouse import init_clickhouse, close_clickhouse
from agentguard_console.api.dashboard import router as dashboard_router
from agentguard_console.api.policies import router as policies_router
from agentguard_console.api.traces import router as traces_router
from agentguard_console.api.alerts import router as alerts_router
from agentguard_console.api.agents import router as agents_router
from agentguard_console.api.sources import router as sources_router
from agentguard_console.api.audit import router as audit_router


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None]:
    await init_db()
    await init_clickhouse()
    yield
    await close_db()
    await close_clickhouse()


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentGuard Console",
        version="1.0.0",
        description="Management console for the AgentGuard runtime security platform",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    prefix = "/api/console/v1"
    app.include_router(dashboard_router, prefix=prefix)
    app.include_router(policies_router, prefix=prefix)
    app.include_router(traces_router, prefix=prefix)
    app.include_router(alerts_router, prefix=prefix)
    app.include_router(agents_router, prefix=prefix)
    app.include_router(sources_router, prefix=prefix)
    app.include_router(audit_router, prefix=prefix)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "console", "version": "1.0.0"}

    return app


app = create_app()


def run() -> None:
    uvicorn.run(
        "agentguard_console.app:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
