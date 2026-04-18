"""FastAPI application factory."""

import uuid
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import Depends, FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from agentguard_core.api.v1.router import v1_router
from agentguard_core.dependencies import get_pipeline
from agentguard_core.engine.pipeline import Pipeline
from agentguard_core.storage.postgres import init_db, close_db
from agentguard_core.storage.clickhouse import init_clickhouse, close_clickhouse

MAX_REQUEST_BODY_SIZE = 10 * 1024 * 1024  # 10 MB


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests with bodies exceeding the size limit."""

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_BODY_SIZE:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )
        return await call_next(request)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add X-Request-ID header for request correlation and debugging."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    await init_db()
    await init_clickhouse()
    yield
    await close_db()
    await close_clickhouse()


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentGuard Core Engine",
        version="1.0.0",
        description=(
            "AI Agent Runtime Security Platform. "
            "Provides tool call interception, data sanitization, "
            "trust-based access control, and intent consistency detection."
        ),
        lifespan=lifespan,
        openapi_tags=[
            {"name": "check", "description": "Tool call security checks"},
            {"name": "sanitize", "description": "Data sanitization pipeline"},
            {"name": "extract", "description": "Two-phase structured extraction"},
            {"name": "sessions", "description": "Session lifecycle management"},
            {"name": "traces", "description": "Trace and span queries"},
            {"name": "policies", "description": "Policy management"},
            {"name": "rules", "description": "Custom rule DSL management"},
        ],
    )

    app.add_middleware(RequestSizeLimitMiddleware)
    app.add_middleware(RequestIDMiddleware)

    app.include_router(v1_router, prefix="/api/v1")

    @app.get("/health")
    async def health() -> dict:
        return {
            "status": "ok",
            "version": "1.0.0",
            "service": "agentguard-core",
        }

    @app.get("/health/detailed")
    async def health_detailed() -> dict:
        """Detailed health check including component status."""
        from agentguard_core.engine.intent.rule_engine import BUILTIN_RULES

        components = {
            "rule_engine": {"status": "ok", "builtin_rules": len(BUILTIN_RULES)},
            "sanitization": {"status": "ok"},
            "trust_marker": {"status": "ok"},
        }

        # Check ClickHouse connectivity
        try:
            from agentguard_core.storage.clickhouse import get_clickhouse

            get_clickhouse()
            components["clickhouse"] = {"status": "ok"}
        except RuntimeError:
            components["clickhouse"] = {"status": "not_initialized"}

        return {
            "status": "ok",
            "version": "1.0.0",
            "service": "agentguard-core",
            "components": components,
        }

    @app.get("/metrics")
    async def metrics(
        pipeline: Pipeline = Depends(get_pipeline),
    ) -> dict:
        """Pipeline performance metrics for monitoring."""
        return pipeline.metrics

    return app


app = create_app()
