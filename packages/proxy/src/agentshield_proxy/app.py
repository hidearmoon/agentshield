"""FastAPI application — catch-all proxy with middleware chain."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request, Response

from agentshield_proxy.config import settings
from agentshield_proxy.middleware.agent_registry import AgentRegistryMiddleware
from agentshield_proxy.middleware.chain import MiddlewareChain
from agentshield_proxy.middleware.header_handler import ProxyHeaderHandler
from agentshield_proxy.middleware.rate_limiter import RateLimiterMiddleware
from agentshield_proxy.middleware.security_context import SecurityContextMiddleware
from agentshield_proxy.routing.router import ToolRouter
from agentshield_proxy.routing.upstream import UpstreamClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared components initialised once at import time.
# ---------------------------------------------------------------------------
tool_router = ToolRouter()
upstream_client = UpstreamClient(router=tool_router)

middleware_chain = MiddlewareChain()
middleware_chain.add(ProxyHeaderHandler())  # 1. Strip untrusted headers
middleware_chain.add(RateLimiterMiddleware())  # 2. Rate limit
middleware_chain.add(AgentRegistryMiddleware())  # 3. Verify agent identity
middleware_chain.add(SecurityContextMiddleware())  # 4. Core engine security check

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AgentShield Proxy",
    version="0.1.0",
    description="Security proxy between AI agents and their tool services.",
)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def catch_all(request: Request, path: str) -> Response:
    """Intercept every request, run through the middleware chain, then
    forward allowed requests to the upstream tool service."""

    result = await middleware_chain.run(request)

    # If any middleware produced a response (block / rate-limit / error),
    # return it directly without forwarding upstream.
    if result.response is not None:
        return result.response

    # All checks passed — forward to the real tool service.
    return await upstream_client.forward(result.request, result.metadata)


def serve() -> None:
    """Entry point for ``python -m agentshield_proxy``."""
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    logger.info(
        "Starting AgentShield Proxy on %s:%d  core=%s  upstream=%s",
        settings.host,
        settings.port,
        settings.core_engine_url,
        settings.upstream_url,
    )
    uvicorn.run(
        "agentshield_proxy.app:app",
        host=settings.host,
        port=settings.port,
    )


if __name__ == "__main__":
    serve()
