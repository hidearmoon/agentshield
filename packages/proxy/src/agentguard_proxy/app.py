"""FastAPI application — catch-all proxy with middleware chain."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request, Response

from agentguard_proxy.config import settings
from agentguard_proxy.middleware.agent_registry import AgentRegistryMiddleware
from agentguard_proxy.middleware.chain import MiddlewareChain
from agentguard_proxy.middleware.header_handler import ProxyHeaderHandler
from agentguard_proxy.middleware.rate_limiter import RateLimiterMiddleware
from agentguard_proxy.middleware.security_context import SecurityContextMiddleware
from agentguard_proxy.routing.router import ToolRouter
from agentguard_proxy.routing.upstream import UpstreamClient

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
    title="AgentGuard Proxy",
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
    """Entry point for ``python -m agentguard_proxy``."""
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    logger.info(
        "Starting AgentGuard Proxy on %s:%d  core=%s  upstream=%s",
        settings.host,
        settings.port,
        settings.core_engine_url,
        settings.upstream_url,
    )
    uvicorn.run(
        "agentguard_proxy.app:app",
        host=settings.host,
        port=settings.port,
    )


if __name__ == "__main__":
    serve()
