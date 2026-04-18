"""Agent registry middleware — verifies the agent_id is pre-registered.

If the ``X-AgentGuard-Agent-ID`` header is present, this middleware
calls the core engine to verify that the agent is known.  Unregistered
agents are rejected with 403 before anything else happens.
"""

from __future__ import annotations

import logging

import httpx
from fastapi import Request, Response

from agentguard_proxy.config import settings
from agentguard_proxy.middleware.chain import MiddlewareResult

logger = logging.getLogger(__name__)

# In-process cache of verified agent IDs.  Entries stay valid for the
# lifetime of the process.  A production deployment would add TTL-based
# expiry — keeping it simple here keeps the hot path fast.
_verified_agents: set[str] = set()


def _reject(reason: str, status: int = 403) -> Response:
    return Response(
        content=f'{{"error":"{reason}"}}',
        status_code=status,
        media_type="application/json",
    )


class AgentRegistryMiddleware:
    """Verifies that the caller's agent_id is registered with the core
    engine.  Blocks unknown agents."""

    def __init__(self, http_client: httpx.AsyncClient | None = None) -> None:
        self._client = http_client

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=settings.core_engine_url,
                timeout=settings.core_timeout,
            )
        return self._client

    async def process(self, request: Request, metadata: dict) -> MiddlewareResult:
        passthrough: dict[str, str] = metadata.get("passthrough_headers", {})
        agent_id = passthrough.get("agent-id", "")

        if not agent_id:
            # No agent ID header — the request may still be valid for
            # anonymous / legacy callers.  Let downstream middleware
            # decide whether to allow or reject.
            return MiddlewareResult(request=request, metadata=metadata)

        # Fast path: already confirmed this agent in the current process.
        if agent_id in _verified_agents:
            metadata["agent_id"] = agent_id
            return MiddlewareResult(request=request, metadata=metadata)

        # Call the core engine's session/agent validation endpoint.
        try:
            client = await self._get_client()
            resp = await client.get(
                f"/api/v1/agents/{agent_id}",
            )
        except httpx.TimeoutException:
            logger.error("Core engine timeout while verifying agent %s", agent_id)
            return MiddlewareResult(
                request=request,
                response=_reject("core engine unreachable", 502),
                metadata=metadata,
            )
        except httpx.HTTPError as exc:
            logger.error("Core engine error verifying agent %s: %s", agent_id, exc)
            return MiddlewareResult(
                request=request,
                response=_reject("core engine error", 502),
                metadata=metadata,
            )

        if resp.status_code == 200:
            _verified_agents.add(agent_id)
            metadata["agent_id"] = agent_id
            logger.debug("Agent %s verified", agent_id)
            return MiddlewareResult(request=request, metadata=metadata)

        if resp.status_code == 404:
            logger.warning("Unregistered agent blocked: %s", agent_id)
            return MiddlewareResult(
                request=request,
                response=_reject("agent not registered"),
                metadata=metadata,
            )

        logger.error(
            "Unexpected status %d from core engine for agent %s",
            resp.status_code,
            agent_id,
        )
        return MiddlewareResult(
            request=request,
            response=_reject("agent verification failed", 502),
            metadata=metadata,
        )
