"""Security context middleware — server-side trust and intent computation.

This middleware enforces the core security invariant: trust level and
user intent are NEVER derived from client headers.  They are computed by
the core engine based on the request body and session state.

The middleware sends a ``POST /api/v1/check`` to the core engine with
the tool call details.  If the engine returns BLOCK the request is
short-circuited.  If it returns ALLOW the computed trust level and
intent are injected as headers for the upstream tool service.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from fastapi import Request, Response

from agentshield_proxy.config import settings
from agentshield_proxy.fallback import infer_context_from_body
from agentshield_proxy.middleware.chain import MiddlewareResult

logger = logging.getLogger(__name__)


def _block_response(reason: str, trace_id: str = "", span_id: str = "") -> Response:
    body = json.dumps(
        {
            "error": "blocked",
            "reason": reason,
            "trace_id": trace_id,
            "span_id": span_id,
        }
    )
    return Response(content=body, status_code=403, media_type="application/json")


class SecurityContextMiddleware:
    """Calls the core engine to compute trust level and intent, then
    injects server-authoritative headers into the upstream request."""

    def __init__(self, http_client: httpx.AsyncClient | None = None) -> None:
        self._client = http_client

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=settings.core_engine_url,
                timeout=settings.core_timeout,
            )
        return self._client

    async def _build_check_payload(self, request: Request, metadata: dict) -> dict[str, Any]:
        """Construct the payload for ``POST /api/v1/check``."""
        passthrough = metadata.get("passthrough_headers", {})
        session_id = passthrough.get("session-id", "")

        # Try to read the body.  For non-JSON requests we still send
        # what we can; the core engine tolerates missing fields.
        body: dict[str, Any] = {}
        try:
            raw = await request.body()
            if len(raw) <= 5_000_000:  # Only parse bodies up to 5MB
                body = json.loads(raw)
        except Exception:
            pass

        # Derive tool_name from the URL path.  The last path segment
        # typically identifies the tool (e.g. /tools/send-email).
        path = request.url.path.rstrip("/")
        tool_name = path.rsplit("/", 1)[-1] if path else "unknown"

        return {
            "session_id": session_id,
            "tool_name": tool_name,
            "params": body,
            "source_id": metadata.get("agent_id", ""),
        }

    async def process(self, request: Request, metadata: dict) -> MiddlewareResult:
        payload = await self._build_check_payload(request, metadata)

        try:
            client = await self._get_client()
            resp = await client.post("/api/v1/check", json=payload)
        except (httpx.TimeoutException, httpx.HTTPError) as exc:
            logger.error("Core engine unreachable for security check: %s", exc)

            if settings.allow_degraded_mode:
                # Fall back to body-based heuristic inference.
                inferred = infer_context_from_body(payload.get("params", {}))
                metadata["data_trust"] = inferred.data_trust
                metadata["user_intent"] = inferred.user_intent
                metadata["degraded"] = True
                logger.warning(
                    "Degraded mode: inferred trust=%s intent=%s",
                    inferred.data_trust,
                    inferred.user_intent,
                )
                return MiddlewareResult(request=request, metadata=metadata)

            return MiddlewareResult(
                request=request,
                response=Response(
                    content='{"error":"core engine unreachable"}',
                    status_code=502,
                    media_type="application/json",
                ),
                metadata=metadata,
            )

        if resp.status_code != 200:
            logger.error("Core engine returned %d for security check", resp.status_code)
            return MiddlewareResult(
                request=request,
                response=Response(
                    content='{"error":"security check failed"}',
                    status_code=502,
                    media_type="application/json",
                ),
                metadata=metadata,
            )

        result = resp.json()
        action = result.get("action", "BLOCK")
        reason = result.get("reason", "")
        trace_id = result.get("trace_id", "")
        span_id = result.get("span_id", "")

        if action == "BLOCK":
            logger.warning("Tool call blocked: %s", reason)
            return MiddlewareResult(
                request=request,
                response=_block_response(reason, trace_id, span_id),
                metadata=metadata,
            )

        if action == "REQUIRE_CONFIRMATION":
            # For now, treat confirmation-required the same as block at
            # the proxy layer.  A future version can surface a
            # confirmation flow to the calling agent.
            logger.info("Tool call requires confirmation: %s", reason)
            body = json.dumps(
                {
                    "error": "confirmation_required",
                    "reason": reason,
                    "trace_id": trace_id,
                    "span_id": span_id,
                }
            )
            return MiddlewareResult(
                request=request,
                response=Response(content=body, status_code=428, media_type="application/json"),
                metadata=metadata,
            )

        # ALLOW — store computed security context in metadata so the
        # upstream forwarder can inject the authoritative headers.
        metadata["trace_id"] = trace_id
        metadata["span_id"] = span_id
        # The core engine's trust/intent are authoritative; we use
        # the source_id mapping as the trust level.
        metadata["data_trust"] = result.get("data_trust", "EXTERNAL")
        metadata["user_intent"] = result.get("user_intent", "")
        metadata["security_action"] = action

        return MiddlewareResult(request=request, metadata=metadata)
