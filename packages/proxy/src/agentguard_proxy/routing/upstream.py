"""Upstream client — forwards inspected requests to actual tool services."""

from __future__ import annotations

import logging

import httpx
from fastapi import Request, Response

from agentguard_proxy.config import settings
from agentguard_proxy.routing.router import ToolRouter

logger = logging.getLogger(__name__)

# Headers injected by the proxy that the upstream tool service can rely
# on as authoritative.
_INJECTED_SECURITY_HEADERS = (
    "X-AgentGuard-Data-Trust",
    "X-AgentGuard-User-Intent",
    "X-AgentGuard-Trace-ID",
    "X-AgentGuard-Span-ID",
)

# Hop-by-hop headers that must not be forwarded.
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
    }
)


class UpstreamClient:
    """Forwards the (now-authorised) request to the real tool service
    and streams the response back to the calling agent."""

    def __init__(
        self,
        router: ToolRouter,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._router = router
        self._client = http_client

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=settings.upstream_timeout,
                follow_redirects=True,
            )
        return self._client

    def _build_upstream_headers(
        self,
        original_headers: list[tuple[bytes, bytes]],
        metadata: dict,
    ) -> dict[str, str]:
        """Build the header map sent to the upstream service.

        * Original request headers are forwarded (minus hop-by-hop).
        * Server-computed security headers are injected from metadata.
        """
        headers: dict[str, str] = {}
        for name_bytes, value_bytes in original_headers:
            name = name_bytes.decode("latin-1").lower()
            if name in _HOP_BY_HOP:
                continue
            headers[name] = value_bytes.decode("latin-1")

        # Inject server-authoritative security context.
        if "data_trust" in metadata:
            headers["X-AgentGuard-Data-Trust"] = str(metadata["data_trust"])
        if "user_intent" in metadata:
            headers["X-AgentGuard-User-Intent"] = str(metadata["user_intent"])
        if "trace_id" in metadata:
            headers["X-AgentGuard-Trace-ID"] = metadata["trace_id"]
        if "span_id" in metadata:
            headers["X-AgentGuard-Span-ID"] = metadata["span_id"]

        return headers

    async def forward(self, request: Request, metadata: dict) -> Response:
        """Forward the request to the resolved upstream and return the
        response."""
        target_url = self._router.resolve(request.url.path)
        if request.url.query:
            target_url = f"{target_url}?{request.url.query}"

        headers = self._build_upstream_headers(list(request.scope["headers"]), metadata)

        body = await request.body()
        method = request.method.upper()

        client = await self._get_client()

        try:
            upstream_resp = await client.request(
                method=method,
                url=target_url,
                headers=headers,
                content=body,
            )
        except httpx.TimeoutException:
            logger.error("Upstream timeout: %s %s", method, target_url)
            return Response(
                content='{"error":"upstream timeout"}',
                status_code=504,
                media_type="application/json",
            )
        except httpx.HTTPError as exc:
            logger.error("Upstream error: %s %s — %s", method, target_url, exc)
            return Response(
                content='{"error":"upstream unreachable"}',
                status_code=502,
                media_type="application/json",
            )

        # Build response headers, stripping hop-by-hop from upstream.
        resp_headers: dict[str, str] = {}
        for key, value in upstream_resp.headers.items():
            if key.lower() not in _HOP_BY_HOP:
                resp_headers[key] = value

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=upstream_resp.headers.get("content-type"),
        )
