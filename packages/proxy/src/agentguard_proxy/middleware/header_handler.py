"""Header handler — enforces the critical security invariant.

The proxy NEVER trusts client-provided security headers.
``X-AgentGuard-Data-Trust`` and ``X-AgentGuard-User-Intent`` are
unconditionally stripped from the incoming request so they can be
recomputed server-side by the SecurityContextMiddleware.

Only passthrough headers (Trace-ID, Session-ID, Agent-ID) are accepted
from the client because they carry correlation metadata, not security
assertions.
"""

from __future__ import annotations

import logging

from fastapi import Request

from agentguard_proxy.middleware.chain import MiddlewareResult

logger = logging.getLogger(__name__)

# Headers the proxy accepts from the client unchanged.
PASSTHROUGH_HEADERS: frozenset[str] = frozenset(
    {
        "x-agentguard-trace-id",
        "x-agentguard-session-id",
        "x-agentguard-agent-id",
    }
)

# Headers that MUST be computed server-side.  Any client-supplied values
# are silently stripped to prevent trust escalation.
COMPUTED_HEADERS: frozenset[str] = frozenset(
    {
        "x-agentguard-data-trust",
        "x-agentguard-user-intent",
    }
)


class ProxyHeaderHandler:
    """First middleware in the chain — strips untrusted headers and
    extracts passthrough values into metadata."""

    async def process(self, request: Request, metadata: dict) -> MiddlewareResult:
        # ----------------------------------------------------------
        # 1.  Strip computed headers — this is the security boundary.
        # ----------------------------------------------------------
        # Starlette's scope is mutable; we rebuild the header list
        # without the forbidden entries.
        raw_headers: list[tuple[bytes, bytes]] = list(request.scope["headers"])
        stripped: list[str] = []
        clean_headers: list[tuple[bytes, bytes]] = []

        for name_bytes, value_bytes in raw_headers:
            header_lower = name_bytes.decode("latin-1").lower()
            if header_lower in COMPUTED_HEADERS:
                stripped.append(header_lower)
            else:
                clean_headers.append((name_bytes, value_bytes))

        if stripped:
            logger.warning(
                "Stripped client-provided security headers: %s",
                ", ".join(stripped),
            )

        # Replace the scope headers in-place.
        request.scope["headers"] = clean_headers

        # ----------------------------------------------------------
        # 2.  Extract passthrough values into metadata for downstream
        #     middleware to consume without re-parsing headers.
        # ----------------------------------------------------------
        passthrough: dict[str, str] = {}
        for name_bytes, value_bytes in clean_headers:
            header_lower = name_bytes.decode("latin-1").lower()
            if header_lower in PASSTHROUGH_HEADERS:
                # Strip the common prefix for convenience.
                key = header_lower.removeprefix("x-agentguard-")
                passthrough[key] = value_bytes.decode("latin-1")

        metadata["passthrough_headers"] = passthrough

        return MiddlewareResult(request=request, metadata=metadata)
