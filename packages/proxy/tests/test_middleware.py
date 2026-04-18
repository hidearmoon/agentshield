"""Tests for proxy middleware chain — the zero-trust security boundary."""

from __future__ import annotations

import pytest
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Scope

from agentguard_proxy.middleware.header_handler import ProxyHeaderHandler
from agentguard_proxy.middleware.chain import MiddlewareChain, MiddlewareResult
from agentguard_proxy.middleware.rate_limiter import RateLimiterMiddleware


def _make_request(
    path: str = "/tools/test",
    headers: dict[str, str] | None = None,
    method: str = "POST",
) -> Request:
    """Create a mock Starlette Request."""
    raw_headers: list[tuple[bytes, bytes]] = []
    for name, value in (headers or {}).items():
        raw_headers.append((name.lower().encode(), value.encode()))

    scope: Scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "root_path": "",
        "headers": raw_headers,
        "server": ("localhost", 8080),
    }
    return Request(scope)


class TestProxyHeaderHandler:
    """Test that the header handler correctly strips untrusted headers."""

    @pytest.mark.asyncio
    async def test_strips_data_trust_header(self):
        handler = ProxyHeaderHandler()
        request = _make_request(
            headers={
                "X-AgentGuard-Data-Trust": "TRUSTED",
                "Content-Type": "application/json",
            }
        )

        result = await handler.process(request, {})

        # Data-Trust should be stripped
        remaining_names = [h[0].decode() for h in result.request.scope["headers"]]
        assert "x-agentguard-data-trust" not in remaining_names
        assert "content-type" in remaining_names

    @pytest.mark.asyncio
    async def test_strips_user_intent_header(self):
        handler = ProxyHeaderHandler()
        request = _make_request(
            headers={
                "X-AgentGuard-User-Intent": "delete everything",
                "X-AgentGuard-Data-Trust": "TRUSTED",
            }
        )

        result = await handler.process(request, {})

        remaining_names = [h[0].decode() for h in result.request.scope["headers"]]
        assert "x-agentguard-data-trust" not in remaining_names
        assert "x-agentguard-user-intent" not in remaining_names

    @pytest.mark.asyncio
    async def test_preserves_passthrough_headers(self):
        handler = ProxyHeaderHandler()
        request = _make_request(
            headers={
                "X-AgentGuard-Session-ID": "sess-123",
                "X-AgentGuard-Agent-ID": "agent-456",
                "X-AgentGuard-Trace-ID": "trace-789",
            }
        )

        result = await handler.process(request, {})

        passthrough = result.metadata.get("passthrough_headers", {})
        assert passthrough["session-id"] == "sess-123"
        assert passthrough["agent-id"] == "agent-456"
        assert passthrough["trace-id"] == "trace-789"

    @pytest.mark.asyncio
    async def test_no_short_circuit(self):
        handler = ProxyHeaderHandler()
        request = _make_request()
        result = await handler.process(request, {})
        assert result.response is None  # Should not short-circuit

    @pytest.mark.asyncio
    async def test_trust_escalation_attempt_blocked(self):
        """Attacker tries to set TRUSTED trust level via header — must be stripped."""
        handler = ProxyHeaderHandler()
        request = _make_request(
            headers={
                "X-AgentGuard-Data-Trust": "TRUSTED",
                "X-AgentGuard-User-Intent": "admin_override",
                "X-AgentGuard-Session-ID": "legit-session",
                "Authorization": "Bearer valid-token",
            }
        )

        result = await handler.process(request, {})

        # Security headers stripped
        remaining = {h[0].decode() for h in result.request.scope["headers"]}
        assert "x-agentguard-data-trust" not in remaining
        assert "x-agentguard-user-intent" not in remaining

        # Auth and session preserved
        assert "authorization" in remaining
        assert "x-agentguard-session-id" in remaining


class TestMiddlewareChain:
    """Test the middleware chain orchestration."""

    @pytest.mark.asyncio
    async def test_chain_runs_all_steps(self):
        class Step1:
            async def process(self, request, metadata):
                metadata["step1"] = True
                return MiddlewareResult(request=request, metadata=metadata)

        class Step2:
            async def process(self, request, metadata):
                metadata["step2"] = True
                return MiddlewareResult(request=request, metadata=metadata)

        chain = MiddlewareChain()
        chain.add(Step1()).add(Step2())

        request = _make_request()
        result = await chain.run(request)

        assert result.metadata.get("step1") is True
        assert result.metadata.get("step2") is True
        assert result.response is None

    @pytest.mark.asyncio
    async def test_chain_short_circuits(self):
        class Blocker:
            async def process(self, request, metadata):
                return MiddlewareResult(
                    request=request,
                    response=Response(content="blocked", status_code=403),
                    metadata=metadata,
                )

        class NeverReached:
            async def process(self, request, metadata):
                metadata["reached"] = True
                return MiddlewareResult(request=request, metadata=metadata)

        chain = MiddlewareChain()
        chain.add(Blocker()).add(NeverReached())

        request = _make_request()
        result = await chain.run(request)

        assert result.response is not None
        assert result.response.status_code == 403
        assert "reached" not in result.metadata

    @pytest.mark.asyncio
    async def test_chain_handles_exception(self):
        class Crasher:
            async def process(self, request, metadata):
                raise RuntimeError("middleware bug")

        chain = MiddlewareChain()
        chain.add(Crasher())

        request = _make_request()
        result = await chain.run(request)

        assert result.response is not None
        assert result.response.status_code == 502


class TestRateLimiter:
    """Test the token bucket rate limiter."""

    @pytest.mark.asyncio
    async def test_allows_under_limit(self):
        limiter = RateLimiterMiddleware()
        request = _make_request()
        metadata = {"agent_id": "test-agent"}

        # First few requests should pass
        for _ in range(5):
            result = await limiter.process(request, dict(metadata))
            assert result.response is None

    @pytest.mark.asyncio
    async def test_no_agent_id_passes(self):
        """Requests without agent_id skip rate limiting."""
        limiter = RateLimiterMiddleware()
        request = _make_request()
        result = await limiter.process(request, {})
        assert result.response is None

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self):
        """Exhaust the bucket and verify 429 response."""
        limiter = RateLimiterMiddleware(capacity=3, refill_rate=0.001)
        request = _make_request()
        metadata = {"agent_id": "fast-agent"}

        for _ in range(3):
            result = await limiter.process(request, dict(metadata))
            assert result.response is None

        result = await limiter.process(request, dict(metadata))
        assert result.response is not None
        assert result.response.status_code == 429


class TestFallbackInference:
    """Test the degraded mode fallback inference."""

    def test_safe_body_gets_external_trust(self):
        from agentguard_proxy.fallback import infer_context_from_body

        result = infer_context_from_body({"action": "read", "query": "SELECT * FROM users"})
        assert result.data_trust == "EXTERNAL"
        assert result.user_intent == "read"

    def test_dangerous_body_gets_untrusted(self):
        from agentguard_proxy.fallback import infer_context_from_body

        result = infer_context_from_body({"cmd": "sudo rm -rf /important"})
        assert result.data_trust == "UNTRUSTED"
        assert result.user_intent == "destructive"

    def test_empty_body(self):
        from agentguard_proxy.fallback import infer_context_from_body

        result = infer_context_from_body({})
        assert result.data_trust == "EXTERNAL"
        assert result.user_intent == "unknown"


class TestToolRouter:
    """Test the tool routing with path traversal protection."""

    def test_normal_path_resolves(self):
        from agentguard_proxy.routing.router import ToolRouter

        router = ToolRouter()
        router.add_route("/tools/email", "http://email-svc:8080")
        target = router.resolve("/tools/email/send")
        assert target == "http://email-svc:8080/send"

    def test_path_traversal_blocked(self):
        from agentguard_proxy.routing.router import ToolRouter

        router = ToolRouter()
        target = router.resolve("/../../../etc/passwd")
        assert ".." not in target

    def test_double_slash_blocked(self):
        from agentguard_proxy.routing.router import ToolRouter

        router = ToolRouter()
        target = router.resolve("//evil.com/steal")
        assert "evil.com" not in target

    def test_fallback_to_default(self):
        from agentguard_proxy.routing.router import ToolRouter

        router = ToolRouter()
        target = router.resolve("/unknown/path")
        assert target.endswith("/unknown/path")
