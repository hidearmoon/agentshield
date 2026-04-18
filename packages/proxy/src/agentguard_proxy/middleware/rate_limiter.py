"""Token-bucket rate limiter keyed by agent_id."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from fastapi import Request, Response

from agentguard_proxy.config import settings
from agentguard_proxy.middleware.chain import MiddlewareResult

logger = logging.getLogger(__name__)


@dataclass
class _Bucket:
    """Single token bucket for one agent."""

    tokens: float
    last_refill: float
    capacity: float
    refill_rate: float  # tokens per second

    def consume(self, now: float) -> bool:
        """Try to consume one token.  Returns True if allowed."""
        # Refill tokens based on elapsed time.
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RateLimiterMiddleware:
    """Per-agent token-bucket rate limiter.

    Each recognised ``agent_id`` gets its own bucket.  Requests without
    an agent_id share a single ``__anonymous__`` bucket.
    """

    def __init__(
        self,
        capacity: float | None = None,
        refill_rate: float | None = None,
    ) -> None:
        self._capacity = capacity if capacity is not None else settings.rate_limit_tokens
        self._refill_rate = refill_rate if refill_rate is not None else settings.rate_limit_refill
        self._buckets: dict[str, _Bucket] = {}
        self._max_buckets = 50_000
        self._last_cleanup = time.monotonic()

    def _get_bucket(self, key: str) -> _Bucket:
        # Periodic cleanup of idle buckets (every 60s)
        now = time.monotonic()
        if now - self._last_cleanup > 60:
            self._cleanup_idle(now)
            self._last_cleanup = now

        if key not in self._buckets:
            self._buckets[key] = _Bucket(
                tokens=self._capacity,
                last_refill=now,
                capacity=self._capacity,
                refill_rate=self._refill_rate,
            )
        return self._buckets[key]

    def _cleanup_idle(self, now: float) -> None:
        """Remove buckets idle for more than 10 minutes."""
        idle_threshold = 600
        expired = [k for k, b in self._buckets.items() if now - b.last_refill > idle_threshold]
        for k in expired:
            del self._buckets[k]
        # Hard cap
        while len(self._buckets) > self._max_buckets:
            oldest_key = min(self._buckets, key=lambda k: self._buckets[k].last_refill)
            del self._buckets[oldest_key]

    async def process(self, request: Request, metadata: dict) -> MiddlewareResult:
        agent_id = metadata.get("agent_id", "__anonymous__")
        bucket = self._get_bucket(agent_id)
        now = time.monotonic()

        if bucket.consume(now):
            return MiddlewareResult(request=request, metadata=metadata)

        retry_after = max(1.0, (1.0 - bucket.tokens) / bucket.refill_rate)
        logger.warning("Rate limit exceeded for agent %s", agent_id)
        return MiddlewareResult(
            request=request,
            response=Response(
                content='{"error":"rate limit exceeded"}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": str(int(retry_after))},
            ),
            metadata=metadata,
        )
