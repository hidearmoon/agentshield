"""Ordered middleware chain with short-circuit support."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

from fastapi import Request, Response

logger = logging.getLogger(__name__)


@dataclass
class MiddlewareResult:
    """Result produced by a single middleware step.

    If ``response`` is set the chain short-circuits and that response is
    returned to the caller immediately — remaining middleware steps and the
    upstream forward are skipped.

    ``metadata`` carries information extracted by earlier middleware (e.g.
    headers, agent identity, security context) that downstream middleware
    and the final forwarder can use.
    """

    request: Request
    response: Response | None = None
    metadata: dict = field(default_factory=dict)


class Middleware(Protocol):
    """Interface every middleware step must satisfy."""

    async def process(self, request: Request, metadata: dict) -> MiddlewareResult:
        """Inspect / modify the request.  Return a result.

        To short-circuit the chain, set ``result.response``.
        To pass data downstream, add entries to ``result.metadata``.
        """
        ...


class MiddlewareChain:
    """Executes an ordered list of middleware, stopping at the first
    short-circuit or after all steps complete successfully."""

    def __init__(self) -> None:
        self._steps: list[Middleware] = []

    def add(self, mw: Middleware) -> MiddlewareChain:
        """Append a middleware step.  Returns ``self`` for chaining."""
        self._steps.append(mw)
        return self

    async def run(self, request: Request) -> MiddlewareResult:
        """Run all middleware in order.

        Returns the final :class:`MiddlewareResult`.  If any step
        short-circuits (sets ``result.response``), the chain stops and
        that result is returned immediately.
        """
        metadata: dict = {}

        for step in self._steps:
            name = type(step).__name__
            try:
                result = await step.process(request, metadata)
            except Exception:
                logger.exception("Middleware %s raised an exception", name)
                return MiddlewareResult(
                    request=request,
                    response=Response(
                        content='{"error":"internal proxy error"}',
                        status_code=502,
                        media_type="application/json",
                    ),
                    metadata=metadata,
                )

            # Merge metadata produced by this step into the shared bag.
            metadata.update(result.metadata)

            if result.response is not None:
                logger.info("Middleware %s short-circuited the chain", name)
                return MiddlewareResult(
                    request=result.request,
                    response=result.response,
                    metadata=metadata,
                )

            # Use the (potentially modified) request for the next step.
            request = result.request

        return MiddlewareResult(request=request, metadata=metadata)
