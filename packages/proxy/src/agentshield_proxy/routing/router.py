"""Dynamic tool routing based on URL path.

Maps incoming proxy paths to upstream tool service URLs.  Routes can be
registered at startup (from config / core engine) and matched at request
time.

Example:
    router.add_route("/tools/email", "http://email-service:8080")
    router.add_route("/tools/calendar", "http://cal-service:8080")

    target = router.resolve("/tools/email/send")
    # -> "http://email-service:8080/send"
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from agentshield_proxy.config import settings

logger = logging.getLogger(__name__)


@dataclass
class _Route:
    prefix: str  # normalized, no trailing slash
    upstream: str  # base URL, no trailing slash


class ToolRouter:
    """Prefix-based router that maps request paths to upstream URLs.

    If no explicit route matches, the request is forwarded to the
    default ``upstream_url`` from settings.
    """

    def __init__(self) -> None:
        self._routes: list[_Route] = []

    def add_route(self, prefix: str, upstream_url: str) -> None:
        """Register a prefix -> upstream mapping.

        Longer (more specific) prefixes are matched first.
        """
        normalized_prefix = prefix.rstrip("/")
        normalized_upstream = upstream_url.rstrip("/")
        self._routes.append(_Route(prefix=normalized_prefix, upstream=normalized_upstream))
        # Keep routes sorted by prefix length descending so the most
        # specific prefix wins on first match.
        self._routes.sort(key=lambda r: len(r.prefix), reverse=True)
        logger.info("Route added: %s -> %s", normalized_prefix, normalized_upstream)

    def resolve(self, path: str) -> str:
        """Return the full upstream URL for the given request path.

        The matched prefix is stripped from the path and the remainder
        is appended to the upstream base URL.
        """
        # Normalize to prevent path traversal (e.g., /../, //, etc.)
        normalized_path = path.rstrip("/") or "/"
        # Block suspicious path patterns
        if ".." in normalized_path or normalized_path.startswith("//"):
            normalized_path = "/"
        for route in self._routes:
            if normalized_path == route.prefix or normalized_path.startswith(route.prefix + "/"):
                remainder = normalized_path[len(route.prefix) :]
                target = route.upstream + remainder
                logger.debug("Resolved %s -> %s", path, target)
                return target

        # Fall back to default upstream with the normalized path.
        fallback = settings.upstream_url.rstrip("/") + normalized_path
        logger.debug("No explicit route for %s, using default: %s", path, fallback)
        return fallback
