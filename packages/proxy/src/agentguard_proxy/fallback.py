"""Degraded mode — infer security context from the request body.

When the core engine is unreachable and ``allow_degraded_mode`` is
enabled, the proxy falls back to conservative heuristic inference.
This module examines the raw request payload and assigns the lowest
defensible trust level and a best-effort intent classification.

IMPORTANT: This is a last-resort path.  Trust levels assigned here are
intentionally conservative (UNTRUSTED or EXTERNAL) because we cannot
verify anything server-side.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Patterns that suggest the request body contains high-risk operations.
_HIGH_RISK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\bdelete\b"),
    re.compile(r"(?i)\bdrop\b"),
    re.compile(r"(?i)\bexec(?:ute)?\b"),
    re.compile(r"(?i)\bsudo\b"),
    re.compile(r"(?i)\brm\s+-rf\b"),
    re.compile(r"(?i)\bsend.*(?:email|message|sms)\b"),
    re.compile(r"(?i)\btransfer\b.*\b(?:fund|money|payment)\b"),
]

# Patterns that suggest data retrieval / read-only intent.
_READ_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\b(?:get|fetch|read|list|search|query|find|lookup)\b"),
]


@dataclass(frozen=True)
class InferredContext:
    """Heuristically inferred security context."""

    data_trust: str
    user_intent: str


def infer_context_from_body(body: dict) -> InferredContext:
    """Inspect the body dict and return a conservative context.

    The logic intentionally errs on the side of caution:
    - If the body looks like it contains a destructive or sensitive
      operation, trust is UNTRUSTED.
    - Otherwise trust defaults to EXTERNAL (never higher).
    - Intent is inferred from keyword patterns; defaults to "unknown".
    """
    serialized = _flatten_to_text(body)

    # --- Trust level ---
    trust = "EXTERNAL"
    for pattern in _HIGH_RISK_PATTERNS:
        if pattern.search(serialized):
            trust = "UNTRUSTED"
            break

    # --- Intent ---
    intent = "unknown"
    if trust == "UNTRUSTED":
        intent = "destructive"
    else:
        for pattern in _READ_PATTERNS:
            if pattern.search(serialized):
                intent = "read"
                break

    logger.debug(
        "Fallback inference: trust=%s intent=%s body_len=%d",
        trust,
        intent,
        len(serialized),
    )
    return InferredContext(data_trust=trust, user_intent=intent)


def _flatten_to_text(obj: object, max_depth: int = 4) -> str:
    """Recursively flatten a dict / list to a single text blob for
    pattern matching.  Limits depth to prevent abuse via deeply nested
    payloads."""
    if max_depth <= 0:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        parts = []
        for k, v in obj.items():
            parts.append(str(k))
            parts.append(_flatten_to_text(v, max_depth - 1))
        return " ".join(parts)
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten_to_text(item, max_depth - 1) for item in obj)
    return str(obj)
