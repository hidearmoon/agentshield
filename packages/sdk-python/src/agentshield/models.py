"""Data models for AgentShield SDK responses."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    """Server-side decision for a tool call."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"


@dataclass(frozen=True)
class CheckResult:
    """Result from POST /api/v1/check."""

    action: Decision
    reason: str = ""
    trace_id: str = ""
    span_id: str = ""


@dataclass(frozen=True)
class SanitizedData:
    """Result from POST /api/v1/sanitize."""

    content: str
    trust_level: str
    sanitization_chain: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ExtractedData:
    """Result from POST /api/v1/extract."""

    extracted: dict = field(default_factory=dict)
    schema_name: str = ""


@dataclass(frozen=True)
class MarkedData:
    """Data annotated with trust metadata by the server."""

    content: str
    trust_level: str
    source_id: str
    allowed_actions: list[str] = field(default_factory=list)
    tool_restrictions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SessionInfo:
    """Result from POST /api/v1/sessions."""

    session_id: str
    trace_id: str
