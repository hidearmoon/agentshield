"""Intent detection data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DecisionAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"


@dataclass
class Decision:
    action: DecisionAction
    reason: str = ""
    confidence: float = 1.0
    engine: str = ""  # rule | anomaly | semantic

    @classmethod
    def allow(cls) -> Decision:
        return cls(action=DecisionAction.ALLOW)

    @classmethod
    def block(cls, reason: str, engine: str = "") -> Decision:
        return cls(action=DecisionAction.BLOCK, reason=reason, engine=engine)

    @classmethod
    def require_confirmation(cls, reason: str, engine: str = "") -> Decision:
        return cls(action=DecisionAction.REQUIRE_CONFIRMATION, reason=reason, engine=engine)


@dataclass
class Intent:
    intent: str
    expected_tools: list[str] = field(default_factory=list)
    sensitive_data_involved: bool = False


@dataclass
class ToolCall:
    name: str
    params: dict = field(default_factory=dict)
    tool_category: str = ""
    estimated_result_size: int = 0


@dataclass
class IntentContext:
    original_message: str
    intent: Intent
    allowed_tool_categories: list[str] = field(default_factory=list)
    tool_call_history: list[ToolCall] = field(default_factory=list)
    current_data_trust_level: int = 5  # TrustLevel value


@dataclass
class RuleResult:
    is_definitive: bool
    decision: Decision = field(default_factory=Decision.allow)
    triggered: bool = False
    rule_name: str = ""


@dataclass
class AnomalyResult:
    score: float  # 0.0 - 1.0
    reason: str = ""
