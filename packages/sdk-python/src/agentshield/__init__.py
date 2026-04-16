"""AgentShield Python SDK — lightweight security guardrails for AI agents."""

from agentshield.shield import Shield
from agentshield.session import ShieldSession
from agentshield.exceptions import (
    AgentShieldError,
    ConfigError,
    ConfirmationRejected,
    ServerError,
    ToolCallBlocked,
)
from agentshield.models import CheckResult, Decision

__all__ = [
    "Shield",
    "ShieldSession",
    "AgentShieldError",
    "ConfigError",
    "ConfirmationRejected",
    "ServerError",
    "ToolCallBlocked",
    "CheckResult",
    "Decision",
]
__version__ = "0.1.0"
