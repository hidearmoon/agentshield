"""AgentGuard Python SDK — lightweight security guardrails for AI agents."""

from agentguard.shield import Shield
from agentguard.local import LocalShield
from agentguard.session import ShieldSession
from agentguard.exceptions import (
    AgentGuardError,
    ConfigError,
    ConfirmationRejected,
    ServerError,
    ToolCallBlocked,
)
from agentguard.models import CheckResult, Decision

__all__ = [
    "Shield",
    "LocalShield",
    "ShieldSession",
    "AgentGuardError",
    "ConfigError",
    "ConfirmationRejected",
    "ServerError",
    "ToolCallBlocked",
    "CheckResult",
    "Decision",
]
__version__ = "0.1.0"
