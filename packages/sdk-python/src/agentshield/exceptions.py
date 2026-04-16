"""AgentShield SDK exceptions."""

from __future__ import annotations


class AgentShieldError(Exception):
    """Base exception for all AgentShield errors."""


class ConfigError(AgentShieldError):
    """Raised when SDK configuration is invalid or missing."""

    def __init__(self, message: str = "Invalid AgentShield configuration") -> None:
        super().__init__(message)


class ToolCallBlocked(AgentShieldError):
    """Raised when the server blocks a tool call."""

    def __init__(self, tool: str, reason: str, trace_id: str) -> None:
        self.tool = tool
        self.reason = reason
        self.trace_id = trace_id
        super().__init__(f"Tool call '{tool}' blocked: {reason} (trace_id={trace_id})")


class ConfirmationRejected(AgentShieldError):
    """Raised when a tool call requiring confirmation is not confirmed."""

    def __init__(self, tool: str) -> None:
        self.tool = tool
        super().__init__(f"Tool call '{tool}' requires confirmation and was not confirmed")


class ServerError(AgentShieldError):
    """Raised when the AgentShield server returns an error or is unreachable."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        self.status_code = status_code
        super().__init__(message)
