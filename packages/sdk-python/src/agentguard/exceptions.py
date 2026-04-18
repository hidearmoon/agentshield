"""AgentGuard SDK exceptions."""

from __future__ import annotations


class AgentGuardError(Exception):
    """Base exception for all AgentGuard errors."""


class ConfigError(AgentGuardError):
    """Raised when SDK configuration is invalid or missing."""

    def __init__(self, message: str = "Invalid AgentGuard configuration") -> None:
        super().__init__(message)


class ToolCallBlocked(AgentGuardError):
    """Raised when the server blocks a tool call."""

    def __init__(self, tool: str, reason: str, trace_id: str) -> None:
        self.tool = tool
        self.reason = reason
        self.trace_id = trace_id
        super().__init__(f"Tool call '{tool}' blocked: {reason} (trace_id={trace_id})")


class ConfirmationRejected(AgentGuardError):
    """Raised when a tool call requiring confirmation is not confirmed."""

    def __init__(self, tool: str) -> None:
        self.tool = tool
        super().__init__(f"Tool call '{tool}' requires confirmation and was not confirmed")


class ServerError(AgentGuardError):
    """Raised when the AgentGuard server returns an error or is unreachable."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        self.status_code = status_code
        super().__init__(message)
