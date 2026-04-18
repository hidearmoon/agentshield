"""Framework integrations for AgentGuard.

Each integration is lazily imported to avoid pulling in heavy optional
dependencies unless they are actually used.
"""

from __future__ import annotations


def __getattr__(name: str):  # noqa: N807
    if name == "LangChainShield":
        from agentguard.integrations.langchain import LangChainShield

        return LangChainShield
    if name == "CrewAIShield":
        from agentguard.integrations.crewai import CrewAIShield

        return CrewAIShield
    if name == "AutoGenShield":
        from agentguard.integrations.autogen import AutoGenShield

        return AutoGenShield
    if name == "ClaudeAgentGuard":
        from agentguard.integrations.claude_agent import ClaudeAgentGuard

        return ClaudeAgentGuard
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "LangChainShield",
    "CrewAIShield",
    "AutoGenShield",
    "ClaudeAgentGuard",
]
