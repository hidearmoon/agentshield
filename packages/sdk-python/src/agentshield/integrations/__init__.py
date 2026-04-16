"""Framework integrations for AgentShield.

Each integration is lazily imported to avoid pulling in heavy optional
dependencies unless they are actually used.
"""

from __future__ import annotations


def __getattr__(name: str):  # noqa: N807
    if name == "LangChainShield":
        from agentshield.integrations.langchain import LangChainShield

        return LangChainShield
    if name == "CrewAIShield":
        from agentshield.integrations.crewai import CrewAIShield

        return CrewAIShield
    if name == "AutoGenShield":
        from agentshield.integrations.autogen import AutoGenShield

        return AutoGenShield
    if name == "ClaudeAgentShield":
        from agentshield.integrations.claude_agent import ClaudeAgentShield

        return ClaudeAgentShield
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "LangChainShield",
    "CrewAIShield",
    "AutoGenShield",
    "ClaudeAgentShield",
]
