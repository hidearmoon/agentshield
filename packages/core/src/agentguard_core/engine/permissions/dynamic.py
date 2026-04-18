"""Dynamic permission shrinking engine."""

from __future__ import annotations

from agentguard_core.engine.trust.levels import TrustLevel
from agentguard_core.engine.trust.marker import TrustPolicy
from agentguard_core.engine.intent.models import Intent


# Tool categories allowed at each trust level
# None = all tools allowed (filtered by blocklist only)
TRUST_TOOL_ALLOWLIST: dict[TrustLevel, set[str] | None] = {
    TrustLevel.TRUSTED: None,  # All tools
    TrustLevel.VERIFIED: None,  # All tools
    TrustLevel.INTERNAL: None,  # All except restricted (blocklist applies)
    TrustLevel.EXTERNAL: None,  # All except blocked (blocklist applies)
    TrustLevel.UNTRUSTED: {"summarize", "classify"},  # Strict allowlist
}

# Tools always blocked at each trust level
TRUST_TOOL_BLOCKLIST: dict[TrustLevel, set[str]] = {
    TrustLevel.TRUSTED: set(),
    TrustLevel.VERIFIED: set(),
    TrustLevel.INTERNAL: {"send_email_external", "export_data", "modify_permissions"},
    TrustLevel.EXTERNAL: {"send_email", "query_database", "execute_code", "call_api", "write_file"},
    TrustLevel.UNTRUSTED: set(),  # ALL blocked via allowlist
}


class DynamicPermissionEngine:
    """
    Dynamically shrinks available tools based on current data trust level.
    Uses a scope stack to handle nested trust contexts.
    """

    def __init__(self, trust_policy: TrustPolicy | None = None):
        self._policy = trust_policy or TrustPolicy()

    def get_available_tools(
        self,
        trust_level: TrustLevel,
        intent: Intent | None = None,
        agent_tools: list[str] | None = None,
    ) -> list[str]:
        """
        Compute available tools for the given trust level and intent.
        Returns empty list if no restriction (all tools allowed).
        """
        allowlist = TRUST_TOOL_ALLOWLIST.get(trust_level)
        blocklist = TRUST_TOOL_BLOCKLIST.get(trust_level, set())

        if agent_tools:
            available = set(agent_tools)
        else:
            # No agent tools registered
            if allowlist is None and not blocklist:
                return []  # No restrictions at all
            if allowlist is None:
                # No allowlist but blocklist exists — cannot enumerate all tools,
                # return empty to signal "all allowed" and let pipeline check
                # blocklist separately via the rule engine.
                return []
            available = set(allowlist)

        # Apply allowlist (intersect if allowlist is defined)
        if allowlist is not None:
            available &= allowlist

        # Apply blocklist
        available -= blocklist

        return sorted(available)
