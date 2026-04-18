"""Trust marker system — server-side trust level computation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from agentguard_core.engine.trust.levels import TrustLevel, TRUST_SOURCE_MAPPING


@dataclass
class SourceInfo:
    trust_level: TrustLevel
    metadata: dict = field(default_factory=dict)


@dataclass
class MarkedData:
    content: str
    trust_level: TrustLevel
    source_id: str
    marked_at: datetime
    allowed_actions: list[str]
    tool_restrictions: list[str]


class TrustMarker:
    """
    Trust marker system.

    Key security invariant: trust_level is ALWAYS computed server-side
    based on source mapping. Client-claimed levels can only downgrade
    (be more conservative), never upgrade.
    """

    def __init__(self, policy: TrustPolicy | None = None):
        self._policy = policy or TrustPolicy()
        self._source_registry: dict[str, SourceInfo] = {}

    def register_source(self, source_id: str, trust_level: TrustLevel, metadata: dict | None = None) -> None:
        self._source_registry[source_id] = SourceInfo(
            trust_level=trust_level,
            metadata=metadata or {},
        )

    def compute_trust_level(self, source_id: str, client_claimed_level: TrustLevel | None = None) -> TrustLevel:
        """
        Compute trust level server-side from source mapping.
        Client-claimed level can only downgrade, never upgrade.
        """
        base_level = self._get_base_level(source_id)

        # Client can only claim LOWER (more conservative) trust
        if client_claimed_level is not None and client_claimed_level < base_level:
            return client_claimed_level

        return base_level

    def _get_base_level(self, source_id: str) -> TrustLevel:
        # Exact match in registry
        if source_id in self._source_registry:
            return self._source_registry[source_id].trust_level

        # Wildcard match in registry (e.g., email/* matches email/gmail)
        for pattern, info in self._source_registry.items():
            if pattern.endswith("/*") and source_id.startswith(pattern[:-2]):
                return info.trust_level

        # Global mapping
        for pattern, level in TRUST_SOURCE_MAPPING.items():
            if pattern == source_id:
                return level
            if pattern.endswith("/*") and source_id.startswith(pattern[:-2]):
                return level

        return TrustLevel.UNTRUSTED

    def mark(self, data: str, source_id: str, client_claimed_level: TrustLevel | None = None) -> MarkedData:
        trust_level = self.compute_trust_level(source_id, client_claimed_level)

        return MarkedData(
            content=data,
            trust_level=trust_level,
            source_id=source_id,
            marked_at=datetime.now(timezone.utc),
            allowed_actions=self._policy.get_allowed_actions(trust_level),
            tool_restrictions=self._policy.get_tool_restrictions(trust_level),
        )

    def get_effective_tools(self, trust_level: TrustLevel, full_tool_set: list[str]) -> list[str]:
        restrictions = self._policy.get_tool_restrictions(trust_level)
        return [t for t in full_tool_set if t not in restrictions]


class TrustPolicy:
    """Trust-level based policy for actions and tool restrictions."""

    DEFAULT_POLICIES: dict[TrustLevel, dict] = {
        TrustLevel.TRUSTED: {
            "allowed_actions": ["ALL"],
            "tool_restrictions": [],
            "require_confirmation": False,
        },
        TrustLevel.VERIFIED: {
            "allowed_actions": ["ALL"],
            "tool_restrictions": [],
            "require_confirmation": False,
        },
        TrustLevel.INTERNAL: {
            "allowed_actions": ["ALL"],
            "tool_restrictions": ["send_email_external", "export_data", "modify_permissions"],
            "require_confirmation": False,
        },
        TrustLevel.EXTERNAL: {
            "allowed_actions": ["read", "summarize", "extract", "classify", "draft_reply"],
            "tool_restrictions": ["send_email", "query_database", "execute_code", "call_api"],
            "require_confirmation": True,
        },
        TrustLevel.UNTRUSTED: {
            "allowed_actions": ["summarize", "classify"],
            "tool_restrictions": ["ALL"],
            "require_confirmation": True,
        },
    }

    _FALLBACK_POLICY: dict = {
        "allowed_actions": [],
        "tool_restrictions": ["ALL"],
        "require_confirmation": True,
    }

    def __init__(self, policies: dict[TrustLevel, dict] | None = None):
        self._policies = policies or self.DEFAULT_POLICIES

    def _get_policy(self, trust_level: TrustLevel) -> dict:
        return self._policies.get(
            trust_level,
            self._policies.get(TrustLevel.UNTRUSTED, self._FALLBACK_POLICY),
        )

    def get_allowed_actions(self, trust_level: TrustLevel) -> list[str]:
        return self._get_policy(trust_level)["allowed_actions"]

    def get_tool_restrictions(self, trust_level: TrustLevel) -> list[str]:
        return self._get_policy(trust_level)["tool_restrictions"]

    def requires_confirmation(self, trust_level: TrustLevel) -> bool:
        return self._get_policy(trust_level)["require_confirmation"]
