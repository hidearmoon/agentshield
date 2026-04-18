"""Trust policy loader from YAML/database."""

from __future__ import annotations

from pathlib import Path

import yaml

from agentguard_core.engine.trust.levels import TrustLevel
from agentguard_core.engine.trust.marker import TrustPolicy


def load_trust_policy(path: str | Path) -> TrustPolicy:
    """Load trust policy from a YAML file."""
    with open(path) as f:
        raw = yaml.safe_load(f)

    policies: dict[TrustLevel, dict] = {}
    for level_name, policy_data in raw.get("trust_policies", {}).items():
        level = TrustLevel[level_name]
        policies[level] = {
            "allowed_actions": policy_data.get("allowed_actions", []),
            "tool_restrictions": _extract_restrictions(policy_data.get("tool_restrictions", [])),
            "require_confirmation": policy_data.get("require_confirmation", True),
        }

    return TrustPolicy(policies)


def _extract_restrictions(restrictions: list) -> list[str]:
    """Extract denied tool names from restriction rules."""
    denied = []
    for rule in restrictions:
        if isinstance(rule, dict) and "deny" in rule:
            deny_list = rule["deny"]
            if isinstance(deny_list, list):
                denied.extend(deny_list)
            elif deny_list == "ALL":
                denied.append("ALL")
    return denied
