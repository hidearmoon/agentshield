"""Tests for TrustPolicy and trust policy YAML loader."""

from __future__ import annotations

import tempfile


from agentguard_core.engine.trust.levels import TrustLevel
from agentguard_core.engine.trust.marker import TrustPolicy
from agentguard_core.engine.trust.policy import load_trust_policy, _extract_restrictions


class TestTrustPolicy:
    def test_default_policy_trusted_allows_all(self):
        policy = TrustPolicy()
        assert "ALL" in policy.get_allowed_actions(TrustLevel.TRUSTED)
        assert policy.get_tool_restrictions(TrustLevel.TRUSTED) == []
        assert not policy.requires_confirmation(TrustLevel.TRUSTED)

    def test_default_policy_external_restricts(self):
        policy = TrustPolicy()
        restrictions = policy.get_tool_restrictions(TrustLevel.EXTERNAL)
        assert "send_email" in restrictions
        assert "execute_code" in restrictions
        assert policy.requires_confirmation(TrustLevel.EXTERNAL)

    def test_default_policy_untrusted_blocks_all(self):
        policy = TrustPolicy()
        assert "ALL" in policy.get_tool_restrictions(TrustLevel.UNTRUSTED)
        assert policy.requires_confirmation(TrustLevel.UNTRUSTED)
        actions = policy.get_allowed_actions(TrustLevel.UNTRUSTED)
        assert actions == ["summarize", "classify"]

    def test_custom_policy_overrides_defaults(self):
        custom = {
            TrustLevel.EXTERNAL: {
                "allowed_actions": ["read"],
                "tool_restrictions": ["everything"],
                "require_confirmation": False,
            }
        }
        policy = TrustPolicy(custom)
        assert policy.get_allowed_actions(TrustLevel.EXTERNAL) == ["read"]
        assert not policy.requires_confirmation(TrustLevel.EXTERNAL)

    def test_unknown_level_falls_back_to_untrusted(self):
        """Custom policy without a level should fall back to UNTRUSTED."""
        policy = TrustPolicy(
            {
                TrustLevel.UNTRUSTED: {
                    "allowed_actions": [],
                    "tool_restrictions": ["ALL"],
                    "require_confirmation": True,
                }
            }
        )
        # TRUSTED is not in the custom policy, should fall back to UNTRUSTED
        assert policy.get_tool_restrictions(TrustLevel.TRUSTED) == ["ALL"]


class TestTrustPolicyLoader:
    def test_load_from_yaml(self):
        yaml_content = """
trust_policies:
  EXTERNAL:
    allowed_actions:
      - read
      - summarize
    tool_restrictions:
      - deny:
          - send_email
          - execute_code
    require_confirmation: true
  UNTRUSTED:
    allowed_actions:
      - classify
    tool_restrictions:
      - deny: ALL
    require_confirmation: true
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            policy = load_trust_policy(f.name)

        actions = policy.get_allowed_actions(TrustLevel.EXTERNAL)
        assert "read" in actions
        assert "summarize" in actions

    def test_extract_restrictions_deny_list(self):
        restrictions = _extract_restrictions(
            [
                {"deny": ["send_email", "execute_code"]},
                {"deny": ["query_database"]},
            ]
        )
        assert "send_email" in restrictions
        assert "execute_code" in restrictions
        assert "query_database" in restrictions

    def test_extract_restrictions_deny_all(self):
        restrictions = _extract_restrictions([{"deny": "ALL"}])
        assert "ALL" in restrictions

    def test_extract_restrictions_empty(self):
        restrictions = _extract_restrictions([])
        assert restrictions == []

    def test_extract_restrictions_invalid_format(self):
        """Non-dict entries should be skipped."""
        restrictions = _extract_restrictions(["not_a_dict", 42])
        assert restrictions == []
