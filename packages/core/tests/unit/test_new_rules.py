"""Tests for newly added builtin rules."""

from __future__ import annotations

from agentguard_core.engine.intent.models import DecisionAction, Intent, IntentContext, ToolCall
from agentguard_core.engine.intent.rule_engine import RuleEngine
from agentguard_core.engine.trust.levels import TrustLevel


class TestSecretAccessRule:
    def test_blocks_secret_access_from_external(self):
        engine = RuleEngine()
        ctx = IntentContext(
            original_message="process",
            intent=Intent(intent="process"),
            current_data_trust_level=TrustLevel.EXTERNAL,
        )
        for tool in ["get_secret", "read_env", "get_api_key", "access_credentials"]:
            result = engine.check(ToolCall(name=tool, params={}), ctx)
            assert result.triggered, f"{tool} should be blocked from EXTERNAL"
            assert result.decision.action == DecisionAction.BLOCK

    def test_allows_secret_access_from_verified(self):
        engine = RuleEngine()
        ctx = IntentContext(
            original_message="manage secrets",
            intent=Intent(intent="manage"),
            current_data_trust_level=TrustLevel.VERIFIED,
        )
        result = engine.check(ToolCall(name="get_secret", params={}), ctx)
        # VERIFIED trust should allow secret access (only rule engine check,
        # other rules like sensitive_data_access may trigger separately)
        # The no_secrets_external rule should NOT trigger for VERIFIED
        if result.triggered:
            assert result.rule_name != "no_secrets_external"


class TestEnvModificationRule:
    def test_blocks_env_modification(self):
        engine = RuleEngine()
        ctx = IntentContext(
            original_message="test",
            intent=Intent(intent="test"),
            current_data_trust_level=TrustLevel.VERIFIED,
        )
        for tool in ["set_env", "modify_env", "update_environment"]:
            result = engine.check(ToolCall(name=tool, params={}), ctx)
            assert result.triggered, f"{tool} should be blocked"
            assert result.rule_name == "env_modification"

    def test_allows_reading_env(self):
        engine = RuleEngine()
        ctx = IntentContext(
            original_message="test",
            intent=Intent(intent="test"),
            current_data_trust_level=TrustLevel.VERIFIED,
        )
        result = engine.check(ToolCall(name="get_env", params={}), ctx)
        # get_env (reading) should not be blocked by env_modification rule
        if result.triggered:
            assert result.rule_name != "env_modification"
