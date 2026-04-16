"""Tests for Rule Engine — Layer 1 detection."""

from agentshield_core.engine.trust.levels import TrustLevel
from agentshield_core.engine.intent.models import (
    ToolCall,
    IntentContext,
    Intent,
    DecisionAction,
)
from agentshield_core.engine.intent.rule_engine import RuleEngine


class TestRuleEngine:
    def test_block_send_during_external_data(self, rule_engine: RuleEngine, email_intent_context: IntentContext):
        tc = ToolCall(name="send_email", params={"to": "evil@attacker.com"}, tool_category="send")
        result = rule_engine.check(tc, email_intent_context)
        assert result.is_definitive
        assert result.decision.action == DecisionAction.BLOCK

    def test_allow_read_during_external_data(self, rule_engine: RuleEngine, email_intent_context: IntentContext):
        tc = ToolCall(name="read_email", params={})
        result = rule_engine.check(tc, email_intent_context)
        assert not result.is_definitive  # No rule blocks this

    def test_block_code_exec_in_external_context(self, rule_engine: RuleEngine, email_intent_context: IntentContext):
        tc = ToolCall(name="execute_code", params={"code": "import os; os.system('rm -rf /')"})
        result = rule_engine.check(tc, email_intent_context)
        assert result.is_definitive
        assert result.decision.action == DecisionAction.BLOCK

    def test_confirm_external_recipient(self, rule_engine: RuleEngine):
        ctx = IntentContext(
            original_message="send email",
            intent=Intent(intent="send email"),
            current_data_trust_level=TrustLevel.VERIFIED,
        )
        tc = ToolCall(name="send_email", params={"to": "user@external.com"})
        result = rule_engine.check(tc, ctx)
        assert result.is_definitive
        assert result.decision.action == DecisionAction.REQUIRE_CONFIRMATION

    def test_block_audit_tampering(self, rule_engine: RuleEngine):
        ctx = IntentContext(
            original_message="clean up logs",
            intent=Intent(intent="clean up"),
            current_data_trust_level=TrustLevel.VERIFIED,
        )
        tc = ToolCall(name="delete_log", params={})
        result = rule_engine.check(tc, ctx)
        assert result.is_definitive
        assert result.decision.action == DecisionAction.BLOCK

    def test_block_data_destruction(self, rule_engine: RuleEngine):
        ctx = IntentContext(
            original_message="reset everything",
            intent=Intent(intent="reset"),
            current_data_trust_level=TrustLevel.VERIFIED,
        )
        tc = ToolCall(name="delete_all", params={})
        result = rule_engine.check(tc, ctx)
        assert result.is_definitive
        assert result.decision.action == DecisionAction.BLOCK

    def test_confirm_financial_operation(self, rule_engine: RuleEngine):
        ctx = IntentContext(
            original_message="process refund",
            intent=Intent(intent="process refund"),
            current_data_trust_level=TrustLevel.VERIFIED,
        )
        tc = ToolCall(name="process_payment", params={"amount": 100})
        result = rule_engine.check(tc, ctx)
        assert result.is_definitive
        assert result.decision.action == DecisionAction.REQUIRE_CONFIRMATION

    def test_no_rule_triggered_for_safe_operation(self, rule_engine: RuleEngine):
        ctx = IntentContext(
            original_message="summarize document",
            intent=Intent(intent="summarize"),
            current_data_trust_level=TrustLevel.VERIFIED,
        )
        tc = ToolCall(name="summarize_text", params={"text": "hello"})
        result = rule_engine.check(tc, ctx)
        assert not result.is_definitive
