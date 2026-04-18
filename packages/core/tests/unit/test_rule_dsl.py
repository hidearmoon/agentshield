"""Tests for custom rule DSL."""

import pytest
from agentguard_core.engine.trust.levels import TrustLevel
from agentguard_core.engine.intent.models import ToolCall, IntentContext, Intent, DecisionAction
from agentguard_core.engine.intent.rule_engine import RuleEngine
from agentguard_core.policy.dsl import load_rules_from_dict, load_rules_from_string, RuleDSLError


class TestRuleDSL:
    def test_simple_tool_match(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "block_delete",
                    "when": {"tool": "delete_user"},
                    "action": "BLOCK",
                    "reason": "Deletion blocked",
                }
            ]
        )
        assert len(rules) == 1
        engine = RuleEngine(rules)

        tc = ToolCall(name="delete_user", params={})
        ctx = IntentContext(original_message="", intent=Intent(intent=""))
        result = engine.check(tc, ctx)
        assert result.triggered
        assert result.decision.action == DecisionAction.BLOCK

    def test_tool_list_match(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "block_destructive",
                    "when": {"tool": ["delete_user", "drop_table", "truncate"]},
                    "action": "BLOCK",
                    "reason": "Destructive operation blocked",
                }
            ]
        )
        engine = RuleEngine(rules)

        for tool in ["delete_user", "drop_table", "truncate"]:
            tc = ToolCall(name=tool, params={})
            ctx = IntentContext(original_message="", intent=Intent(intent=""))
            result = engine.check(tc, ctx)
            assert result.triggered, f"Should block {tool}"

        tc = ToolCall(name="read_user", params={})
        ctx = IntentContext(original_message="", intent=Intent(intent=""))
        result = engine.check(tc, ctx)
        assert not result.triggered

    def test_trust_level_filter(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "block_send_external",
                    "when": {
                        "tool": "send_email",
                        "trust_level": ["EXTERNAL", "UNTRUSTED"],
                    },
                    "action": "BLOCK",
                    "reason": "Send blocked in external context",
                }
            ]
        )
        engine = RuleEngine(rules)

        # EXTERNAL context → should block
        tc = ToolCall(name="send_email", params={})
        ctx = IntentContext(
            original_message="",
            intent=Intent(intent=""),
            current_data_trust_level=TrustLevel.EXTERNAL,
        )
        result = engine.check(tc, ctx)
        assert result.triggered

        # VERIFIED context → should not block
        ctx2 = IntentContext(
            original_message="",
            intent=Intent(intent=""),
            current_data_trust_level=TrustLevel.VERIFIED,
        )
        result2 = engine.check(tc, ctx2)
        assert not result2.triggered

    def test_param_regex_match(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "block_competitor_email",
                    "when": {
                        "tool": "send_email",
                        "params": {"to": {"matches": ".*@competitor\\.com$"}},
                    },
                    "action": "BLOCK",
                    "reason": "Cannot email competitors",
                }
            ]
        )
        engine = RuleEngine(rules)

        tc_block = ToolCall(name="send_email", params={"to": "ceo@competitor.com"})
        tc_allow = ToolCall(name="send_email", params={"to": "friend@gmail.com"})
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        assert engine.check(tc_block, ctx).triggered
        assert not engine.check(tc_allow, ctx).triggered

    def test_param_numeric_comparison(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "confirm_large_export",
                    "when": {
                        "tool": "export_data",
                        "params": {"limit": {"gt": 100}},
                    },
                    "action": "REQUIRE_CONFIRMATION",
                    "reason": "Large export needs confirmation",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        tc_large = ToolCall(name="export_data", params={"limit": 500})
        tc_small = ToolCall(name="export_data", params={"limit": 10})

        assert engine.check(tc_large, ctx).triggered
        assert engine.check(tc_large, ctx).decision.action == DecisionAction.REQUIRE_CONFIRMATION
        assert not engine.check(tc_small, ctx).triggered

    def test_param_contains(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "block_sql_injection",
                    "when": {
                        "tool": "query_database",
                        "params": {"query": {"contains": "DROP TABLE"}},
                    },
                    "action": "BLOCK",
                    "reason": "SQL injection detected",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        tc_bad = ToolCall(name="query_database", params={"query": "SELECT 1; DROP TABLE users"})
        tc_ok = ToolCall(name="query_database", params={"query": "SELECT * FROM users"})

        assert engine.check(tc_bad, ctx).triggered
        assert not engine.check(tc_ok, ctx).triggered

    def test_param_in_list(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "restrict_regions",
                    "when": {
                        "tool": "deploy",
                        "params": {"region": {"not_in": ["us-east-1", "eu-west-1"]}},
                    },
                    "action": "BLOCK",
                    "reason": "Deployment only allowed in approved regions",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        tc_ok = ToolCall(name="deploy", params={"region": "us-east-1"})
        tc_bad = ToolCall(name="deploy", params={"region": "ap-southeast-1"})

        assert not engine.check(tc_ok, ctx).triggered
        assert engine.check(tc_bad, ctx).triggered

    def test_yaml_string_loading(self):
        yaml_str = """
rules:
  - name: test_rule
    when:
      tool: dangerous_tool
    action: BLOCK
    reason: "Blocked by YAML"
"""
        rules = load_rules_from_string(yaml_str)
        assert len(rules) == 1
        assert rules[0].name == "test_rule"

    def test_invalid_action_raises(self):
        with pytest.raises(RuleDSLError):
            load_rules_from_dict(
                [
                    {
                        "name": "bad_rule",
                        "when": {"tool": "test"},
                        "action": "INVALID_ACTION",
                    }
                ]
            )

    def test_disabled_rule_not_triggered(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "disabled_rule",
                    "enabled": False,
                    "when": {"tool": "send_email"},
                    "action": "BLOCK",
                }
            ]
        )
        engine = RuleEngine(rules)
        tc = ToolCall(name="send_email", params={})
        ctx = IntentContext(original_message="", intent=Intent(intent=""))
        result = engine.check(tc, ctx)
        assert not result.triggered

    def test_combined_conditions(self):
        """Multiple conditions must ALL be true (AND logic)."""
        rules = load_rules_from_dict(
            [
                {
                    "name": "strict_rule",
                    "when": {
                        "tool": "send_email",
                        "trust_level": ["EXTERNAL"],
                        "params": {"to": {"matches": ".*@external\\.com$"}},
                    },
                    "action": "BLOCK",
                    "reason": "All conditions met",
                }
            ]
        )
        engine = RuleEngine(rules)

        # All conditions met → block
        tc = ToolCall(name="send_email", params={"to": "user@external.com"})
        ctx = IntentContext(
            original_message="",
            intent=Intent(intent=""),
            current_data_trust_level=TrustLevel.EXTERNAL,
        )
        assert engine.check(tc, ctx).triggered

        # Wrong tool → no block
        tc2 = ToolCall(name="read_email", params={"to": "user@external.com"})
        assert not engine.check(tc2, ctx).triggered

        # Wrong trust level → no block
        ctx2 = IntentContext(
            original_message="",
            intent=Intent(intent=""),
            current_data_trust_level=TrustLevel.VERIFIED,
        )
        assert not engine.check(tc, ctx2).triggered

    def test_invalid_regex_raises_at_parse_time(self):
        """Invalid regex in rule DSL should raise RuleDSLError."""
        with pytest.raises(RuleDSLError):
            load_rules_from_dict(
                [
                    {
                        "name": "bad_regex",
                        "when": {
                            "tool": "test",
                            "params": {"query": {"matches": "[invalid(regex"}},
                        },
                        "action": "BLOCK",
                    }
                ]
            )

    def test_very_long_param_skips_regex(self):
        """Params longer than 10000 chars should not match regex (ReDoS protection)."""
        rules = load_rules_from_dict(
            [
                {
                    "name": "regex_rule",
                    "when": {
                        "tool": "query",
                        "params": {"input": {"matches": ".*malicious.*"}},
                    },
                    "action": "BLOCK",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        # Normal length → should match
        tc_normal = ToolCall(name="query", params={"input": "this is malicious content"})
        assert engine.check(tc_normal, ctx).triggered

        # Very long → should NOT match (ReDoS protection)
        tc_long = ToolCall(name="query", params={"input": "malicious " + "x" * 10001})
        assert not engine.check(tc_long, ctx).triggered
