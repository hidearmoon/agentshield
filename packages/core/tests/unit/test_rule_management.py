"""Tests for rule management operations (add, remove, list, enable/disable)."""

from agentguard_core.engine.intent.rule_engine import RuleEngine, Rule, BUILTIN_RULES
from agentguard_core.engine.intent.models import (
    ToolCall,
    IntentContext,
    Intent,
    Decision,
)
from agentguard_core.policy.dsl import load_rules_from_dict, load_rules_from_string


class TestRuleManagement:
    def test_add_custom_rule(self):
        engine = RuleEngine()
        initial_count = len(engine._rules)

        custom = Rule(
            name="custom_block",
            description="Block custom tool",
            condition=lambda tc, ctx: tc.name == "custom_tool",
            decision=Decision.block("custom blocked", "custom"),
        )
        engine.add_rule(custom)
        assert len(engine._rules) == initial_count + 1

    def test_add_multiple_rules(self):
        engine = RuleEngine()
        initial = len(engine._rules)

        rules = [
            Rule(name=f"rule_{i}", description="", condition=lambda tc, ctx: False, decision=Decision.allow())
            for i in range(5)
        ]
        engine.add_rules(rules)
        assert len(engine._rules) == initial + 5

    def test_remove_existing_rule(self):
        engine = RuleEngine()
        initial = len(engine._rules)

        # Remove a known builtin rule
        removed = engine.remove_rule("no_send_during_external_data")
        assert removed
        assert len(engine._rules) == initial - 1

    def test_remove_nonexistent_rule(self):
        engine = RuleEngine()
        removed = engine.remove_rule("nonexistent_rule_xyz")
        assert not removed

    def test_list_rules(self):
        engine = RuleEngine()
        rules_list = engine.list_rules()
        assert len(rules_list) == len(BUILTIN_RULES)
        for r in rules_list:
            assert "name" in r
            assert "description" in r
            assert "enabled" in r
            assert "type" in r

    def test_enable_disable_rule(self):
        engine = RuleEngine()

        # Disable a rule
        result = engine.set_rule_enabled("data_destruction", False)
        assert result

        # Verify it's disabled
        ctx = IntentContext(
            original_message="",
            intent=Intent(intent=""),
        )
        tc = ToolCall(name="delete_all", params={})
        check_result = engine.check(tc, ctx)
        assert not check_result.triggered  # Should not trigger when disabled

        # Re-enable
        engine.set_rule_enabled("data_destruction", True)
        check_result2 = engine.check(tc, ctx)
        assert check_result2.triggered

    def test_enable_nonexistent_rule(self):
        engine = RuleEngine()
        result = engine.set_rule_enabled("nonexistent_xyz", True)
        assert not result

    def test_rule_exception_handled(self):
        """Rule that raises an exception should be skipped, not crash."""

        def bad_condition(tc, ctx):
            raise ValueError("rule bug")

        engine = RuleEngine(
            rules=[
                Rule(name="bad_rule", description="", condition=bad_condition, decision=Decision.block("x", "rule")),
            ]
        )

        tc = ToolCall(name="test", params={})
        ctx = IntentContext(original_message="", intent=Intent(intent=""))
        result = engine.check(tc, ctx)
        # Should not crash, should return non-definitive
        assert not result.is_definitive


class TestDSLExtraConditions:
    """Test DSL extra conditions: time_range, intent_match, history_count."""

    def test_intent_match_condition(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "block_if_intent_destructive",
                    "when": {
                        "tool": "query_database",
                        "conditions": [
                            {"type": "intent_match", "pattern": "delete|destroy|remove"},
                        ],
                    },
                    "action": "BLOCK",
                }
            ]
        )
        engine = RuleEngine(rules)

        tc = ToolCall(name="query_database", params={})

        # Matching intent
        ctx_match = IntentContext(
            original_message="delete everything",
            intent=Intent(intent="delete all records"),
        )
        assert engine.check(tc, ctx_match).triggered

        # Non-matching intent
        ctx_nomatch = IntentContext(
            original_message="read data",
            intent=Intent(intent="read user list"),
        )
        assert not engine.check(tc, ctx_nomatch).triggered

    def test_intent_not_match_condition(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "block_if_not_expected",
                    "when": {
                        "tool": "send_email",
                        "conditions": [
                            {"type": "intent_not_match", "pattern": "send|email|notify"},
                        ],
                    },
                    "action": "BLOCK",
                }
            ]
        )
        engine = RuleEngine(rules)

        tc = ToolCall(name="send_email", params={})

        # Intent does NOT match "send|email|notify" → should block
        ctx = IntentContext(
            original_message="summarize document",
            intent=Intent(intent="summarize"),
        )
        assert engine.check(tc, ctx).triggered

        # Intent DOES match → should not block
        ctx2 = IntentContext(
            original_message="send email",
            intent=Intent(intent="send email to team"),
        )
        assert not engine.check(tc, ctx2).triggered

    def test_history_count_condition(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "block_after_many_calls",
                    "when": {
                        "tool": "query_database",
                        "conditions": [
                            {"type": "history_count", "op": "gte", "value": 5},
                        ],
                    },
                    "action": "REQUIRE_CONFIRMATION",
                }
            ]
        )
        engine = RuleEngine(rules)

        tc = ToolCall(name="query_database", params={})

        # Less than 5 history items → no trigger
        ctx_few = IntentContext(
            original_message="",
            intent=Intent(intent=""),
            tool_call_history=[ToolCall(name="x", params={}) for _ in range(3)],
        )
        assert not engine.check(tc, ctx_few).triggered

        # Exactly 5 → should trigger
        ctx_many = IntentContext(
            original_message="",
            intent=Intent(intent=""),
            tool_call_history=[ToolCall(name="x", params={}) for _ in range(5)],
        )
        assert engine.check(tc, ctx_many).triggered

    def test_unknown_condition_type_ignored(self):
        """Unknown condition type should not crash."""
        rules = load_rules_from_dict(
            [
                {
                    "name": "rule_with_unknown_cond",
                    "when": {
                        "tool": "test",
                        "conditions": [
                            {"type": "unknown_future_feature", "value": 42},
                        ],
                    },
                    "action": "BLOCK",
                }
            ]
        )
        engine = RuleEngine(rules)

        tc = ToolCall(name="test", params={})
        ctx = IntentContext(original_message="", intent=Intent(intent=""))
        # Unknown condition is ignored (returns None → not added to matchers)
        # So the rule only matches on tool name
        result = engine.check(tc, ctx)
        assert result.triggered  # Tool matches, unknown condition is skipped

    def test_empty_rules_yaml(self):
        rules = load_rules_from_string("rules: []")
        assert rules == []

    def test_param_equals_shorthand(self):
        """Simple value in param spec is treated as equals."""
        rules = load_rules_from_dict(
            [
                {
                    "name": "exact_match",
                    "when": {
                        "tool": "deploy",
                        "params": {"env": "production"},
                    },
                    "action": "REQUIRE_CONFIRMATION",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        tc_match = ToolCall(name="deploy", params={"env": "production"})
        tc_nomatch = ToolCall(name="deploy", params={"env": "staging"})

        assert engine.check(tc_match, ctx).triggered
        assert not engine.check(tc_nomatch, ctx).triggered

    def test_param_lte_matcher(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "small_limit",
                    "when": {"tool": "query", "params": {"limit": {"lte": 10}}},
                    "action": "ALLOW",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        assert engine.check(ToolCall(name="query", params={"limit": 10}), ctx).triggered
        assert engine.check(ToolCall(name="query", params={"limit": 5}), ctx).triggered
        assert not engine.check(ToolCall(name="query", params={"limit": 11}), ctx).triggered

    def test_param_gte_matcher(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "big_limit",
                    "when": {"tool": "query", "params": {"limit": {"gte": 100}}},
                    "action": "BLOCK",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        assert engine.check(ToolCall(name="query", params={"limit": 100}), ctx).triggered
        assert engine.check(ToolCall(name="query", params={"limit": 500}), ctx).triggered
        assert not engine.check(ToolCall(name="query", params={"limit": 99}), ctx).triggered

    def test_param_lt_matcher(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "negative_check",
                    "when": {"tool": "transfer", "params": {"amount": {"lt": 0}}},
                    "action": "BLOCK",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        assert engine.check(ToolCall(name="transfer", params={"amount": -1}), ctx).triggered
        assert not engine.check(ToolCall(name="transfer", params={"amount": 0}), ctx).triggered

    def test_param_in_list_matcher(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "allow_regions",
                    "when": {"tool": "deploy", "params": {"region": {"in": ["us-east-1", "eu-west-1"]}}},
                    "action": "ALLOW",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        assert engine.check(ToolCall(name="deploy", params={"region": "us-east-1"}), ctx).triggered
        assert not engine.check(ToolCall(name="deploy", params={"region": "cn-north-1"}), ctx).triggered

    def test_tool_category_matcher(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "block_send_category",
                    "when": {"tool_category": "send"},
                    "action": "BLOCK",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        assert engine.check(ToolCall(name="any_tool", tool_category="send"), ctx).triggered
        assert not engine.check(ToolCall(name="any_tool", tool_category="read"), ctx).triggered

    def test_tool_category_list_matcher(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "block_dangerous",
                    "when": {"tool_category": ["send", "execute", "delete"]},
                    "action": "BLOCK",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        assert engine.check(ToolCall(name="x", tool_category="execute"), ctx).triggered
        assert not engine.check(ToolCall(name="x", tool_category="read"), ctx).triggered

    def test_no_when_clause_matches_all(self):
        """Rule with empty when should match everything."""
        rules = load_rules_from_dict(
            [
                {
                    "name": "catch_all",
                    "when": {},
                    "action": "REQUIRE_CONFIRMATION",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        assert engine.check(ToolCall(name="anything"), ctx).triggered

    def test_time_range_outside_condition(self):
        """Time range outside condition should evaluate."""
        rules = load_rules_from_dict(
            [
                {
                    "name": "after_hours",
                    "when": {
                        "tool": "send_email",
                        "conditions": [{"type": "time_range", "outside": "09:00-18:00"}],
                    },
                    "action": "BLOCK",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))
        tc = ToolCall(name="send_email", params={})
        result = engine.check(tc, ctx)
        assert result is not None

    def test_time_range_within_condition(self):
        """Time range within condition — 00:00-23:59 covers all day."""
        rules = load_rules_from_dict(
            [
                {
                    "name": "always_match",
                    "when": {
                        "tool": "deploy",
                        "conditions": [{"type": "time_range", "within": "00:00-23:59"}],
                    },
                    "action": "REQUIRE_CONFIRMATION",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))
        result = engine.check(ToolCall(name="deploy"), ctx)
        assert result.triggered

    def test_load_rules_from_yaml_file(self, tmp_path):
        """Load rules from a YAML file."""
        yaml_content = (
            "rules:\n"
            "  - name: yaml_rule_1\n"
            "    when:\n"
            "      tool: dangerous_op\n"
            "    action: BLOCK\n"
            "    reason: Blocked by YAML\n"
            "  - name: yaml_rule_2\n"
            "    when:\n"
            "      tool: risky_op\n"
            "    action: REQUIRE_CONFIRMATION\n"
        )
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text(yaml_content)

        from agentguard_core.policy.dsl import load_rules_from_yaml

        rules = load_rules_from_yaml(yaml_file)
        assert len(rules) == 2
        assert rules[0].name == "yaml_rule_1"

        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))
        result = engine.check(ToolCall(name="dangerous_op"), ctx)
        assert result.triggered

    def test_param_not_equals(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "not_prod",
                    "when": {"tool": "deploy", "params": {"env": {"not_equals": "production"}}},
                    "action": "ALLOW",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        assert engine.check(ToolCall(name="deploy", params={"env": "staging"}), ctx).triggered
        assert not engine.check(ToolCall(name="deploy", params={"env": "production"}), ctx).triggered

    def test_param_starts_with(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "block_external",
                    "when": {"tool": "send", "params": {"to": {"starts_with": "ext-"}}},
                    "action": "BLOCK",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        assert engine.check(ToolCall(name="send", params={"to": "ext-user@evil.com"}), ctx).triggered
        assert not engine.check(ToolCall(name="send", params={"to": "internal@company.com"}), ctx).triggered

    def test_param_ends_with(self):
        rules = load_rules_from_dict(
            [
                {
                    "name": "block_csv",
                    "when": {"tool": "export", "params": {"format": {"ends_with": ".csv"}}},
                    "action": "REQUIRE_CONFIRMATION",
                }
            ]
        )
        engine = RuleEngine(rules)
        ctx = IntentContext(original_message="", intent=Intent(intent=""))

        assert engine.check(ToolCall(name="export", params={"format": "data.csv"}), ctx).triggered
        assert not engine.check(ToolCall(name="export", params={"format": "data.json"}), ctx).triggered
