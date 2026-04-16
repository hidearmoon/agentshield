"""
Custom rule DSL — allows users to define detection rules in YAML without writing Python.

Rule DSL syntax:
```yaml
rules:
  - name: block_email_to_competitors
    description: "Block sending emails to competitor domains"
    when:
      tool: send_email
      trust_level: ["EXTERNAL", "UNTRUSTED"]
      params:
        to:
          matches: ".*@(competitor1|competitor2)\\.com$"
    action: BLOCK
    reason: "Sending to competitor domain is prohibited"

  - name: confirm_large_query
    description: "Require confirmation for queries returning >50 rows"
    when:
      tool: query_database
      params:
        limit:
          gt: 50
    action: REQUIRE_CONFIRMATION
    reason: "Large query requires confirmation"

  - name: block_after_hours_actions
    description: "Block sensitive actions outside business hours"
    when:
      tool_category: send
      trust_level: ["EXTERNAL"]
      conditions:
        - type: time_range
          outside: "09:00-18:00"
    action: BLOCK
    reason: "Sensitive actions blocked outside business hours"
```

Supported matchers:
- tool: exact tool name or list of names
- tool_category: tool category string
- trust_level: list of trust levels where rule applies
- params.<field>.equals: exact match
- params.<field>.matches: regex match
- params.<field>.contains: substring match
- params.<field>.gt / gte / lt / lte: numeric comparison
- params.<field>.in: value in list
- params.<field>.not_in: value not in list
- conditions: list of extra condition checks (time_range, intent_match, etc.)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from agentshield_core.engine.intent.models import (
    ToolCall,
    IntentContext,
    Decision,
    DecisionAction,
)
from agentshield_core.engine.intent.rule_engine import Rule


def load_rules_from_yaml(path: str | Path) -> list[Rule]:
    """Load custom rules from a YAML file."""
    with open(path) as f:
        data = yaml.safe_load(f)
    return parse_rules(data.get("rules", []))


def load_rules_from_string(yaml_string: str) -> list[Rule]:
    """Load custom rules from a YAML string."""
    data = yaml.safe_load(yaml_string)
    return parse_rules(data.get("rules", []))


def load_rules_from_dict(rules_list: list[dict]) -> list[Rule]:
    """Load custom rules from a list of rule dicts (e.g., from database)."""
    return parse_rules(rules_list)


def parse_rules(rules_data: list[dict]) -> list[Rule]:
    """Parse a list of rule definitions into Rule objects."""
    rules = []
    for rule_def in rules_data:
        try:
            rule = _parse_single_rule(rule_def)
            rules.append(rule)
        except (KeyError, ValueError) as e:
            raise RuleDSLError(f"Invalid rule '{rule_def.get('name', 'unknown')}': {e}") from e
    return rules


class RuleDSLError(Exception):
    """Raised when a rule DSL definition is invalid."""

    pass


# ─── Internal Parsing ────────────────────────────────────────────────────────


def _parse_single_rule(rule_def: dict) -> Rule:
    name = rule_def["name"]
    description = rule_def.get("description", "")
    enabled = rule_def.get("enabled", True)
    when = rule_def.get("when", {})
    action_str = rule_def.get("action", "BLOCK")
    reason = rule_def.get("reason", f"Rule '{name}' triggered")

    # Parse action
    action_map = {
        "BLOCK": DecisionAction.BLOCK,
        "REQUIRE_CONFIRMATION": DecisionAction.REQUIRE_CONFIRMATION,
        "ALLOW": DecisionAction.ALLOW,
    }
    if action_str not in action_map:
        raise ValueError(f"Unknown action: {action_str}")

    decision = Decision(action=action_map[action_str], reason=reason, engine="custom_rule")

    # Build condition function from DSL
    condition = _build_condition(when)

    # Custom rules get higher priority so they take precedence over builtins.
    # BLOCK rules get priority 20, REQUIRE_CONFIRMATION gets 10, ALLOW gets 5.
    priority = rule_def.get("priority", None)
    if priority is None:
        priority = {"BLOCK": 20, "REQUIRE_CONFIRMATION": 10, "ALLOW": 5}.get(action_str, 0)

    return Rule(
        name=name,
        description=description,
        condition=condition,
        decision=decision,
        enabled=enabled,
        priority=priority,
    )


def _build_condition(when: dict) -> callable:
    """Build a Python callable from a 'when' block."""
    matchers: list[callable] = []

    # Tool name matcher
    if "tool" in when:
        tool_spec = when["tool"]
        if isinstance(tool_spec, str):
            matchers.append(lambda tc, ctx, t=tool_spec: tc.name == t)
        elif isinstance(tool_spec, list):
            matchers.append(lambda tc, ctx, ts=set(tool_spec): tc.name in ts)

    # Tool category matcher
    if "tool_category" in when:
        cat = when["tool_category"]
        if isinstance(cat, str):
            matchers.append(lambda tc, ctx, c=cat: tc.tool_category == c)
        elif isinstance(cat, list):
            matchers.append(lambda tc, ctx, cs=set(cat): tc.tool_category in cs)

    # Trust level matcher
    if "trust_level" in when:
        levels = when["trust_level"]
        if isinstance(levels, str):
            levels = [levels]
        level_values = set()
        level_name_map = {
            "TRUSTED": 5,
            "VERIFIED": 4,
            "INTERNAL": 3,
            "EXTERNAL": 2,
            "UNTRUSTED": 1,
        }
        for lv in levels:
            if lv in level_name_map:
                level_values.add(level_name_map[lv])
        matchers.append(lambda tc, ctx, lvs=level_values: ctx.current_data_trust_level in lvs)

    # Parameter matchers
    if "params" in when:
        for param_name, param_spec in when["params"].items():
            matcher = _build_param_matcher(param_name, param_spec)
            matchers.append(matcher)

    # Extra conditions
    if "conditions" in when:
        for cond in when["conditions"]:
            matcher = _build_extra_condition(cond)
            if matcher:
                matchers.append(matcher)

    # Combine all matchers with AND logic
    if not matchers:
        # No conditions = always matches (probably a mistake, but valid)
        return lambda tc, ctx: True

    def combined_condition(tc: ToolCall, ctx: IntentContext) -> bool:
        return all(m(tc, ctx) for m in matchers)

    return combined_condition


def _build_param_matcher(param_name: str, spec: Any) -> callable:
    """Build a matcher for a single parameter."""

    if isinstance(spec, dict):
        checks: list[callable] = []

        if "equals" in spec:
            val = spec["equals"]
            checks.append(lambda tc, ctx, p=param_name, v=val: tc.params.get(p) == v)

        if "matches" in spec:
            try:
                pattern = re.compile(spec["matches"])
            except re.error as e:
                raise ValueError(f"Invalid regex in param '{param_name}': {e}")
            # Limit input length to prevent ReDoS
            checks.append(
                lambda tc, ctx, p=param_name, pat=pattern: (
                    isinstance(tc.params.get(p), str)
                    and len(tc.params.get(p, "")) <= 10000
                    and pat.search(tc.params.get(p, "")) is not None
                )
            )

        if "contains" in spec:
            substr = spec["contains"]
            checks.append(
                lambda tc, ctx, p=param_name, s=substr: isinstance(tc.params.get(p), str) and s in tc.params.get(p, "")
            )

        if "gt" in spec:
            threshold = spec["gt"]
            checks.append(
                lambda tc, ctx, p=param_name, t=threshold: (
                    isinstance(tc.params.get(p), (int, float)) and tc.params.get(p, 0) > t
                )
            )

        if "gte" in spec:
            threshold = spec["gte"]
            checks.append(
                lambda tc, ctx, p=param_name, t=threshold: (
                    isinstance(tc.params.get(p), (int, float)) and tc.params.get(p, 0) >= t
                )
            )

        if "lt" in spec:
            threshold = spec["lt"]
            checks.append(
                lambda tc, ctx, p=param_name, t=threshold: (
                    isinstance(tc.params.get(p), (int, float)) and tc.params.get(p, 0) < t
                )
            )

        if "lte" in spec:
            threshold = spec["lte"]
            checks.append(
                lambda tc, ctx, p=param_name, t=threshold: (
                    isinstance(tc.params.get(p), (int, float)) and tc.params.get(p, 0) <= t
                )
            )

        if "in" in spec:
            allowed = set(spec["in"])
            checks.append(lambda tc, ctx, p=param_name, a=allowed: tc.params.get(p) in a)

        if "not_in" in spec:
            blocked = set(spec["not_in"])
            checks.append(lambda tc, ctx, p=param_name, b=blocked: tc.params.get(p) not in b)

        if "not_equals" in spec:
            val = spec["not_equals"]
            checks.append(lambda tc, ctx, p=param_name, v=val: tc.params.get(p) != v)

        if "starts_with" in spec:
            prefix = spec["starts_with"]
            checks.append(
                lambda tc, ctx, p=param_name, pf=prefix: (
                    isinstance(tc.params.get(p), str) and tc.params.get(p, "").startswith(pf)
                )
            )

        if "ends_with" in spec:
            suffix = spec["ends_with"]
            checks.append(
                lambda tc, ctx, p=param_name, sf=suffix: (
                    isinstance(tc.params.get(p), str) and tc.params.get(p, "").endswith(sf)
                )
            )

        if not checks:
            return lambda tc, ctx: True

        return lambda tc, ctx: all(c(tc, ctx) for c in checks)

    else:
        # Simple value = equals
        return lambda tc, ctx, p=param_name, v=spec: tc.params.get(p) == v


def _build_extra_condition(cond: dict) -> callable | None:
    """Build a matcher for extra conditions like time_range, intent_match."""
    cond_type = cond.get("type")

    if cond_type == "time_range":
        if "outside" in cond:
            start_str, end_str = cond["outside"].split("-")
            start_h, start_m = map(int, start_str.strip().split(":"))
            end_h, end_m = map(int, end_str.strip().split(":"))

            def time_outside(tc: ToolCall, ctx: IntentContext) -> bool:
                now = datetime.now(timezone.utc)
                current_minutes = now.hour * 60 + now.minute
                start_minutes = start_h * 60 + start_m
                end_minutes = end_h * 60 + end_m
                return current_minutes < start_minutes or current_minutes > end_minutes

            return time_outside

        if "within" in cond:
            start_str, end_str = cond["within"].split("-")
            start_h, start_m = map(int, start_str.strip().split(":"))
            end_h, end_m = map(int, end_str.strip().split(":"))

            def time_within(tc: ToolCall, ctx: IntentContext) -> bool:
                now = datetime.now(timezone.utc)
                current_minutes = now.hour * 60 + now.minute
                start_minutes = start_h * 60 + start_m
                end_minutes = end_h * 60 + end_m
                return start_minutes <= current_minutes <= end_minutes

            return time_within

    elif cond_type == "intent_match":
        pattern = re.compile(cond.get("pattern", ""), re.IGNORECASE)

        def intent_match(tc: ToolCall, ctx: IntentContext) -> bool:
            return pattern.search(ctx.intent.intent) is not None

        return intent_match

    elif cond_type == "intent_not_match":
        pattern = re.compile(cond.get("pattern", ""), re.IGNORECASE)

        def intent_not_match(tc: ToolCall, ctx: IntentContext) -> bool:
            return pattern.search(ctx.intent.intent) is None

        return intent_not_match

    elif cond_type == "history_count":
        op = cond.get("op", "gte")
        value = cond.get("value", 0)
        ops = {
            "gt": lambda a, b: a > b,
            "gte": lambda a, b: a >= b,
            "lt": lambda a, b: a < b,
            "lte": lambda a, b: a <= b,
            "eq": lambda a, b: a == b,
        }
        compare = ops.get(op, ops["gte"])

        def history_count(tc: ToolCall, ctx: IntentContext) -> bool:
            return compare(len(ctx.tool_call_history), value)

        return history_count

    return None
