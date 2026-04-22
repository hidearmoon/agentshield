"""
AgentGuard Local Mode — zero-dependency, no server required.

Embeds the rule engine and anomaly scoring directly in the SDK.
No PostgreSQL, no ClickHouse, no Docker, no API key.

    pip install agentguard
    # That's it. No server needed.

Usage:

    from agentguard import LocalShield

    shield = LocalShield()

    @shield.guard
    async def send_email(to: str, body: str) -> str:
        return f"sent to {to}"

    # Works immediately — no server, no config
    await send_email(to="user@company.com", body="hello")

    # Set trust context when processing external data
    shield.set_trust("EXTERNAL")
    await send_email(to="attacker@evil.com", body="data")
    # → raises ToolCallBlocked

For the full server-backed mode with LLM semantic checks,
session tracking, and Merkle audit trail, use Shield() instead.
"""

from __future__ import annotations

import functools
import inspect
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Coroutine, TypeVar

from agentguard.exceptions import ConfirmationRejected, ToolCallBlocked
from agentguard.models import CheckResult, Decision

F = TypeVar("F", bound=Callable[..., Coroutine[Any, Any, Any]])


# ─── Trust Levels (embedded) ───────────────────────────────────────────


class TrustLevel(IntEnum):
    TRUSTED = 5
    VERIFIED = 4
    INTERNAL = 3
    EXTERNAL = 2
    UNTRUSTED = 1


# ─── Rule System (embedded, no imports from core) ─────────────────────


@dataclass
class ToolCall:
    name: str
    params: dict = field(default_factory=dict)


@dataclass
class RuleContext:
    trust_level: TrustLevel
    intent: str
    tool_history: list[str] = field(default_factory=list)


@dataclass
class LocalRule:
    name: str
    description: str
    check: Callable[[ToolCall, RuleContext], bool]
    action: Decision
    reason: str


def _is_external(ctx: RuleContext) -> bool:
    return ctx.trust_level <= TrustLevel.EXTERNAL


def _is_untrusted(ctx: RuleContext) -> bool:
    return ctx.trust_level <= TrustLevel.UNTRUSTED


SEND_TOOLS = {
    "send_email",
    "send_message",
    "post_message",
    "send_notification",
    "send_sms",
    "publish",
    "send_webhook",
}

CODE_EXEC_TOOLS = {
    "execute_code",
    "run_script",
    "eval",
    "exec_command",
    "run_shell",
    "exec",
    "spawn",
    "shell",
}

FS_WRITE_TOOLS = {
    "write_file",
    "create_file",
    "delete_file",
    "modify_file",
    "fs_write",
    "fs_delete",
}

NETWORK_TOOLS = {
    "http_request",
    "fetch_url",
    "call_api",
    "webhook_send",
    "call_external_api",
}

SECRET_TOOLS = {
    "get_secret",
    "read_env",
    "get_api_key",
    "access_credentials",
    "read_secrets",
    "get_token",
}

DESTRUCTIVE_TOOLS = {
    "delete_all",
    "purge_data",
    "wipe_storage",
    "factory_reset",
    "destroy_resource",
    "terminate_instance",
    "drop_table",
    "drop_database",
    "truncate_table",
}

AUDIT_TOOLS = {
    "delete_log",
    "modify_log",
    "clear_audit",
    "truncate_logs",
}

PERMISSION_TOOLS = {
    "modify_permissions",
    "grant_access",
    "revoke_access",
    "change_role",
    "add_user",
    "delete_user",
}

FINANCIAL_TOOLS = {
    "process_payment",
    "transfer_funds",
    "issue_refund",
    "modify_billing",
    "create_invoice",
    "authorize_payment",
}

ESCALATION_TOOLS = {
    "sudo",
    "run_as_admin",
    "elevate_privileges",
    "assume_role",
}


def _build_default_rules(internal_domains: set[str] | None = None) -> list[LocalRule]:
    """Build default rules with configurable internal domains."""
    domains = internal_domains or {"company.com", "internal.io"}
    return list(_BUILTIN_LOCAL_RULES_TEMPLATE(domains))


def _BUILTIN_LOCAL_RULES_TEMPLATE(domains: set[str]) -> list[LocalRule]:
    """Generate rules with the given internal domains."""
    return [
        # --- BLOCK rules (external/untrusted context) ---
        LocalRule(
            name="no_send_external",
            description="Block send operations in external data context",
            check=lambda tc, ctx: _is_external(ctx) and tc.name in SEND_TOOLS,
            action=Decision.BLOCK,
            reason="Send operations blocked during external data processing",
        ),
        LocalRule(
            name="no_code_exec_external",
            description="Block code execution in external data context",
            check=lambda tc, ctx: _is_external(ctx) and tc.name in CODE_EXEC_TOOLS,
            action=Decision.BLOCK,
            reason="Code execution blocked during external data processing",
        ),
        LocalRule(
            name="no_fs_write_untrusted",
            description="Block file writes in untrusted context",
            check=lambda tc, ctx: _is_untrusted(ctx) and tc.name in FS_WRITE_TOOLS,
            action=Decision.BLOCK,
            reason="File writes blocked in untrusted context",
        ),
        LocalRule(
            name="no_network_untrusted",
            description="Block network calls in untrusted context",
            check=lambda tc, ctx: _is_untrusted(ctx) and tc.name in NETWORK_TOOLS,
            action=Decision.BLOCK,
            reason="Network operations blocked in untrusted context",
        ),
        LocalRule(
            name="no_secrets_external",
            description="Block secret access in external context",
            check=lambda tc, ctx: _is_external(ctx) and tc.name in SECRET_TOOLS,
            action=Decision.BLOCK,
            reason="Secret access blocked during external data processing",
        ),
        LocalRule(
            name="no_data_destruction",
            description="Block data destruction operations",
            check=lambda tc, ctx: tc.name in DESTRUCTIVE_TOOLS,
            action=Decision.BLOCK,
            reason="Data destruction requires explicit authorization",
        ),
        LocalRule(
            name="no_audit_tampering",
            description="Block audit log modification",
            check=lambda tc, ctx: tc.name in AUDIT_TOOLS,
            action=Decision.BLOCK,
            reason="Audit log modification is prohibited",
        ),
        LocalRule(
            name="no_escalation_external",
            description="Block privilege escalation from external context",
            check=lambda tc, ctx: _is_external(ctx) and tc.name in ESCALATION_TOOLS,
            action=Decision.BLOCK,
            reason="Privilege escalation blocked in external context",
        ),
        LocalRule(
            name="no_cross_system_transfer",
            description="Block cross-system data transfer in external context",
            check=lambda tc, ctx: (
                _is_external(ctx) and tc.name in {"upload_file", "sync_data", "transfer_data", "copy_to_external"}
            ),
            action=Decision.BLOCK,
            reason="Cross-system data transfer blocked in external context",
        ),
        # --- Pattern-based injection detection (runs before CONFIRM rules) ---
        LocalRule(
            name="detect_injection_in_params",
            description="Detect common prompt injection patterns in tool parameters",
            check=lambda tc, ctx: _has_injection_pattern(tc.params),
            action=Decision.BLOCK,
            reason="Potential prompt injection detected in tool parameters",
        ),
        # --- REQUIRE_CONFIRMATION rules ---
        LocalRule(
            name="confirm_permissions",
            description="Confirm permission changes",
            check=lambda tc, ctx: tc.name in PERMISSION_TOOLS,
            action=Decision.REQUIRE_CONFIRMATION,
            reason="Permission modification requires confirmation",
        ),
        LocalRule(
            name="confirm_financial",
            description="Confirm financial operations",
            check=lambda tc, ctx: tc.name in FINANCIAL_TOOLS,
            action=Decision.REQUIRE_CONFIRMATION,
            reason="Financial operation requires confirmation",
        ),
        LocalRule(
            name="confirm_external_email",
            description="Confirm external email recipients",
            check=lambda tc, ctx, d=domains: (
                tc.name == "send_email"
                and "@" in tc.params.get("to", "")
                and tc.params.get("to", "").split("@")[1].lower() not in d
            ),
            action=Decision.REQUIRE_CONFIRMATION,
            reason="External email recipient requires confirmation",
        ),
    ]


# Keep a module-level reference for backward compat
BUILTIN_LOCAL_RULES: list[LocalRule] = _build_default_rules()


_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|rules|prompts)", re.IGNORECASE),
    re.compile(r"(system|admin)\s*(prompt|instruction|override|command)\s*:", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an|the)\s+", re.IGNORECASE),
    re.compile(r"do\s+not\s+mention\s+this\s+to\s+the\s+user", re.IGNORECASE),
    re.compile(r"IMPORTANT\s*:?\s*(SYSTEM|ADMIN|OVERRIDE)", re.IGNORECASE),
    re.compile(r"<\s*(system|admin|instruction)\s*>", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all|your)\s+(you|instructions|rules)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"act\s+as\s+(if|though)\s+you\s+(are|were)", re.IGNORECASE),
]


def _has_injection_pattern(params: dict) -> bool:
    """Scan tool parameters for common prompt injection patterns."""
    for value in params.values():
        if not isinstance(value, str):
            continue
        if len(value) > 10000:
            continue  # Skip very large values to prevent ReDoS
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(value):
                return True
    return False


# ─── Anomaly Scoring (lightweight, embedded) ──────────────────────────


def _compute_anomaly_score(tool_call: ToolCall, ctx: RuleContext) -> float:
    """Simple anomaly scoring without ML. Returns 0.0 - 1.0."""
    score = 0.0

    # Sensitive tool at low trust
    sensitive_tools = SEND_TOOLS | CODE_EXEC_TOOLS | FS_WRITE_TOOLS | NETWORK_TOOLS
    if tool_call.name in sensitive_tools and ctx.trust_level <= TrustLevel.EXTERNAL:
        score += 0.4

    # Rapid repetition
    if len(ctx.tool_history) >= 5:
        last_5 = ctx.tool_history[-5:]
        if all(t == tool_call.name for t in last_5):
            score += 0.3

    # Suspicious parameter patterns (long strings, URLs, etc.)
    for v in tool_call.params.values():
        if isinstance(v, str):
            if len(v) > 5000:
                score += 0.2
            if "http" in v and ctx.trust_level <= TrustLevel.EXTERNAL:
                score += 0.1

    return min(1.0, score)


# ─── LocalShield ──────────────────────────────────────────────────────


class LocalShield:
    """
    Zero-dependency local security guard. No server required.

    Embeds the rule engine and anomaly scoring directly. Provides
    the same @shield.guard decorator and session API as the full Shield.

    Limitations vs full Shield:
    - No LLM-based semantic checking (Layer 3)
    - No persistent audit trail (in-memory only)
    - No Merkle hash chain
    - No server-side trust computation (client sets trust)

    For production use with full capabilities, use Shield() with a server.
    """

    def __init__(
        self,
        *,
        trust_level: str = "VERIFIED",
        rules: list[LocalRule] | None = None,
        anomaly_threshold: float = 0.7,
        confirm_callback: Callable[[str, dict], Coroutine[Any, Any, bool]] | None = None,
        sync_confirm_callback: Callable[[str, dict], bool] | None = None,
        internal_domains: list[str] | None = None,
    ) -> None:
        self._trust_level = TrustLevel[trust_level]
        self._anomaly_threshold = anomaly_threshold
        self._confirm_callback = confirm_callback
        self._sync_confirm_callback = sync_confirm_callback
        self._tool_history: list[str] = []
        self._intent: str = ""
        self._decisions: list[dict] = []

        # Configurable internal domains (used by confirm_external_email rule)
        domains = set(internal_domains or ["company.com", "internal.io"])
        if rules is not None:
            self._rules = rules
        else:
            self._rules = _build_default_rules(domains)

    # --- Trust level control ---

    def set_trust(self, level: str) -> None:
        """Set the current data trust level.

        Call this when the agent starts processing external data:

            shield.set_trust("EXTERNAL")
            # ... process emails ...
            shield.set_trust("VERIFIED")  # back to normal
        """
        self._trust_level = TrustLevel[level]

    @property
    def trust_level(self) -> str:
        return self._trust_level.name

    # --- Intent ---

    def set_intent(self, intent: str) -> None:
        """Set the current user intent for context-aware checks."""
        self._intent = intent

    # --- Core check ---

    def check(self, tool_name: str, params: dict | None = None) -> CheckResult:
        """Check a tool call against local rules and anomaly scoring.

        Returns a CheckResult with action = ALLOW / BLOCK / REQUIRE_CONFIRMATION.
        """
        tc = ToolCall(name=tool_name, params=params or {})
        ctx = RuleContext(
            trust_level=self._trust_level,
            intent=self._intent,
            tool_history=self._tool_history,
        )

        # Layer 1: Rule engine
        for rule in self._rules:
            try:
                if rule.check(tc, ctx):
                    result = CheckResult(
                        action=rule.action,
                        reason=rule.reason,
                        trace_id=str(uuid.uuid4()),
                    )
                    self._record(tool_name, result)
                    return result
            except Exception:
                continue

        # Layer 2: Anomaly scoring
        score = _compute_anomaly_score(tc, ctx)
        if score >= self._anomaly_threshold:
            result = CheckResult(
                action=Decision.BLOCK,
                reason=f"Anomaly score {score:.2f} exceeds threshold {self._anomaly_threshold}",
                trace_id=str(uuid.uuid4()),
            )
            self._record(tool_name, result)
            return result

        # All clear
        result = CheckResult(action=Decision.ALLOW, trace_id=str(uuid.uuid4()))
        self._record(tool_name, result)
        return result

    # --- Guard decorator ---

    def guard(
        self,
        func: Any | None = None,
        *,
        tool_name: str | None = None,
    ) -> Any:
        """Decorator that checks every call against local security rules.

        Works with both sync and async functions::

            @shield.guard
            def send_email(to: str, body: str) -> str:
                ...

            @shield.guard
            async def read_inbox(limit: int = 10) -> list:
                ...
        """

        def decorator(fn: Any) -> Any:
            resolved_name = tool_name or fn.__name__

            if inspect.iscoroutinefunction(fn):
                # Async function
                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    await self._enforce_async(resolved_name, fn, args, kwargs)
                    return await fn(*args, **kwargs)

                return async_wrapper
            else:
                # Sync function
                @functools.wraps(fn)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                    self._enforce(resolved_name, fn, args, kwargs)
                    return fn(*args, **kwargs)

                return sync_wrapper

        if func is not None:
            return decorator(func)
        return decorator

    async def _enforce_async(self, tool_name: str, fn: Any, args: tuple, kwargs: dict) -> None:
        """Async version of _enforce — properly awaits async confirm callbacks."""
        sig = inspect.signature(fn)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        params = dict(bound.arguments)

        result = self.check(tool_name, params)

        if result.action is Decision.BLOCK:
            raise ToolCallBlocked(
                tool=tool_name,
                reason=result.reason,
                trace_id=result.trace_id,
            )

        if result.action is Decision.REQUIRE_CONFIRMATION:
            if self._confirm_callback is not None:
                confirmed = await self._confirm_callback(tool_name, params)
                if not confirmed:
                    raise ConfirmationRejected(tool=tool_name)
                return
            if self._sync_confirm_callback is not None:
                if not self._sync_confirm_callback(tool_name, params):
                    raise ConfirmationRejected(tool=tool_name)
                return
            raise ConfirmationRejected(tool=tool_name)

    def _enforce(self, tool_name: str, fn: Any, args: tuple, kwargs: dict) -> None:
        """Run security check and raise on BLOCK/CONFIRM. Used by guard()."""
        sig = inspect.signature(fn)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        params = dict(bound.arguments)

        result = self.check(tool_name, params)

        if result.action is Decision.BLOCK:
            raise ToolCallBlocked(
                tool=tool_name,
                reason=result.reason,
                trace_id=result.trace_id,
            )

        if result.action is Decision.REQUIRE_CONFIRMATION:
            # Try sync callback first, then async
            if self._sync_confirm_callback is not None:
                if not self._sync_confirm_callback(tool_name, params):
                    raise ConfirmationRejected(tool=tool_name)
                return
            if self._confirm_callback is not None:
                import asyncio

                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None
                if loop and loop.is_running():
                    # We're in an async context — caller should use async guard
                    raise ConfirmationRejected(tool=tool_name)
                else:
                    confirmed = asyncio.run(self._confirm_callback(tool_name, params))
                    if not confirmed:
                        raise ConfirmationRejected(tool=tool_name)
                return
            raise ConfirmationRejected(tool=tool_name)

    # --- Rules management ---

    def add_rule(self, rule: LocalRule) -> None:
        """Add a custom rule."""
        self._rules.insert(0, rule)  # Custom rules take priority

    def disable_rule(self, name: str) -> bool:
        """Disable a rule by name."""
        self._rules = [r for r in self._rules if r.name != name]
        return True

    def list_rules(self) -> list[str]:
        """List active rule names."""
        return [r.name for r in self._rules]

    # --- Audit (in-memory) ---

    def _record(self, tool_name: str, result: CheckResult) -> None:
        self._tool_history.append(tool_name)
        self._decisions.append(
            {
                "timestamp": time.time(),
                "tool": tool_name,
                "action": result.action.value,
                "reason": result.reason,
                "trust_level": self._trust_level.name,
                "trace_id": result.trace_id,
            }
        )

    @property
    def audit_log(self) -> list[dict]:
        """In-memory audit log of all decisions."""
        return list(self._decisions)

    @property
    def stats(self) -> dict:
        """Decision statistics."""
        total = len(self._decisions)
        blocked = sum(1 for d in self._decisions if d["action"] == "BLOCK")
        confirmed = sum(1 for d in self._decisions if d["action"] == "REQUIRE_CONFIRMATION")
        return {
            "total_checks": total,
            "allowed": total - blocked - confirmed,
            "blocked": blocked,
            "confirmation_required": confirmed,
            "active_rules": len(self._rules),
            "trust_level": self._trust_level.name,
        }

    def reset(self) -> None:
        """Reset history and audit log."""
        self._tool_history.clear()
        self._decisions.clear()

    # --- YAML rule loading ---

    def load_rules_yaml(self, yaml_str: str) -> int:
        """Load custom rules from a YAML string.

        Returns the number of rules loaded.

        YAML format::

            rules:
              - name: block_competitor
                tool: send_email
                param_match:
                  to: ".*@competitor\\.com$"
                action: BLOCK
                reason: "Competitor domain blocked"

              - name: confirm_large_query
                tool: query_database
                param_gt:
                  limit: 100
                action: REQUIRE_CONFIRMATION
                reason: "Large query needs approval"
        """
        import yaml

        data = yaml.safe_load(yaml_str)
        rules_data = data.get("rules", [])
        count = 0
        for rd in rules_data:
            rule = _parse_yaml_rule(rd)
            if rule:
                self._rules.insert(0, rule)
                count += 1
        return count

    def load_rules_file(self, path: str) -> int:
        """Load custom rules from a YAML file. Returns count loaded."""
        with open(path) as f:
            return self.load_rules_yaml(f.read())


def _parse_yaml_rule(rd: dict) -> LocalRule | None:
    """Parse a single YAML rule definition into a LocalRule."""
    name = rd.get("name", "")
    if not name:
        return None

    action_str = rd.get("action", "BLOCK").upper()
    action_map = {
        "BLOCK": Decision.BLOCK,
        "REQUIRE_CONFIRMATION": Decision.REQUIRE_CONFIRMATION,
        "ALLOW": Decision.ALLOW,
    }
    action = action_map.get(action_str, Decision.BLOCK)
    reason = rd.get("reason", f"Rule '{name}' triggered")

    # Build check function from YAML fields
    tool_name = rd.get("tool")
    tool_names = rd.get("tools")
    param_match = rd.get("param_match", {})
    param_contains = rd.get("param_contains", {})
    param_gt = rd.get("param_gt", {})
    param_lt = rd.get("param_lt", {})
    trust_levels = rd.get("trust_level", [])
    if isinstance(trust_levels, str):
        trust_levels = [trust_levels]

    trust_values = set()
    for tl in trust_levels:
        try:
            trust_values.add(TrustLevel[tl])
        except KeyError:
            pass

    def check_fn(
        tc: ToolCall,
        ctx: RuleContext,
        _tool=tool_name,
        _tools=set(tool_names) if tool_names else None,
        _pm=param_match,
        _pc=param_contains,
        _pgt=param_gt,
        _plt=param_lt,
        _tv=trust_values,
    ) -> bool:
        # Tool name filter
        if _tool and tc.name != _tool:
            return False
        if _tools and tc.name not in _tools:
            return False
        # Trust level filter
        if _tv and ctx.trust_level not in _tv:
            return False
        # Param regex match
        for key, pattern in _pm.items():
            val = str(tc.params.get(key, ""))
            if not re.search(pattern, val):
                return False
        # Param contains
        for key, substr in _pc.items():
            val = str(tc.params.get(key, ""))
            if substr not in val:
                return False
        # Param greater than
        for key, threshold in _pgt.items():
            val = tc.params.get(key, 0)
            if not isinstance(val, (int, float)) or val <= threshold:
                return False
        # Param less than
        for key, threshold in _plt.items():
            val = tc.params.get(key, 0)
            if not isinstance(val, (int, float)) or val >= threshold:
                return False
        return True

    return LocalRule(
        name=name,
        description=rd.get("description", ""),
        check=check_fn,
        action=action,
        reason=reason,
    )
