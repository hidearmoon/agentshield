"""Layer 1: Rule-based detection — fast, deterministic, millisecond-level."""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass
from typing import Callable

from agentguard_core.engine.intent.models import (
    Decision,
    IntentContext,
    RuleResult,
    ToolCall,
)

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    name: str
    description: str
    condition: Callable[[ToolCall, IntentContext], bool]
    decision: Decision
    enabled: bool = True
    priority: int = 0  # Higher priority rules are checked first


class RuleEngine:
    """Layer 1: Rule-based detection. Fast, deterministic."""

    def __init__(self, rules: list[Rule] | None = None):
        if rules is not None:
            self._rules = list(rules)
        else:
            self._rules = [copy.copy(r) for r in BUILTIN_RULES]
        self._sort_rules()

    def _sort_rules(self) -> None:
        """Sort rules by priority descending. Called after any mutation."""
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def add_rule(self, rule: Rule) -> None:
        self._rules.append(rule)
        self._sort_rules()

    def add_rules(self, rules: list[Rule]) -> None:
        self._rules.extend(rules)
        self._sort_rules()

    def remove_rule(self, name: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.name != name]
        return len(self._rules) < before

    def list_rules(self) -> list[dict]:
        builtin_names = {r.name for r in BUILTIN_RULES}
        return [
            {
                "name": r.name,
                "description": r.description,
                "enabled": r.enabled,
                "type": "builtin" if r.name in builtin_names else "custom",
            }
            for r in self._rules
        ]

    def set_rule_enabled(self, name: str, enabled: bool) -> bool:
        for r in self._rules:
            if r.name == name:
                r.enabled = enabled
                return True
        return False

    def check(self, tool_call: ToolCall, context: IntentContext) -> RuleResult:
        # Rules are pre-sorted by priority (highest first) via _sort_rules().
        for rule in self._rules:
            if not rule.enabled:
                continue
            try:
                if rule.condition(tool_call, context):
                    return RuleResult(
                        is_definitive=True,
                        decision=rule.decision,
                        triggered=True,
                        rule_name=rule.name,
                    )
            except Exception:  # noqa: S112
                logger.debug("Rule '%s' evaluation failed, skipping", rule.name, exc_info=True)
                continue
        return RuleResult(is_definitive=False)


# ─── Built-in Rules ──────────────────────────────────────────────────────────


def _is_external_data_context(ctx: IntentContext) -> bool:
    return ctx.current_data_trust_level <= 2  # EXTERNAL or UNTRUSTED


def _is_send_operation(tc: ToolCall) -> bool:
    send_tools = {
        "send_email",
        "send_message",
        "post_message",
        "send_notification",
        "send_sms",
        "publish",
        "send_webhook",
    }
    return tc.name in send_tools or tc.tool_category == "send"


def _is_data_export(tc: ToolCall) -> bool:
    export_tools = {"query_database", "export_data", "download_file", "bulk_export", "export_csv", "export_json"}
    return tc.name in export_tools


def _is_external_email(email: str) -> bool:
    internal_domains = {"company.com", "internal.io"}  # Configurable
    if "@" in email:
        domain = email.split("@")[1].lower()
        return domain not in internal_domains
    return True


BUILTIN_RULES: list[Rule] = [
    # 1. Block send operations during external data processing
    Rule(
        name="no_send_during_external_data",
        description="Block send operations when processing external/untrusted data",
        condition=lambda tc, ctx: _is_external_data_context(ctx) and _is_send_operation(tc),
        decision=Decision.block("Send operations blocked during external data processing", "rule"),
    ),
    # 2. Large data export detection
    Rule(
        name="bulk_data_export",
        description="Require confirmation for large data exports",
        condition=lambda tc, ctx: (
            _is_data_export(tc) and tc.estimated_result_size > 100 and "export" not in ctx.intent.intent.lower()
        ),
        decision=Decision.require_confirmation("Large data export detected, confirmation required", "rule"),
    ),
    # 3. External recipient check
    Rule(
        name="external_recipient",
        description="Require confirmation for external email recipients",
        condition=lambda tc, ctx: tc.name == "send_email" and _is_external_email(tc.params.get("to", "")),
        decision=Decision.require_confirmation("External email recipient, confirmation required", "rule"),
    ),
    # 4. Tool category shift detection
    Rule(
        name="tool_category_shift",
        description="Detect when tool usage shifts away from original intent",
        condition=lambda tc, ctx: (
            len(ctx.tool_call_history) > 0
            and len(ctx.allowed_tool_categories) > 0
            and tc.tool_category != ""
            and tc.tool_category not in ctx.allowed_tool_categories
        ),
        decision=Decision.require_confirmation("Tool category shift from original intent detected", "rule"),
    ),
    # 5. Code execution in external data context
    Rule(
        name="no_code_exec_external",
        description="Block code execution when processing external data",
        condition=lambda tc, ctx: (
            _is_external_data_context(ctx)
            and tc.name in {"execute_code", "run_script", "eval", "exec_command", "run_shell"}
        ),
        decision=Decision.block("Code execution blocked during external data processing", "rule"),
    ),
    # 6. Permission modification
    Rule(
        name="permission_modification",
        description="Require confirmation for permission changes",
        condition=lambda tc, ctx: (
            tc.name
            in {
                "modify_permissions",
                "grant_access",
                "revoke_access",
                "change_role",
                "add_user",
                "delete_user",
            }
        ),
        decision=Decision.require_confirmation("Permission modification requires confirmation", "rule"),
    ),
    # 7. File system write in untrusted context
    Rule(
        name="no_fs_write_untrusted",
        description="Block file system writes in untrusted data context",
        condition=lambda tc, ctx: (
            ctx.current_data_trust_level <= 1  # UNTRUSTED
            and tc.name in {"write_file", "create_file", "delete_file", "modify_file"}
        ),
        decision=Decision.block("File system writes blocked in untrusted context", "rule"),
    ),
    # 8. Database schema modification
    Rule(
        name="db_schema_change",
        description="Block database schema changes from agent context",
        condition=lambda tc, ctx: (
            tc.name
            in {
                "alter_table",
                "drop_table",
                "create_table",
                "migrate_db",
                "truncate_table",
                "drop_database",
            }
        ),
        decision=Decision.block("Database schema changes are not allowed", "rule"),
    ),
    # 9. Rapid-fire tool calls (potential automation attack)
    Rule(
        name="rapid_fire_detection",
        description="Detect rapid successive tool calls of the same type",
        condition=lambda tc, ctx: (
            len(ctx.tool_call_history) >= 10 and all(h.name == tc.name for h in ctx.tool_call_history[-10:])
        ),
        decision=Decision.require_confirmation("Rapid repeated tool calls detected", "rule"),
    ),
    # 10. Sensitive data access
    Rule(
        name="sensitive_data_access",
        description="Require confirmation for accessing sensitive data stores",
        condition=lambda tc, ctx: tc.name in {"query_pii", "access_credentials", "read_secrets", "get_api_keys"},
        decision=Decision.require_confirmation("Sensitive data access requires confirmation", "rule"),
    ),
    # 11. Cross-system data transfer
    Rule(
        name="cross_system_transfer",
        description="Require confirmation for transferring data between systems",
        condition=lambda tc, ctx: (
            _is_external_data_context(ctx)
            and tc.name in {"upload_file", "sync_data", "transfer_data", "copy_to_external"}
        ),
        decision=Decision.block("Cross-system data transfer blocked in external context", "rule"),
    ),
    # 12. Network operations in untrusted context
    Rule(
        name="no_network_untrusted",
        description="Block outbound network calls in untrusted data context",
        condition=lambda tc, ctx: (
            ctx.current_data_trust_level <= 1 and tc.name in {"http_request", "fetch_url", "call_api", "webhook_send"}
        ),
        decision=Decision.block("Network operations blocked in untrusted context", "rule"),
    ),
    # 13. Escalation attempt detection
    Rule(
        name="escalation_attempt",
        description="Detect privilege escalation patterns",
        condition=lambda tc, ctx: (
            ctx.current_data_trust_level <= 2
            and tc.name in {"sudo", "run_as_admin", "elevate_privileges", "assume_role"}
        ),
        decision=Decision.block("Privilege escalation attempt detected", "rule"),
    ),
    # 14. Bulk user operation
    Rule(
        name="bulk_user_operation",
        description="Require confirmation for bulk user operations",
        condition=lambda tc, ctx: (
            tc.name in {"bulk_delete_users", "bulk_modify", "mass_email", "bulk_update"}
            or tc.estimated_result_size > 50
        ),
        decision=Decision.require_confirmation("Bulk operation requires confirmation", "rule"),
    ),
    # 15. Payment/financial operations
    Rule(
        name="financial_operation",
        description="Require confirmation for financial operations",
        condition=lambda tc, ctx: (
            tc.name
            in {
                "process_payment",
                "transfer_funds",
                "issue_refund",
                "modify_billing",
                "create_invoice",
                "authorize_payment",
            }
        ),
        decision=Decision.require_confirmation("Financial operation requires confirmation", "rule"),
    ),
    # 16. Agent-to-agent call with data
    Rule(
        name="agent_call_with_external_data",
        description="Block agent-to-agent calls carrying external data",
        condition=lambda tc, ctx: (
            _is_external_data_context(ctx) and tc.name in {"call_agent", "delegate_task", "forward_to_agent"}
        ),
        decision=Decision.require_confirmation("Agent delegation with external data requires confirmation", "rule"),
    ),
    # 17. Logging/audit tampering
    Rule(
        name="audit_tampering",
        description="Block any attempts to modify audit logs",
        condition=lambda tc, ctx: (
            tc.name
            in {
                "delete_log",
                "modify_log",
                "clear_audit",
                "truncate_logs",
            }
        ),
        decision=Decision.block("Audit log modification is prohibited", "rule"),
    ),
    # 18. Configuration changes
    Rule(
        name="config_change",
        description="Require confirmation for system configuration changes",
        condition=lambda tc, ctx: (
            tc.name
            in {
                "update_config",
                "modify_settings",
                "change_environment",
                "update_secrets",
                "rotate_keys",
            }
        ),
        decision=Decision.require_confirmation("Configuration change requires confirmation", "rule"),
    ),
    # 19. External API integration
    Rule(
        name="external_api_untrusted",
        description="Block external API calls in untrusted context",
        condition=lambda tc, ctx: (
            ctx.current_data_trust_level <= 1 and tc.name in {"call_external_api", "oauth_authorize", "connect_service"}
        ),
        decision=Decision.block("External API calls blocked in untrusted context", "rule"),
    ),
    # 20. Data destruction
    Rule(
        name="data_destruction",
        description="Block data destruction operations",
        condition=lambda tc, ctx: (
            tc.name
            in {
                "delete_all",
                "purge_data",
                "wipe_storage",
                "factory_reset",
                "destroy_resource",
                "terminate_instance",
            }
        ),
        decision=Decision.block("Data destruction requires explicit authorization", "rule"),
    ),
    # 21. Credential/secret access from external context
    Rule(
        name="no_secrets_external",
        description="Block secret/credential access when processing external data",
        condition=lambda tc, ctx: (
            _is_external_data_context(ctx)
            and tc.name
            in {
                "get_secret",
                "read_env",
                "get_api_key",
                "access_credentials",
                "read_secrets",
                "get_token",
            }
        ),
        decision=Decision.block("Secret access blocked during external data processing", "rule"),
        priority=1,  # Higher than default 0 to run before REQUIRE_CONFIRMATION rules
    ),
    # 22. Environment modification
    Rule(
        name="env_modification",
        description="Block environment variable modification",
        condition=lambda tc, ctx: tc.name in {"set_env", "modify_env", "update_environment"},
        decision=Decision.block("Environment modification is not allowed", "rule"),
    ),
]
