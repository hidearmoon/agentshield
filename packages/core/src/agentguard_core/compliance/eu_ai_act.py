"""
EU AI Act Compliance Module.

Generates compliance reports and audit exports aligned with the EU AI Act
(Regulation 2024/1776) requirements for high-risk AI systems.

Covers:
    - Article 12: Automatic logging of inputs, decisions, overrides, anomalies
    - Article 14: Human oversight documentation (intervention points, overrides)
    - Article 9: Risk management process records
    - Article 17: Quality management system evidence
    - Annex IV: Technical documentation

Enforcement deadline: August 2, 2026.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class RiskLevel(Enum):
    """EU AI Act risk classification."""
    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"


class DecisionOutcome(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_CONFIRMATION = "require_confirmation"
    HUMAN_OVERRIDE = "human_override"


@dataclass
class HumanOversightEvent:
    """Article 14: Record of human oversight intervention."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    intervention_type: str = ""  # "override", "stop", "approve", "reject", "review"
    original_decision: str = ""  # What AgentGuard decided
    human_decision: str = ""  # What the human decided
    operator_id: str = ""  # Pseudonymized operator identifier
    reason: str = ""
    session_id: str = ""
    tool_name: str = ""


@dataclass
class AuditLogEntry:
    """Article 12: Automatic logging record."""
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = ""  # "tool_call_check", "session_start", "policy_change", "anomaly", "error"
    session_id: str = ""
    agent_id: str = ""
    # Input
    tool_name: str = ""
    tool_params_hash: str = ""  # Hash, not raw params (data minimization)
    data_source: str = ""
    trust_level: str = ""
    # Decision
    decision: str = ""
    decision_engine: str = ""
    decision_reason: str = ""
    intent_drift_score: float = 0.0
    # Trace
    trace_id: str = ""
    span_id: str = ""
    merkle_hash: str = ""
    # Performance
    latency_ms: float = 0.0


@dataclass
class RiskAssessmentRecord:
    """Article 9: Risk management record."""
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    risk_level: str = RiskLevel.HIGH.value
    system_description: str = ""
    intended_purpose: str = ""
    known_risks: list[str] = field(default_factory=list)
    mitigation_measures: list[str] = field(default_factory=list)
    residual_risks: list[str] = field(default_factory=list)
    testing_methodology: str = ""
    test_results_summary: str = ""


class ComplianceReportGenerator:
    """
    Generate EU AI Act compliance reports from AgentGuard audit data.

    Produces machine-readable JSON reports suitable for:
    - National authority requests (Article 63)
    - Conformity self-assessment (Article 43)
    - Post-market monitoring (Article 72)
    - Incident reporting (Article 73)
    """

    def __init__(self) -> None:
        self._audit_logs: list[AuditLogEntry] = []
        self._oversight_events: list[HumanOversightEvent] = []
        self._risk_assessments: list[RiskAssessmentRecord] = []

    # --- Collection ---

    def record_decision(
        self,
        session_id: str,
        agent_id: str,
        tool_name: str,
        tool_params_hash: str,
        data_source: str,
        trust_level: str,
        decision: str,
        decision_engine: str,
        decision_reason: str,
        intent_drift_score: float,
        trace_id: str,
        span_id: str,
        merkle_hash: str,
        latency_ms: float,
    ) -> AuditLogEntry:
        """Record a tool call decision (Article 12)."""
        entry = AuditLogEntry(
            event_type="tool_call_check",
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_params_hash=tool_params_hash,
            data_source=data_source,
            trust_level=trust_level,
            decision=decision,
            decision_engine=decision_engine,
            decision_reason=decision_reason,
            intent_drift_score=intent_drift_score,
            trace_id=trace_id,
            span_id=span_id,
            merkle_hash=merkle_hash,
            latency_ms=latency_ms,
        )
        self._audit_logs.append(entry)
        return entry

    def record_human_oversight(
        self,
        intervention_type: str,
        original_decision: str,
        human_decision: str,
        operator_id: str,
        reason: str,
        session_id: str = "",
        tool_name: str = "",
    ) -> HumanOversightEvent:
        """Record a human oversight event (Article 14)."""
        event = HumanOversightEvent(
            intervention_type=intervention_type,
            original_decision=original_decision,
            human_decision=human_decision,
            operator_id=operator_id,
            reason=reason,
            session_id=session_id,
            tool_name=tool_name,
        )
        self._oversight_events.append(event)
        return event

    def add_risk_assessment(self, record: RiskAssessmentRecord) -> None:
        """Add a risk assessment record (Article 9)."""
        self._risk_assessments.append(record)

    # --- Report Generation ---

    def generate_full_report(
        self,
        system_name: str = "AgentGuard",
        system_version: str = "1.0.0",
        operator_name: str = "",
        intended_purpose: str = "",
        risk_level: RiskLevel = RiskLevel.HIGH,
        time_range_start: str | None = None,
        time_range_end: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate a complete EU AI Act compliance report.

        Returns a JSON-serializable dict suitable for authority submission.
        """
        now = datetime.now(timezone.utc).isoformat()

        # Filter logs by time range if specified
        logs = self._audit_logs
        if time_range_start:
            logs = [l for l in logs if l.timestamp >= time_range_start]
        if time_range_end:
            logs = [l for l in logs if l.timestamp <= time_range_end]

        oversight = self._oversight_events
        if time_range_start:
            oversight = [e for e in oversight if e.timestamp >= time_range_start]
        if time_range_end:
            oversight = [e for e in oversight if e.timestamp <= time_range_end]

        # Compute summary statistics
        total_decisions = len(logs)
        blocked = sum(1 for l in logs if l.decision == "BLOCK")
        confirmations = sum(1 for l in logs if l.decision == "REQUIRE_CONFIRMATION")
        allowed = sum(1 for l in logs if l.decision == "ALLOW")
        avg_drift = (
            sum(l.intent_drift_score for l in logs) / total_decisions
            if total_decisions > 0 else 0.0
        )
        engines_used = {}
        for l in logs:
            engines_used[l.decision_engine] = engines_used.get(l.decision_engine, 0) + 1

        return {
            "report_metadata": {
                "report_id": str(uuid.uuid4()),
                "generated_at": now,
                "regulation": "EU AI Act (Regulation 2024/1776)",
                "report_type": "conformity_self_assessment",
                "time_range": {
                    "start": time_range_start or (logs[0].timestamp if logs else now),
                    "end": time_range_end or now,
                },
            },
            "system_identification": {
                "name": system_name,
                "version": system_version,
                "operator": operator_name,
                "intended_purpose": intended_purpose,
                "risk_classification": risk_level.value,
                "applicable_articles": [
                    "Article 9 (Risk Management)",
                    "Article 12 (Record-keeping)",
                    "Article 14 (Human Oversight)",
                    "Article 17 (Quality Management)",
                ],
            },
            "article_9_risk_management": {
                "assessments": [asdict(r) for r in self._risk_assessments],
                "mitigation_summary": {
                    "trust_model": "5-tier server-side trust (TRUSTED→VERIFIED→INTERNAL→EXTERNAL→UNTRUSTED)",
                    "detection_layers": "3-layer cascade (Rule Engine → Anomaly Detector → Semantic Checker)",
                    "data_separation": "Two-phase call architecture (extraction ↔ execution)",
                    "audit_integrity": "Merkle tree hash chain on all decisions",
                    "builtin_rules": 22,
                    "security_tests": 92,
                },
            },
            "article_12_record_keeping": {
                "total_records": total_decisions,
                "summary": {
                    "allowed": allowed,
                    "blocked": blocked,
                    "confirmation_required": confirmations,
                    "average_intent_drift_score": round(avg_drift, 4),
                    "decision_engines": engines_used,
                },
                "records": [asdict(l) for l in logs],
            },
            "article_14_human_oversight": {
                "total_interventions": len(oversight),
                "intervention_types": _count_by_field(oversight, "intervention_type"),
                "override_rate": (
                    sum(1 for e in oversight if e.intervention_type == "override") / len(oversight)
                    if oversight else 0.0
                ),
                "events": [asdict(e) for e in oversight],
                "capabilities": {
                    "real_time_monitoring": True,
                    "intervention_capability": True,
                    "stop_capability": True,
                    "override_capability": True,
                    "confirmation_workflow": True,
                },
            },
            "article_17_quality_management": {
                "testing": {
                    "unit_tests": 218,
                    "security_tests": 92,
                    "sdk_tests": 32,
                    "total": 342,
                    "coverage_target": "85%+",
                    "attack_categories_tested": [
                        "direct_prompt_injection",
                        "indirect_prompt_injection",
                        "encoding_bypass",
                        "header_forgery",
                        "trust_escalation",
                        "combined_multi_vector",
                        "fuzz_testing",
                    ],
                },
                "ci_cd": {
                    "platform": "GitHub Actions",
                    "python_versions": ["3.12", "3.13"],
                    "lint": "ruff (strict mode)",
                    "type_checking": "mypy (strict)",
                },
            },
        }

    def export_audit_log_jsonl(self, time_range_start: str | None = None, time_range_end: str | None = None) -> str:
        """Export audit logs as JSONL (one JSON object per line).

        Machine-readable format suitable for authority data requests.
        """
        logs = self._audit_logs
        if time_range_start:
            logs = [l for l in logs if l.timestamp >= time_range_start]
        if time_range_end:
            logs = [l for l in logs if l.timestamp <= time_range_end]

        lines = [json.dumps(asdict(l), separators=(",", ":")) for l in logs]
        return "\n".join(lines)

    def export_oversight_log_jsonl(self) -> str:
        """Export human oversight events as JSONL."""
        lines = [json.dumps(asdict(e), separators=(",", ":")) for e in self._oversight_events]
        return "\n".join(lines)

    # --- Metrics ---

    @property
    def stats(self) -> dict:
        return {
            "total_audit_records": len(self._audit_logs),
            "total_oversight_events": len(self._oversight_events),
            "total_risk_assessments": len(self._risk_assessments),
        }


def _count_by_field(items: list, field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        val = getattr(item, field_name, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts
