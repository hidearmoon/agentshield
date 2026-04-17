"""Tests for EU AI Act compliance module."""

import json

import pytest

from agentshield_core.compliance.eu_ai_act import (
    ComplianceReportGenerator,
    RiskLevel,
    RiskAssessmentRecord,
)


@pytest.fixture
def generator():
    return ComplianceReportGenerator()


@pytest.fixture
def populated_generator():
    gen = ComplianceReportGenerator()
    # Record some decisions
    for i in range(5):
        gen.record_decision(
            session_id=f"sess-{i}",
            agent_id="test-agent",
            tool_name="send_email" if i % 2 == 0 else "read_inbox",
            tool_params_hash=f"hash-{i}",
            data_source="email/external",
            trust_level="EXTERNAL",
            decision="ALLOW" if i < 3 else "BLOCK",
            decision_engine="rule" if i < 3 else "anomaly",
            decision_reason="" if i < 3 else "Anomaly detected",
            intent_drift_score=0.1 * i,
            trace_id=f"trace-{i}",
            span_id=f"span-{i}",
            merkle_hash=f"merkle-{i}",
            latency_ms=1.5 + i,
        )
    # Record human oversight events
    gen.record_human_oversight(
        intervention_type="override",
        original_decision="BLOCK",
        human_decision="ALLOW",
        operator_id="operator-001",
        reason="False positive — approved after review",
        session_id="sess-3",
        tool_name="send_email",
    )
    gen.record_human_oversight(
        intervention_type="approve",
        original_decision="REQUIRE_CONFIRMATION",
        human_decision="ALLOW",
        operator_id="operator-002",
        reason="Reviewed and approved",
    )
    # Risk assessment
    gen.add_risk_assessment(RiskAssessmentRecord(
        risk_level=RiskLevel.HIGH.value,
        system_description="AI agent email processing pipeline",
        intended_purpose="Automate email summarization and draft replies",
        known_risks=["prompt injection via email body", "data exfiltration"],
        mitigation_measures=["trust-aware data flow", "intent consistency detection", "two-phase call architecture"],
        residual_risks=["novel zero-day injection techniques"],
        testing_methodology="92 security tests including fuzz testing",
        test_results_summary="All 342 tests passing, 85%+ coverage",
    ))
    return gen


class TestRecordCollection:
    def test_record_decision(self, generator):
        entry = generator.record_decision(
            session_id="s1", agent_id="a1", tool_name="tool1",
            tool_params_hash="h1", data_source="user_input",
            trust_level="VERIFIED", decision="ALLOW",
            decision_engine="rule", decision_reason="",
            intent_drift_score=0.0, trace_id="t1", span_id="sp1",
            merkle_hash="m1", latency_ms=2.0,
        )
        assert entry.entry_id
        assert entry.timestamp
        assert entry.tool_name == "tool1"
        assert generator.stats["total_audit_records"] == 1

    def test_record_human_oversight(self, generator):
        event = generator.record_human_oversight(
            intervention_type="override",
            original_decision="BLOCK",
            human_decision="ALLOW",
            operator_id="op1",
            reason="False positive",
        )
        assert event.event_id
        assert event.intervention_type == "override"
        assert generator.stats["total_oversight_events"] == 1

    def test_add_risk_assessment(self, generator):
        record = RiskAssessmentRecord(
            risk_level="high",
            system_description="test system",
        )
        generator.add_risk_assessment(record)
        assert generator.stats["total_risk_assessments"] == 1


class TestReportGeneration:
    def test_full_report_structure(self, populated_generator):
        report = populated_generator.generate_full_report(
            system_name="AgentShield",
            system_version="1.0.0",
            operator_name="Test Corp",
            intended_purpose="AI agent security",
            risk_level=RiskLevel.HIGH,
        )

        # Check top-level sections exist
        assert "report_metadata" in report
        assert "system_identification" in report
        assert "article_9_risk_management" in report
        assert "article_12_record_keeping" in report
        assert "article_14_human_oversight" in report
        assert "article_17_quality_management" in report

    def test_report_metadata(self, populated_generator):
        report = populated_generator.generate_full_report()
        meta = report["report_metadata"]
        assert meta["regulation"] == "EU AI Act (Regulation 2024/1776)"
        assert meta["report_type"] == "conformity_self_assessment"
        assert meta["report_id"]

    def test_article_12_statistics(self, populated_generator):
        report = populated_generator.generate_full_report()
        a12 = report["article_12_record_keeping"]
        assert a12["total_records"] == 5
        assert a12["summary"]["allowed"] == 3
        assert a12["summary"]["blocked"] == 2
        assert len(a12["records"]) == 5

    def test_article_14_oversight(self, populated_generator):
        report = populated_generator.generate_full_report()
        a14 = report["article_14_human_oversight"]
        assert a14["total_interventions"] == 2
        assert "override" in a14["intervention_types"]
        assert a14["capabilities"]["real_time_monitoring"] is True
        assert a14["capabilities"]["stop_capability"] is True

    def test_article_9_risk_management(self, populated_generator):
        report = populated_generator.generate_full_report()
        a9 = report["article_9_risk_management"]
        assert len(a9["assessments"]) == 1
        assert a9["mitigation_summary"]["builtin_rules"] == 22

    def test_report_is_json_serializable(self, populated_generator):
        report = populated_generator.generate_full_report()
        serialized = json.dumps(report)
        assert len(serialized) > 0
        roundtrip = json.loads(serialized)
        assert roundtrip["article_12_record_keeping"]["total_records"] == 5


class TestExportFormats:
    def test_audit_log_jsonl(self, populated_generator):
        jsonl = populated_generator.export_audit_log_jsonl()
        lines = jsonl.strip().split("\n")
        assert len(lines) == 5
        # Each line is valid JSON
        for line in lines:
            parsed = json.loads(line)
            assert "entry_id" in parsed
            assert "tool_name" in parsed

    def test_oversight_log_jsonl(self, populated_generator):
        jsonl = populated_generator.export_oversight_log_jsonl()
        lines = jsonl.strip().split("\n")
        assert len(lines) == 2
        parsed = json.loads(lines[0])
        assert parsed["intervention_type"] == "override"

    def test_empty_generator_exports(self, generator):
        report = generator.generate_full_report()
        assert report["article_12_record_keeping"]["total_records"] == 0
        assert report["article_14_human_oversight"]["total_interventions"] == 0
        jsonl = generator.export_audit_log_jsonl()
        assert jsonl == ""
