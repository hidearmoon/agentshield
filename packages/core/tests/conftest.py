"""Shared test fixtures."""

from __future__ import annotations

import pytest

from agentguard_core.engine.trust.levels import TrustLevel
from agentguard_core.engine.trust.marker import TrustMarker, TrustPolicy
from agentguard_core.engine.intent.models import IntentContext, Intent
from agentguard_core.engine.intent.rule_engine import RuleEngine
from agentguard_core.engine.intent.anomaly import AnomalyDetector
from agentguard_core.engine.trace.merkle import MerkleChain
from agentguard_core.engine.sanitization.format_cleansing import FormatCleansingStage
from agentguard_core.engine.sanitization.pipeline import DataSanitizationPipeline
from agentguard_core.schemas.registry import SchemaRegistry


@pytest.fixture
def trust_marker() -> TrustMarker:
    return TrustMarker(TrustPolicy())


@pytest.fixture
def rule_engine() -> RuleEngine:
    return RuleEngine()


@pytest.fixture
def anomaly_detector() -> AnomalyDetector:
    return AnomalyDetector()


@pytest.fixture
def merkle_chain() -> MerkleChain:
    return MerkleChain()


@pytest.fixture
def format_cleansing() -> FormatCleansingStage:
    return FormatCleansingStage()


@pytest.fixture
def schema_registry() -> SchemaRegistry:
    return SchemaRegistry.create_default()


@pytest.fixture
def sanitization_pipeline(format_cleansing: FormatCleansingStage) -> DataSanitizationPipeline:
    return DataSanitizationPipeline(stages=[format_cleansing])


@pytest.fixture
def email_intent_context() -> IntentContext:
    return IntentContext(
        original_message="帮我总结今天的邮件",
        intent=Intent(
            intent="summarize emails",
            expected_tools=["read_email", "summarize"],
            sensitive_data_involved=False,
        ),
        allowed_tool_categories=["read", "summarize"],
        current_data_trust_level=TrustLevel.EXTERNAL,
    )
