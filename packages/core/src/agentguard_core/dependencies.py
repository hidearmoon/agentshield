"""FastAPI dependency injection wiring."""

from __future__ import annotations

from functools import lru_cache

from agentguard_core.config import settings
from agentguard_core.llm.client import LLMClient
from agentguard_core.llm.providers.openai import OpenAIClient
from agentguard_core.llm.providers.anthropic import AnthropicClient
from agentguard_core.engine.trust.marker import TrustMarker, TrustPolicy
from agentguard_core.engine.intent.engine import IntentConsistencyEngine
from agentguard_core.engine.intent.rule_engine import RuleEngine
from agentguard_core.engine.intent.anomaly import AnomalyDetector
from agentguard_core.engine.intent.semantic import SemanticChecker
from agentguard_core.engine.permissions.dynamic import DynamicPermissionEngine
from agentguard_core.engine.trace.engine import TraceEngine
from agentguard_core.engine.sanitization.pipeline import DataSanitizationPipeline
from agentguard_core.engine.sanitization.format_cleansing import FormatCleansingStage
from agentguard_core.engine.sanitization.semantic_compression import SemanticCompressionStage
from agentguard_core.engine.two_phase import TwoPhaseEngine
from agentguard_core.engine.pipeline import Pipeline
from agentguard_core.schemas.registry import SchemaRegistry


@lru_cache
def get_llm_client() -> LLMClient:
    if settings.llm_provider == "anthropic":
        return AnthropicClient(api_key=settings.anthropic_api_key, model=settings.llm_model)
    return OpenAIClient(api_key=settings.openai_api_key, model=settings.llm_model)


@lru_cache
def get_trust_marker() -> TrustMarker:
    return TrustMarker(TrustPolicy())


@lru_cache
def get_rule_engine() -> RuleEngine:
    return RuleEngine()


@lru_cache
def get_anomaly_detector() -> AnomalyDetector:
    return AnomalyDetector()


@lru_cache
def get_semantic_checker() -> SemanticChecker:
    return SemanticChecker(get_llm_client())


@lru_cache
def get_intent_engine() -> IntentConsistencyEngine:
    return IntentConsistencyEngine(
        llm_client=get_llm_client(),
        rule_engine=get_rule_engine(),
        anomaly_detector=get_anomaly_detector(),
        semantic_checker=get_semantic_checker(),
    )


@lru_cache
def get_permission_engine() -> DynamicPermissionEngine:
    return DynamicPermissionEngine()


@lru_cache
def get_trace_engine() -> TraceEngine:
    return TraceEngine()


@lru_cache
def get_schema_registry() -> SchemaRegistry:
    return SchemaRegistry.create_default()


@lru_cache
def get_sanitization_pipeline() -> DataSanitizationPipeline:
    llm = get_llm_client()
    stages = [
        FormatCleansingStage(),
        SemanticCompressionStage(llm_client=llm, apply_to_sources=["untrusted/*"]),
    ]
    return DataSanitizationPipeline(stages=stages, trust_marker=get_trust_marker())


@lru_cache
def get_two_phase_engine() -> TwoPhaseEngine:
    return TwoPhaseEngine(
        llm_client=get_llm_client(),
        schema_registry=get_schema_registry(),
    )


@lru_cache
def get_pipeline() -> Pipeline:
    return Pipeline(
        trust_marker=get_trust_marker(),
        intent_engine=get_intent_engine(),
        permission_engine=get_permission_engine(),
        trace_engine=get_trace_engine(),
    )
