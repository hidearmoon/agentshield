"""Tests for dependency injection factories."""

from __future__ import annotations


from agentshield_core.dependencies import (
    get_anomaly_detector,
    get_permission_engine,
    get_pipeline,
    get_rule_engine,
    get_schema_registry,
    get_trace_engine,
    get_trust_marker,
)


class TestDependencyFactories:
    """Test that DI factories return correct types and are cached."""

    def test_get_trust_marker(self):
        from agentshield_core.engine.trust.marker import TrustMarker

        result = get_trust_marker()
        assert isinstance(result, TrustMarker)
        # Should be cached (same instance)
        assert get_trust_marker() is result

    def test_get_rule_engine(self):
        from agentshield_core.engine.intent.rule_engine import RuleEngine

        result = get_rule_engine()
        assert isinstance(result, RuleEngine)

    def test_get_anomaly_detector(self):
        from agentshield_core.engine.intent.anomaly import AnomalyDetector

        result = get_anomaly_detector()
        assert isinstance(result, AnomalyDetector)

    def test_get_permission_engine(self):
        from agentshield_core.engine.permissions.dynamic import DynamicPermissionEngine

        result = get_permission_engine()
        assert isinstance(result, DynamicPermissionEngine)

    def test_get_trace_engine(self):
        from agentshield_core.engine.trace.engine import TraceEngine

        result = get_trace_engine()
        assert isinstance(result, TraceEngine)

    def test_get_schema_registry(self):
        from agentshield_core.schemas.registry import SchemaRegistry

        result = get_schema_registry()
        assert isinstance(result, SchemaRegistry)
        assert "email" in result.list_types()

    def test_get_pipeline(self):
        from agentshield_core.engine.pipeline import Pipeline

        result = get_pipeline()
        assert isinstance(result, Pipeline)
