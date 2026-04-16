"""API error handling tests — verify correct HTTP status codes and error responses."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from agentshield_core.app import create_app
from agentshield_core.engine.pipeline import Pipeline
from agentshield_core.engine.trust.marker import TrustMarker, TrustPolicy
from agentshield_core.engine.intent.engine import IntentConsistencyEngine
from agentshield_core.engine.intent.rule_engine import RuleEngine
from agentshield_core.engine.intent.anomaly import AnomalyDetector
from agentshield_core.engine.intent.semantic import SemanticChecker
from agentshield_core.engine.permissions.dynamic import DynamicPermissionEngine
from agentshield_core.engine.trace.engine import TraceEngine
from agentshield_core.engine.sanitization.format_cleansing import FormatCleansingStage
from agentshield_core.engine.sanitization.pipeline import DataSanitizationPipeline
from agentshield_core.llm.client import LLMClient, LLMResponse
from agentshield_core.dependencies import get_pipeline, get_sanitization_pipeline, get_rule_engine


class MockLLM(LLMClient):
    async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
        return LLMResponse(
            content=json.dumps({"intent": "test", "expected_tools": [], "sensitive_data_involved": False}),
            model="mock",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )


@pytest.fixture
def client():
    app = create_app()
    mock_llm = MockLLM()
    trust_marker = TrustMarker(TrustPolicy())
    rule_engine = RuleEngine()
    pipeline = Pipeline(
        trust_marker=trust_marker,
        intent_engine=IntentConsistencyEngine(
            llm_client=mock_llm,
            rule_engine=rule_engine,
            anomaly_detector=AnomalyDetector(),
            semantic_checker=SemanticChecker(mock_llm),
        ),
        permission_engine=DynamicPermissionEngine(),
        trace_engine=TraceEngine(),
    )
    sanitization = DataSanitizationPipeline(stages=[FormatCleansingStage()], trust_marker=trust_marker)
    app.dependency_overrides[get_pipeline] = lambda: pipeline
    app.dependency_overrides[get_sanitization_pipeline] = lambda: sanitization
    app.dependency_overrides[get_rule_engine] = lambda: rule_engine

    with (
        patch("agentshield_core.app.init_db", new_callable=AsyncMock),
        patch("agentshield_core.app.close_db", new_callable=AsyncMock),
        patch("agentshield_core.app.init_clickhouse", new_callable=AsyncMock),
        patch("agentshield_core.app.close_clickhouse", new_callable=AsyncMock),
        patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock),
    ):
        with TestClient(app) as c:
            yield c


class TestHTTPStatusCodes:
    """Verify correct HTTP status codes for various scenarios."""

    def test_404_for_unknown_endpoints(self, client):
        resp = client.get("/api/v1/nonexistent")
        assert resp.status_code == 404

    def test_405_for_wrong_method(self, client):
        resp = client.get("/api/v1/check")  # Should be POST
        assert resp.status_code == 405

    def test_422_for_missing_required_fields(self, client):
        resp = client.post("/api/v1/check", json={})
        assert resp.status_code == 422

    def test_422_for_invalid_json(self, client):
        resp = client.post(
            "/api/v1/check",
            content="not json at all",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_200_for_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_200_for_detailed_health(self, client):
        resp = client.get("/health/detailed")
        assert resp.status_code == 200
        data = resp.json()
        assert "components" in data

    def test_201_for_rule_creation(self, client):
        resp = client.post(
            "/api/v1/rules",
            json={
                "name": "test_rule",
                "when": {"tool": "test"},
                "action": "BLOCK",
            },
        )
        assert resp.status_code == 201

    def test_check_response_includes_all_fields(self, client):
        """Verify the check response has all expected fields."""
        resp = client.post("/api/v1/sessions", json={"user_message": "test"})
        sid = resp.json()["session_id"]

        resp2 = client.post(
            "/api/v1/check",
            json={"session_id": sid, "tool_name": "summarize", "params": {}},
        )
        data = resp2.json()
        assert "action" in data
        assert "reason" in data
        assert "trace_id" in data
        assert "span_id" in data
        assert "engine" in data
        assert "trust_level" in data

    def test_request_id_in_all_responses(self, client):
        """Every response should include X-Request-ID."""
        endpoints = [
            ("GET", "/health"),
            ("POST", "/api/v1/sessions"),
        ]
        for method, path in endpoints:
            if method == "GET":
                resp = client.get(path)
            else:
                resp = client.post(path, json={"user_message": "test"})
            assert "x-request-id" in resp.headers, f"Missing X-Request-ID for {method} {path}"

    def test_sanitize_response_format(self, client):
        resp = client.post(
            "/api/v1/sanitize",
            json={"data": "hello", "source": "user_input"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "content" in data
        assert "trust_level" in data
        assert "sanitization_chain" in data

    def test_metrics_endpoint(self, client):
        # Make some check calls first to generate metrics
        sess = client.post("/api/v1/sessions", json={"user_message": "test"})
        sid = sess.json()["session_id"]
        client.post("/api/v1/check", json={"session_id": sid, "tool_name": "summarize", "params": {}})
        client.post("/api/v1/check", json={"session_id": sid, "tool_name": "delete_all", "params": {}})

        resp = client.get("/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_checks" in data
        assert data["total_checks"] >= 2
