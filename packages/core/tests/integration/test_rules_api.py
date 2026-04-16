"""Integration tests for the rules management API."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from agentshield_core.app import create_app
from agentshield_core.engine.intent.rule_engine import RuleEngine
from agentshield_core.dependencies import get_rule_engine, get_pipeline
from agentshield_core.engine.pipeline import Pipeline
from agentshield_core.engine.trust.marker import TrustMarker, TrustPolicy
from agentshield_core.engine.intent.engine import IntentConsistencyEngine
from agentshield_core.engine.intent.anomaly import AnomalyDetector
from agentshield_core.engine.intent.semantic import SemanticChecker
from agentshield_core.engine.permissions.dynamic import DynamicPermissionEngine
from agentshield_core.engine.trace.engine import TraceEngine
from agentshield_core.llm.client import LLMClient, LLMResponse


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
    rule_engine = RuleEngine()
    mock_llm = MockLLM()
    pipeline = Pipeline(
        trust_marker=TrustMarker(TrustPolicy()),
        intent_engine=IntentConsistencyEngine(
            llm_client=mock_llm,
            rule_engine=rule_engine,
            anomaly_detector=AnomalyDetector(),
            semantic_checker=SemanticChecker(mock_llm),
        ),
        permission_engine=DynamicPermissionEngine(),
        trace_engine=TraceEngine(),
    )
    app.dependency_overrides[get_rule_engine] = lambda: rule_engine
    app.dependency_overrides[get_pipeline] = lambda: pipeline

    with (
        patch("agentshield_core.app.init_db", new_callable=AsyncMock),
        patch("agentshield_core.app.close_db", new_callable=AsyncMock),
        patch("agentshield_core.app.init_clickhouse", new_callable=AsyncMock),
        patch("agentshield_core.app.close_clickhouse", new_callable=AsyncMock),
        patch("agentshield_core.storage.clickhouse.insert_span", new_callable=AsyncMock),
    ):
        with TestClient(app) as c:
            yield c


class TestRulesAPI:
    def test_list_builtin_rules(self, client):
        resp = client.get("/api/v1/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 22  # 22 builtin rules
        # All should be type "builtin"
        for rule in data["rules"]:
            assert rule["type"] == "builtin"

    def test_create_custom_rule(self, client):
        resp = client.post(
            "/api/v1/rules",
            json={
                "name": "block_test_tool",
                "description": "Block test tool usage",
                "when": {"tool": "test_tool"},
                "action": "BLOCK",
                "reason": "Test tool blocked",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "block_test_tool"
        assert data["type"] == "custom"

        # Verify it appears in list
        resp2 = client.get("/api/v1/rules")
        assert resp2.json()["total"] == 23

    def test_create_rule_with_invalid_action(self, client):
        resp = client.post(
            "/api/v1/rules",
            json={
                "name": "bad_rule",
                "when": {"tool": "test"},
                "action": "INVALID",
            },
        )
        assert resp.status_code == 422

    def test_create_rule_with_invalid_regex(self, client):
        resp = client.post(
            "/api/v1/rules",
            json={
                "name": "bad_regex_rule",
                "when": {
                    "tool": "test",
                    "params": {"q": {"matches": "[invalid("}},
                },
                "action": "BLOCK",
            },
        )
        assert resp.status_code == 422

    def test_delete_custom_rule(self, client):
        # Create then delete
        client.post(
            "/api/v1/rules",
            json={
                "name": "temp_rule",
                "when": {"tool": "temp"},
                "action": "BLOCK",
            },
        )
        resp = client.delete("/api/v1/rules/temp_rule")
        assert resp.status_code == 200
        assert resp.json()["deleted"] == "temp_rule"

    def test_cannot_delete_builtin_rule(self, client):
        resp = client.delete("/api/v1/rules/data_destruction")
        assert resp.status_code == 400
        assert "built-in" in resp.json()["detail"]

    def test_delete_nonexistent_rule(self, client):
        resp = client.delete("/api/v1/rules/no_such_rule")
        assert resp.status_code == 404

    def test_toggle_rule_enabled(self, client):
        resp = client.patch("/api/v1/rules/data_destruction/enabled?enabled=false")
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

        resp2 = client.patch("/api/v1/rules/data_destruction/enabled?enabled=true")
        assert resp2.json()["enabled"] is True

    def test_toggle_nonexistent_rule(self, client):
        resp = client.patch("/api/v1/rules/no_such_rule/enabled?enabled=true")
        assert resp.status_code == 404

    def test_validate_valid_rule(self, client):
        resp = client.post(
            "/api/v1/rules/validate",
            json={
                "name": "valid_rule",
                "when": {"tool": "send_email", "trust_level": ["EXTERNAL"]},
                "action": "BLOCK",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_validate_invalid_rule(self, client):
        resp = client.post(
            "/api/v1/rules/validate",
            json={
                "name": "invalid_rule",
                "when": {"tool": "test"},
                "action": "DESTROY",  # Invalid action
            },
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    def test_batch_create_rules(self, client):
        resp = client.post(
            "/api/v1/rules/batch",
            json=[
                {"name": "batch_1", "when": {"tool": "a"}, "action": "BLOCK"},
                {"name": "batch_2", "when": {"tool": "b"}, "action": "BLOCK"},
                {"name": "batch_3", "when": {"tool": "c"}, "action": "REQUIRE_CONFIRMATION"},
            ],
        )
        assert resp.status_code == 201
        assert resp.json()["total"] == 3

    def test_custom_rule_actually_blocks(self, client):
        """End-to-end: create rule via API, then verify it blocks tool calls."""
        # Create rule
        client.post(
            "/api/v1/rules",
            json={
                "name": "block_evil_tool",
                "when": {"tool": "evil_tool"},
                "action": "BLOCK",
                "reason": "Evil tool blocked by custom rule",
            },
        )

        # Create session
        resp = client.post("/api/v1/sessions", json={"user_message": "test"})
        session_id = resp.json()["session_id"]

        # Check evil_tool — should be blocked
        resp2 = client.post(
            "/api/v1/check",
            json={
                "session_id": session_id,
                "tool_name": "evil_tool",
                "params": {},
                "source_id": "user_input",
            },
        )
        assert resp2.json()["action"] == "BLOCK"
        assert "Evil tool blocked" in resp2.json()["reason"]
