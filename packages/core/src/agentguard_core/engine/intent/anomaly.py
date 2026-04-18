"""Layer 2: Anomaly detection — fast, statistical, millisecond-level."""

from __future__ import annotations

import unicodedata
from urllib.parse import unquote

import numpy as np

from agentguard_core.engine.intent.models import ToolCall, IntentContext, AnomalyResult


class AnomalyDetector:
    """
    Layer 2: Statistical anomaly detection.
    Uses weighted feature scoring (upgradable to IsolationForest with training data).
    Must remain sub-millisecond.
    """

    def __init__(self) -> None:
        # Feature weights (tuned based on attack patterns)
        self._weights = {
            "trust_action_mismatch": 0.30,
            "tool_category_novelty": 0.15,
            "param_anomaly": 0.25,
            "temporal_anomaly": 0.10,
            "intent_distance": 0.20,
        }

    def check(self, tool_call: ToolCall, context: IntentContext) -> AnomalyResult:
        features = self._extract_features(tool_call, context)
        score = self._compute_score(features)
        reason = self._explain(features, score)
        return AnomalyResult(score=score, reason=reason)

    def _extract_features(self, tc: ToolCall, ctx: IntentContext) -> dict[str, float]:
        features: dict[str, float] = {}

        # Feature 1: Trust level vs action sensitivity mismatch
        action_sensitivity = self._get_action_sensitivity(tc.name)
        trust_normalized = ctx.current_data_trust_level / 5.0  # Normalize to 0-1
        features["trust_action_mismatch"] = max(0, action_sensitivity - trust_normalized)

        # Feature 2: Tool category novelty (unseen category in session)
        if ctx.allowed_tool_categories and tc.tool_category:
            features["tool_category_novelty"] = 0.0 if tc.tool_category in ctx.allowed_tool_categories else 0.8
        else:
            features["tool_category_novelty"] = 0.0

        # Feature 3: Parameter anomaly (unusually large params, unusual patterns)
        features["param_anomaly"] = self._check_param_anomaly(tc.params)

        # Feature 4: Temporal anomaly (too many calls in session)
        history_len = len(ctx.tool_call_history)
        features["temporal_anomaly"] = min(1.0, history_len / 50.0) if history_len > 20 else 0.0

        # Feature 5: Intent distance (tool name similarity to expected tools)
        if ctx.intent.expected_tools:
            features["intent_distance"] = 0.0 if tc.name in ctx.intent.expected_tools else 0.5
        else:
            features["intent_distance"] = 0.0

        return features

    def _compute_score(self, features: dict[str, float]) -> float:
        score = sum(features.get(name, 0.0) * weight for name, weight in self._weights.items())
        return float(np.clip(score, 0.0, 1.0))

    def _explain(self, features: dict[str, float], score: float) -> str:
        if score < 0.3:
            return ""
        top_features = sorted(features.items(), key=lambda x: x[1], reverse=True)[:3]
        parts = [f"{name}={value:.2f}" for name, value in top_features if value > 0]
        return f"Anomaly score {score:.2f}: {', '.join(parts)}"

    @staticmethod
    def _get_action_sensitivity(tool_name: str) -> float:
        """Map tool names to sensitivity scores (0=safe, 1=critical)."""
        critical = {"execute_code", "run_shell", "delete_all", "drop_table", "process_payment"}
        high = {"send_email", "query_database", "modify_permissions", "export_data"}
        medium = {"write_file", "create_file", "call_api", "update_config"}

        if tool_name in critical:
            return 1.0
        if tool_name in high:
            return 0.75
        if tool_name in medium:
            return 0.5
        return 0.25

    _SUSPICIOUS_PATTERNS = [
        # Prompt injection patterns
        "ignore previous",
        "ignore all",
        "forget everything",
        "disregard above",
        "new instructions",
        "override safety",
        "system prompt",
        "developer mode",
        "do anything now",
        "jailbreak",
        "you are now",
        "act as if",
        "pretend you",
        # Code execution
        "eval(",
        "exec(",
        "import os",
        "subprocess",
        "os.system",
        "__import__",
        "compile(",
        # SQL injection
        "drop table",
        "delete from",
        "'; --",
        "union select",
        "or 1=1",
        # System access
        "curl ",
        "wget ",
        "/etc/passwd",
        "/etc/shadow",
        ".ssh/id_rsa",
        # Data exfiltration
        "send_email",
        "export_data",
        "transfer_funds",
        # Markdown/code block injection
        "```",
    ]

    @staticmethod
    def _extract_string_values(obj: object, max_depth: int = 5, limit: int = 20) -> list[str]:
        """Recursively extract string values from nested dicts/lists."""
        if max_depth <= 0 or limit <= 0:
            return []
        results: list[str] = []
        if isinstance(obj, str):
            results.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                results.extend(AnomalyDetector._extract_string_values(v, max_depth - 1, limit - len(results)))
                if len(results) >= limit:
                    break
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                results.extend(AnomalyDetector._extract_string_values(item, max_depth - 1, limit - len(results)))
                if len(results) >= limit:
                    break
        return results[:limit]

    @staticmethod
    def _check_param_anomaly(params: dict) -> float:
        """Check for anomalous parameter patterns including nested values."""
        if not params or not isinstance(params, dict):
            return 0.0

        anomaly = 0.0
        # Extract all string values from nested params (max depth 5, max 20 values)
        string_values = AnomalyDetector._extract_string_values(params)

        # Cross-param concatenation check — detect split-param attacks
        if len(string_values) >= 2:
            combined = " ".join(v[:200] for v in string_values[:10]).lower()
            combined = unicodedata.normalize("NFKD", combined)
            for pattern in AnomalyDetector._SUSPICIOUS_PATTERNS:
                if pattern in combined:
                    anomaly = max(anomaly, 0.6)
                    break
        checked = 0
        for value in string_values:
            if checked >= 20:
                break
            if isinstance(value, str):
                checked += 1
                # Unusually long strings might contain injections
                if len(value) > 5000:
                    anomaly = max(anomaly, 0.6)
                # Check first 10000 chars for injection patterns
                sample = value[:10000].lower()
                # Unicode normalize (NFKD) to catch homoglyph/fullwidth attacks
                sample = unicodedata.normalize("NFKD", sample)
                # Iterative URL decode to catch double/triple encoding
                if "%" in sample:
                    for _ in range(3):  # Max 3 decode rounds
                        decoded = unquote(sample)
                        if decoded == sample:
                            break
                        sample = decoded.lower()
                for pattern in AnomalyDetector._SUSPICIOUS_PATTERNS:
                    if pattern in sample:
                        anomaly = max(anomaly, 0.8)
                        break  # One match is enough

        return float(np.clip(anomaly, 0.0, 1.0))
