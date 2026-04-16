"""Lightweight fuzz testing — random inputs to catch crashes and unexpected behavior."""

from __future__ import annotations

import random
import string

import pytest

from agentshield_core.engine.sanitization.format_cleansing import FormatCleansingStage
from agentshield_core.engine.intent.rule_engine import RuleEngine
from agentshield_core.engine.intent.anomaly import AnomalyDetector
from agentshield_core.engine.intent.models import ToolCall, IntentContext, Intent
from agentshield_core.engine.trust.levels import TrustLevel
from agentshield_core.engine.trust.marker import TrustMarker, TrustPolicy


def _random_string(min_len=0, max_len=500):
    length = random.randint(min_len, max_len)
    chars = string.printable + "\u200b\u200c\u200d\ufeff\u202e\u202c"
    return "".join(random.choice(chars) for _ in range(length))


def _random_params(depth=0):
    if depth > 3:
        return _random_string(0, 50)
    t = random.choice(["str", "int", "float", "dict", "list", "none"])
    if t == "str":
        return _random_string(0, 200)
    elif t == "int":
        return random.randint(-1000, 1000)
    elif t == "float":
        return random.uniform(-100, 100)
    elif t == "dict":
        return {_random_string(1, 20): _random_params(depth + 1) for _ in range(random.randint(0, 5))}
    elif t == "list":
        return [_random_params(depth + 1) for _ in range(random.randint(0, 5))]
    else:
        return None


class TestFuzzSanitization:
    """Fuzz the sanitization stage with random inputs."""

    @pytest.fixture
    def stage(self):
        return FormatCleansingStage()

    @pytest.mark.asyncio
    async def test_random_strings_dont_crash(self, stage):
        """100 random strings should not crash the sanitizer."""
        random.seed(42)
        for _ in range(100):
            data = _random_string(0, 2000)
            result = await stage.process(data)
            assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_random_html_dont_crash(self, stage):
        """Random HTML-like content should not crash."""
        random.seed(123)
        tags = ["div", "span", "p", "script", "style"]
        styles = ["display:none", "visibility:hidden", "opacity:0", "position:absolute;left:-9999px"]

        for _ in range(50):
            tag = random.choice(tags)
            style = random.choice(styles)
            content = _random_string(0, 100)
            html = f'<{tag} style="{style}">{content}</{tag}>'
            result = await stage.process(html)
            assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_mixed_unicode_dont_crash(self, stage):
        """Mixed Unicode categories should not crash."""
        samples = [
            "你好世界 Hello 🌍 مرحبا",
            "\x00\x01\x02\x7f\x80\x9f",
            "\u200b\u200c\u200d\u202e\u2066\ufeff",
            "¡Hola! Ñoño café résumé naïve",
            "∑∏∐∫∮∯∰∱∲∳",
            "🎉🔒🛡️💉🔥",
        ]
        for s in samples:
            result = await stage.process(s)
            assert isinstance(result, str)


class TestFuzzRuleEngine:
    """Fuzz the rule engine with random tool calls."""

    @pytest.fixture
    def engine(self):
        return RuleEngine()

    def test_random_tool_calls_dont_crash(self, engine):
        """100 random tool calls should not crash the rule engine."""
        random.seed(42)
        trust_levels = list(TrustLevel)

        for _ in range(100):
            tc = ToolCall(
                name=_random_string(0, 50),
                params={_random_string(1, 20): _random_string(0, 100) for _ in range(random.randint(0, 10))},
                tool_category=_random_string(0, 20),
                estimated_result_size=random.randint(0, 10000),
            )
            ctx = IntentContext(
                original_message=_random_string(0, 200),
                intent=Intent(intent=_random_string(0, 100)),
                current_data_trust_level=random.choice(trust_levels),
                tool_call_history=[ToolCall(name=_random_string(1, 20)) for _ in range(random.randint(0, 15))],
            )
            result = engine.check(tc, ctx)
            assert result is not None


class TestFuzzAnomalyDetector:
    """Fuzz the anomaly detector with random inputs."""

    @pytest.fixture
    def detector(self):
        return AnomalyDetector()

    def test_random_inputs_produce_valid_scores(self, detector):
        """100 random inputs should produce scores between 0 and 1."""
        random.seed(42)
        for _ in range(100):
            tc = ToolCall(
                name=_random_string(0, 50),
                params=_random_params(),
                tool_category=_random_string(0, 20),
            )
            ctx = IntentContext(
                original_message=_random_string(0, 200),
                intent=Intent(
                    intent=_random_string(0, 100),
                    expected_tools=[_random_string(1, 20) for _ in range(random.randint(0, 5))],
                ),
                current_data_trust_level=random.choice(list(TrustLevel)),
                allowed_tool_categories=[_random_string(1, 20) for _ in range(random.randint(0, 5))],
            )
            result = detector.check(tc, ctx)
            assert 0.0 <= result.score <= 1.0, f"Score {result.score} out of range"


class TestFuzzTrustMarker:
    """Fuzz the trust marker with random source IDs."""

    def test_random_source_ids_dont_crash(self):
        marker = TrustMarker(TrustPolicy())
        random.seed(42)
        for _ in range(100):
            source = _random_string(0, 100)
            level = marker.compute_trust_level(source)
            assert level in TrustLevel
