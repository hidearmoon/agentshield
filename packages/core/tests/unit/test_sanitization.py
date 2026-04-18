"""Tests for data sanitization pipeline."""

import pytest
from agentguard_core.engine.sanitization.format_cleansing import FormatCleansingStage


class TestFormatCleansing:
    @pytest.fixture
    def stage(self) -> FormatCleansingStage:
        return FormatCleansingStage()

    @pytest.mark.asyncio
    async def test_removes_zero_width_chars(self, stage: FormatCleansingStage):
        data = "hello\u200bworld\u200c\u200d\ufeff"
        result = await stage.process(data)
        assert result == "helloworld"

    @pytest.mark.asyncio
    async def test_removes_control_chars(self, stage: FormatCleansingStage):
        data = "hello\x00\x01\x02world"
        result = await stage.process(data)
        assert result == "helloworld"

    @pytest.mark.asyncio
    async def test_decodes_html_entities(self, stage: FormatCleansingStage):
        """HTML entities are decoded, then <script> tags are removed."""
        data = "&lt;script&gt;alert(1)&lt;/script&gt;"
        result = await stage.process(data)
        # After decode: <script>alert(1)</script> → then script tag removed
        assert "&lt;" not in result
        assert "<script>" not in result  # Script tags should be stripped

    @pytest.mark.asyncio
    async def test_removes_hidden_html(self, stage: FormatCleansingStage):
        data = '<div style="display:none">hidden content</div>visible content'
        result = await stage.process(data)
        assert "hidden content" not in result
        assert "visible content" in result

    @pytest.mark.asyncio
    async def test_removes_html_comments(self, stage: FormatCleansingStage):
        data = "before<!-- hidden comment -->after"
        result = await stage.process(data)
        assert "hidden comment" not in result
        assert "beforeafter" in result

    @pytest.mark.asyncio
    async def test_depth_limit_prevents_infinite_recursion(self, stage: FormatCleansingStage):
        """Nested base64 should not cause infinite recursion."""
        import base64

        # Create nested base64 (10 layers — enough to exceed max_depth=3)
        data = "normal text"
        for _ in range(10):
            data = base64.b64encode(data.encode()).decode()

        # Should not hang or crash
        result = await stage.process(data)
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_cycle_detection(self, stage: FormatCleansingStage):
        """Content that decodes to itself should not loop."""
        data = "simple text with no encoding"
        result = await stage.process(data)
        assert result == data
