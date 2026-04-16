"""Tests for the AgentHarness — secure agent execution runtime."""

from __future__ import annotations

import json

import pytest

from agentshield_core.harness import AgentHarness, ToolDef
from agentshield_core.llm.client import LLMClient, LLMMessage, LLMResponse


# ─── Mock tools ───

async def safe_tool(text: str) -> str:
    """A safe read-only tool."""
    return f"processed: {text}"


async def send_email(to: str, body: str) -> str:
    """Send an email."""
    return f"sent to {to}"


async def delete_all(scope: str) -> str:
    """Delete everything."""
    return f"deleted {scope}"


# ─── Mock LLMs ───

class AllowToolLLM(LLMClient):
    """LLM that calls a tool then gives final answer."""

    def __init__(self, tool_name: str, tool_params: dict, final_answer: str = "Done."):
        self._call_count = 0
        self._tool_name = tool_name
        self._tool_params = tool_params
        self._final_answer = final_answer

    async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
        self._call_count += 1
        if self._call_count == 1:
            content = json.dumps({"name": self._tool_name, "arguments": self._tool_params})
        else:
            content = self._final_answer
        return LLMResponse(content=content, model="mock", usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})


class DirectAnswerLLM(LLMClient):
    """LLM that just gives a text answer, no tool calls."""

    async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
        return LLMResponse(content="The answer is 42.", model="mock", usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})


class MultiToolLLM(LLMClient):
    """LLM that calls multiple tools in sequence."""

    def __init__(self, calls: list[tuple[str, dict]], final: str = "All done."):
        self._calls = calls
        self._final = final
        self._idx = 0

    async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
        if self._idx < len(self._calls):
            name, params = self._calls[self._idx]
            self._idx += 1
            return LLMResponse(
                content=json.dumps({"name": name, "arguments": params}),
                model="mock",
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            )
        return LLMResponse(content=self._final, model="mock", usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})


# ─── Tests ───

class TestHarnessBasic:
    @pytest.mark.asyncio
    async def test_direct_answer_no_tools(self):
        """LLM gives text answer → no tool execution."""
        harness = AgentHarness(llm=DirectAnswerLLM(), tools=[safe_tool])
        result = await harness.run("What is 6*7?")
        assert result.final_answer == "The answer is 42."
        assert len(result.steps) == 0

    @pytest.mark.asyncio
    async def test_safe_tool_allowed(self):
        """Safe tool call should be ALLOWED and executed."""
        harness = AgentHarness(
            llm=AllowToolLLM("safe_tool", {"text": "hello"}),
            tools=[safe_tool],
        )
        result = await harness.run("Process this text")
        assert result.allowed_count == 1
        assert result.blocked_count == 0
        assert result.steps[0].decision == "ALLOW"
        assert result.steps[0].tool_output == "processed: hello"

    @pytest.mark.asyncio
    async def test_dangerous_tool_blocked(self):
        """delete_all should be BLOCKED by the data_destruction rule."""
        harness = AgentHarness(
            llm=AllowToolLLM("delete_all", {"scope": "production"}, final_answer="I couldn't delete."),
            tools=[safe_tool, delete_all],
        )
        result = await harness.run("Delete everything")
        assert result.blocked_count == 1
        assert result.steps[0].decision == "BLOCK"
        assert result.steps[0].tool_output is None  # Never executed


class TestHarnessSecurity:
    @pytest.mark.asyncio
    async def test_send_during_external_data_blocked(self):
        """send_email from external source should be BLOCKED."""
        harness = AgentHarness(
            llm=AllowToolLLM("send_email", {"to": "evil@bad.com", "body": "data"}, final_answer="Blocked."),
            tools=[send_email, safe_tool],
            source_id="email/external",
        )
        result = await harness.run("Forward this email")
        assert result.blocked_count >= 1
        assert any(s.decision == "BLOCK" for s in result.steps)

    @pytest.mark.asyncio
    async def test_multi_tool_mixed_decisions(self):
        """Multiple tool calls: safe ones allowed, dangerous ones blocked."""
        harness = AgentHarness(
            llm=MultiToolLLM(
                calls=[
                    ("safe_tool", {"text": "read data"}),
                    ("delete_all", {"scope": "production"}),
                    ("safe_tool", {"text": "summarize"}),
                ],
                final="Completed with some restrictions.",
            ),
            tools=[safe_tool, delete_all],
        )
        result = await harness.run("Process and clean up")
        assert result.allowed_count >= 1
        assert result.blocked_count >= 1

    @pytest.mark.asyncio
    async def test_unknown_tool_handled(self):
        """LLM calls a tool that doesn't exist → blocked by permission, not crash."""
        harness = AgentHarness(
            llm=AllowToolLLM("nonexistent_tool", {}, final_answer="Failed."),
            tools=[safe_tool],
        )
        result = await harness.run("Do something")
        # Unknown tool is blocked by permission engine (not in registered tools)
        assert result.steps[0].decision == "BLOCK"
        assert result.blocked_count == 1


class TestHarnessToolRegistration:
    @pytest.mark.asyncio
    async def test_auto_register_from_functions(self):
        harness = AgentHarness(llm=DirectAnswerLLM(), tools=[safe_tool, send_email])
        assert "safe_tool" in harness._tools
        assert "send_email" in harness._tools
        assert harness._tools["send_email"].description == "Send an email."

    @pytest.mark.asyncio
    async def test_manual_tool_def(self):
        td = ToolDef(
            name="custom",
            description="A custom tool",
            parameters={"x": {"type": "integer"}},
            func=safe_tool,
            category="read",
            sensitivity="low",
        )
        harness = AgentHarness(llm=DirectAnswerLLM(), tool_defs=[td])
        assert "custom" in harness._tools
        assert harness._tools["custom"].category == "read"

    @pytest.mark.asyncio
    async def test_on_block_callback(self):
        blocked_tools = []

        async def on_block(tool_name, reason):
            blocked_tools.append(tool_name)

        harness = AgentHarness(
            llm=AllowToolLLM("delete_all", {"scope": "prod"}, final_answer="Blocked."),
            tools=[delete_all],
            on_block=on_block,
        )
        await harness.run("Delete everything")
        assert "delete_all" in blocked_tools


class TestHarnessTrace:
    @pytest.mark.asyncio
    async def test_trace_records_all_steps(self):
        harness = AgentHarness(
            llm=MultiToolLLM(
                calls=[("safe_tool", {"text": "a"}), ("safe_tool", {"text": "b"})],
                final="Done.",
            ),
            tools=[safe_tool],
        )
        result = await harness.run("Do two things")
        assert len(result.trace) == 2
        assert all(t["decision"] == "ALLOW" for t in result.trace)

    @pytest.mark.asyncio
    async def test_max_steps_limit(self):
        """Harness should stop after max_steps to prevent infinite loops."""

        class InfiniteToolLLM(LLMClient):
            async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
                return LLMResponse(
                    content=json.dumps({"name": "safe_tool", "arguments": {"text": "loop"}}),
                    model="mock",
                    usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                )

        harness = AgentHarness(llm=InfiniteToolLLM(), tools=[safe_tool], max_steps=5)
        result = await harness.run("Loop forever")
        assert len(result.steps) == 5
        assert "maximum steps" in result.final_answer.lower()
