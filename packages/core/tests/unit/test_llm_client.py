"""Tests for LLM client abstraction."""

from __future__ import annotations

import json

import pytest

from agentshield_core.llm.client import LLMClient, LLMMessage, LLMResponse


class MockLLMClient(LLMClient):
    """Concrete implementation for testing the abstract interface."""

    def __init__(self, response_content: str = "test response"):
        self._response_content = response_content
        self.last_messages = None
        self.last_tools = None

    async def chat(self, messages, tools=None, temperature=0.0, max_tokens=4096):
        self.last_messages = messages
        self.last_tools = tools
        return LLMResponse(
            content=self._response_content,
            model="mock-model",
            usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        )


class TestLLMClient:
    @pytest.mark.asyncio
    async def test_chat_returns_response(self):
        client = MockLLMClient("hello world")
        msgs = [LLMMessage(role="user", content="hi")]
        resp = await client.chat(msgs)
        assert resp.content == "hello world"
        assert resp.model == "mock-model"
        assert resp.usage["total_tokens"] == 15

    @pytest.mark.asyncio
    async def test_extract_json_uses_chat(self):
        json_data = json.dumps({"key": "value"})
        client = MockLLMClient(json_data)
        msgs = [LLMMessage(role="system", content="output json")]
        result = await client.extract_json(msgs)
        assert result == json_data
        assert client.last_tools is None  # extract_json uses no tools

    @pytest.mark.asyncio
    async def test_chat_passes_tools(self):
        client = MockLLMClient()
        tools = [{"type": "function", "function": {"name": "test"}}]
        await client.chat([LLMMessage(role="user", content="use tool")], tools=tools)
        assert client.last_tools == tools

    @pytest.mark.asyncio
    async def test_chat_without_tools(self):
        client = MockLLMClient()
        await client.chat([LLMMessage(role="user", content="no tools")])
        assert client.last_tools is None


class TestLLMModels:
    def test_message_creation(self):
        msg = LLMMessage(role="system", content="you are helpful")
        assert msg.role == "system"
        assert msg.content == "you are helpful"

    def test_response_creation(self):
        resp = LLMResponse(
            content="answer",
            model="gpt-4",
            usage={"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        )
        assert resp.content == "answer"
        assert resp.usage["total_tokens"] == 150
