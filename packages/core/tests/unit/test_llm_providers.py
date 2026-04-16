"""Tests for LLM provider implementations using mock HTTP responses."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentshield_core.llm.client import LLMMessage


class TestOpenAIProvider:
    @pytest.mark.asyncio
    async def test_chat_returns_response(self):
        from agentshield_core.llm.providers.openai import OpenAIClient

        # Mock the OpenAI async client
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Hello from OpenAI"
        mock_response.model = "gpt-4o-mini"
        mock_response.usage = MagicMock()
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 5
        mock_response.usage.total_tokens = 15

        with patch("agentshield_core.llm.providers.openai.AsyncOpenAI") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_instance

            client = OpenAIClient(api_key="test-key", model="gpt-4o-mini")
            result = await client.chat([LLMMessage(role="user", content="Hi")])

            assert result.content == "Hello from OpenAI"
            assert result.model == "gpt-4o-mini"
            assert result.usage["total_tokens"] == 15

    @pytest.mark.asyncio
    async def test_chat_passes_tools(self):
        from agentshield_core.llm.providers.openai import OpenAIClient

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "tool response"
        mock_response.model = "gpt-4o-mini"
        mock_response.usage = MagicMock()
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 5
        mock_response.usage.total_tokens = 15

        with patch("agentshield_core.llm.providers.openai.AsyncOpenAI") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_instance

            client = OpenAIClient(api_key="test-key")
            tools = [{"type": "function", "function": {"name": "test"}}]
            await client.chat([LLMMessage(role="user", content="use tool")], tools=tools)

            call_kwargs = mock_instance.chat.completions.create.call_args[1]
            assert call_kwargs["tools"] == tools

    @pytest.mark.asyncio
    async def test_chat_no_usage(self):
        """Handle response with no usage data."""
        from agentshield_core.llm.providers.openai import OpenAIClient

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "response"
        mock_response.model = "gpt-4o-mini"
        mock_response.usage = None

        with patch("agentshield_core.llm.providers.openai.AsyncOpenAI") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_instance

            client = OpenAIClient(api_key="test-key")
            result = await client.chat([LLMMessage(role="user", content="Hi")])
            assert result.usage["total_tokens"] == 0


class TestLocalProvider:
    @pytest.mark.asyncio
    async def test_local_client_uses_custom_base_url(self):
        from agentshield_core.llm.providers.local import LocalClient

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "local response"
        mock_response.model = "llama-3"
        mock_response.usage = MagicMock()
        mock_response.usage.prompt_tokens = 5
        mock_response.usage.completion_tokens = 3
        mock_response.usage.total_tokens = 8

        with patch("agentshield_core.llm.providers.local.AsyncOpenAI") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_instance

            client = LocalClient(base_url="http://localhost:11434/v1", model="llama-3")
            result = await client.chat([LLMMessage(role="user", content="Hello")])

            assert result.content == "local response"
            assert result.model == "llama-3"
            mock_cls.assert_called_once_with(base_url="http://localhost:11434/v1", api_key="not-needed")


class TestAnthropicProvider:
    @pytest.mark.asyncio
    async def test_chat_separates_system_message(self):
        from agentshield_core.llm.providers.anthropic import AnthropicClient

        mock_block = MagicMock()
        mock_block.type = "text"
        mock_block.text = "Anthropic response"

        mock_response = MagicMock()
        mock_response.content = [mock_block]
        mock_response.model = "claude-sonnet-4-6"
        mock_response.usage = MagicMock()
        mock_response.usage.input_tokens = 10
        mock_response.usage.output_tokens = 5

        with patch("agentshield_core.llm.providers.anthropic.anthropic") as mock_mod:
            mock_instance = MagicMock()
            mock_instance.messages.create = AsyncMock(return_value=mock_response)
            mock_mod.AsyncAnthropic.return_value = mock_instance

            client = AnthropicClient(api_key="test-key")
            result = await client.chat(
                [
                    LLMMessage(role="system", content="You are helpful"),
                    LLMMessage(role="user", content="Hi"),
                ]
            )

            assert result.content == "Anthropic response"
            # Verify system message was extracted
            call_kwargs = mock_instance.messages.create.call_args[1]
            assert call_kwargs["system"] == "You are helpful"
            assert len(call_kwargs["messages"]) == 1  # Only user message

    @pytest.mark.asyncio
    async def test_chat_usage_mapping(self):
        from agentshield_core.llm.providers.anthropic import AnthropicClient

        mock_block = MagicMock()
        mock_block.type = "text"
        mock_block.text = "ok"

        mock_response = MagicMock()
        mock_response.content = [mock_block]
        mock_response.model = "claude-sonnet-4-6"
        mock_response.usage = MagicMock()
        mock_response.usage.input_tokens = 100
        mock_response.usage.output_tokens = 50

        with patch("agentshield_core.llm.providers.anthropic.anthropic") as mock_mod:
            mock_instance = MagicMock()
            mock_instance.messages.create = AsyncMock(return_value=mock_response)
            mock_mod.AsyncAnthropic.return_value = mock_instance

            client = AnthropicClient(api_key="test-key")
            result = await client.chat([LLMMessage(role="user", content="Hi")])

            assert result.usage["prompt_tokens"] == 100
            assert result.usage["completion_tokens"] == 50
            assert result.usage["total_tokens"] == 150
