"""Anthropic LLM provider."""

from __future__ import annotations

import anthropic

from agentguard_core.llm.client import LLMClient, LLMMessage, LLMResponse


class AnthropicClient(LLMClient):
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6"):
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        # Separate system message from conversation
        system_content = ""
        conversation = []
        for m in messages:
            if m.role == "system":
                system_content += m.content + "\n"
            else:
                conversation.append({"role": m.role, "content": m.content})

        kwargs: dict = {
            "model": self._model,
            "messages": conversation,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_content:
            kwargs["system"] = system_content.strip()
        if tools:
            kwargs["tools"] = tools

        response = await self._client.messages.create(**kwargs)

        content = ""
        for block in response.content:
            if block.type == "text":
                content += block.text

        return LLMResponse(
            content=content,
            model=response.model,
            usage={
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
            },
        )
