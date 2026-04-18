"""OpenAI LLM provider."""

from __future__ import annotations

from openai import AsyncOpenAI

from agentguard_core.llm.client import LLMClient, LLMMessage, LLMResponse


class OpenAIClient(LLMClient):
    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        self._client = AsyncOpenAI(api_key=api_key)
        self._model = model

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        openai_messages = [{"role": m.role, "content": m.content} for m in messages]

        kwargs: dict = {
            "model": self._model,
            "messages": openai_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            kwargs["tools"] = tools

        response = await self._client.chat.completions.create(**kwargs)
        choice = response.choices[0]

        return LLMResponse(
            content=choice.message.content or "",
            model=response.model,
            usage={
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": response.usage.total_tokens if response.usage else 0,
            },
        )
