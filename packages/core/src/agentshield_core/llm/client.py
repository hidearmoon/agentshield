"""LLM client abstraction — provider-agnostic interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class LLMMessage:
    role: str  # system | user | assistant
    content: str


@dataclass
class LLMResponse:
    content: str
    model: str
    usage: dict[str, int]  # prompt_tokens, completion_tokens, total_tokens


class LLMClient(ABC):
    """Abstract LLM client interface."""

    @abstractmethod
    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse: ...

    async def extract_json(self, messages: list[LLMMessage]) -> str:
        """Chat with JSON output mode, no tools."""
        response = await self.chat(messages, tools=None, temperature=0.0)
        return response.content
