"""Layer 3: Semantic intent consistency check — LLM-powered, only triggered when suspicious."""

from __future__ import annotations

import json

from agentguard_core.engine.intent.models import ToolCall, IntentContext, Decision
from agentguard_core.llm.client import LLMClient, LLMMessage


class SemanticChecker:
    """
    Layer 3: LLM-based semantic intent consistency check.
    Only called when anomaly score is between SUSPICIOUS_THRESHOLD and ANOMALY_THRESHOLD.
    Cost: 500ms-2s per call.
    """

    def __init__(self, llm_client: LLMClient):
        self._llm = llm_client

    async def check(self, tool_call: ToolCall, context: IntentContext) -> Decision:
        prompt = self._build_prompt(tool_call, context)

        response = await self._llm.extract_json(
            [
                LLMMessage(
                    role="system",
                    content=(
                        "You are a security analyzer. Determine if a tool call is consistent "
                        "with the user's original intent. Respond with JSON:\n"
                        '{"consistent": true/false, "confidence": 0.0-1.0, "reason": "..."}'
                    ),
                ),
                LLMMessage(role="user", content=prompt),
            ]
        )

        return self._parse_response(response)

    def _build_prompt(self, tc: ToolCall, ctx: IntentContext) -> str:
        recent_tools = [h.name for h in ctx.tool_call_history[-5:]]
        return (
            f'Original user request: "{ctx.original_message}"\n'
            f"Extracted intent: {ctx.intent.intent}\n"
            f"Expected tool categories: {ctx.allowed_tool_categories}\n"
            f"Recent tool calls: {recent_tools}\n"
            f"Current data trust level: {ctx.current_data_trust_level}\n\n"
            f"New tool call to evaluate:\n"
            f"  Tool: {tc.name}\n"
            f"  Parameters: {json.dumps(tc.params, default=str)}\n\n"
            f"Is this tool call consistent with the user's original intent?"
        )

    @staticmethod
    def _parse_response(response: str) -> Decision:
        try:
            data = json.loads(response)
            consistent = data.get("consistent", True)
            confidence = data.get("confidence", 0.5)
            reason = data.get("reason", "")

            if not consistent and confidence > 0.7:
                return Decision.block(
                    reason=f"Semantic check: {reason}",
                    engine="semantic",
                )
            elif not consistent:
                return Decision.require_confirmation(
                    reason=f"Semantic check (low confidence): {reason}",
                    engine="semantic",
                )
            return Decision.allow()
        except (json.JSONDecodeError, KeyError):
            # If LLM response is unparseable, fail open (allow)
            return Decision.allow()
