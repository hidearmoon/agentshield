"""AgentGuard Harness — secure agent execution runtime.

The harness IS the agent loop. Tools are registered with it, and every
tool call goes through security checks before execution. The LLM never
directly executes anything — the harness controls all side effects.

Usage::

    from agentguard_core.harness import AgentHarness

    async def send_email(to: str, body: str) -> str:
        return f"Email sent to {to}"

    async def query_db(sql: str) -> str:
        return f"Results for: {sql}"

    harness = AgentHarness(
        llm=your_llm_client,
        tools=[send_email, query_db],
    )

    result = await harness.run("帮我处理邮件并回复")
    print(result.final_answer)
    print(result.trace)  # Every tool call + decision
"""

from __future__ import annotations

import inspect
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine

from agentguard_core.engine.intent.anomaly import AnomalyDetector
from agentguard_core.engine.intent.engine import IntentConsistencyEngine
from agentguard_core.engine.intent.models import Decision, DecisionAction, Intent, IntentContext, ToolCall
from agentguard_core.engine.intent.rule_engine import RuleEngine
from agentguard_core.engine.intent.semantic import SemanticChecker
from agentguard_core.engine.permissions.dynamic import DynamicPermissionEngine
from agentguard_core.engine.sanitization.format_cleansing import FormatCleansingStage
from agentguard_core.engine.trust.levels import TrustLevel
from agentguard_core.engine.trust.marker import TrustMarker, TrustPolicy
from agentguard_core.llm.client import LLMClient, LLMMessage, LLMResponse

logger = logging.getLogger(__name__)


@dataclass
class ToolDef:
    """Registered tool definition."""

    name: str
    description: str
    parameters: dict[str, Any]
    func: Callable[..., Coroutine[Any, Any, Any]]
    category: str = ""
    sensitivity: str = "medium"  # low | medium | high | critical


@dataclass
class StepResult:
    """One step in the agent execution."""

    tool_name: str
    tool_params: dict[str, Any]
    decision: str  # ALLOW | BLOCK | REQUIRE_CONFIRMATION
    decision_reason: str
    tool_output: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class HarnessResult:
    """Final result of a harness.run() call."""

    final_answer: str
    steps: list[StepResult] = field(default_factory=list)
    blocked_count: int = 0
    allowed_count: int = 0

    @property
    def trace(self) -> list[dict]:
        return [
            {
                "tool": s.tool_name,
                "params": s.tool_params,
                "decision": s.decision,
                "reason": s.decision_reason,
                "output": s.tool_output[:100] if s.tool_output else None,
            }
            for s in self.steps
        ]


class AgentHarness:
    """Secure agent execution harness.

    Controls the entire agent loop:
    1. Send user message + tool definitions to LLM
    2. LLM returns tool_use or final answer
    3. Harness checks tool call against security policies
    4. If ALLOW → execute tool, feed result back to LLM
    5. If BLOCK → tell LLM the call was rejected
    6. Loop until LLM gives final text answer

    The LLM never executes anything directly. The harness is the
    only code path that can invoke tool functions.
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: list[Callable] | None = None,
        tool_defs: list[ToolDef] | None = None,
        policy: TrustPolicy | None = None,
        source_id: str = "user_input",
        max_steps: int = 20,
        on_block: Callable | None = None,
    ):
        self._llm = llm
        self._source_id = source_id
        self._max_steps = max_steps
        self._on_block = on_block

        # Register tools
        self._tools: dict[str, ToolDef] = {}
        if tool_defs:
            for td in tool_defs:
                self._tools[td.name] = td
        if tools:
            for func in tools:
                td = self._func_to_tool_def(func)
                self._tools[td.name] = td

        # Security components
        self._trust_marker = TrustMarker(policy or TrustPolicy())
        self._rule_engine = RuleEngine()
        self._anomaly_detector = AnomalyDetector()
        self._sanitizer = FormatCleansingStage()
        self._permission_engine = DynamicPermissionEngine()

    @staticmethod
    def _func_to_tool_def(func: Callable) -> ToolDef:
        """Auto-generate a ToolDef from a function signature."""
        sig = inspect.signature(func)
        params = {}
        for name, param in sig.parameters.items():
            annotation = param.annotation
            ptype = "string"
            if annotation == int:
                ptype = "integer"
            elif annotation == float:
                ptype = "number"
            elif annotation == bool:
                ptype = "boolean"
            params[name] = {"type": ptype}

        return ToolDef(
            name=func.__name__,
            description=inspect.getdoc(func) or func.__name__,
            parameters=params,
            func=func,
        )

    def _build_tools_for_llm(self) -> list[dict]:
        """Build OpenAI-compatible tool definitions for the LLM."""
        return [
            {
                "type": "function",
                "function": {
                    "name": td.name,
                    "description": td.description,
                    "parameters": {
                        "type": "object",
                        "properties": td.parameters,
                    },
                },
            }
            for td in self._tools.values()
        ]

    def _check_tool_call(self, tool_name: str, params: dict, trust_level: TrustLevel) -> Decision:
        """Run security checks on a tool call. This is the core security gate."""
        tc = ToolCall(name=tool_name, params=params)
        ctx = IntentContext(
            original_message="",
            intent=Intent(intent=""),
            current_data_trust_level=trust_level,
        )

        # Layer 1: Rule engine
        rule_result = self._rule_engine.check(tc, ctx)
        if rule_result.is_definitive:
            return rule_result.decision

        # Layer 2: Permission check
        tool_names = list(self._tools.keys())
        available = self._permission_engine.get_available_tools(
            trust_level=trust_level,
            agent_tools=tool_names,
        )
        if available and tool_name not in available:
            return Decision.block(
                reason=f"Tool '{tool_name}' not permitted at trust level {trust_level.name}",
                engine="permission",
            )

        # Layer 3: Anomaly detection
        anomaly = self._anomaly_detector.check(tc, ctx)
        if anomaly.score >= 0.85:
            return Decision.block(reason=f"Anomaly detected: {anomaly.reason}", engine="anomaly")

        return Decision.allow()

    def _parse_tool_call(self, content: str) -> tuple[str, dict] | None:
        """Try to parse a tool call from LLM response.

        Supports both OpenAI function_call format and plain JSON.
        """
        try:
            data = json.loads(content)
            if isinstance(data, dict) and "name" in data:
                return data["name"], data.get("arguments", data.get("params", {}))
        except (json.JSONDecodeError, KeyError):
            pass
        return None

    async def run(
        self,
        user_message: str,
        source_id: str | None = None,
    ) -> HarnessResult:
        """Run the agent loop with full security enforcement.

        This is the main entry point. The harness:
        1. Sends user message to LLM with available tools
        2. Intercepts every tool call for security check
        3. Executes allowed tools, blocks dangerous ones
        4. Returns final answer with full execution trace
        """
        src = source_id or self._source_id
        trust_level = self._trust_marker.compute_trust_level(src)
        tools_schema = self._build_tools_for_llm()
        result = HarnessResult(final_answer="")

        messages = [
            LLMMessage(role="system", content=self._build_system_prompt()),
            LLMMessage(role="user", content=user_message),
        ]

        for step in range(self._max_steps):
            # Call LLM
            response = await self._llm.chat(messages=messages, tools=tools_schema)

            # Check if LLM wants to call a tool
            parsed = self._parse_tool_call(response.content)

            if parsed is None:
                # LLM gave a final text answer — we're done
                result.final_answer = response.content
                break

            tool_name, tool_params = parsed

            # === SECURITY GATE — this is where the harness enforces safety ===
            decision = self._check_tool_call(tool_name, tool_params, trust_level)

            step_result = StepResult(
                tool_name=tool_name,
                tool_params=tool_params,
                decision=decision.action.value,
                decision_reason=decision.reason,
            )

            if decision.action == DecisionAction.BLOCK:
                logger.warning("Harness BLOCKED: tool=%s reason=%s", tool_name, decision.reason)
                result.blocked_count += 1

                if self._on_block:
                    try:
                        await self._on_block(tool_name, decision.reason)
                    except Exception:
                        pass

                # Tell LLM the call was rejected
                messages.append(LLMMessage(role="assistant", content=response.content))
                messages.append(
                    LLMMessage(
                        role="user",
                        content=f"[SECURITY] Tool call '{tool_name}' was blocked: {decision.reason}. "
                        f"Please find an alternative approach or explain to the user why this action cannot be performed.",
                    )
                )
            elif decision.action == DecisionAction.ALLOW:
                # Execute the tool
                tool_def = self._tools.get(tool_name)
                if tool_def is None:
                    step_result.tool_output = f"Error: Unknown tool '{tool_name}'"
                else:
                    try:
                        output = await tool_def.func(**tool_params)
                        step_result.tool_output = str(output)
                        result.allowed_count += 1
                    except Exception as e:
                        step_result.tool_output = f"Error: {e}"

                messages.append(LLMMessage(role="assistant", content=response.content))
                messages.append(
                    LLMMessage(
                        role="user",
                        content=f"[Tool result for {tool_name}]: {step_result.tool_output}",
                    )
                )
            else:
                # REQUIRE_CONFIRMATION — treat as block in harness mode
                # (confirmation flow can be added via callback)
                step_result.decision = "REQUIRE_CONFIRMATION"
                messages.append(LLMMessage(role="assistant", content=response.content))
                messages.append(
                    LLMMessage(
                        role="user",
                        content=f"[SECURITY] Tool call '{tool_name}' requires human confirmation and was held. "
                        f"Reason: {decision.reason}",
                    )
                )

            result.steps.append(step_result)

        if not result.final_answer:
            result.final_answer = "(Agent reached maximum steps without a final answer)"

        return result

    def _build_system_prompt(self) -> str:
        return (
            "You are a helpful assistant with access to tools. "
            "Use the provided tools to help the user. "
            "When you want to call a tool, respond with JSON: "
            '{"name": "tool_name", "arguments": {"param": "value"}}. '
            "When you have the final answer, respond with plain text (no JSON)."
        )
