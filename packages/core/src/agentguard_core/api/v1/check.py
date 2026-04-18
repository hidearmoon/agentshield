"""POST /api/v1/check — Main tool call interception endpoint."""

from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends

from agentguard_core.dependencies import get_pipeline
from agentguard_core.engine.pipeline import Pipeline

router = APIRouter()


class CheckRequest(BaseModel):
    session_id: str
    tool_name: str
    params: dict = Field(default_factory=dict)
    sdk_version: str = ""
    source_id: str = ""
    client_trust_level: str | None = None


class CheckResponse(BaseModel):
    action: str  # ALLOW | BLOCK | REQUIRE_CONFIRMATION
    reason: str = ""
    trace_id: str = ""
    span_id: str = ""
    engine: str = ""  # rule | anomaly | semantic | permission
    trust_level: str = ""  # Server-computed trust level


@router.post("/check", response_model=CheckResponse)
async def check_tool_call(
    request: CheckRequest,
    pipeline: Pipeline = Depends(get_pipeline),
) -> CheckResponse:
    result = await pipeline.check_tool_call(
        session_id=request.session_id,
        tool_name=request.tool_name,
        tool_params=request.params,
        source_id=request.source_id,
        client_trust_level=request.client_trust_level,
    )
    return CheckResponse(
        action=result.action,
        reason=result.reason,
        trace_id=result.trace_id,
        span_id=result.span_id,
        engine=result.engine,
        trust_level=result.trust_level,
    )


class BatchCheckRequest(BaseModel):
    session_id: str
    checks: list[CheckRequest]


class BatchCheckResponse(BaseModel):
    results: list[CheckResponse]
    all_allowed: bool


@router.post("/check/batch", response_model=BatchCheckResponse)
async def batch_check_tool_calls(
    request: BatchCheckRequest,
    pipeline: Pipeline = Depends(get_pipeline),
) -> BatchCheckResponse:
    """Check multiple tool calls at once. Useful for planning phases."""
    results = []
    for check in request.checks:
        result = await pipeline.check_tool_call(
            session_id=request.session_id,
            tool_name=check.tool_name,
            tool_params=check.params,
            source_id=check.source_id,
            client_trust_level=check.client_trust_level,
        )
        results.append(
            CheckResponse(
                action=result.action,
                reason=result.reason,
                trace_id=result.trace_id,
                span_id=result.span_id,
                engine=result.engine,
                trust_level=result.trust_level,
            )
        )
    return BatchCheckResponse(
        results=results,
        all_allowed=all(r.action == "ALLOW" for r in results),
    )


@router.post("/check/explain")
async def explain_check(
    request: CheckRequest,
    pipeline: Pipeline = Depends(get_pipeline),
) -> dict:
    """Explain what would happen for a tool call — which rules match and why.

    Useful for debugging and understanding why a tool call is blocked.
    Does NOT record a trace span (dry-run mode).
    """
    from agentguard_core.engine.intent.models import ToolCall, IntentContext, Intent

    # Compute trust level
    source_id = request.source_id or "unknown"
    trust_level = pipeline._trust_marker.compute_trust_level(source_id)

    # Check rules
    tc = ToolCall(name=request.tool_name, params=request.params)
    ctx = IntentContext(
        original_message="",
        intent=Intent(intent=""),
        current_data_trust_level=trust_level,
    )

    rule_engine = pipeline._intent_engine._rule_engine
    anomaly_detector = pipeline._intent_engine._anomaly_detector

    # Evaluate all rules
    rule_evaluations = []
    for rule in rule_engine._rules:
        if not rule.enabled:
            rule_evaluations.append({"name": rule.name, "enabled": False, "matched": False})
            continue
        try:
            matched = rule.condition(tc, ctx)
        except Exception:
            matched = False
        rule_evaluations.append(
            {
                "name": rule.name,
                "enabled": True,
                "matched": matched,
                "action": rule.decision.action.value if matched else None,
                "reason": rule.decision.reason if matched else None,
            }
        )

    # Anomaly score with feature breakdown
    features = anomaly_detector._extract_features(tc, ctx)
    anomaly_result = anomaly_detector.check(tc, ctx)

    # Permission engine check
    perm_engine = pipeline._permission_engine
    available = perm_engine.get_available_tools(trust_level=trust_level)
    perm_blocked = bool(available) and request.tool_name not in available

    return {
        "tool_name": request.tool_name,
        "source_id": source_id,
        "computed_trust_level": trust_level.name,
        "permission": {
            "blocked": perm_blocked,
            "reason": f"Tool not in allowlist for {trust_level.name}" if perm_blocked else "",
        },
        "anomaly": {
            "score": round(anomaly_result.score, 4),
            "reason": anomaly_result.reason,
            "features": {k: round(v, 4) for k, v in features.items()},
        },
        "rules_evaluated": len(rule_evaluations),
        "rules_matched": sum(1 for r in rule_evaluations if r.get("matched")),
        "rule_evaluations": [r for r in rule_evaluations if r.get("matched") or not r.get("enabled", True)],
    }
