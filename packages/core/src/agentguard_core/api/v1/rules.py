"""Custom rule management endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException

from agentguard_core.dependencies import get_rule_engine
from agentguard_core.engine.intent.rule_engine import RuleEngine
from agentguard_core.policy.dsl import load_rules_from_dict, RuleDSLError

router = APIRouter(prefix="/rules")


class RuleDefinition(BaseModel):
    """User-defined rule in DSL format."""

    name: str
    description: str = ""
    enabled: bool = True
    when: dict = Field(default_factory=dict)
    action: str = "BLOCK"  # BLOCK | REQUIRE_CONFIRMATION | ALLOW
    reason: str = ""

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "name": "block_email_to_competitors",
                    "description": "Block sending emails to competitor domains",
                    "when": {
                        "tool": "send_email",
                        "trust_level": ["EXTERNAL", "UNTRUSTED"],
                        "params": {"to": {"matches": ".*@(competitor1|competitor2)\\.com$"}},
                    },
                    "action": "BLOCK",
                    "reason": "Sending to competitor domain is prohibited",
                }
            ]
        }
    }


class RuleResponse(BaseModel):
    name: str
    description: str
    enabled: bool
    type: str  # builtin | custom


class RuleListResponse(BaseModel):
    rules: list[RuleResponse]
    total: int


@router.get("", response_model=RuleListResponse)
async def list_rules(
    engine: RuleEngine = Depends(get_rule_engine),
) -> RuleListResponse:
    """List all rules (builtin + custom)."""
    rules = engine.list_rules()
    return RuleListResponse(
        rules=[RuleResponse(**r) for r in rules],
        total=len(rules),
    )


@router.post("", response_model=RuleResponse, status_code=201)
async def create_rule(
    rule_def: RuleDefinition,
    engine: RuleEngine = Depends(get_rule_engine),
) -> RuleResponse:
    """Create a custom rule using the DSL."""
    try:
        parsed = load_rules_from_dict([rule_def.model_dump()])
    except RuleDSLError as e:
        raise HTTPException(status_code=422, detail=str(e))

    if not parsed:
        raise HTTPException(status_code=422, detail="Failed to parse rule")

    engine.add_rule(parsed[0])
    return RuleResponse(
        name=rule_def.name,
        description=rule_def.description,
        enabled=rule_def.enabled,
        type="custom",
    )


@router.post("/batch", response_model=RuleListResponse, status_code=201)
async def create_rules_batch(
    rule_defs: list[RuleDefinition],
    engine: RuleEngine = Depends(get_rule_engine),
) -> RuleListResponse:
    """Create multiple custom rules at once."""
    try:
        parsed = load_rules_from_dict([r.model_dump() for r in rule_defs])
    except RuleDSLError as e:
        raise HTTPException(status_code=422, detail=str(e))

    engine.add_rules(parsed)
    return RuleListResponse(
        rules=[RuleResponse(name=r.name, description=r.description, enabled=r.enabled, type="custom") for r in parsed],
        total=len(parsed),
    )


@router.delete("/{rule_name}")
async def delete_rule(
    rule_name: str,
    engine: RuleEngine = Depends(get_rule_engine),
) -> dict:
    """Delete a custom rule by name. Built-in rules cannot be deleted but can be disabled."""
    # Check if it's a builtin
    rules = engine.list_rules()
    for r in rules:
        if r["name"] == rule_name and r["type"] == "builtin":
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete built-in rule '{rule_name}'. Use PATCH to disable it instead.",
            )

    if engine.remove_rule(rule_name):
        return {"deleted": rule_name}
    raise HTTPException(status_code=404, detail=f"Rule '{rule_name}' not found")


@router.patch("/{rule_name}/enabled")
async def toggle_rule(
    rule_name: str,
    enabled: bool,
    engine: RuleEngine = Depends(get_rule_engine),
) -> dict:
    """Enable or disable a rule (works for both builtin and custom)."""
    if engine.set_rule_enabled(rule_name, enabled):
        return {"name": rule_name, "enabled": enabled}
    raise HTTPException(status_code=404, detail=f"Rule '{rule_name}' not found")


@router.post("/validate")
async def validate_rule(rule_def: RuleDefinition) -> dict:
    """Validate a rule definition without creating it. Useful for the UI editor."""
    try:
        parsed = load_rules_from_dict([rule_def.model_dump()])
        return {"valid": True, "name": parsed[0].name}
    except RuleDSLError as e:
        return {"valid": False, "error": str(e)}
