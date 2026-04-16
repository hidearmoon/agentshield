"""Policy management service with version history."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from agentshield_console.storage.postgres import Policy, PolicyRule


async def list_policies(
    db: AsyncSession,
    active_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    stmt = select(Policy).options(selectinload(Policy.rules)).order_by(Policy.name, Policy.version.desc())
    if active_only:
        stmt = stmt.where(Policy.is_active.is_(True))
    stmt = stmt.limit(limit).offset(offset)
    result = await db.execute(stmt)
    policies = result.scalars().all()
    return [_policy_to_dict(p) for p in policies]


async def get_policy(db: AsyncSession, policy_id: uuid.UUID) -> dict[str, Any] | None:
    stmt = select(Policy).options(selectinload(Policy.rules)).where(Policy.id == policy_id)
    result = await db.execute(stmt)
    policy = result.scalar_one_or_none()
    return _policy_to_dict(policy) if policy else None


async def get_policy_versions(db: AsyncSession, name: str) -> list[dict[str, Any]]:
    stmt = select(Policy).options(selectinload(Policy.rules)).where(Policy.name == name).order_by(Policy.version.desc())
    result = await db.execute(stmt)
    return [_policy_to_dict(p) for p in result.scalars().all()]


async def create_policy(
    db: AsyncSession,
    name: str,
    content: dict,
    rules: list[dict],
    created_by: uuid.UUID | None = None,
) -> dict[str, Any]:
    # Determine next version number
    max_ver = await db.execute(select(func.coalesce(func.max(Policy.version), 0)).where(Policy.name == name))
    next_version = max_ver.scalar() + 1  # type: ignore[operator]

    policy = Policy(
        name=name,
        version=next_version,
        content=content,
        is_active=False,
        rollout_percentage=100,
        created_by=created_by,
    )

    for r in rules:
        policy.rules.append(
            PolicyRule(
                rule_name=r["rule_name"],
                rule_type=r.get("rule_type", "custom"),
                condition=r["condition"],
                action=r["action"],
                priority=r.get("priority", 0),
                enabled=r.get("enabled", True),
            )
        )

    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return _policy_to_dict(policy)


async def update_policy(
    db: AsyncSession,
    policy_id: uuid.UUID,
    updates: dict[str, Any],
) -> dict[str, Any] | None:
    stmt = select(Policy).options(selectinload(Policy.rules)).where(Policy.id == policy_id)
    result = await db.execute(stmt)
    policy = result.scalar_one_or_none()
    if not policy:
        return None

    for field in ("is_active", "rollout_percentage", "content"):
        if field in updates:
            setattr(policy, field, updates[field])

    if "rules" in updates:
        policy.rules.clear()
        for r in updates["rules"]:
            policy.rules.append(
                PolicyRule(
                    rule_name=r["rule_name"],
                    rule_type=r.get("rule_type", "custom"),
                    condition=r["condition"],
                    action=r["action"],
                    priority=r.get("priority", 0),
                    enabled=r.get("enabled", True),
                )
            )

    await db.commit()
    await db.refresh(policy)
    return _policy_to_dict(policy)


async def activate_policy(db: AsyncSession, policy_id: uuid.UUID) -> dict[str, Any] | None:
    stmt = select(Policy).options(selectinload(Policy.rules)).where(Policy.id == policy_id)
    result = await db.execute(stmt)
    policy = result.scalar_one_or_none()
    if not policy:
        return None

    # Deactivate other versions of the same policy
    others = await db.execute(
        select(Policy).where(Policy.name == policy.name, Policy.id != policy_id, Policy.is_active.is_(True))
    )
    for other in others.scalars():
        other.is_active = False

    policy.is_active = True
    await db.commit()
    await db.refresh(policy)
    return _policy_to_dict(policy)


async def simulate_policy(content: dict, rules: list[dict], test_input: dict) -> dict[str, Any]:
    """Dry-run a policy against a test input. Returns simulated decisions."""
    decisions: list[dict[str, Any]] = []

    for rule in sorted(rules, key=lambda r: r.get("priority", 0), reverse=True):
        matched = _evaluate_condition(rule.get("condition", {}), test_input)
        decisions.append(
            {
                "rule_name": rule.get("rule_name", "unnamed"),
                "matched": matched,
                "action": rule.get("action", "ALLOW") if matched else None,
            }
        )

    final_action = "ALLOW"
    for d in decisions:
        if d["matched"] and d["action"] == "BLOCK":
            final_action = "BLOCK"
            break
        if d["matched"] and d["action"] == "REQUIRE_CONFIRMATION":
            final_action = "REQUIRE_CONFIRMATION"

    return {
        "final_action": final_action,
        "rule_evaluations": decisions,
        "test_input": test_input,
    }


def _evaluate_condition(condition: dict, test_input: dict) -> bool:
    """Simple condition evaluator for simulation."""
    op = condition.get("operator", "equals")
    field = condition.get("field", "")
    value = condition.get("value")
    actual = test_input.get(field)

    if op == "equals":
        return actual == value
    if op == "contains":
        return isinstance(actual, str) and isinstance(value, str) and value in actual
    if op == "gt":
        return isinstance(actual, (int, float)) and isinstance(value, (int, float)) and actual > value
    if op == "lt":
        return isinstance(actual, (int, float)) and isinstance(value, (int, float)) and actual < value
    if op == "in":
        return actual in (value if isinstance(value, list) else [value])
    if op == "regex":
        import re

        return bool(re.search(str(value), str(actual))) if actual else False
    return False


def _policy_to_dict(policy: Policy) -> dict[str, Any]:
    return {
        "id": str(policy.id),
        "name": policy.name,
        "version": policy.version,
        "content": policy.content,
        "is_active": policy.is_active,
        "rollout_percentage": policy.rollout_percentage,
        "created_by": str(policy.created_by) if policy.created_by else None,
        "created_at": policy.created_at.isoformat() if policy.created_at else None,
        "rules": [
            {
                "id": str(r.id),
                "rule_name": r.rule_name,
                "rule_type": r.rule_type,
                "condition": r.condition,
                "action": r.action,
                "priority": r.priority,
                "enabled": r.enabled,
            }
            for r in policy.rules
        ],
    }
