"""Integration tests for PostgreSQL storage layer.

Requires a running PostgreSQL instance on localhost:5433.
"""

from __future__ import annotations

import uuid

import pytest

try:
    import asyncpg  # noqa: F401

    _conn_ok = True
except ImportError:
    _conn_ok = False

PG_URL = "postgresql+asyncpg://agentshield:test-password@localhost:5433/agentshield_test"

pytestmark = pytest.mark.skipif(not _conn_ok, reason="asyncpg not available")


@pytest.fixture(autouse=True)
def set_pg_url(monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_DATABASE_URL", PG_URL)


@pytest.fixture
async def db():
    """Initialize DB and yield a session."""
    # Re-import to pick up env var
    from importlib import reload
    import agentshield_core.config

    reload(agentshield_core.config)
    import agentshield_core.storage.postgres as pg_mod

    # Create new engine with test URL
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    test_engine = create_async_engine(PG_URL, echo=False, pool_size=5)
    test_session = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    # Create tables
    async with test_engine.begin() as conn:
        await conn.run_sync(pg_mod.Base.metadata.create_all)

    async with test_session() as session:
        yield session

    await test_engine.dispose()


class TestAgentCRUD:
    @pytest.mark.asyncio
    async def test_create_and_read_agent(self, db):
        from agentshield_core.storage.postgres import Agent

        agent = Agent(
            agent_id=f"test-agent-{uuid.uuid4().hex[:8]}",
            name="Test Agent",
            description="A test agent",
            allowed_tools=["summarize", "read"],
        )
        db.add(agent)
        await db.commit()
        await db.refresh(agent)

        assert agent.id is not None
        assert agent.name == "Test Agent"
        assert "summarize" in agent.allowed_tools

    @pytest.mark.asyncio
    async def test_query_agent(self, db):
        from sqlalchemy import select
        from agentshield_core.storage.postgres import Agent

        agent_id = f"query-agent-{uuid.uuid4().hex[:8]}"
        db.add(Agent(agent_id=agent_id, name="Query Agent"))
        await db.commit()

        result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
        found = result.scalar_one_or_none()
        assert found is not None
        assert found.name == "Query Agent"


class TestPolicyCRUD:
    @pytest.mark.asyncio
    async def test_create_policy_with_rules(self, db):
        from agentshield_core.storage.postgres import Policy, PolicyRule

        policy = Policy(
            name=f"test-policy-{uuid.uuid4().hex[:8]}",
            version=1,
            content={"description": "Test policy"},
            signature=b"test-sig",
            is_active=True,
        )
        policy.rules.append(
            PolicyRule(
                rule_name="block_evil",
                rule_type="custom",
                condition={"tool": "evil_tool"},
                action="BLOCK",
            )
        )
        db.add(policy)
        await db.commit()

        # Re-query with eager loading to access rules
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        result = await db.execute(select(Policy).options(selectinload(Policy.rules)).where(Policy.id == policy.id))
        loaded = result.scalar_one()
        assert loaded.id is not None
        assert len(loaded.rules) == 1
        assert loaded.rules[0].rule_name == "block_evil"

    @pytest.mark.asyncio
    async def test_policy_version_uniqueness(self, db):
        from agentshield_core.storage.postgres import Policy
        from sqlalchemy.exc import IntegrityError

        unique_name = f"unique-{uuid.uuid4().hex[:8]}"
        p1 = Policy(name=unique_name, version=1, content={}, signature=b"s1")
        db.add(p1)
        await db.commit()

        p2 = Policy(name=unique_name, version=1, content={}, signature=b"s2")
        db.add(p2)
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()


class TestUserCRUD:
    @pytest.mark.asyncio
    async def test_create_user(self, db):
        from agentshield_core.storage.postgres import User

        user = User(
            email=f"test-{uuid.uuid4().hex[:8]}@example.com",
            name="Test User",
            role="admin",
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

        assert user.id is not None
        assert user.role == "admin"
