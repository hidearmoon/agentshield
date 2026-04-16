"""LangChain Integration Example.

Demonstrates how to wrap a LangChain agent with AgentShield
so every tool call is security-checked before execution.

Prerequisites:
    pip install langchain langchain-openai agentshield

Usage:
    export AGENTSHIELD_API_KEY=your-key
    export OPENAI_API_KEY=your-key
    python examples/langchain_integration.py
"""

import asyncio

from agentshield import Shield, ServerError


async def main():
    # In a real scenario, you'd have LangChain tools and an agent.
    # This example shows the pattern without requiring LangChain installed.

    shield = Shield(api_key="demo-key")

    # Pattern 1: Using the guard decorator on tool functions
    print("=== Pattern 1: Guard Decorator ===")

    @shield.guard
    async def search_web(query: str) -> str:
        """Search the web for information."""
        return f"Search results for: {query}"

    @shield.guard
    async def send_email(to: str, body: str) -> str:
        """Send an email."""
        return f"Email sent to {to}"

    try:
        # This would work if AgentShield server is running
        result = await search_web(query="weather today")
        print(f"Search: {result}")
    except ServerError:
        print("Server not running — that's OK for this demo")

    # Pattern 2: Using the LangChain integration wrapper
    print("\n=== Pattern 2: LangChain Wrapper ===")
    print("""
    from langchain.agents import AgentExecutor
    from agentshield.integrations import LangChainShield

    shield = Shield()
    agent = AgentExecutor(agent=..., tools=[search, email])

    # Wrap the agent — all tool calls now go through AgentShield
    guarded_agent = LangChainShield(shield).wrap(agent)

    # Use normally — security is transparent
    result = await guarded_agent.ainvoke({"input": "Summarize my emails"})
    """)

    # Pattern 3: Manual check before execution
    print("=== Pattern 3: Manual Check ===")
    print("""
    result = await shield.check("send_email", {"to": "user@test.com"})
    if result.action == Decision.ALLOW:
        await send_email(to="user@test.com", body="Hello")
    elif result.action == Decision.BLOCK:
        print(f"Blocked: {result.reason}")
    """)

    await shield.close()


if __name__ == "__main__":
    asyncio.run(main())
