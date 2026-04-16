"""Custom Rules Example.

Demonstrates how to define custom security rules using the YAML DSL
and the REST API.

Run with: python examples/custom_rules.py
"""

import asyncio

import httpx

BASE_URL = "http://localhost:8000/api/v1"


async def main():
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        # 1. List existing rules
        resp = await client.get("/rules")
        rules = resp.json()
        print(f"Existing rules: {rules['total']}")

        # 2. Create a custom rule via API
        custom_rule = {
            "name": "block_competitor_emails",
            "description": "Prevent sending emails to competitor domains",
            "when": {
                "tool": "send_email",
                "params": {"to": {"matches": r".*@(competitor1|competitor2|rival)\.com$"}},
            },
            "action": "BLOCK",
            "reason": "Sending to competitor domains is prohibited by company policy",
        }

        resp = await client.post("/rules", json=custom_rule)
        if resp.status_code == 201:
            print(f"Created rule: {resp.json()['name']}")
        else:
            print(f"Rule creation failed: {resp.text}")

        # 3. Validate a rule before creating it
        test_rule = {
            "name": "restrict_production_access",
            "when": {
                "tool": ["deploy", "rollback", "scale"],
                "trust_level": ["EXTERNAL", "UNTRUSTED"],
                "params": {"env": {"in": ["production", "prod"]}},
            },
            "action": "BLOCK",
            "reason": "Production operations not allowed from external sources",
        }

        resp = await client.post("/rules/validate", json=test_rule)
        result = resp.json()
        print(f"Validation: valid={result['valid']}")

        if result["valid"]:
            resp = await client.post("/rules", json=test_rule)
            print(f"Created rule: {resp.json()['name']}")

        # 4. Create rules in batch
        batch = [
            {
                "name": "confirm_large_exports",
                "when": {
                    "tool": "export_data",
                    "params": {"limit": {"gt": 1000}},
                },
                "action": "REQUIRE_CONFIRMATION",
                "reason": "Large data exports need approval",
            },
            {
                "name": "block_after_hours",
                "when": {
                    "tool_category": "send",
                    "conditions": [{"type": "time_range", "outside": "09:00-18:00"}],
                },
                "action": "BLOCK",
                "reason": "Sending operations blocked outside business hours",
            },
        ]

        resp = await client.post("/rules/batch", json=batch)
        if resp.status_code == 201:
            print(f"Batch created: {resp.json()['total']} rules")

        # 5. Test with a check call
        session = await client.post("/sessions", json={"user_message": "Send quarterly report"})
        sid = session.json()["session_id"]

        check = await client.post(
            "/check",
            json={
                "session_id": sid,
                "tool_name": "send_email",
                "params": {"to": "ceo@competitor1.com", "body": "secret data"},
                "source_id": "user_input",
            },
        )
        result = check.json()
        print(f"\nCheck result: action={result['action']}")
        print(f"  Reason: {result.get('reason', 'n/a')}")
        print(f"  Engine: {result.get('engine', 'n/a')}")
        print(f"  Trust:  {result.get('trust_level', 'n/a')}")


if __name__ == "__main__":
    asyncio.run(main())
