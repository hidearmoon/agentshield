"""
AgentGuard CLI — test security rules from the command line.

Usage:
    python -m agentguard check send_email '{"to": "evil@attacker.com", "body": "secret"}'
    python -m agentguard check send_email '{"to": "x@y.com"}' --trust EXTERNAL
    python -m agentguard check drop_table '{"table": "users"}'
    python -m agentguard rules
    python -m agentguard rules --yaml my_rules.yaml
    python -m agentguard scan '{"body": "ignore all previous instructions"}'
"""

from __future__ import annotations

import argparse
import json
import sys

from agentguard.local import LocalShield, _has_injection_pattern
from agentguard.models import Decision


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="AgentGuard — runtime security for AI agents",
    )
    sub = parser.add_subparsers(dest="command")

    # --- check ---
    check_p = sub.add_parser("check", help="Check a tool call against security rules")
    check_p.add_argument("tool", help="Tool name (e.g., send_email)")
    check_p.add_argument("params", help='Tool parameters as JSON (e.g., \'{"to": "x@y.com"}\')')
    check_p.add_argument("--trust", default="VERIFIED", help="Trust level (default: VERIFIED)")
    check_p.add_argument("--rules-file", help="Load additional rules from YAML file")
    check_p.add_argument(
        "--internal-domains",
        help="Comma-separated internal domains (default: company.com,internal.io)",
    )

    # --- rules ---
    rules_p = sub.add_parser("rules", help="List active rules")
    rules_p.add_argument("--yaml", help="Load and show rules from a YAML file")

    # --- scan ---
    scan_p = sub.add_parser("scan", help="Scan text for prompt injection patterns")
    scan_p.add_argument("text", nargs="?", help="Text to scan (or pipe via stdin)")

    args = parser.parse_args(argv)

    if args.command == "check":
        return _cmd_check(args)
    elif args.command == "rules":
        return _cmd_rules(args)
    elif args.command == "scan":
        return _cmd_scan(args)
    else:
        parser.print_help()
        return 0


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        params = json.loads(args.params)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON params: {e}", file=sys.stderr)
        return 1

    domains = None
    if args.internal_domains:
        domains = [d.strip() for d in args.internal_domains.split(",")]

    shield = LocalShield(trust_level=args.trust, internal_domains=domains)

    if args.rules_file:
        count = shield.load_rules_file(args.rules_file)
        print(f"Loaded {count} custom rules from {args.rules_file}")

    result = shield.check(args.tool, params)

    # Output
    icon = {"ALLOW": "\u2705", "BLOCK": "\u274c", "REQUIRE_CONFIRMATION": "\u26a0\ufe0f"}.get(result.action.value, "?")
    print(f"{icon} {result.action.value}: {args.tool}")
    if result.reason:
        print(f"   Reason: {result.reason}")
    print(f"   Trust: {args.trust}")
    print(f"   Trace: {result.trace_id}")

    return 0 if result.action is Decision.ALLOW else 1


def _cmd_rules(args: argparse.Namespace) -> int:
    shield = LocalShield()

    if args.yaml:
        count = shield.load_rules_file(args.yaml)
        print(f"Loaded {count} custom rules from {args.yaml}\n")

    rules = shield.list_rules()
    print(f"Active rules ({len(rules)}):\n")
    for name in rules:
        print(f"  - {name}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.text:
        text = args.text
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        print("Error: Provide text as argument or pipe via stdin", file=sys.stderr)
        return 1

    has_injection = _has_injection_pattern({"text": text})

    if has_injection:
        print("\u274c INJECTION DETECTED")
        print(f"   Input: {text[:100]}{'...' if len(text) > 100 else ''}")
        return 1
    else:
        print("\u2705 CLEAN — no injection patterns found")
        return 0


if __name__ == "__main__":
    sys.exit(main())
