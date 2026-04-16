# Contributing to AgentShield

Thank you for your interest in contributing to AgentShield. This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful. Be constructive. Assume good intent. We are building security infrastructure — precision and clarity matter more than speed.

## Getting Started

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- Node.js 20+ (for console frontend)
- Docker & Docker Compose (for integration tests)

### Development Setup

```bash
# Clone the repository
git clone https://github.com/hidearmoon/agentshield.git
cd agentshield

# Start dependencies
make dev

# Install core engine dependencies
cd packages/core && uv sync --extra dev

# Install SDK dependencies
cd packages/sdk-python && uv sync --extra dev

# Install frontend dependencies
cd packages/console/frontend && npm install
```

### Running Tests

```bash
# Run the primary test suite (unit + security)
make test

# Run individual test suites
make test-unit          # 218 unit tests
make test-security      # 92 security tests
make test-integration   # Integration tests (requires Docker services)
make test-perf          # Performance benchmarks

# Run with coverage
make test-coverage
```

## How to Contribute

### Reporting Issues

- **Security vulnerabilities**: Please report security issues privately. Do NOT open a public issue. Email the maintainers directly.
- **Bugs**: Open an issue with a minimal reproduction case, your Python version, and the output of `uv pip list`.
- **Feature requests**: Open an issue describing the use case, not just the solution.

### Pull Requests

1. Fork the repository and create a branch from `main`.
2. If you've added code, add tests. Security-related changes require security tests in `packages/core/tests/security/`.
3. Ensure all tests pass: `make test`
4. Ensure code passes linting: `make lint`
5. Write a clear PR description explaining **why**, not just **what**.

### Commit Messages

Use conventional commits:

```
feat(core): add time-based condition to rule DSL
fix(sdk-python): handle connection timeout in guard decorator
test(security): add encoding bypass test for base64 payloads
docs: update trust model documentation
```

## Project Structure

| Package | Description | Language |
|---------|-------------|----------|
| `packages/core` | Security engine — the brain | Python (FastAPI) |
| `packages/proxy` | Transparent sidecar proxy | Python |
| `packages/console` | Management UI | React (frontend) + Python (backend) |
| `packages/sdk-python` | Python SDK | Python |
| `packages/sdk-typescript` | TypeScript SDK | TypeScript |
| `packages/sdk-go` | Go SDK | Go |

## Code Style

- **Python**: Enforced by [Ruff](https://docs.astral.sh/ruff/) with strict settings. Run `make format` before committing.
- **TypeScript**: Enforced by Prettier and TypeScript strict mode.
- **Go**: Standard `gofmt`.

Key conventions:
- Type annotations on all public functions (Python)
- No `# type: ignore` without an explanation comment
- Security-sensitive code must have explicit test coverage
- Custom rules in YAML DSL should include a `reason` field

## Writing Security Tests

Security tests live in `packages/core/tests/security/`. When adding a new detection rule or modifying the security pipeline, you must add corresponding tests.

Test categories:
- `test_attack_samples.py` — Tests against real-world attack payloads (JSONL format)
- `test_bypass_attempts.py` — Tests for known bypass techniques
- `test_encoding_bypass.py` — Unicode, base64, and other encoding attacks
- `test_header_forgery.py` — Trust level spoofing via headers
- `test_trust_escalation.py` — Privilege escalation attempts
- `test_combined_attacks.py` — Multi-vector attack chains
- `test_fuzz.py` — Fuzzing with random inputs

Attack samples are stored in `tests/security/samples/` as JSONL files. Each line contains:
```json
{"input": "the attack payload", "expected": "BLOCK", "category": "direct_injection"}
```

## Adding a New Built-in Rule

1. Add the rule logic in `packages/core/src/agentshield_core/engine/intent/rule_engine.py`
2. Register it in `configs/builtin_rules.yaml`
3. Add unit tests in `packages/core/tests/unit/test_rule_engine.py`
4. Add security tests with attack samples that the rule should catch
5. Update the rule count in documentation if applicable

## Adding a Framework Integration

1. Create `packages/sdk-python/src/agentshield/integrations/your_framework.py`
2. Export it from `packages/sdk-python/src/agentshield/integrations/__init__.py`
3. Add tests in `packages/sdk-python/tests/test_integrations.py`
4. Add an example in `examples/`
5. Update the SDK README

## License

By contributing to AgentShield, you agree that your contributions will be licensed under the Apache License 2.0.
