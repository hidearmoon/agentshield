# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-16

### Added

**Core Engine**
- 5-tier trust model (Trusted → Verified → Internal → External → Untrusted) with server-side computation
- 3-layer intent consistency cascade: Rule Engine (μs) → Anomaly Detector (μs) → Semantic Checker (ms)
- Two-phase call architecture separating data extraction from action execution
- Dynamic permission engine with trust-level-aware tool filtering
- Data sanitization pipeline with format cleansing and semantic compression
- Merkle tree-based trace engine for tamper-proof audit trails
- Policy DSL for defining custom rules in YAML
- Policy signing and verification
- 22 built-in security rules covering injection, exfiltration, escalation, and operational safety
- Session management with TTL and capacity limits
- Performance metrics and structured logging for SIEM integration
- Authentication: API Key, mTLS, OAuth 2.0
- Storage backends: PostgreSQL (policies, sessions) + ClickHouse (traces, analytics)
- REST API (FastAPI) with versioned endpoints

**Proxy**
- Transparent sidecar proxy for agent-to-tool traffic interception
- Middleware chain: agent registry, header handling, rate limiting, security context
- Configurable upstream routing
- Graceful fallback handling

**SDKs**
- Python SDK with `@shield.guard` decorator and session-based protection
- Framework integrations: LangChain, CrewAI, AutoGen, Claude Agent SDK
- TypeScript SDK (client, session, shield)
- Go SDK (client, session, shield)

**Console**
- React management UI with dashboard, trace viewer, alert feed, policy editor
- Backend API for agents, alerts, audit, policies, sources, traces
- Auth middleware with role-based permissions
- ClickHouse analytics and PostgreSQL state storage

**Infrastructure**
- Docker Compose full-stack deployment (Core + Proxy + Console + PostgreSQL + ClickHouse)
- GitHub Actions CI (Python 3.12/3.13 matrix, lint, test, coverage)
- Makefile for development workflow
- 342 tests: 218 unit + 92 security + 32 SDK
- Attack sample corpus: direct injection, indirect injection, encoding attacks (JSONL)
