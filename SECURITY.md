# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AgentGuard, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

Email the maintainers directly with:

1. A description of the vulnerability
2. Steps to reproduce
3. Potential impact assessment
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for the fix.

## Scope

The following are in scope for security reports:

- Bypass of trust level enforcement (e.g., client successfully upgrading trust)
- Evasion of built-in or custom security rules
- Injection attacks that circumvent the sanitization pipeline
- Privilege escalation through the permission engine
- Tampering with the Merkle audit trail
- Authentication bypass (API key, mTLS, OAuth)
- Information disclosure through error messages or API responses

## Security Testing

AgentGuard includes a dedicated security test suite (`packages/core/tests/security/`) with 92 tests covering:

- Direct and indirect prompt injection
- Encoding-based bypass (Unicode, base64, URL encoding, HTML entities)
- Header forgery and trust level spoofing
- Privilege escalation patterns
- Combined multi-vector attacks
- Fuzz testing with random inputs

Run the security test suite:

```bash
make test-security
```

## Security Design Principles

1. **Server-side trust computation**: Clients cannot escalate trust levels. The server always has the final say.
2. **Defense in depth**: Three independent detection layers (rules, anomaly, semantic) must all agree before allowing suspicious operations.
3. **Physical separation**: Two-phase architecture ensures raw external data never coexists with tool execution capability.
4. **Fail-closed**: When in doubt, block and require human confirmation.
5. **Immutable audit**: Merkle tree traces make tampering detectable.
