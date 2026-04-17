"""
MCP Tool Supply Chain Verifier.

Validates tool integrity at runtime to detect tool-poisoning attacks
(OWASP Agentic Top 10 #1 for 2026). Attackers modify MCP tool descriptions
so agents unknowingly exfiltrate data or execute malicious actions.

How it works:
    1. Tools are registered with their expected schema (name, description,
       parameter schema) and signed with Ed25519.
    2. At runtime, before each tool call, the actual tool schema from the
       MCP server is compared against the registered+signed version.
    3. If the description, parameters, or behavior has been tampered with,
       the tool call is blocked.

Three verification modes:
    - STRICT: Tool must be registered and signature must match. Unknown tools blocked.
    - AUDIT: All tools allowed, but mismatches are logged and traced.
    - ALLOWLIST: Only registered tools are allowed; unregistered tools blocked.
"""

from __future__ import annotations

import enum
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field

from agentshield_core.policy.signer import PolicySigner

logger = logging.getLogger(__name__)


class VerificationMode(enum.Enum):
    STRICT = "strict"
    AUDIT = "audit"
    ALLOWLIST = "allowlist"


@dataclass
class ToolManifest:
    """A registered, signed tool definition."""

    name: str
    provider: str  # e.g., "mcp://my-server", "builtin", "api"
    description_hash: str  # SHA-256 of the tool description
    parameter_schema_hash: str  # SHA-256 of the parameter JSON schema
    signature: bytes  # Ed25519 signature over the canonical manifest
    registered_at: float = field(default_factory=time.time)
    version: str = "1.0"
    allowed_trust_levels: list[str] = field(default_factory=lambda: ["TRUSTED", "VERIFIED", "INTERNAL"])
    max_calls_per_session: int = 0  # 0 = unlimited
    metadata: dict = field(default_factory=dict)

    @property
    def canonical(self) -> dict:
        """Canonical representation for signing/verification."""
        return {
            "name": self.name,
            "provider": self.provider,
            "description_hash": self.description_hash,
            "parameter_schema_hash": self.parameter_schema_hash,
            "version": self.version,
            "allowed_trust_levels": sorted(self.allowed_trust_levels),
        }


@dataclass
class VerificationResult:
    """Result of a tool verification check."""

    verified: bool
    tool_name: str
    reason: str = ""
    mismatch_fields: list[str] = field(default_factory=list)
    is_registered: bool = False
    signature_valid: bool = False


class ToolRegistryVerifier:
    """
    Runtime tool integrity verifier.

    Maintains a registry of known-good tool manifests (signed with Ed25519)
    and verifies tool schemas at runtime before execution.
    """

    def __init__(
        self,
        signer: PolicySigner | None = None,
        mode: VerificationMode = VerificationMode.AUDIT,
    ) -> None:
        self._signer = signer or PolicySigner()
        self._mode = mode
        self._registry: dict[str, ToolManifest] = {}  # key: "provider/name"
        # Runtime counters
        self._verified_count = 0
        self._mismatch_count = 0
        self._unknown_count = 0

    @property
    def mode(self) -> VerificationMode:
        return self._mode

    def _tool_key(self, provider: str, name: str) -> str:
        return f"{provider}/{name}"

    # --- Registration ---

    def register_tool(
        self,
        name: str,
        provider: str,
        description: str,
        parameter_schema: dict,
        version: str = "1.0",
        allowed_trust_levels: list[str] | None = None,
        max_calls_per_session: int = 0,
        metadata: dict | None = None,
    ) -> ToolManifest:
        """Register a tool and sign its manifest."""
        desc_hash = self._hash_content(description)
        param_hash = self._hash_content(json.dumps(parameter_schema, sort_keys=True))

        manifest = ToolManifest(
            name=name,
            provider=provider,
            description_hash=desc_hash,
            parameter_schema_hash=param_hash,
            signature=b"",  # will be set below
            version=version,
            allowed_trust_levels=allowed_trust_levels or ["TRUSTED", "VERIFIED", "INTERNAL"],
            max_calls_per_session=max_calls_per_session,
            metadata=metadata or {},
        )

        # Sign the canonical manifest
        manifest.signature = self._signer.sign(manifest.canonical)

        key = self._tool_key(provider, name)
        self._registry[key] = manifest
        logger.info("Registered tool: %s (provider=%s, version=%s)", name, provider, version)

        return manifest

    def register_from_mcp_listing(
        self,
        tools: list[dict],
        provider: str = "mcp",
    ) -> list[ToolManifest]:
        """Bulk-register tools from an MCP tools/list response."""
        manifests = []
        for tool in tools:
            manifest = self.register_tool(
                name=tool.get("name", ""),
                provider=provider,
                description=tool.get("description", ""),
                parameter_schema=tool.get("inputSchema", {}),
            )
            manifests.append(manifest)
        return manifests

    # --- Verification ---

    def verify_tool(
        self,
        name: str,
        provider: str,
        current_description: str,
        current_parameter_schema: dict,
    ) -> VerificationResult:
        """
        Verify a tool's current schema against its registered manifest.

        Called at runtime before each tool execution.
        """
        key = self._tool_key(provider, name)
        manifest = self._registry.get(key)

        # Unknown tool
        if manifest is None:
            self._unknown_count += 1
            if self._mode in (VerificationMode.STRICT, VerificationMode.ALLOWLIST):
                logger.warning("Unknown tool blocked: %s (provider=%s)", name, provider)
                return VerificationResult(
                    verified=False,
                    tool_name=name,
                    reason=f"Tool '{name}' from '{provider}' is not registered",
                    is_registered=False,
                )
            # AUDIT mode: log and allow
            logger.info("Unknown tool (audit mode): %s (provider=%s)", name, provider)
            return VerificationResult(
                verified=True,
                tool_name=name,
                reason="Unknown tool allowed (audit mode)",
                is_registered=False,
            )

        # Verify signature first
        sig_valid = self._signer.verify(manifest.canonical, manifest.signature)
        if not sig_valid:
            self._mismatch_count += 1
            logger.error("SIGNATURE INVALID: tool=%s provider=%s — manifest may be corrupted", name, provider)
            return VerificationResult(
                verified=False,
                tool_name=name,
                reason="Tool manifest signature is invalid — possible tampering",
                is_registered=True,
                signature_valid=False,
            )

        # Compare current schema against registered hashes
        mismatches: list[str] = []

        current_desc_hash = self._hash_content(current_description)
        if current_desc_hash != manifest.description_hash:
            mismatches.append("description")

        current_param_hash = self._hash_content(
            json.dumps(current_parameter_schema, sort_keys=True)
        )
        if current_param_hash != manifest.parameter_schema_hash:
            mismatches.append("parameter_schema")

        if mismatches:
            self._mismatch_count += 1
            reason = f"Tool schema mismatch: {', '.join(mismatches)} changed since registration"
            logger.warning(
                "TOOL TAMPERED: tool=%s provider=%s mismatches=%s",
                name, provider, mismatches,
            )

            if self._mode == VerificationMode.STRICT:
                return VerificationResult(
                    verified=False,
                    tool_name=name,
                    reason=reason,
                    mismatch_fields=mismatches,
                    is_registered=True,
                    signature_valid=True,
                )

            # AUDIT / ALLOWLIST: log but allow
            return VerificationResult(
                verified=True,
                tool_name=name,
                reason=f"Mismatch detected but allowed ({self._mode.value}): {reason}",
                mismatch_fields=mismatches,
                is_registered=True,
                signature_valid=True,
            )

        # All good
        self._verified_count += 1
        return VerificationResult(
            verified=True,
            tool_name=name,
            is_registered=True,
            signature_valid=True,
        )

    def verify_trust_level(self, name: str, provider: str, trust_level: str) -> bool:
        """Check if a tool is allowed at the given trust level."""
        key = self._tool_key(provider, name)
        manifest = self._registry.get(key)
        if manifest is None:
            return self._mode == VerificationMode.AUDIT
        return trust_level in manifest.allowed_trust_levels

    # --- Queries ---

    def is_registered(self, name: str, provider: str) -> bool:
        return self._tool_key(provider, name) in self._registry

    def list_tools(self) -> list[dict]:
        """List all registered tools."""
        return [
            {
                "name": m.name,
                "provider": m.provider,
                "version": m.version,
                "registered_at": m.registered_at,
                "allowed_trust_levels": m.allowed_trust_levels,
            }
            for m in self._registry.values()
        ]

    @property
    def metrics(self) -> dict:
        return {
            "registered_tools": len(self._registry),
            "verified_count": self._verified_count,
            "mismatch_count": self._mismatch_count,
            "unknown_count": self._unknown_count,
            "mode": self._mode.value,
        }

    # --- Helpers ---

    @staticmethod
    def _hash_content(content: str) -> str:
        """SHA-256 hash of content string."""
        return hashlib.sha256(content.encode()).hexdigest()

    # --- Export / Import ---

    def export_registry(self) -> list[dict]:
        """Export all manifests for backup or distribution."""
        result = []
        for manifest in self._registry.values():
            entry = manifest.canonical.copy()
            entry["signature"] = manifest.signature.hex()
            entry["registered_at"] = manifest.registered_at
            entry["max_calls_per_session"] = manifest.max_calls_per_session
            entry["metadata"] = manifest.metadata
            result.append(entry)
        return result

    def import_registry(self, entries: list[dict]) -> int:
        """Import manifests from a previous export. Returns count imported."""
        imported = 0
        for entry in entries:
            sig_bytes = bytes.fromhex(entry.get("signature", ""))
            manifest = ToolManifest(
                name=entry["name"],
                provider=entry["provider"],
                description_hash=entry["description_hash"],
                parameter_schema_hash=entry["parameter_schema_hash"],
                signature=sig_bytes,
                version=entry.get("version", "1.0"),
                allowed_trust_levels=entry.get("allowed_trust_levels", []),
                max_calls_per_session=entry.get("max_calls_per_session", 0),
                registered_at=entry.get("registered_at", time.time()),
                metadata=entry.get("metadata", {}),
            )
            # Verify signature before importing
            if self._signer.verify(manifest.canonical, manifest.signature):
                key = self._tool_key(manifest.provider, manifest.name)
                self._registry[key] = manifest
                imported += 1
            else:
                logger.warning("Skipped import of %s/%s — invalid signature", manifest.provider, manifest.name)
        return imported
