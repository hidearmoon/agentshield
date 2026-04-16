"""mTLS configuration for inter-service communication.

Provides TLS certificate management for:
- SDK ↔ Core Engine
- Proxy ↔ Core Engine
- Console Backend ↔ Core Engine

Usage:
    # Server-side (Core Engine)
    ssl_context = create_server_ssl_context(
        cert_file="/certs/server.crt",
        key_file="/certs/server.key",
        ca_file="/certs/ca.crt",
    )
    uvicorn.run(app, ssl=ssl_context)

    # Client-side (SDK/Proxy)
    ssl_context = create_client_ssl_context(
        cert_file="/certs/client.crt",
        key_file="/certs/client.key",
        ca_file="/certs/ca.crt",
    )
    httpx.AsyncClient(verify=ssl_context)
"""

from __future__ import annotations

import ssl
from pathlib import Path


def create_server_ssl_context(
    cert_file: str | Path,
    key_file: str | Path,
    ca_file: str | Path,
    require_client_cert: bool = True,
) -> ssl.SSLContext:
    """
    Create SSL context for the server side (Core Engine).
    Requires client certificates when require_client_cert=True (mTLS).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    # Load server certificate and private key
    ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

    # Load CA certificate for verifying client certificates
    ctx.load_verify_locations(cafile=str(ca_file))

    if require_client_cert:
        # Require client to present a certificate signed by our CA
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_OPTIONAL

    # Security hardening — TLS 1.3 minimum already enforced above,
    # so OP_NO_* flags are unnecessary and deprecated in Python 3.12+.
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")

    return ctx


def create_client_ssl_context(
    cert_file: str | Path,
    key_file: str | Path,
    ca_file: str | Path,
) -> ssl.SSLContext:
    """
    Create SSL context for the client side (SDK/Proxy connecting to Core).
    Presents client certificate for mutual authentication.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    # Load client certificate and private key
    ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

    # Load CA certificate for verifying the server
    ctx.load_verify_locations(cafile=str(ca_file))

    # Verify server certificate
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True

    return ctx


def generate_self_signed_certs(output_dir: str | Path) -> dict[str, Path]:
    """
    Generate self-signed CA, server, and client certificates for development.
    NOT for production use.

    Returns dict with paths: ca_cert, ca_key, server_cert, server_key, client_cert, client_key
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from datetime import datetime, timedelta, timezone

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    # Generate CA key and certificate
    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentShield"),
            x509.NameAttribute(NameOID.COMMON_NAME, "AgentShield Dev CA"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA384())
    )

    def _issue_cert(common_name: str, san_dns: list[str]) -> tuple:
        key = ec.generate_private_key(ec.SECP384R1())
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentShield"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        )
        if san_dns:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
                critical=False,
            )
        cert = builder.sign(ca_key, hashes.SHA384())
        return key, cert

    server_key, server_cert = _issue_cert("agentshield-core", ["localhost", "core", "*.agentshield.local"])
    client_key, client_cert = _issue_cert("agentshield-client", [])

    def _write_pem(path: Path, data: bytes) -> Path:
        path.write_bytes(data)
        return path

    paths = {
        "ca_cert": _write_pem(output / "ca.crt", ca_cert.public_bytes(serialization.Encoding.PEM)),
        "ca_key": _write_pem(
            output / "ca.key",
            ca_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
        ),
        "server_cert": _write_pem(output / "server.crt", server_cert.public_bytes(serialization.Encoding.PEM)),
        "server_key": _write_pem(
            output / "server.key",
            server_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
        ),
        "client_cert": _write_pem(output / "client.crt", client_cert.public_bytes(serialization.Encoding.PEM)),
        "client_key": _write_pem(
            output / "client.key",
            client_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
        ),
    }
    return paths
