"""Strict TLS contexts used after ZTP enrollment; verification is never disabled."""
from __future__ import annotations

from pathlib import Path
import ssl


def client_context(ca_bundle: Path, certificate: Path, private_key: Path, expected_hostname: str) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_bundle))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=str(certificate), keyfile=str(private_key))
    if not expected_hostname:
        raise ValueError("mTLS expected service identity is required")
    return context


def server_context(ca_bundle: Path, certificate: Path, private_key: Path, *, require_client_certificate: bool) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(certificate), keyfile=str(private_key))
    context.load_verify_locations(cafile=str(ca_bundle))
    context.verify_mode = ssl.CERT_REQUIRED if require_client_certificate else ssl.CERT_OPTIONAL
    return context
