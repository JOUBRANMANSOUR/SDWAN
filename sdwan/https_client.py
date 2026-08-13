"""Small HTTPS client with an explicit TCP connect address and verified TLS name.

The Containernet management network reaches services by address while laboratory
certificates are issued to stable service DNS names (``ztp`` and ``policy``).
This module keeps those two concerns separate without disabling TLS hostname
verification or relying on mutable container DNS configuration.
"""
from __future__ import annotations

import http.client
import json
from pathlib import Path
import socket
import ssl
from typing import Any, Mapping
from urllib.parse import urlsplit


class HTTPSClientError(RuntimeError):
    """An authenticated control-plane request could not be completed."""


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, connect_host: str, port: int, server_name: str, context: ssl.SSLContext, timeout: float = 15.0):
        super().__init__(connect_host, port=port, context=context, timeout=timeout)
        self._server_name = server_name

    def connect(self) -> None:
        raw_socket = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self._server_name)


def _endpoint(url: str) -> tuple[str, int, str]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HTTPSClientError("service URL must be a simple https:// DNS-name[:port] URL")
    if parsed.path not in {"", "/"}:
        raise HTTPSClientError("service URL must not include a path")
    return parsed.hostname, parsed.port or 443, parsed.hostname


def request_json(
    *,
    base_url: str,
    connect_host: str | None,
    method: str,
    path: str,
    ca_certificate: Path,
    payload: Mapping[str, Any] | None = None,
    certificate: Path | None = None,
    private_key: Path | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Send JSON while connecting to an explicit address and verifying DNS SAN."""
    if not path.startswith("/"):
        raise HTTPSClientError("request path must begin with '/'")
    hostname, port, server_name = _endpoint(base_url)
    context = ssl.create_default_context(cafile=str(ca_certificate))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if certificate is not None or private_key is not None:
        if certificate is None or private_key is None:
            raise HTTPSClientError("both client certificate and private key are required for mTLS")
        context.load_cert_chain(str(certificate), str(private_key))
    body = None if payload is None else json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))
    connection = _PinnedHTTPSConnection(connect_host or hostname, port, server_name, context, timeout)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise HTTPSClientError(f"control-plane request failed: {exc}") from exc
    finally:
        connection.close()
    try:
        decoded = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPSClientError("service returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise HTTPSClientError("service returned a non-object JSON response")
    if response.status < 200 or response.status >= 300:
        detail = str(decoded.get("error", "request rejected"))
        raise HTTPSClientError(f"service rejected request ({response.status}): {detail}")
    return decoded
