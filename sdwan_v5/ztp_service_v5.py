#!/usr/bin/env python3
"""Dedicated lightweight ZTP Enrollment Service using HTTPS and service-owned SQLite."""
from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
from typing import Any, Mapping

from .identity_ca import LaboratoryCA, CertificateError
from .mtls import server_context
from .persistence.ztp_store import ClaimRejected, ZTPStore


@dataclass
class ZTPApplication:
    store: ZTPStore
    ca: LaboratoryCA

    def enroll(self, payload: Mapping[str, Any]) -> dict[str, str]:
        required = {"claim_id", "claim_secret", "device_id", "nonce", "csr_pem", "request_id"}
        if required - set(payload):
            raise ClaimRejected("enrollment request is incomplete")
        device_id, csr_pem = str(payload["device_id"]), str(payload["csr_pem"])
        return self.store.consume_claim(
            str(payload["claim_id"]), str(payload["claim_secret"]), device_id, str(payload["nonce"]),
            lambda site: self.ca.issue(site=site, device_id=device_id, csr_pem=csr_pem), request_id=str(payload["request_id"]),
        )

    def stage_device(self, payload: Mapping[str, Any], actor: str) -> None:
        device_id, site = str(payload["device_id"]), str(payload["site"])
        if not device_id or not site:
            raise ValueError("device_id and site are required")
        self.store.stage_device(device_id, site, actor)

    def create_claim(self, payload: Mapping[str, Any], actor: str) -> dict[str, str]:
        claim_id, secret = self.store.create_claim(str(payload["device_id"]), str(payload["site"]), lifetime_s=int(payload.get("lifetime_s", 900)), actor=actor)
        # The plaintext secret exists only in this immediate administrator response.
        return {"claim_id": claim_id, "claim_secret": secret}

    def revoke(self, payload: Mapping[str, Any], actor: str) -> None:
        self.store.revoke_certificate(str(payload["serial"]), actor, str(payload["reason"]))


class _Handler(BaseHTTPRequestHandler):
    application: ZTPApplication

    def log_message(self, format: str, *args: object) -> None:
        # Do not log request bodies because they can contain a one-time claim.
        return

    def _json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 256_000:
            raise ValueError("invalid request length")
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def _send(self, status: HTTPStatus, value: Mapping[str, Any]) -> None:
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _admin_actor(self) -> str:
        peer = self.connection.getpeercert()
        subject = str(peer.get("subject", "")) if peer else ""
        if "sdwan-admin" not in subject.lower():
            raise PermissionError("administrator mTLS certificate is required")
        return "mtls:sdwan-admin"

    def do_GET(self) -> None:
        if self.path == "/healthz":
            try:
                self.application.store.integrity_check()
                self._send(HTTPStatus.OK, {"status": "ok", "schema_version": self.application.store.schema_version})
            except Exception:
                self._send(HTTPStatus.SERVICE_UNAVAILABLE, {"status": "unhealthy"})
            return
        self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        try:
            payload = self._json()
            if self.path == "/v1/enroll":
                result = self.application.enroll(payload)
                self._send(HTTPStatus.CREATED, result)
                return
            actor = self._admin_actor()
            if self.path == "/v1/admin/stage":
                self.application.stage_device(payload, actor)
                self._send(HTTPStatus.OK, {"status": "staged"})
                return
            if self.path == "/v1/admin/claims":
                self._send(HTTPStatus.CREATED, self.application.create_claim(payload, actor))
                return
            if self.path == "/v1/admin/revoke":
                self.application.revoke(payload, actor)
                self._send(HTTPStatus.OK, {"status": "revoked"})
                return
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except PermissionError as exc:
            self._send(HTTPStatus.FORBIDDEN, {"error": str(exc)})
        except (ClaimRejected, CertificateError, KeyError, ValueError) as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception:
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "enrollment processing failed"})


def serve(*, bind: str, port: int, database: Path, ca_certificate: Path, ca_signing_key: Path, tls_certificate: Path, tls_private_key: Path, client_ca: Path) -> None:
    app = ZTPApplication(ZTPStore(database), LaboratoryCA(ca_certificate, ca_signing_key))
    handler = type("ZTPHandler", (_Handler,), {"application": app})
    server = ThreadingHTTPServer((bind, port), handler)
    # Bootstrap uses server-authenticated TLS plus claim/CSR proof.  Admin
    # endpoints require an operational mTLS certificate in the handler.
    server.socket = server_context(client_ca, tls_certificate, tls_private_key, require_client_certificate=False).wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.store.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--ca-certificate", type=Path, required=True)
    parser.add_argument("--ca-signing-key", type=Path, required=True)
    parser.add_argument("--tls-certificate", type=Path, required=True)
    parser.add_argument("--tls-private-key", type=Path, required=True)
    parser.add_argument("--client-ca", type=Path, required=True)
    arguments = parser.parse_args()
    serve(bind=arguments.bind, port=arguments.port, database=arguments.database, ca_certificate=arguments.ca_certificate, ca_signing_key=arguments.ca_signing_key, tls_certificate=arguments.tls_certificate, tls_private_key=arguments.tls_private_key, client_ca=arguments.client_ca)
