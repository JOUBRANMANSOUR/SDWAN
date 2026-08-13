#!/usr/bin/env python3
"""Small deterministic HTTPS service for the isolated Sensitive SaaS workload."""
from __future__ import annotations

import argparse
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl


class SensitiveHandler(BaseHTTPRequestHandler):
    server_version = "sdwan-v5-sensitive"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _reply(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/api/status":
            self._reply(200, {"service": "sensitive_saas", "status": "ok"})
        elif self.path == "/health":
            self._reply(200, {"status": "ok"})
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 64 * 1024 * 1024:
            self._reply(413, {"error": "payload too large"})
            return
        payload = self.rfile.read(length)
        if self.path == "/api/data":
            self._reply(200, {"bytes": len(payload), "service": "sensitive_saas", "status": "accepted"})
        elif self.path == "/upload":
            self._reply(200, {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(), "status": "stored"})
        else:
            self._reply(404, {"error": "not found"})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--certificate", default="/etc/nginx/tls/lab.crt")
    parser.add_argument("--private-key", default="/etc/nginx/tls/lab.key")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.bind, args.port), SensitiveHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.certificate, args.private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
