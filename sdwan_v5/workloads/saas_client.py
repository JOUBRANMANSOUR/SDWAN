#!/usr/bin/env python3
"""Controlled DSCP-labelled interactive and file SaaS workloads.

The DSCP value is installed on the socket before connect(), so the TCP SYN and
all following packets are classified consistently by the branch edge.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import time
from typing import Dict, List, Optional, Tuple


class DSCPHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, dscp: int, timeout: float = 30.0):
        super().__init__(host, 443, context=ssl._create_unverified_context(), timeout=timeout)
        if not 0 <= dscp <= 63:
            raise ValueError("DSCP must be between 0 and 63")
        self._dscp = dscp

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, self._dscp << 2)
        if self._tunnel_host:
            self.sock = raw
            self._tunnel()
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def connection(host: str, dscp: int) -> DSCPHTTPSConnection:
    return DSCPHTTPSConnection(host, dscp)


def request_json(conn: http.client.HTTPSConnection, method: str, path: str, body: Optional[bytes] = None,
                 headers: Optional[Dict[str, str]] = None) -> Tuple[int, object]:
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    payload = response.read()
    try:
        parsed: object = json.loads(payload) if payload else {}
    except json.JSONDecodeError:
        parsed = {"raw": payload.decode("utf-8", errors="replace")}
    return response.status, parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("interactive", "upload", "download"))
    parser.add_argument("--host", default="198.18.0.10")
    parser.add_argument("--file", type=Path, default=Path("/tmp/saas-document.bin"))
    parser.add_argument("--requests", type=int, default=20)
    parser.add_argument("--interval", type=float, default=0.1)
    args = parser.parse_args()
    if args.requests < 1 or args.interval < 0:
        parser.error("requests must be positive and interval must be non-negative")

    started = time.monotonic()
    if args.mode == "interactive":
        latencies: List[float] = []
        timeouts = 0
        failures = 0
        for number in range(args.requests):
            before = time.monotonic()
            try:
                conn = connection(args.host, 18)
                body = json.dumps({"message": f"collaboration-message-{number}"}).encode("utf-8")
                status, _ = request_json(conn, "POST", "/api/messages", body, {"Content-Type": "application/json"})
                conn.close()
                if status >= 300:
                    failures += 1
                else:
                    latencies.append((time.monotonic() - before) * 1000.0)
            except (OSError, TimeoutError, http.client.HTTPException):
                timeouts += 1
            if args.interval:
                time.sleep(args.interval)
        result = {
            "mode": "interactive",
            "requests": args.requests,
            "successful_requests": len(latencies),
            "http_failures": failures,
            "timeouts": timeouts,
            "average_response_ms": sum(latencies) / len(latencies) if latencies else None,
            "max_response_ms": max(latencies) if latencies else None,
        }
        print(json.dumps(result, sort_keys=True))
        return 0 if failures == 0 and timeouts == 0 else 1

    if args.mode == "upload":
        if not args.file.exists():
            args.file.write_bytes(hashlib.sha256(b"public-saas-file").digest() * 32768)
        data = args.file.read_bytes()
        conn = connection(args.host, 10)
        status, result = request_json(
            conn,
            "POST",
            "/files/upload",
            data,
            {"Content-Type": "application/octet-stream", "X-Filename": args.file.name},
        )
        conn.close()
        output = dict(result) if isinstance(result, dict) else {"response": result}
        output["seconds"] = time.monotonic() - started
        output["client_sha256"] = hashlib.sha256(data).hexdigest()
        print(json.dumps(output, sort_keys=True))
        return 0 if status < 300 else 1

    conn = connection(args.host, 10)
    conn.request("GET", f"/files/{args.file.name}")
    response = conn.getresponse()
    data = response.read()
    conn.close()
    print(json.dumps({
        "mode": "download",
        "filename": args.file.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "seconds": time.monotonic() - started,
        "http_status": response.status,
    }, sort_keys=True))
    return 0 if response.status < 300 else 1


if __name__ == "__main__":
    raise SystemExit(main())
