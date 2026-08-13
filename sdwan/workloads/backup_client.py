#!/usr/bin/env python3
"""Create and upload a deterministic backup while reporting transfer evidence."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import time


class DSCPHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection whose DSCP marking is present on the TCP SYN."""

    def __init__(self, host: str, port: int, dscp: int, timeout: float):
        super().__init__(host, port, context=ssl._create_unverified_context(), timeout=timeout)
        self._dscp = dscp

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, self._dscp << 2)
        if self._tunnel_host:
            self.sock = raw
            self._tunnel()
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def deterministic_file(path: Path, size_mib: int) -> str:
    if size_mib < 1:
        raise ValueError("size_mib must be positive")
    block = hashlib.sha256(b"sdwan-v5-central-backup").digest() * 2048
    remaining, digest = size_mib * 1024 * 1024, hashlib.sha256()
    with path.open("wb") as output:
        while remaining:
            chunk = block[:min(len(block), remaining)]
            output.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("branch", choices=[f"node{n}" for n in range(1, 6)])
    parser.add_argument("--host", default="10.100.0.10")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--size-mib", type=int, default=64)
    parser.add_argument("--file", type=Path, default=Path("/tmp/sdwan-backup.bin"))
    args = parser.parse_args()
    if args.size_mib < 1:
        parser.error("size-mib must be positive")

    expected = deterministic_file(args.file, args.size_mib)
    connection = DSCPHTTPSConnection(args.host, args.port, dscp=8, timeout=300)
    started = time.monotonic()
    connection.putrequest("POST", f"/backup/{args.branch}")
    connection.putheader("Content-Type", "application/octet-stream")
    connection.putheader("Content-Length", str(args.file.stat().st_size))
    connection.endheaders()
    with args.file.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            connection.send(chunk)
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = {"error": raw.decode("utf-8", errors="replace")}
    elapsed = time.monotonic() - started
    payload.update({
        "client_sha256": expected,
        "sha256_verified": payload.get("sha256") == expected,
        "seconds": elapsed,
        "average_throughput_mbps": args.file.stat().st_size * 8 / elapsed / 1_000_000,
        "http_status": response.status,
    })
    print(json.dumps(payload, sort_keys=True))
    return 0 if response.status < 300 and payload["sha256_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
