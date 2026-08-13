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
    def __init__(
        self,
        host: str,
        dscp: int,
        timeout: float = 30.0,
    ):
        super().__init__(
            host,
            443,
            context=ssl._create_unverified_context(),
            timeout=timeout,
        )

        if not 0 <= dscp <= 63:
            raise ValueError("DSCP must be between 0 and 63")

        self._dscp = dscp

    def connect(self) -> None:
        # Create the TCP socket manually so DSCP is installed
        # before the initial TCP SYN is transmitted.
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            raw.settimeout(self.timeout)

            if self.source_address:
                raw.bind(self.source_address)

            raw.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_TOS,
                self._dscp << 2,
            )

            raw.connect((self.host, self.port))

            if self._tunnel_host:
                self.sock = raw
                self._tunnel()

            self.sock = self._context.wrap_socket(
                raw,
                server_hostname=self.host,
            )

        except Exception:
            raw.close()
            raise

def connection(
    host: str,
    dscp: int,
    timeout: float = 30.0,
) -> DSCPHTTPSConnection:
    return DSCPHTTPSConnection(
        host,
        dscp,
        timeout=timeout,
    )


def request_json(
    conn: http.client.HTTPSConnection,
    method: str,
    path: str,
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, object]:
    conn.request(
        method,
        path,
        body=body,
        headers=headers or {},
    )

    response = conn.getresponse()
    payload = response.read()

    try:
        parsed: object = json.loads(payload) if payload else {}
    except json.JSONDecodeError:
        parsed = {
            "raw": payload.decode(
                "utf-8",
                errors="replace",
            )
        }

    return response.status, parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "mode",
        choices=("interactive", "upload", "download"),
    )

    parser.add_argument(
        "--host",
        default="198.18.0.10",
    )

    parser.add_argument(
        "--file",
        type=Path,
        default=Path("/tmp/saas-document.bin"),
    )

    parser.add_argument(
        "--requests",
        type=int,
        default=20,
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=0.1,
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Socket timeout in seconds (default: 30)",
    )

    args = parser.parse_args()

    if args.requests < 1:
        parser.error("requests must be positive")

    if args.interval < 0:
        parser.error("interval must be non-negative")

    if args.timeout <= 0:
        parser.error("timeout must be positive")

    started = time.monotonic()

    # ================================================================
    # Interactive SaaS workload
    # DSCP 18
    # ================================================================
    if args.mode == "interactive":
        latencies: List[float] = []
        timeouts = 0
        failures = 0

        for number in range(args.requests):
            before = time.monotonic()
            conn: Optional[DSCPHTTPSConnection] = None

            try:
                conn = connection(
                    args.host,
                    18,
                    args.timeout,
                )

                body = json.dumps(
                    {
                        "message": (
                            f"collaboration-message-{number}"
                        )
                    }
                ).encode("utf-8")

                status, _ = request_json(
                    conn,
                    "POST",
                    "/api/messages",
                    body,
                    {
                        "Content-Type": "application/json",
                    },
                )

                if status >= 300:
                    failures += 1
                else:
                    latencies.append(
                        (time.monotonic() - before) * 1000.0
                    )

            except (
                OSError,
                TimeoutError,
                http.client.HTTPException,
            ):
                timeouts += 1

            finally:
                if conn is not None:
                    conn.close()

            if args.interval:
                time.sleep(args.interval)

        average_response_ms = (
            sum(latencies) / len(latencies)
            if latencies
            else None
        )

        max_response_ms = (
            max(latencies)
            if latencies
            else None
        )

        result = {
            "mode": "interactive",
            "requests": args.requests,
            "successful_requests": len(latencies),
            "http_failures": failures,
            "timeouts": timeouts,
            "average_response_ms": (
                round(average_response_ms, 3)
                if average_response_ms is not None
                else None
            ),
            "max_response_ms": (
                round(max_response_ms, 3)
                if max_response_ms is not None
                else None
            ),
        }

        print(
            json.dumps(
                result,
                indent=2,
                sort_keys=True,
            )
        )

        return (
            0
            if failures == 0 and timeouts == 0
            else 1
        )

    # ================================================================
    # SaaS File Upload
    # DSCP 10
    # ================================================================
    if args.mode == "upload":
        if not args.file.exists():
            args.file.write_bytes(
                hashlib.sha256(
                    b"public-saas-file"
                ).digest()
                * 32768
            )

        data = args.file.read_bytes()

        conn = connection(
            args.host,
            10,
            args.timeout,
        )

        try:
            status, result = request_json(
                conn,
                "POST",
                "/files/upload",
                data,
                {
                    "Content-Type": "application/octet-stream",
                    "X-Filename": args.file.name,
                },
            )
        finally:
            conn.close()

        elapsed = time.monotonic() - started

        output = (
            dict(result)
            if isinstance(result, dict)
            else {"response": result}
        )

        output["client_bytes"] = len(data)
        output["client_sha256"] = hashlib.sha256(
            data
        ).hexdigest()
        output["seconds"] = round(elapsed, 3)

        if elapsed > 0:
            output["client_throughput_mbps"] = round(
                (len(data) * 8)
                / (elapsed * 1_000_000),
                3,
            )

        print(
            json.dumps(
                output,
                indent=2,
                sort_keys=True,
            )
        )

        return 0 if status < 300 else 1

    # ================================================================
    # SaaS File Download
    # DSCP 10
    # ================================================================
    conn = connection(
        args.host,
        10,
        args.timeout,
    )

    try:
        conn.request(
            "GET",
            f"/files/{args.file.name}",
        )

        response = conn.getresponse()
        data = response.read()

    finally:
        conn.close()

    elapsed = time.monotonic() - started

    output = {
        "mode": "download",
        "filename": args.file.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "seconds": round(elapsed, 3),
        "http_status": response.status,
    }

    if elapsed > 0:
        output["throughput_mbps"] = round(
            (len(data) * 8)
            / (elapsed * 1_000_000),
            3,
        )

    print(
        json.dumps(
            output,
            indent=2,
            sort_keys=True,
        )
    )

    return 0 if response.status < 300 else 1


if __name__ == "__main__":
    raise SystemExit(main())
