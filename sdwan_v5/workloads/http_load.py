#!/usr/bin/env python3
"""Concurrent reproducible HTTP download measurement; no public Internet dependency."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import time
from urllib.request import urlopen


def download(url: str, expected_sha256: str | None) -> dict[str, object]:
    started = time.monotonic()
    with urlopen(url, timeout=60) as response:
        payload = response.read()
    elapsed = time.monotonic() - started
    digest = hashlib.sha256(payload).hexdigest()
    if expected_sha256 and digest != expected_sha256:
        raise ValueError("SaaS fixture checksum mismatch")
    return {"bytes": len(payload), "seconds": elapsed, "throughput_mbps": (len(payload) * 8 / max(elapsed, 0.001)) / 1_000_000, "sha256": digest}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--clients", type=int, choices=(1, 2, 3, 10), required=True)
    parser.add_argument("--sha256")
    args = parser.parse_args()
    with ThreadPoolExecutor(max_workers=args.clients) as executor:
        results = list(executor.map(lambda _: download(args.url, args.sha256), range(args.clients)))
    print(json.dumps({"clients": args.clients, "results": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
