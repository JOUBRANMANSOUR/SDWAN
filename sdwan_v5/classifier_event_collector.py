"""Metadata-only receiver for the native nDPI classifier event socket."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
from typing import Any

_STOP = False


def _stop(_signum: int, _frame: Any) -> None:
    global _STOP
    _STOP = True


def _open_private(path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    return os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)


def _append(fd: int, path: Path, payload: bytes, limit: int) -> int:
    if os.fstat(fd).st_size + len(payload) > limit:
        os.close(fd)
        rotated = path.with_suffix(path.suffix + ".1")
        rotated.unlink(missing_ok=True)
        if path.exists():
            path.replace(rotated)
        fd = _open_private(path)
    os.write(fd, payload)
    return fd


def serve(socket_path: Path, output: Path, max_bytes: int) -> None:
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    receiver.bind(str(socket_path))
    os.chmod(socket_path, 0o600)
    receiver.settimeout(1.0)
    fd = _open_private(output)
    try:
        while not _STOP:
            try:
                raw = receiver.recv(65535)
            except socket.timeout:
                continue
            try:
                event = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(event, dict):
                continue
            # The native exporter has no packet payload field. Enforce that
            # boundary if future exporters add one.
            event.pop("payload", None)
            event.pop("packet", None)
            fd = _append(fd, output, json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n", max_bytes)
    finally:
        os.close(fd)
        receiver.close()
        socket_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, default=Path("/run/sdwan/classifier-events.sock"))
    parser.add_argument("--output", type=Path, default=Path("/var/lib/sdwan/state/classifier-events.jsonl"))
    parser.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    arguments = parser.parse_args()
    if arguments.max_bytes < 4096:
        parser.error("--max-bytes must be at least 4096")
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    serve(arguments.socket, arguments.output, arguments.max_bytes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
