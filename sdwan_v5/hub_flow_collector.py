"""Passive, bounded conntrack metadata collector for Hub transit flows."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Iterable

@dataclass(frozen=True)
class HubFlow:
    hub_id: str
    timestamp: str
    protocol: str
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    conntrack_state: str | None
    mark: str | None
    flow_id: str
    first_seen: str


_TOKEN = re.compile(r"(?P<key>[a-z_]+)=(?P<value>[^ ]+)")


def _field(tokens: dict[str, list[str]], key: str, index: int = 0) -> str | None:
    values = tokens.get(key, ())
    return values[index] if len(values) > index else None


def _port(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None

def parse_new_flow(hub_id: str, line: str, now: datetime | None = None) -> HubFlow | None:
    """Parse a conntrack NEW event into metadata; never changes conntrack state."""
    if "[NEW]" not in line:
        return None
    tokens: dict[str, list[str]] = {}
    for match in _TOKEN.finditer(line):
        tokens.setdefault(match.group("key"), []).append(match.group("value"))
    source, destination = _field(tokens, "src"), _field(tokens, "dst")
    if not source or not destination:
        return None
    words = line.replace("[", " ").replace("]", " ").split()
    protocol = next((word.lower() for word in words if word.lower() in {"tcp", "udp", "icmp", "icmpv6", "sctp", "dccp"}), None)
    if protocol is None:
        return None
    timestamp = (now or datetime.now(timezone.utc)).isoformat()
    source_port, destination_port = _port(_field(tokens, "sport")), _port(_field(tokens, "dport"))
    identity = "|".join((hub_id, protocol, source, destination, str(source_port), str(destination_port)))
    flow_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
    state_match = re.search(r"\[([A-Z_]+)\]", line)
    state = state_match.group(1) if state_match else None
    return HubFlow(
        hub_id=hub_id, timestamp=timestamp, protocol=protocol,
        source_ip=source, destination_ip=destination,
        source_port=source_port, destination_port=destination_port,
        conntrack_state=state, mark=_field(tokens, "mark"),
        flow_id=flow_id, first_seen=timestamp,
    )


def append_flow(output: Path, flow: HubFlow) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(flow), sort_keys=True, separators=(",", ":")) + "\n")


def collect(hub_id: str, output: Path, lines: Iterable[str]) -> Iterable[HubFlow]:
    seen: set[str] = set()
    for line in lines:
        flow = parse_new_flow(hub_id, line)
        if flow is None:
            continue
        if flow.flow_id in seen:
            continue
        seen.add(flow.flow_id)
        append_flow(output, flow)
        yield flow


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hub", required=True, choices=("hub1", "hub2"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    process = subprocess.Popen(["conntrack", "-E", "-o", "extended"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        for _ in collect(args.hub, args.output, process.stdout or ()):
            pass
    finally:
        process.terminate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
