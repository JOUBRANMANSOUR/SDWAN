#!/usr/bin/env python3
"""Privileged experiment orchestrator for staged, incremental Containernet ZTP.

Run this only after Ryu, Policy, ZTP, and the Containernet topology are up.
It never prints claim secrets, CSRs, certificates, or private keys. Claims are
created one device at a time, delivered through protected in-container files,
and removed after the bootstrap client has consumed them.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from sdwan.device_inventory import InventoryEntry, load_inventory
from sdwan.https_client import request_json


class EnrollmentError(RuntimeError):
    pass


def _docker(container: str, arguments: list[str], *, input_text: str | None = None) -> str:
    result = subprocess.run(["docker", "exec", "-i", container, *arguments], input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise EnrollmentError(f"{container}: container command failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def _write_protected(container: str, destination: str, contents: str) -> None:
    # The data travels over stdin. It is never embedded in a command line or
    # echoed by this script. os.open gives the file mode atomically.
    program = (
        "import os,sys; from pathlib import Path; "
        "path=Path(sys.argv[1]); path.parent.mkdir(parents=True,exist_ok=True); "
        "fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600); "
        "os.write(fd,sys.stdin.buffer.read()); os.close(fd); os.chmod(path,0o600)"
    )
    _docker(container, ["python3", "-c", program, destination], input_text=contents)


def _remove_claim(container: str) -> None:
    _docker(container, ["python3", "-c", "from pathlib import Path; Path('/run/sdwan/claim.json').unlink(missing_ok=True)"])


class Administrator:
    def __init__(self, state_root: Path, ztp_url: str, policy_url: str):
        trust = state_root / "trust"
        self.ca = trust / "ca-cert.pem"
        self.certificate = trust / "sdwan-admin-cert.pem"
        self.private_key = trust / "sdwan-admin-key.pem"
        self.ztp_url, self.policy_url = ztp_url, policy_url

    def post_ztp(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return request_json(base_url=self.ztp_url, connect_host="127.0.0.1", method="POST", path=path, ca_certificate=self.ca, certificate=self.certificate, private_key=self.private_key, payload=payload)

    def post_policy(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        return request_json(base_url=self.policy_url, connect_host="127.0.0.1", method="POST", path=path, ca_certificate=self.ca, certificate=self.certificate, private_key=self.private_key, payload=payload or {})


def _stage_inventory(administrator: Administrator, inventory: dict[str, InventoryEntry]) -> None:
    for entry in inventory.values():
        administrator.post_ztp("/v1/admin/stage", {"device_id": entry.device_id, "site": entry.assigned_site})


def _enrolled_site(site: str) -> str | None:
    program = "from pathlib import Path; import json; path=Path('/var/lib/sdwan/state/enrollment.json'); print(json.loads(path.read_text())['site'] if path.exists() else '')"
    result = subprocess.run(["docker", "exec", f"mn.{site}", "python3", "-c", program], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode:
        raise EnrollmentError(f"mn.{site}: cannot inspect durable enrollment state: {result.stderr.strip()}")
    value = result.stdout.strip()
    if value and value != site:
        raise EnrollmentError(f"mn.{site}: durable enrollment is bound to unexpected site {value}")
    return value or None


def _bootstrap_device(administrator: Administrator, entry: InventoryEntry, management_host: str) -> dict[str, str]:
    container = f"mn.{entry.assigned_site}"
    claim = administrator.post_ztp("/v1/admin/claims", {"device_id": entry.device_id, "site": entry.assigned_site, "lifetime_s": 900})
    _write_protected(container, "/var/lib/sdwan/bootstrap-ca.pem", administrator.ca.read_text(encoding="utf-8"))
    _write_protected(container, "/run/sdwan/claim.json", json.dumps({"claim_id": claim["claim_id"], "claim_secret": claim["claim_secret"]}, separators=(",", ":")))
    try:
        output = _docker(container, [
            "python3", "-m", "sdwan.edge_bootstrap", "enroll",
            "--device-id", entry.device_id, "--claim-file", "/run/sdwan/claim.json",
            "--ztp-url", administrator.ztp_url, "--ztp-connect-host", management_host,
            "--policy-url", administrator.policy_url, "--policy-connect-host", management_host,
        ])
    finally:
        _remove_claim(container)
    try:
        result = json.loads(output)
    except json.JSONDecodeError as exc:
        raise EnrollmentError(f"{entry.assigned_site}: bootstrap returned invalid JSON") from exc
    return {"site": str(result["site"]), "state": str(result["state"]), "registration": str(result["registration"])}


def _reconcile(administrator: Administrator, site: str, management_host: str) -> dict[str, str]:
    output = _docker(f"mn.{site}", [
        "python3", "-m", "sdwan.edge_bootstrap", "reconcile",
        "--policy-url", administrator.policy_url, "--policy-connect-host", management_host,
    ])
    try:
        result = json.loads(output)
    except json.JSONDecodeError as exc:
        raise EnrollmentError(f"{site}: reconcile returned invalid JSON") from exc
    return {key: str(value) for key, value in result.items()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, default=Path("/mnt/data/sdwan-state"))
    parser.add_argument("--inventory", type=Path, default=Path("/mnt/data/sdwan-lab/sdwan/config/site_inventory.yaml"))
    parser.add_argument("--ztp-url", default="https://ztp:8443")
    parser.add_argument("--policy-url", default="https://policy:8080")
    parser.add_argument("--management-host", default="172.30.0.254")
    parser.add_argument("--site", action="append", dest="sites", help="enroll only one or more staged sites")
    arguments = parser.parse_args()
    inventory = load_inventory(arguments.inventory)
    selected = set(arguments.sites or (entry.assigned_site for entry in inventory.values()))
    unknown = selected - {entry.assigned_site for entry in inventory.values()}
    if unknown:
        parser.error(f"unknown inventory site(s): {', '.join(sorted(unknown))}")
    administrator = Administrator(arguments.state_root, arguments.ztp_url, arguments.policy_url)
    _stage_inventory(administrator, inventory)
    by_site = {entry.assigned_site: entry for entry in inventory.values()}
    summary: list[dict[str, str]] = []
    hubs = [site for site in ("hub1", "hub2") if site in selected]
    for site in hubs:
        enrolled = _enrolled_site(site)
        result = ({"site": site, "state": "RESUME", "registration": "EXISTING"}
                  if enrolled else _bootstrap_device(administrator, by_site[site], arguments.management_host))
        summary.append({"phase": "resume" if enrolled else "enroll", **result})
    if {"hub1", "hub2"}.issubset(selected):
        for site in ("hub1", "hub2"):
            summary.append({"phase": "reconcile-hub", **_reconcile(administrator, site, arguments.management_host)})
    for site in sorted(selected - set(hubs)):
        if site not in selected:
            continue
        enrolled = _enrolled_site(site)
        result = ({"site": site, "state": "RESUME", "registration": "EXISTING"}
                  if enrolled else _bootstrap_device(administrator, by_site[site], arguments.management_host))
        summary.append({"phase": "resume" if enrolled else "enroll", **result})
        for hub in ("hub1", "hub2"):
            summary.append({"phase": "reconcile-hub", **_reconcile(administrator, hub, arguments.management_host)})
        activation = administrator.post_policy(f"/v1/admin/activate/{site}")
        summary.append({"phase": "activate", "site": site, "state": str(activation["state"])})
        if activation["state"] != "EDGE_CONFIGURING":
            raise EnrollmentError(f"{site}: activation did not reach EDGE_CONFIGURING: {activation.get('detail', '')}")
        summary.append({"phase": "reconcile-spoke", **_reconcile(administrator, site, arguments.management_host)})
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EnrollmentError as exc:
        print(f"live enrollment failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
