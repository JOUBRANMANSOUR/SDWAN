#!/usr/bin/env python3
"""Generate laboratory CA and ZTP/Policy service certificates outside Git."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

from sdwan_v5.identity_ca import LaboratoryCA


def run(arguments: list[str]) -> None:
    subprocess.run(arguments, check=True)


def issue_service(ca: LaboratoryCA, root: Path, name: str) -> None:
    key, csr, cert = root / f"{name}-key.pem", root / f"{name}.csr.pem", root / f"{name}-cert.pem"
    if not key.exists():
        run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)])
        key.chmod(0o600)
    run(["openssl", "req", "-new", "-key", str(key), "-subj", f"/CN={name}", "-out", str(csr)])
    _, _, _, _, certificate = ca.issue(site=name, device_id=name, csr_pem=csr.read_text(encoding="utf-8"))
    cert.write_text(certificate, encoding="utf-8")
    cert.chmod(0o600)
    csr.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, required=True)
    args = parser.parse_args()
    trust = args.state_root / "trust"
    trust.mkdir(parents=True, exist_ok=True)
    trust.chmod(0o700)
    ca = LaboratoryCA(trust / "ca-cert.pem", trust / "ca-key.pem")
    ca.initialize()
    for service in ("ztp", "policy", "sdwan-admin"):
        issue_service(ca, trust, service)
    print(f"laboratory trust initialized at {trust}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
