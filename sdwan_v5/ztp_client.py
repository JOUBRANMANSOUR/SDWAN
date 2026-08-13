#!/usr/bin/env python3
"""Generic first-boot ZTP client: no trusted `--site` argument exists."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import stat
from uuid import uuid4

from .https_client import request_json
from .identity_ca import generate_device_csr
from .identity_store import IdentityStore


def _read_claim(path: Path) -> tuple[str, str]:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError("claim file must not be group/world-readable")
    value = json.loads(path.read_text(encoding="utf-8"))
    return str(value["claim_id"]), str(value["claim_secret"])


def enroll(*, device_id: str, claim_file: Path, bootstrap_ca: Path, ztp_url: str, identity_root: Path, connect_host: str | None = None) -> dict[str, str]:
    """Enroll a generic device without trusting a caller-supplied site name."""
    store = IdentityStore(identity_root)
    claim_id, claim_secret = _read_claim(claim_file)
    csr = generate_device_csr(store, device_id)
    result = request_json(
        base_url=ztp_url, connect_host=connect_host, method="POST", path="/v1/enroll",
        ca_certificate=bootstrap_ca,
        payload={"claim_id": claim_id, "claim_secret": claim_secret, "device_id": device_id,
                 "nonce": str(uuid4()), "csr_pem": csr, "request_id": str(uuid4())},
    )
    store.store_certificate(str(result["certificate_pem"]), str(result["site"]), str(result["serial"]), str(result["fingerprint"]))
    return {"site": str(result["site"]), "serial": str(result["serial"]), "fingerprint": str(result["fingerprint"])}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--claim-file", type=Path, required=True)
    parser.add_argument("--bootstrap-ca", type=Path, required=True)
    parser.add_argument("--ztp-url", required=True)
    parser.add_argument("--identity-root", type=Path, required=True)
    parser.add_argument("--connect-host", help="TCP address for the ZTP service; TLS still verifies the DNS name in --ztp-url")
    arguments = parser.parse_args()
    print(json.dumps(enroll(device_id=arguments.device_id, claim_file=arguments.claim_file, bootstrap_ca=arguments.bootstrap_ca, ztp_url=arguments.ztp_url, identity_root=arguments.identity_root, connect_host=arguments.connect_host), sort_keys=True))
