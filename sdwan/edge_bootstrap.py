"""Generic edge bootstrap and reconciliation entry point for Docker edge nodes.

The command intentionally has no ``--site`` option. A device starts with only
its immutable simulated device ID, a one-time protected claim, a pinned CA,
and a generic service identity. The assigned site is persisted only after the
ZTP service authenticates and consumes that claim.
"""
from __future__ import annotations

import argparse
import os
import sys
import base64
import json
from pathlib import Path
import subprocess
from typing import Any

from .common.model import load_config
from .dynamic_profile import overlay_site_profile
from .edge_agent_v5 import EdgeAgent, SystemRunner
from .https_client import request_json
from .identity_store import IdentityStore
from .ztp_client import enroll


class BootstrapError(RuntimeError):
    pass


def _wireguard_public_key(store: IdentityStore) -> str:
    key_path = store.wireguard_device_private_key()
    if not key_path.exists():
        generated = subprocess.run(["wg", "genkey"], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if generated.returncode or not generated.stdout.strip():
            raise BootstrapError("could not generate local WireGuard private key")
        store.store_wireguard_device_private_key(generated.stdout)
    private_key = key_path.read_text(encoding="utf-8")
    result = subprocess.run(["wg", "pubkey"], input=private_key, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        raise BootstrapError("could not derive WireGuard public key")
    public_key = result.stdout.strip()
    try:
        if len(base64.b64decode(public_key.encode("ascii"), validate=True)) != 32:
            raise ValueError
    except (ValueError, UnicodeError) as exc:
        raise BootstrapError("generated WireGuard public key is invalid") from exc
    return public_key


def _policy_request(
    *,
    identity: IdentityStore,
    bootstrap_ca: Path,
    policy_url: str,
    policy_connect_host: str | None,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return request_json(
        base_url=policy_url, connect_host=policy_connect_host, method=method, path=path,
        ca_certificate=bootstrap_ca, certificate=identity.certificate_path(),
        private_key=identity.private_key_path(), payload=payload,
    )


def bootstrap(arguments: argparse.Namespace) -> dict[str, str]:
    identity = IdentityStore(arguments.identity_root)
    enrollment = enroll(
        device_id=arguments.device_id, claim_file=arguments.claim_file,
        bootstrap_ca=arguments.bootstrap_ca, ztp_url=arguments.ztp_url,
        identity_root=arguments.identity_root, connect_host=arguments.ztp_connect_host,
    )
    public_key = _wireguard_public_key(identity)
    registration = _policy_request(
        identity=identity, bootstrap_ca=arguments.bootstrap_ca, policy_url=arguments.policy_url,
        policy_connect_host=arguments.policy_connect_host, method="POST", path="/v1/edge/register",
        payload={"wireguard_public_key": public_key},
    )
    # No claim secret, private key, CSR, certificate, or WireGuard key is
    # returned to stdout. This is safe to retain as a lab event summary.
    return {"site": enrollment["site"], "serial": enrollment["serial"], "registration": str(registration["registration"]), "state": str(registration["state"])}
def _start_spoke_failover(site: str, identity: IdentityStore, config_path: Path) -> None:
    """Start one durable local monitor; it uses cached desired state only."""
    state = identity.load_json("failover-monitor.json") or {}
    pid = state.get("pid")
    if isinstance(pid, int):
        try:
            command = Path(f"/proc/{pid}/cmdline").read_bytes()
            if b"sdwan.edge_failover_runtime" in command:
                return
        except OSError:
            pass
    log_path = identity.state_dir / "failover.log"
    log_file = log_path.open("ab", buffering=0)
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", "sdwan.edge_failover_runtime", "--site", site,
             "--config", str(config_path), "--site-profile", str(identity.state_dir / "site-profile.json"), "--identity-root", str(identity.root)],
            stdin=subprocess.DEVNULL, stdout=log_file, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        log_file.close()
    identity.persist_json("failover-monitor.json", {"pid": process.pid, "site": site})




def reconcile(arguments: argparse.Namespace) -> dict[str, str]:
    identity = IdentityStore(arguments.identity_root)
    enrollment = identity.load_json("enrollment.json")
    if enrollment is None:
        raise BootstrapError("edge is not enrolled")
    desired = _policy_request(
        identity=identity, bootstrap_ca=arguments.bootstrap_ca, policy_url=arguments.policy_url,
        policy_connect_host=arguments.policy_connect_host, method="GET", path="/v1/edge/desired",
    )
    if desired.get("status") == "PENDING":
        return {"site": str(enrollment["site"]), "state": "PENDING"}
    site = str(enrollment["site"])
    config = overlay_site_profile(load_config(arguments.config), site, desired.get("site_profile"))
    agent = EdgeAgent(site, config, arguments.identity_root, SystemRunner())
    # ``enrollment.json`` may contain the historical Containernet name
    # (node1), while the desired state is keyed by the logical site (site1).
    # EdgeAgent resolves that mapping; use its canonical value for all
    # control-plane branch/hub decisions.
    logical_site = agent.site
    outcome = agent.reconcile(desired)
    if outcome.status in {"VERIFIED", "MATCHED"}:
        if logical_site in config.sites:
            policy_snapshot = _policy_request(
                identity=identity, bootstrap_ca=arguments.bootstrap_ca, policy_url=arguments.policy_url,
                policy_connect_host=arguments.policy_connect_host, method="GET", path=f"/v1/edge/policy/{logical_site}",
            )
            agent.install_spoke_dataplane(desired, policy_snapshot)
            identity.persist_json("desired-state.json", desired)
            identity.persist_json("site-profile.json", desired.get("site_profile") or {})
            identity.persist_json("policy-snapshot.json", policy_snapshot)
            _start_spoke_failover(logical_site, identity, arguments.config)
        else:
            agent.install_hub_backhaul(desired)
    _policy_request(
        identity=identity, bootstrap_ca=arguments.bootstrap_ca, policy_url=arguments.policy_url,
        policy_connect_host=arguments.policy_connect_host, method="POST", path="/v1/edge/ack",
        payload={"desired_state_version": outcome.desired_state_version, "configuration_digest": str(desired["configuration_digest"]), "route_version": outcome.route_version, "status": "VERIFIED" if outcome.status in {"VERIFIED", "MATCHED"} else outcome.status, "detail": outcome.detail},
    )
    return {"site": logical_site, "state": outcome.status, "route_version": str(outcome.route_version)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("enroll", "reconcile"))
    parser.add_argument("--identity-root", type=Path, default=Path("/var/lib/sdwan"))
    parser.add_argument("--bootstrap-ca", type=Path, default=Path("/var/lib/sdwan/bootstrap-ca.pem"))
    parser.add_argument("--policy-url", required=True)
    parser.add_argument("--policy-connect-host")
    parser.add_argument("--config", type=Path, default=Path("/opt/sdwan/config/topology.yaml"))
    parser.add_argument("--device-id")
    parser.add_argument("--claim-file", type=Path)
    parser.add_argument("--ztp-url")
    parser.add_argument("--ztp-connect-host")
    arguments = parser.parse_args()
    if arguments.action == "enroll":
        if not all((arguments.device_id, arguments.claim_file, arguments.ztp_url)):
            parser.error("enroll requires --device-id, --claim-file, and --ztp-url")
        result = bootstrap(arguments)
    else:
        result = reconcile(arguments)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
