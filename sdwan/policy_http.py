"""mTLS Policy Service HTTP boundary for policy snapshots and edge reports."""
from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any, Mapping

import yaml

from .common.marks import EgressMode
from .device_inventory import InventoryEntry, load_inventory
from .common.model import TopologyConfig, load_config
from .mtls import server_context
from .policy_service_v5 import PolicyService
from .common.destination_models import load_destination_policy


def load_application_policy(path: Path, config: TopologyConfig) -> dict[str, dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping) or int(raw.get("schema_version", 0)) != 5 or not isinstance(raw.get("classes"), Mapping):
        raise ValueError("application policy must be a v5 classes mapping")
    result: dict[str, dict[str, Any]] = {}
    for name, item in raw["classes"].items():
        egress = [str(value) for value in item["allowed_egress"]]
        transports = [str(value) for value in item["candidate_transports"]]
        if any(value not in {mode.value for mode in EgressMode} for value in egress):
            raise ValueError("unknown egress mode")
        if any(value not in config.transports for value in transports):
            raise ValueError("unknown transport in application policy")
        if EgressMode.DIRECT_INTERNET.value in egress and not any(config.transports[value].internet_capable for value in transports):
            raise ValueError("direct Internet policy has no Internet-capable transport")
        if EgressMode.DIRECT_INTERNET.value in egress and any(not config.transports[value].internet_capable for value in transports):
            raise ValueError("direct Internet application candidates must all be Internet-capable")
        match = item.get("match", {})
        if not isinstance(match, Mapping):
            raise ValueError("application match must be a mapping")
        result[str(name)] = {
            "sla_class": str(item["sla_class"]), "allowed_egress": egress,
            "candidate_transports": transports, "ranked_transports": transports,
            "match": dict(match),
        }
    return result

class PolicyApplication:
    def __init__(
        self, config: TopologyConfig, database: Path, app_policy: Path, inventory_path: Path,
        destination_policy: Path | None = None,
    ):
        self.config, self.service = config, PolicyService(config, database)
        self.application_policy = load_application_policy(app_policy, config)
        policy_path = destination_policy or Path(__file__).with_name("config") / "destination_policy.yaml"
        self.destination_policy = load_destination_policy(policy_path, config)
        self.destination_policy_version, _ = self.service.store.activate_destination_policy(
            self.destination_policy.to_mapping(), "policy-config",
        )
        self.inventory: dict[str, InventoryEntry] = load_inventory(inventory_path)
        self.service.stage_inventory()
        self.config = self.service.config

    def _refresh_inventory(self) -> None:
        """Refresh the policy view from persistent, authoritative inventory."""
        self.service.stage_inventory()
        self.config = self.service.config


    def site_for_device(self, device_id: str) -> str:
        self._refresh_inventory()
        for record in self.service.inventory.list():
            if record.device_id != device_id:
                continue
            # A recoverable lifecycle failure does not revoke the operational
            # identity. Retry reconciliation must therefore be able to fetch
            # the already-compiled desired state with the same mTLS identity.
            # Terminal/decommissioning records and explicitly
            # non-recoverable failures remain denied.
            if record.lifecycle in {"DELETING", "DECOMMISSIONING", "REVOKED", "DELETED"}:
                raise PermissionError("operational certificate belongs to a terminal inventory record")
            if record.lifecycle == "FAILED" and not bool(record.recoverable):
                raise PermissionError("operational certificate belongs to a non-recoverable inventory record")
            return record.site

        try:
            return self.inventory[device_id].assigned_site
        except KeyError as exc:
            raise PermissionError("operational certificate is not assigned in authoritative inventory") from exc

    def _intent(self, application: str, prefix: str | None = None) -> dict[str, Any]:
        try:
            intent = {"application": application, **self.application_policy[application]}
        except KeyError as exc:
            raise ValueError(f"application policy lacks required class {application}") from exc
        if prefix is not None:
            intent["prefix"] = prefix
        return intent

    def snapshot(self, site: str) -> dict[str, Any]:
        try:
            site = self.config.logical_site(site)
        except KeyError:
            pass
        self._refresh_inventory()
        if site not in self.config.sites:
            raise ValueError("unknown edge site")
        profile = self.config.sites[site]
        realtime = self.application_policy["REALTIME_RTP"]
        intents = [
            {
                "policy_id": f"branch_private_{name}", "priority": 100 + index,
                "prefix": str(item.lan_network), "destination_type": "BRANCH_PRIVATE",
                "application": "REALTIME_RTP", "application_classes": ["REALTIME_RTP"],
                "allowed_egress": list(realtime["allowed_egress"]),
                "candidate_transports": list(realtime["candidate_transports"]),
                "ranked_transports": list(realtime["candidate_transports"]),
                "failure_action": "FAIL_CLOSED", "application_matchers": ["RTP", "UDP/5004"],
            }
            for index, (name, item) in enumerate(self.config.sites.items()) if name != site
        ]
        for policy in self.destination_policy.policies:
            if policy.destination_type.value == "CLOUD_VPC" and not self.config.cloud_vpc.enabled:
                continue
            intents.append(policy.to_intent())
        desired = self.service.desired_state_for(site)
        self.service.store.record_destination_policy_delivery(
            site, self.destination_policy_version,
            int(desired["desired_state_version"]) if desired else 0,
            applied_status="DELIVERED", observed_status="UNOBSERVED",
        )
        return {
            "schema_version": 5,
            "site": site,
            "preferred_hub": profile.preferred_hub,
            "standby_hub": profile.standby_hub,
            "policy_version": self.destination_policy_version,
            "application_policy": self.application_policy,
            "destination_intents": intents,
            "default_intent": self.destination_policy.default_policy.to_intent(),
            "transport_marks": {name: item.route_slot for name, item in self.config.transports.items()},
            "mark_connection_mask": self.config.settings.marks.connection_mask,
        }


class _Handler(BaseHTTPRequestHandler):
    application: PolicyApplication

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, status: HTTPStatus, body: Mapping[str, Any]) -> None:
        payload = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 256_000:
            raise ValueError("invalid request length")
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def _peer_common_name(self) -> str:
        certificate = self.connection.getpeercert()
        for rdn in certificate.get("subject", ()) if certificate else ():
            for key, value in rdn:
                if key == "commonName":
                    return str(value)
        raise PermissionError("mTLS client certificate common name is required")

    def _edge_site(self) -> str:
        return self.application.site_for_device(self._peer_common_name())

    def _admin_actor(self) -> str:
        if self._peer_common_name() != "sdwan-admin":
            raise PermissionError("administrator mTLS certificate is required")
        return "mtls:sdwan-admin"

    def do_GET(self) -> None:
        try:
            if self.path == "/healthz":
                self.application.service.store.integrity_check()
                self._send(HTTPStatus.OK, {"status": "ok", "schema_version": self.application.service.store.schema_version})
                return
            if self.path == "/v1/edge/desired":
                site = self._edge_site()
                desired = self.application.service.desired_state_for(site)
                if desired is None:
                    self._send(HTTPStatus.ACCEPTED, {"site": site, "status": "PENDING"})
                else:
                    self._send(HTTPStatus.OK, desired)
                return
            prefix = "/v1/edge/policy/"
            if self.path.startswith(prefix):
                site = self._edge_site()
                requested = self.path[len(prefix):]
                if requested != site:
                    raise PermissionError("edge may read only its own policy snapshot")
                self._send(HTTPStatus.OK, self.application.snapshot(site))
                return
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except PermissionError as exc:
            self._send(HTTPStatus.FORBIDDEN, {"error": str(exc)})
        except ValueError as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            value = self._json()
            if self.path == "/v1/edge/register":
                site = self._edge_site()
                result = self.application.service.register_edge_identity(site, str(value["wireguard_public_key"]), actor=f"mtls:{self._peer_common_name()}")
                self._send(HTTPStatus.OK, result)
                return
            if self.path == "/v1/edge/ack":
                site = self._edge_site()
                self.application.service.acknowledge_edge(site, int(value["desired_state_version"]), str(value["configuration_digest"]), int(value["route_version"]), str(value["status"]), str(value.get("detail", "")))
                self._send(HTTPStatus.OK, {"site": site, "status": "recorded"})
                return
            activate_prefix = "/v1/admin/activate/"
            if self.path.startswith(activate_prefix):
                actor = self._admin_actor()
                result = self.application.service.activate_spoke(self.path[len(activate_prefix):], actor=actor)
                self._send(HTTPStatus.OK, {"site": result.site, "state": result.state, "detail": result.detail})
                return
            if self.path == "/v1/edge/event":
                site = self._edge_site()
                status = self.application.service.reconcile_edge_report(site, int(value["desired_state_version"]), int(value["route_version"]), str(value["status"]))
                self._send(HTTPStatus.OK, {"reconciliation": status})
                return
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except PermissionError as exc:
            self._send(HTTPStatus.FORBIDDEN, {"error": str(exc)})
        except (KeyError, ValueError) as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})


def serve(*, config_path: Path, database: Path, app_policy: Path, inventory_path: Path, destination_policy: Path, bind: str, port: int, ca_bundle: Path, certificate: Path, private_key: Path) -> None:
    application = PolicyApplication(load_config(config_path), database, app_policy, inventory_path, destination_policy)
    handler = type("PolicyHandler", (_Handler,), {"application": application})
    server = ThreadingHTTPServer((bind, port), handler)
    # After ZTP, every edge/policy request is mTLS; no shared token fallback.
    server.socket = server_context(ca_bundle, certificate, private_key, require_client_certificate=True).wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        application.service.store.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--app-policy", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--destination-policy", type=Path, required=True)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--ca-bundle", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    args = parser.parse_args()
    serve(config_path=args.config, database=args.database, app_policy=args.app_policy, inventory_path=args.inventory, destination_policy=args.destination_policy, bind=args.bind, port=args.port, ca_bundle=args.ca_bundle, certificate=args.certificate, private_key=args.private_key)
