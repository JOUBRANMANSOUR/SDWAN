"""Docker Edge Agent: local Linux actuation, cached state, and emergency routing."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import sys
import time
from pathlib import Path
import subprocess
from typing import Any, Iterable, Mapping, Protocol

from .common.marks import EgressMode
from .common.model import TopologyConfig
from .identity_store import IdentityStore
from .local_failover import LocalFailoverEvent, LocalFailoverManager, SlotTarget


class CommandError(RuntimeError):
    pass


class CommandRunner(Protocol):
    def run(self, command: list[str]) -> None: ...


class SystemRunner:
    def run(self, command: list[str]) -> None:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if result.returncode:
            raise CommandError(f"command failed ({' '.join(command[:4])}): {result.stderr.strip()}")


@dataclass(frozen=True)
class ReconciliationResult:
    status: str
    desired_state_version: int
    route_version: int
    detail: str


class EdgeAgent:
    """Owns local route/NAT/WireGuard mutations; it is not a policy authority."""

    def __init__(self, site: str, config: TopologyConfig, identity_root: Path, runner: CommandRunner | None = None):
        if site not in config.sites and site not in config.hubs:
            raise ValueError("unknown edge site")
        self.site, self.config = site, config
        self.store = IdentityStore(identity_root)
        self.runner: CommandRunner = runner or SystemRunner()
        self.local_state = self.store.load_json("last-confirmed.json") or {"desired_state_version": 0, "route_version": 0, "digest": ""}
        self.event_queue = self.store.load_json("events.json") or {"events": []}

    def _run(self, *command: str) -> None:
        self.runner.run(list(command))

    def _ensure_chain(self, table: str, chain: str) -> None:
        if not isinstance(self.runner, SystemRunner):
            self._run("iptables", "-t", table, "-N", chain)
            return
        try:
            self._run("iptables", "-t", table, "-N", chain)
        except CommandError as exc:
            if "Chain already exists" not in str(exc):
                raise

    def _ensure_rule(self, table: str, chain: str, *rule: str) -> None:
        if not isinstance(self.runner, SystemRunner):
            self._run("iptables", "-t", table, "-A", chain, *rule)
            return
        try:
            self._run("iptables", "-t", table, "-C", chain, *rule)
        except CommandError as exc:
            # ``-C`` returns a nonzero status when a rule is absent. That is
            # the expected first-reconciliation condition, not a failure.
            if "Bad rule" not in str(exc) and "does a matching rule exist" not in str(exc):
                raise
            self._run("iptables", "-t", table, "-A", chain, *rule)
    def _start_native_classifier(self, queue_number: int) -> None:
        """Start the Docker-native metadata classifier before installing NFQUEUE."""
        if not isinstance(self.runner, SystemRunner):
            return
        binary = "/usr/local/sbin/sdwan-classifier-v5"
        log_path = self.store.state_dir / "classifier.log"
        policy_socket = Path("/run/sdwan/classifier-policy.sock")
        event_socket = Path("/run/sdwan/classifier-events.sock")
        policy_socket.unlink(missing_ok=True)
        self._start_classifier_event_collector(event_socket)
        subprocess.run(["pkill", "-f", binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        with log_path.open("ab", buffering=0) as log_file:
            process = subprocess.Popen(
                [
                    binary, "--site", self.site, "--queue-start", str(queue_number),
                    "--queue-end", str(queue_number), "--policy-socket",
                    str(policy_socket), "--event-socket", str(event_socket), "--fail-mode", "open",
                ],
                stdin=subprocess.DEVNULL, stdout=log_file, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        time.sleep(0.2)
        if process.poll() is not None:
            detail = log_path.read_text(encoding="utf-8", errors="replace")[-1000:]
            raise CommandError(f"native classifier exited during startup: {detail.strip()}")
        self.store.persist_json("classifier.json", {"pid": process.pid, "queue": queue_number, "site": self.site})

    def _start_classifier_event_collector(self, event_socket: Path) -> None:
        """Bind the event socket before nDPI starts; retain metadata, never packets."""
        if not isinstance(self.runner, SystemRunner):
            return
        collector_log = self.store.state_dir / "classifier-events.log"
        event_socket.unlink(missing_ok=True)
        subprocess.run(
            ["pkill", "-f", "sdwan_v5.classifier_event_collector"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        with collector_log.open("ab", buffering=0) as log_file:
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "sdwan_v5.classifier_event_collector",
                    "--socket", str(event_socket), "--output",
                    str(self.store.state_dir / "classifier-events.jsonl"),
                ],
                stdin=subprocess.DEVNULL, stdout=log_file, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        for _ in range(10):
            if event_socket.exists():
                break
            if process.poll() is not None:
                detail = collector_log.read_text(encoding="utf-8", errors="replace")[-1000:]
                raise CommandError(f"classifier event collector exited during startup: {detail.strip()}")
            time.sleep(0.05)
        else:
            process.terminate()
            raise CommandError("classifier event collector did not bind its Unix socket")
        self.store.persist_json(
            "classifier-events.json",
            {"pid": process.pid, "socket": str(event_socket), "output": str(self.store.state_dir / "classifier-events.jsonl")},
        )

    def install_connmark_rules(
        self, lan_interface: str, prefix_marks: Iterable[tuple[str, int]], default_mark: int,
        queue_number: int = 4100,
    ) -> None:
        """Pin Edge-selected marks, then send pre-encryption packets to nDPI."""
        marks = self.config.settings.marks
        connection_mask = hex(marks.connection_mask)
        affinity_mask = hex(marks.affinity_mask)
        chain = "SDWAN_V5_MARK"
        self._ensure_chain("mangle", chain)
        self._ensure_rule("mangle", "PREROUTING", "-i", lan_interface, "-j", chain)
        self._run("iptables", "-t", "mangle", "-F", chain)
        self._run("iptables", "-t", "mangle", "-A", chain, "-j", "CONNMARK", "--restore-mark", "--nfmask", connection_mask, "--ctmask", connection_mask)
        for prefix, mark in prefix_marks:
            self._run("iptables", "-t", "mangle", "-A", chain, "-m", "mark", "--mark", f"0/{connection_mask}", "-d", prefix, "-j", "MARK", "--set-xmark", f"{hex(mark)}/{affinity_mask}")
        self._run("iptables", "-t", "mangle", "-A", chain, "-m", "mark", "--mark", f"0/{connection_mask}", "-j", "MARK", "--set-xmark", f"{hex(default_mark)}/{affinity_mask}")
        self._run("iptables", "-t", "mangle", "-A", chain, "-m", "mark", "--mark", f"0/{hex(marks.terminal_bit)}", "-j", "NFQUEUE", "--queue-num", str(queue_number), "--queue-bypass")
        self._run("iptables", "-t", "mangle", "-A", chain, "-j", "CONNMARK", "--save-mark", "--nfmask", connection_mask, "--ctmask", connection_mask)

    def _intent_mark(self, desired: Mapping[str, Any], intent: Mapping[str, Any]) -> tuple[int, str, EgressMode]:
        marks = self.config.settings.marks
        allowed = {str(value) for value in intent.get("allowed_egress", ())}
        ranked = tuple(str(value) for value in intent.get("ranked_transports", ()))
        if not ranked:
            raise ValueError("policy intent has no ranked transport")
        if EgressMode.DIRECT_INTERNET.value in allowed:
            for transport in ranked:
                if self.config.transports[transport].internet_capable:
                    return marks.encode(self.config.transports[transport].route_slot, egress=EgressMode.DIRECT_INTERNET), transport, EgressMode.DIRECT_INTERNET
        if EgressMode.HUB_OVERLAY.value in allowed:
            active = desired.get("active_target_by_slot", {})
            for transport in ranked:
                target = active.get(transport)
                if isinstance(target, Mapping) and str(target.get("hub")) in {"hub1", "hub2"}:
                    return marks.encode(self.config.transports[transport].route_slot, hub=str(target["hub"])), transport, EgressMode.HUB_OVERLAY
        raise ValueError("policy intent has no locally usable egress target")

    def install_spoke_dataplane(self, desired: Mapping[str, Any], policy_snapshot: Mapping[str, Any]) -> None:
        """Apply Policy-Service intent; the classifier only supplies metadata."""
        if policy_snapshot.get("site") != self.site:
            raise ValueError("policy snapshot belongs to another site")
        intents = policy_snapshot.get("destination_intents")
        default_intent = policy_snapshot.get("default_intent")
        if not isinstance(intents, list) or not isinstance(default_intent, Mapping):
            raise ValueError("policy snapshot lacks destination intents")
        prefix_marks: list[tuple[str, int]] = []
        seen_prefixes: set[str] = set()
        for raw_intent in intents:
            if not isinstance(raw_intent, Mapping):
                raise ValueError("policy destination intent must be an object")
            prefix = str(raw_intent.get("prefix", ""))
            if not prefix or prefix in seen_prefixes:
                raise ValueError("policy destination prefixes must be unique and nonempty")
            mark, transport, egress = self._intent_mark(desired, raw_intent)
            prefix_marks.append((prefix, mark))
            seen_prefixes.add(prefix)
            if egress is EgressMode.DIRECT_INTERNET:
                if prefix != str(self.config.saas_network):
                    raise ValueError("direct Internet policy is limited to the simulated SaaS network")
                self._run("ip", "route", "replace", prefix, "via", str(self.config.saas_transport_ips[transport]), "dev", f"{self.site}-{transport}", "table", str(self.config.transports[transport].route_table))
        default_mark, _, _ = self._intent_mark(desired, default_intent)
        self.install_policy_rules()
        self.install_scoped_direct_nat(str(self.config.sites[self.site].lan_network), {"bb": f"{self.site}-bb", "lte": f"{self.site}-lte"})
        self._start_native_classifier(4100)
        self.install_connmark_rules(f"{self.site}-lan", prefix_marks, default_mark)

    def install_hub_backhaul(self) -> None:
        """Install symmetric branch returns and scoped SaaS backhaul NAT on a hub."""
        if self.site not in self.config.hubs:
            raise ValueError("hub backhaul may be installed only on a hub")
        spoke_interface = "wg-spokes-mpls"
        for profile in self.config.sites.values():
            self._run("ip", "route", "replace", str(profile.lan_network), "dev", spoke_interface)
        transport = next(name for name, item in self.config.transports.items() if item.internet_capable)
        uplink = f"{self.site}-{transport}"
        self._run("ip", "route", "replace", str(self.config.saas_network), "via", str(self.config.saas_transport_ips[transport]), "dev", uplink)
        chain = "SDWAN_V5_HUB_NAT"
        self._ensure_chain("nat", chain)
        for profile in self.config.sites.values():
            self._ensure_rule("nat", "POSTROUTING", "-s", str(profile.lan_network), "-j", chain)
        for prefix in self.config.protected_private_prefixes:
            self._ensure_rule("nat", chain, "-d", str(prefix), "-j", "RETURN")
        self._ensure_rule("nat", chain, "-d", str(self.config.saas_network), "-o", uplink, "-j", "MASQUERADE")

    def _replace_owned_rule(self, priority: int, mark: str, table: int) -> None:
        """Replace a rule in the v5-reserved priority range portably.

        Ubuntu's iproute2 accepts ``ip route replace`` but not ``ip rule
        replace``. A rule priority is the v5-owned key, so deleting that exact
        priority then adding the new match is deterministic and does not touch
        system/default rule priorities.
        """
        try:
            self._run("ip", "rule", "del", "priority", str(priority))
        except CommandError as exc:
            if "No such file" not in str(exc) and "Cannot find" not in str(exc):
                raise
        self._run("ip", "rule", "add", "priority", str(priority), "fwmark", mark, "lookup", str(table))

    def install_policy_rules(self) -> None:
        marks = self.config.settings.marks
        for transport in self.config.transports.values():
            self._replace_owned_rule(2000 + transport.route_slot, f"{transport.route_slot}/{marks.route_mask}", transport.route_table)
        for hub in ("hub1", "hub2"):
            hub_bit = marks.hub1_bit if hub == "hub1" else marks.hub2_bit
            for transport in self.config.transports.values():
                target = self.config.target(hub, transport.name)
                mark = transport.route_slot | hub_bit
                mask = marks.route_mask | marks.target_hub_mask
                self._replace_owned_rule(1000 + target.route_table, f"{mark}/{mask}", target.route_table)

    def install_scoped_direct_nat(self, lan_prefix: str, uplinks: Mapping[str, str]) -> None:
        """NAT only direct-Internet traffic; private DC/cloud/branch prefixes return."""
        marks = self.config.settings.marks
        self._ensure_chain("nat", "SDWAN_V5_DIRECT_NAT")
        self._ensure_rule("nat", "POSTROUTING", "-s", lan_prefix, "-j", "SDWAN_V5_DIRECT_NAT")
        for prefix in self.config.protected_private_prefixes:
            self._ensure_rule("nat", "SDWAN_V5_DIRECT_NAT", "-d", str(prefix), "-j", "RETURN")
        for transport, interface in uplinks.items():
            if transport not in self.config.transports or not self.config.transports[transport].internet_capable:
                raise ValueError("only configured Internet-capable Broadband/LTE uplinks may NAT")
            self._ensure_rule("nat", "SDWAN_V5_DIRECT_NAT", "-m", "mark", "--mark", f"{marks.direct_internet_bit}/{marks.egress_mask}", "-o", interface, "-j", "MASQUERADE")

    def reconcile(self, desired: Mapping[str, Any]) -> ReconciliationResult:
        if desired.get("site") != self.site or int(desired.get("schema_version", 0)) != 5:
            raise ValueError("desired state site/schema mismatch")
        version, route_version = int(desired["desired_state_version"]), int(desired["route_version"])
        digest = str(desired["configuration_digest"])
        current_version, current_route = int(self.local_state["desired_state_version"]), int(self.local_state["route_version"])
        if version < current_version:
            return ReconciliationResult("STALE", version, route_version, "older desired state rejected")
        # ``last-confirmed.json`` is durable, while WireGuard interfaces,
        # route tables, and their routes are kernel state. A container (or
        # host) restart therefore leaves the former intact but loses the
        # latter. A matching desired-state digest is an idempotent control
        # plane result, not evidence that the live data plane still exists.
        # Re-apply the desired state below even in this case, then report the
        # idempotent outcome to the caller.
        matched = version == current_version and digest == self.local_state["digest"]
        if route_version < current_route:
            return ReconciliationResult("EDGE_AHEAD", version, route_version, "central route version cannot overwrite newer local emergency state")
        for interface in desired["interfaces"]:
            self._apply_interface(interface)
        if self.site in self.config.sites:
            self._apply_active_slot_routes(desired)
        if matched:
            return ReconciliationResult("MATCHED", version, route_version, "idempotent desired state re-applied to live kernel state")
        self.local_state = {"desired_state_version": version, "route_version": route_version, "digest": digest}
        self.store.persist_json("last-confirmed.json", self.local_state)
        return ReconciliationResult("VERIFIED", version, route_version, "exact desired state applied")

    def _apply_interface(self, interface: Mapping[str, Any]) -> None:
        name, address = str(interface["name"]), str(interface["address"])
        try:
            self._run("ip", "link", "add", "dev", name, "type", "wireguard")
        except CommandError as exc:
            # Reconciliation is restart-safe: an existing interface is updated
            # in place, while every other ip/wg failure remains actionable.
            if "File exists" not in str(exc):
                raise
        self._run("ip", "address", "replace", address, "dev", name)
        key = self.store.wireguard_device_private_key()
        if isinstance(self.runner, SystemRunner) and not key.exists():
            raise CommandError("persistent WireGuard device key is missing; enroll before reconciliation")
        self._run("wg", "set", name, "listen-port", str(interface["listen_port"]), "private-key", str(key))
        for peer in interface["peers"]:
            command = ["wg", "set", name, "peer", str(peer["public_key"]), "allowed-ips", ",".join(peer["allowed_ips"]), "persistent-keepalive", str(peer["keepalive_s"])]
            if peer.get("endpoint"):
                command.extend(["endpoint", str(peer["endpoint"])])
            self.runner.run(command)
        self._run("ip", "link", "set", "up", "dev", name)
        for prefix in interface["routes"]:
            self._run("ip", "route", "replace", str(prefix), "dev", name, "table", str(interface["route_table"]))

    def _apply_active_slot_routes(self, desired: Mapping[str, Any]) -> None:
        interfaces = {str(item["name"]): item for item in desired["interfaces"]}
        active = desired.get("active_target_by_slot", {})
        for transport, target in active.items():
            if transport not in self.config.transports:
                raise ValueError("desired state references an unknown transport")
            interface_name = str(target["interface"])
            interface = interfaces.get(interface_name)
            if interface is None:
                raise ValueError("active target does not name an applied interface")
            table = self.config.transports[transport].route_table
            for prefix in interface["routes"]:
                self._run("ip", "route", "replace", str(prefix), "dev", interface_name, "table", str(table))

    def enqueue_event(self, event: LocalFailoverEvent) -> None:
        events = list(self.event_queue.get("events", []))
        event_payload = {"event_id": event.event_id, "site": event.site, "slot": event.slot, "old_target": event.old_target.__dict__, "new_target": event.new_target.__dict__, "reason": event.reason, "local_route_version": event.local_route_version, "timestamp": event.monotonic_timestamp}
        if not any(item["event_id"] == event.event_id for item in events):
            events.append(event_payload)
        self.event_queue = {"events": events[-256:]}
        self.store.persist_json("events.json", self.event_queue)
