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
from ipaddress import ip_network
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


@dataclass(frozen=True)
class ClassMarkRule:
    application_class: str
    prefix: str
    mark: int
    protocol: str | None = None
    destination_ports: tuple[int, ...] = ()
    dscp: int | None = None
    blocked: bool = False


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
            ["pkill", "-f", "sdwan.classifier_event_collector"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        with collector_log.open("ab", buffering=0) as log_file:
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "sdwan.classifier_event_collector",
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


    def _start_hub_flow_collector(self) -> None:
        """Start passive conntrack NEW-event observation; forwarding never waits for it."""
        if not isinstance(self.runner, SystemRunner):
            return
        log_path = self.store.state_dir / "hub-flow-collector.log"
        try:
            subprocess.run(["pkill", "-f", "sdwan.hub_flow_collector"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            with log_path.open("ab", buffering=0) as log_file:
                process = subprocess.Popen([sys.executable, "-m", "sdwan.hub_flow_collector", "--hub", self.site, "--output", str(self.store.state_dir / "hub-flow-events.jsonl")], stdin=subprocess.DEVNULL, stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as exc:
            self.store.persist_json("hub-flow-collector.json", {"site": self.site, "status": "UNAVAILABLE", "detail": str(exc)[:240]})
            return
        self.store.persist_json("hub-flow-collector.json", {"site": self.site, "status": "RUNNING", "pid": process.pid, "output": str(self.store.state_dir / "hub-flow-events.jsonl")})

    def install_connmark_rules(
        self, lan_interface: str, prefix_marks: Iterable[tuple[str, int]], default_mark: int,
        queue_number: int = 4100, class_marks: Iterable[ClassMarkRule] = (),
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
        for rule in class_marks:
            match = ["-m", "mark", "--mark", f"0/{connection_mask}", "-d", rule.prefix]
            if rule.protocol:
                match.extend(["-p", rule.protocol])
            if rule.destination_ports:
                match.extend(["-m", "multiport", "--dports", ",".join(str(value) for value in rule.destination_ports)])
            if rule.dscp is not None:
                if not 0 <= rule.dscp <= 63:
                    raise ValueError("DSCP must be between 0 and 63")
                match.extend(["-m", "dscp", "--dscp", str(rule.dscp)])
            if rule.blocked:
                # A no-eligible-path result is observability/control state,
                # never a packet-filtering instruction.  Leave the flow to
                # the existing default routing behavior.
                continue
            self._run("iptables", "-t", "mangle", "-A", chain, *match, "-j", "MARK", "--set-xmark", f"{hex(rule.mark)}/{affinity_mask}")
        for prefix, mark in prefix_marks:
            self._run("iptables", "-t", "mangle", "-A", chain, "-m", "mark", "--mark", f"0/{connection_mask}", "-d", prefix, "-j", "MARK", "--set-xmark", f"{hex(mark)}/{affinity_mask}")
        self._run("iptables", "-t", "mangle", "-A", chain, "-m", "mark", "--mark", f"0/{connection_mask}", "-j", "MARK", "--set-xmark", f"{hex(default_mark)}/{affinity_mask}")
        self._run("iptables", "-t", "mangle", "-A", chain, "-m", "mark", "--mark", f"0/{hex(marks.terminal_bit)}", "-j", "NFQUEUE", "--queue-num", str(queue_number), "--queue-bypass")
        self._run("iptables", "-t", "mangle", "-A", chain, "-j", "CONNMARK", "--save-mark", "--nfmask", connection_mask, "--ctmask", connection_mask)

    def _install_return_path_affinity(self, interface_marks: Mapping[str, int]) -> None:
        """Persist the ingress/egress path selected for every routed connection.

        Marks are local to one Linux network namespace; they are not carried in
        a WireGuard packet.  Every spoke and hub therefore records its own
        path decision in conntrack.  The PREROUTING chain restores a known
        connection or stamps a new connection from its ingress interface.  The
        POSTROUTING chain records the route selected for a connection that was
        initiated from the opposite side (for example DC-to-branch).

        The terminal bit prevents the reverse direction of an ingress-pinned
        flow from being sent through nDPI again and changing its transport
        slot.  Only the v5-owned connection bits are saved/restored.
        """
        if not interface_marks:
            raise ValueError("return-path affinity requires at least one path interface")
        marks = self.config.settings.marks
        connection_mask = hex(marks.connection_mask)
        affinity_mask = hex(marks.affinity_mask)
        stamp_mask = hex(marks.affinity_mask | marks.terminal_bit)
        ingress_chain = "SDWAN_V5_RPA_IN"
        egress_chain = "SDWAN_V5_RPA_OUT"

        self._ensure_chain("mangle", ingress_chain)
        self._ensure_chain("mangle", egress_chain)
        self._ensure_rule("mangle", "PREROUTING", "-j", ingress_chain)
        self._ensure_rule("mangle", "POSTROUTING", "-j", egress_chain)
        self._run("iptables", "-t", "mangle", "-F", ingress_chain)
        self._run("iptables", "-t", "mangle", "-F", egress_chain)

        self._run(
            "iptables", "-t", "mangle", "-A", ingress_chain,
            "-j", "CONNMARK", "--restore-mark",
            "--nfmask", connection_mask, "--ctmask", connection_mask,
        )
        for interface, affinity_mark in interface_marks.items():
            if affinity_mark <= 0 or affinity_mark & ~marks.affinity_mask:
                raise ValueError(f"invalid return-affinity mark for {interface}")
            stamped_mark = affinity_mark | marks.terminal_bit
            self._run(
                "iptables", "-t", "mangle", "-A", ingress_chain,
                "-i", interface, "-m", "conntrack", "--ctstate", "NEW",
                "-m", "mark", "--mark", f"0/{affinity_mask}",
                "-j", "MARK", "--set-xmark", f"{hex(stamped_mark)}/{stamp_mask}",
            )
        self._run(
            "iptables", "-t", "mangle", "-A", ingress_chain,
            "-j", "CONNMARK", "--save-mark",
            "--nfmask", connection_mask, "--ctmask", connection_mask,
        )

        for interface, affinity_mark in interface_marks.items():
            stamped_mark = affinity_mark | marks.terminal_bit
            self._run(
                "iptables", "-t", "mangle", "-A", egress_chain,
                "-o", interface, "-m", "conntrack", "--ctstate", "NEW",
                "-m", "mark", "--mark", f"0/{affinity_mask}",
                "-j", "MARK", "--set-xmark", f"{hex(stamped_mark)}/{stamp_mask}",
            )
            self._run(
                "iptables", "-t", "mangle", "-A", egress_chain,
                "-o", interface, "-m", "conntrack", "--ctstate", "NEW",
                "-m", "mark", "--mark", f"{hex(stamped_mark)}/{stamp_mask}",
                "-j", "CONNMARK", "--save-mark",
                "--nfmask", connection_mask, "--ctmask", connection_mask,
            )

    def install_spoke_return_affinity(self) -> None:
        """Pin every spoke flow to the hub and transport that carried it."""
        if self.site not in self.config.sites:
            raise ValueError("spoke return affinity may be installed only on a spoke")
        marks = self.config.settings.marks
        interface_marks: dict[str, int] = {}
        for hub in ("hub1", "hub2"):
            hub_bit = marks.hub1_bit if hub == "hub1" else marks.hub2_bit
            for transport in self.config.transports.values():
                interface_marks[self.config.target(hub, transport.name).interface_name] = (
                    transport.route_slot | hub_bit
                )
        self._install_return_path_affinity(interface_marks)

    def install_hub_return_affinity(self) -> None:
        """Pin hub return traffic to the ingress spoke transport."""
        if self.site not in self.config.hubs:
            raise ValueError("hub return affinity may be installed only on a hub")
        marks = self.config.settings.marks
        hub_bit = marks.hub1_bit if self.site == "hub1" else marks.hub2_bit
        interface_marks = {
            f"wg-spokes-{transport.name}": transport.route_slot | hub_bit
            for transport in self.config.transports.values()
        }
        self._install_return_path_affinity(interface_marks)

    def _intent_mark(self, desired: Mapping[str, Any], intent: Mapping[str, Any]) -> tuple[int, str, EgressMode]:
        marks = self.config.settings.marks
        allowed = {str(value) for value in intent.get("allowed_egress", ())}
        ranked = tuple(str(value) for value in intent.get("candidate_transports", intent.get("ranked_transports", ())))
        if not ranked:
            raise ValueError("policy intent has no candidate transport")
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
        class_marks: list[ClassMarkRule] = []
        seen_prefixes: set[str] = set()
        hub_overlay_prefixes: dict[str, list[str]] = {}
        for raw_intent in intents:
            if not isinstance(raw_intent, Mapping):
                raise ValueError("policy destination intent must be an object")
            prefix = str(raw_intent.get("prefix", ""))
            if not prefix or prefix in seen_prefixes:
                raise ValueError("policy destination prefixes must be unique and nonempty")
            mark, transport, egress = self._intent_mark(desired, raw_intent)
            prefix_marks.append((prefix, mark))
            seen_prefixes.add(prefix)
            candidates = tuple(str(value) for value in raw_intent.get("candidate_transports", raw_intent.get("ranked_transports", ())))
            application_policy = policy_snapshot.get("application_policy", {})
            for application_class in raw_intent.get("application_classes", ()):
                class_policy = application_policy.get(str(application_class), {}) if isinstance(application_policy, Mapping) else {}
                match = class_policy.get("match", {}) if isinstance(class_policy, Mapping) else {}
                ports = match.get("destination_ports", ()) if isinstance(match, Mapping) else ()
                if isinstance(match, Mapping) and match.get("destination_port") is not None:
                    ports = (match["destination_port"],)
                class_marks.append(ClassMarkRule(
                    application_class=str(application_class), prefix=prefix, mark=mark,
                    protocol=str(match["transport_protocol"]) if isinstance(match, Mapping) and match.get("transport_protocol") else None,
                    destination_ports=tuple(int(value) for value in ports),
                    dscp=int(match["dscp"]) if isinstance(match, Mapping) and match.get("dscp") is not None else None,
                ))
            if egress is EgressMode.DIRECT_INTERNET:
                if not ip_network(prefix).subnet_of(self.config.saas_network):
                    raise ValueError("direct Internet policy is limited to the simulated SaaS network")
                for candidate in candidates:
                    if not self.config.transports[candidate].internet_capable:
                        raise ValueError("direct Internet candidates must be Internet-capable")
                    self._run("ip", "route", "replace", prefix, "via", str(self.config.underlay_gateway_ip(candidate)), "dev", f"{self.site}-{candidate}", "onlink", "table", str(self.config.transports[candidate].route_table))
            elif egress is EgressMode.HUB_OVERLAY:
                for candidate in candidates:
                    for hub in ("hub1", "hub2"):
                        target = self.config.target(hub, candidate)
                        interface = target.interface_name
                        hub_overlay_prefixes.setdefault(interface, []).append(prefix)
                        self._run("ip", "route", "replace", prefix, "dev", interface, "table", str(target.route_table))
        self._ensure_hub_overlay_allowed_ips(desired, hub_overlay_prefixes)
        default_mark, _, _ = self._intent_mark(desired, default_intent)
        self.install_policy_rules()
        self.install_spoke_return_affinity()
        self.install_scoped_direct_nat(str(self.config.sites[self.site].lan_network), {"bb": f"{self.site}-bb", "lte": f"{self.site}-lte"})
        self._start_native_classifier(4100)
        self.install_connmark_rules(f"{self.site}-lan", prefix_marks, default_mark, class_marks=class_marks)
        self.store.persist_json("steering-rules.json", {
            "site": self.site,
            "lan_interface": f"{self.site}-lan",
            "prefix_marks": [{"prefix": prefix, "mark": mark} for prefix, mark in prefix_marks],
            "default_mark": default_mark,
            "queue_number": 4100,
            "rules": [rule.__dict__ for rule in class_marks],
        })
    def _ensure_hub_overlay_allowed_ips(self, desired: Mapping[str, Any], prefixes_by_interface: Mapping[str, list[str]]) -> None:
        """Reconcile policy-required prefixes into the selected hub peer only."""
        interfaces = {str(item["name"]): item for item in desired["interfaces"]}
        for interface_name, prefixes in prefixes_by_interface.items():
            interface = interfaces.get(interface_name)
            if not isinstance(interface, Mapping):
                raise ValueError("hub-overlay policy names an unknown WireGuard interface")
            peers = interface.get("peers")
            if not isinstance(peers, (list, tuple)) or len(peers) != 1 or not isinstance(peers[0], Mapping):
                raise ValueError("spoke hub-overlay interface must have exactly one peer")
            peer = peers[0]
            allowed = {str(value) for value in peer.get("allowed_ips", ())}
            allowed.update(prefixes)
            self._run("wg", "set", interface_name, "peer", str(peer["public_key"]), "allowed-ips", ",".join(sorted(allowed)), "persistent-keepalive", str(peer["keepalive_s"]))


    def install_hub_backhaul(self, desired: Mapping[str, Any] | None = None) -> None:
        """Install private-overlay return affinity and scoped Data Center NAT."""
        if self.site not in self.config.hubs:
            raise ValueError("hub backhaul may be installed only on a hub")
        private_prefixes = {str(profile.lan_network) for profile in self.config.sites.values()}
        if desired:
            for interface in desired.get("interfaces", ()):
                if not str(interface.get("name", "")).startswith("wg-spokes-"):
                    continue
                for peer in interface.get("peers", ()):
                    for candidate in peer.get("allowed_ips", ()):
                        try:
                            network = ip_network(str(candidate))
                        except ValueError:
                            continue
                        if network.version == 4 and network.subnet_of(ip_network("10.0.0.0/8")):
                            private_prefixes.add(str(network))
        spoke_interface = "wg-spokes-mpls"
        for prefix in sorted(private_prefixes):
            self._run("ip", "route", "replace", prefix, "dev", spoke_interface)
        self.install_hub_policy_rules()
        self.install_hub_return_affinity()
        self._start_hub_flow_collector()
        chain = "SDWAN_V5_HUB_NAT"
        self._ensure_chain("nat", chain)
        for prefix in sorted(private_prefixes):
            self._ensure_rule("nat", "POSTROUTING", "-s", prefix, "-j", chain)
        self._run("iptables", "-t", "nat", "-F", chain)
        self._run(
            "iptables", "-t", "nat", "-A", chain,
            "-d", str(self.config.data_center_network), "-o", f"{self.site}-dc",
            "-j", "SNAT", "--to-source", str(self.config.data_center_hub_ips[self.site]),
        )
        for prefix in self.config.protected_private_prefixes:
            self._run("iptables", "-t", "nat", "-A", chain, "-d", str(prefix), "-j", "RETURN")

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
                # Hub-specific affinity must be evaluated before the generic
                # transport-slot rule at priorities 2001..2003.
                try:
                    self._run("ip", "rule", "del", "priority", str(1000 + target.route_table))
                except CommandError as exc:
                    if "No such file" not in str(exc) and "Cannot find" not in str(exc):
                        raise
                self._replace_owned_rule(target.route_table, f"{mark}/{mask}", target.route_table)

    def install_hub_policy_rules(self) -> None:
        """Install only this hub's transport-affinity route-table rules."""
        if self.site not in self.config.hubs:
            raise ValueError("hub policy rules may be installed only on a hub")
        marks = self.config.settings.marks
        hub_bit = marks.hub1_bit if self.site == "hub1" else marks.hub2_bit
        mask = marks.route_mask | marks.target_hub_mask
        for transport in self.config.transports.values():
            target = self.config.target(self.site, transport.name)
            mark = transport.route_slot | hub_bit
            self._replace_owned_rule(target.route_table, f"{mark}/{mask}", target.route_table)

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
