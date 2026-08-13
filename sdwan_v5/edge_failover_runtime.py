"""Continuous spoke path monitoring, SLA steering, and emergency failover."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import time
from threading import Lock
import uuid
from typing import Any, Mapping, Protocol

from sdwan_v5.common.marks import EgressMode
from sdwan_v5.common.model import TopologyConfig, load_config
from sdwan_v5.dynamic_profile import overlay_site_profile
from sdwan_v5.common.path_selection import ApplicationClass, MetricWindow, NoEligibleAction, PathSelector
from sdwan_v5.edge_agent_v5 import ClassMarkRule, CommandError, EdgeAgent, SystemRunner
from sdwan_v5.hub_health import aggregate_hub
from sdwan_v5.local_failover import LocalFailoverManager, SlotTarget
from sdwan_v5.route_resolver import RouteResolver, Target
from sdwan_v5.tunnel_health import StaleMeasurement, TunnelHealth, TunnelHealthMachine, TunnelSample, TunnelState


class Runner(Protocol):
    def run(self, command: list[str]) -> None: ...


class FailoverRouteActuator:
    """Replace one generic transport table after a hard path failure."""

    def __init__(self, site: str, config: TopologyConfig, desired: Mapping[str, Any], runner: Runner):
        self.site, self.config, self.desired, self.runner = site, config, desired, runner
        self._interfaces = {str(item["name"]): item for item in desired["interfaces"]}

    def repoint(self, slot: str, interface: str) -> None:
        item = self._interfaces[interface]
        table = self.config.transports[slot].route_table
        for prefix in item["routes"]:
            if str(prefix) == str(self.config.saas_network):
                continue
            self.runner.run(["ip", "route", "replace", str(prefix), "dev", interface, "table", str(table)])


class LocalFailoverRuntime:
    """Extend the existing monitor with live metrics and policy-constrained SLA selection."""

    def __init__(self, site: str, config: TopologyConfig, desired: Mapping[str, Any], identity_root: Path, *, runner: Runner | None = None):
        self.site, self.config, self.desired = site, config, desired
        self.runner: Runner = runner or SystemRunner()
        self.agent = EdgeAgent(site, config, identity_root, self.runner)
        self.actuator = FailoverRouteActuator(site, config, desired, self.runner)
        self.interfaces = {str(item["name"]): item for item in desired["interfaces"]}
        self.transport_by_interface = {
            name: next(transport for transport, profile in config.transports.items() if profile.route_slot == int(item["transport_slot"]))
            for name, item in self.interfaces.items()
        }
        targets: dict[str, SlotTarget] = {}
        for slot, value in desired.get("active_target_by_slot", {}).items():
            name = str(value["interface"])
            targets[str(slot)] = SlotTarget(str(value["hub"]), self.transport_by_interface[name], name, config.transports[str(slot)].route_table)
        self.manager = LocalFailoverManager(site, targets, drain_timeout_s=config.settings.drain_timeout_s)
        self.health = {
            name: TunnelHealthMachine(
                suspect_failures=config.settings.suspect_failures,
                failed_failures=config.settings.failed_failures,
                recovery_successes=config.settings.recovery_successes,
                hold_down_s=config.settings.hold_down_s,
                stale_after_s=config.measurement.stale_after_seconds,
            )
            for name in self.interfaces
        }
        self.selector = PathSelector(config.path_selection, stale_after_seconds=config.measurement.stale_after_seconds)
        self.resolver = RouteResolver()
        self.metric_windows = {
            name: MetricWindow(config.measurement, config.transports[self.transport_by_interface[name]].bandwidth_mbps)
            for name in self.interfaces
        }
        for transport in ("bb", "lte"):
            if config.transports[transport].internet_capable:
                self.metric_windows[f"direct-{transport}"] = MetricWindow(config.measurement, config.transports[transport].bandwidth_mbps)
        self._measurements: dict[str, dict[str, Any]] = {}
        self._decisions: dict[str, dict[str, Any]] = {}
        self.sequence = 0
        self._sequence_lock = Lock()
        self._measurement_lock = Lock()
        self.recovery_started: set[str] = set()
        self._last_status: dict[str, tuple[str, str, int]] = {}

    @staticmethod
    def _check(command: list[str]) -> tuple[bool, str]:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False)
        return result.returncode == 0, result.stdout

    @staticmethod
    def _parse_ping(output: str, successful: bool) -> tuple[float | None, float, int | None, int | None]:
        loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", output)
        packets = re.search(r"(\d+) packets transmitted, (\d+) received", output)
        rtt = re.search(r"=\s*[\d.]+/([\d.]+)/", output)
        transmitted = int(packets.group(1)) if packets else None
        received = int(packets.group(2)) if packets else None
        return (
            float(rtt.group(1)) if rtt else None,
            float(loss.group(1)) if loss else (0.0 if successful else 100.0),
            transmitted,
            received,
        )

    def _next_sequence(self) -> int:
        with self._sequence_lock:
            self.sequence += 1
            return self.sequence

    def _interface_bytes(self, interface: str) -> int | None:
        """Return the busiest-direction byte counter for capacity estimation."""
        try:
            root = Path("/sys/class/net") / interface / "statistics"
            rx_bytes = int((root / "rx_bytes").read_text(encoding="ascii").strip())
            tx_bytes = int((root / "tx_bytes").read_text(encoding="ascii").strip())
            return max(rx_bytes, tx_bytes)
        except (OSError, ValueError):
            return None

    def _measure(
        self, path_id: str, interface: str, destination: str, *,
        hub: str | None, transport: str, egress_mode: EgressMode, fwmark: int | None = None,
    ) -> dict[str, Any]:
        command = ["ping", "-I", interface]
        if fwmark is not None:
            command.extend(["-m", str(fwmark)])
        command.extend(["-c", "10", "-i", "0.1", "-W", "1", "-q", destination])
        successful, output = self._check(command)
        now = time.monotonic()
        rtt_sample, loss_sample, transmitted, received = self._parse_ping(output, successful)
        rtt, jitter, loss, available = self.metric_windows[path_id].update(
            successful=successful, rtt_ms=rtt_sample, loss_pct_sample=loss_sample,
            transmitted_packets=transmitted, received_packets=received,
            counter_timestamp=now, interface_bytes=self._interface_bytes(f"{self.site}-{transport}"),
        )
        record = {
            "path_id": path_id, "interface": interface, "hub": hub, "transport": transport,
            "egress_mode": egress_mode.value, "administratively_enabled": True,
            "operationally_reachable": successful, "rtt_ms": rtt,
            "latency_semantics": "round-trip time; not one-way delay", "jitter_ms": jitter,
            "jitter_formula": "EWMA(abs(current raw RTT sample - previous raw RTT sample))",
            "loss_pct": loss, "loss_window_samples": self.config.measurement.loss_window_samples,
            "configured_capacity_mbps": self.config.transports[transport].bandwidth_mbps,
            "estimated_available_bandwidth_mbps": available,
            "bandwidth_semantics": "configured capacity minus busiest-direction interface utilization, EWMA-smoothed; first sample bootstraps at configured capacity",
            "transport_cost": self.config.transports[transport].cost,
            "measured_at_monotonic": now, "measured_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._measurement_lock:
            self._measurements[path_id] = record
        return record

    def _probe(self, name: str) -> TunnelSample:
        item = self.interfaces[name]
        hub, transport = str(item["hub"]), self.transport_by_interface[name]
        sequence = self._next_sequence()
        now_wall, now_monotonic = time.time(), time.monotonic()
        link_up, _ = self._check(["ip", "link", "show", "dev", name, "up"])
        underlay_up, _ = self._check(["ping", "-I", f"{self.site}-{transport}", "-c", "1", "-W", "1", str(self.config.underlay_ip(hub, transport))])
        metric = self._measure(name, name, str(self.config.overlay_ip(hub, hub, transport)), hub=hub, transport=transport, egress_mode=EgressMode.HUB_OVERLAY)
        shown, output = self._check(["wg", "show", name, "latest-handshakes"])
        timestamps = [int(line.rsplit("\t", 1)[-1]) for line in output.splitlines() if "\t" in line and line.rsplit("\t", 1)[-1].isdigit()]
        age = now_wall - max(timestamps) if shown and timestamps and max(timestamps) else None
        return TunnelSample(
            self.site, hub, transport, name, now_wall, now_monotonic, sequence,
            "edge-local-active-probe", link_up, underlay_up, link_up,
            bool(metric["operationally_reachable"]), age,
            metric["rtt_ms"], metric["jitter_ms"], metric["loss_pct"],
        )

    def _targets(self, health: Mapping[str, TunnelHealth]) -> list[Target]:
        by_hub: dict[str, dict[str, TunnelHealth]] = {"hub1": {}, "hub2": {}}
        for name, item in self.interfaces.items():
            by_hub[str(item["hub"])][name] = health[name]
        hubs = {name: aggregate_hub(name, values).state for name, values in by_hub.items()}
        targets: list[Target] = []
        for name, item in self.interfaces.items():
            transport, metric = self.transport_by_interface[name], self._measurements[name]
            targets.append(Target(
                hub=str(item["hub"]), transport=transport, interface=name,
                egress_mode=EgressMode.HUB_OVERLAY, tunnel_state=health[name].state,
                hub_state=hubs[str(item["hub"])],
                rtt_ms=float(metric["rtt_ms"]) if metric.get("rtt_ms") is not None else None,
                jitter_ms=float(metric["jitter_ms"]) if metric.get("jitter_ms") is not None else None,
                loss_pct=float(metric["loss_pct"]) if metric.get("loss_pct") is not None else None,
                available_mbps=float(metric["estimated_available_bandwidth_mbps"]) if metric.get("estimated_available_bandwidth_mbps") is not None else None,
                measured_at_monotonic=float(metric["measured_at_monotonic"]),
                configured_capacity_mbps=self.config.transports[transport].bandwidth_mbps,
                cost=self.config.transports[transport].cost,
            ))
        return targets

    def _direct_target(self, transport: str) -> Target:
        profile = self.config.transports[transport]
        path_id, interface = f"direct-{transport}", f"{self.site}-{transport}"
        mark = self.config.settings.marks.encode(
            profile.route_slot, egress=EgressMode.DIRECT_INTERNET,
        )
        metric = self._measure(
            path_id, interface, str(self.config.saas_ip), hub=None, transport=transport,
            egress_mode=EgressMode.DIRECT_INTERNET, fwmark=mark,
        )
        reachable = bool(metric["operationally_reachable"])
        return Target(
            None, transport, interface, EgressMode.DIRECT_INTERNET,
            TunnelState.HEALTHY if reachable else TunnelState.FAILED, None,
            float(metric["rtt_ms"]) if metric.get("rtt_ms") is not None else None,
            float(metric["jitter_ms"]) if metric.get("jitter_ms") is not None else None,
            float(metric["loss_pct"]) if metric.get("loss_pct") is not None else None,
            float(metric["estimated_available_bandwidth_mbps"]) if metric.get("estimated_available_bandwidth_mbps") is not None else None,
            True, float(metric["measured_at_monotonic"]), profile.bandwidth_mbps, profile.cost,
        )

    def _direct_targets(self) -> list[Target]:
        return [
            self._direct_target(transport)
            for transport in ("bb", "lte")
            if self.config.transports[transport].internet_capable
        ]

    def _selection_mark(self, target: Target) -> int:
        slot = self.config.transports[target.transport].route_slot
        return self.config.settings.marks.encode(slot, egress=EgressMode.DIRECT_INTERNET) if target.egress_mode is EgressMode.DIRECT_INTERNET else self.config.settings.marks.encode(slot, hub=target.hub)

    def _apply_class_marks(self, steering: Mapping[str, Any], rules: list[ClassMarkRule]) -> None:
        prefix_marks = [(str(item["prefix"]), int(item["mark"])) for item in steering.get("prefix_marks", ())]
        self.agent.install_connmark_rules(
            str(steering.get("lan_interface", f"{self.site}-lan")), prefix_marks,
            int(steering["default_mark"]), int(steering.get("queue_number", 4100)), class_marks=rules,
        )

    def _resteer_rtp(self, mark: int) -> None:
        try:
            self.runner.run([
                "conntrack", "-U", "-p", "udp", "--orig-src", str(self.config.sites[self.site].host_ip),
                "--dport", "5004", "--mark", f"{mark}/{self.config.settings.marks.affinity_mask}",
            ])
        except CommandError:
            pass

    def _record_switch_event(self, decision: Mapping[str, Any], previous: Mapping[str, Any] | None) -> None:
        state = self.agent.store.load_json("path-events.json") or {"events": []}
        events = list(state.get("events", ()))
        old_metrics = previous.get("selected_path") if previous else None
        new_metrics = decision.get("selected_path")
        events.append({
            "application_class": decision["application_class"],
            "source": decision["source"],
            "destination": decision["destination"],
            "destination_policy": decision.get("destination_policy"),
            "old_path": old_metrics.get("path_id") if isinstance(old_metrics, Mapping) else None,
            "new_path": new_metrics.get("path_id") if isinstance(new_metrics, Mapping) else None,
            "old_metrics": old_metrics,
            "new_metrics": new_metrics,
            "reason": decision["selection_reason"],
            "timestamp": decision["timestamp"],
            "timestamp_monotonic": decision.get("timestamp_monotonic"),
        })
        self.agent.store.persist_json("path-events.json", {"site": self.site, "events": events[-200:]})

    def _run_sla_selection(self, targets: list[Target]) -> None:
        snapshot = self.agent.store.load_json("policy-snapshot.json")
        steering = self.agent.store.load_json("steering-rules.json")
        if not snapshot or not steering:
            return
        rules = [ClassMarkRule(
            str(item["application_class"]), str(item["prefix"]), int(item["mark"]),
            str(item["protocol"]) if item.get("protocol") else None,
            tuple(int(value) for value in item.get("destination_ports", ())),
            int(item["dscp"]) if item.get("dscp") is not None else None,
            bool(item.get("blocked", False)),
        ) for item in steering.get("rules", ())]
        updated_rules, changed_rules = list(rules), False
        for intent in snapshot.get("destination_intents", ()):
            allowed = tuple(EgressMode(value) for value in intent.get("allowed_egress", ()))
            transports = tuple(intent.get("candidate_transports", intent.get("ranked_transports", ())))
            for name in intent.get("application_classes", ()):
                try:
                    app_class = ApplicationClass(str(name))
                except ValueError:
                    continue
                result = self.resolver.resolve_sla(
                    selector=self.selector, application_class=app_class, source=self.site,
                    destination=str(intent["prefix"]), destination_policy=str(intent["policy_id"]),
                    allowed_egress=allowed, candidate_transports=transports, targets=targets,
                    sla=self.config.application_slas[app_class], weights=self.config.path_scoring[app_class],
                )
                decision = result.decision.to_mapping()
                key = f"{app_class.value}:{intent['prefix']}"
                previous = self._decisions.get(key)
                self._decisions[key] = decision
                if decision["changed"]:
                    self._record_switch_event(decision, previous)
                matching_indexes = [
                    index for index, rule in enumerate(updated_rules)
                    if rule.application_class == app_class.value and rule.prefix == str(intent["prefix"])
                ]
                if result.resolution is None:
                    # FAIL_CLOSED must be enforced in the dataplane rather
                    # than merely reported by the selector. The DROP rule is
                    # class-specific and is evaluated only for unmarked/new
                    # flows, after conntrack restoration.
                    should_block = (
                        self.config.application_slas[app_class].no_eligible_action
                        is NoEligibleAction.FAIL_CLOSED
                    )
                    if should_block:
                        for index in matching_indexes:
                            rule = updated_rules[index]
                            if not rule.blocked:
                                updated_rules[index] = ClassMarkRule(
                                    rule.application_class, rule.prefix, rule.mark, rule.protocol,
                                    rule.destination_ports, rule.dscp, True,
                                )
                                changed_rules = True
                    continue
                mark = self._selection_mark(result.resolution.target)
                for index in matching_indexes:
                    rule = updated_rules[index]
                    if rule.mark != mark or rule.blocked:
                        updated_rules[index] = ClassMarkRule(
                            rule.application_class, rule.prefix, mark, rule.protocol,
                            rule.destination_ports, rule.dscp, False,
                        )
                        changed_rules = True
                if app_class is ApplicationClass.REALTIME_RTP and decision["changed"]:
                    self._resteer_rtp(mark)
        if changed_rules:
            self._apply_class_marks(steering, updated_rules)
            steering_state = dict(steering)
            steering_state["rules"] = [rule.__dict__ for rule in updated_rules]
            self.agent.store.persist_json("steering-rules.json", steering_state)
        self.agent.store.persist_json("path-metrics.json", {"site": self.site, "paths": list(self._measurements.values())})
        self.agent.store.persist_json("path-decisions.json", {"site": self.site, "decisions": list(self._decisions.values())})

    def _persist_status(self, slot: str, state: str, detail: str) -> None:
        record = (state, detail, self.manager.route_version)
        if self._last_status.get(slot) == record:
            return
        previous = self.agent.store.load_json("failover-status.json") or {}
        slots = previous.get("slots") if isinstance(previous.get("slots"), dict) else {}
        slots[slot] = {"state": state, "detail": detail, "route_version": self.manager.route_version, "updated_monotonic": time.monotonic()}
        self.agent.store.persist_json("failover-status.json", {"site": self.site, "slots": slots})
        self._last_status[slot] = record

    def _active_flow_count(self, slot: str) -> int:
        mark = self.config.transports[slot].route_slot
        ok, output = self._check(["conntrack", "-L", "-o", "extended", "--mark", f"{mark}/{self.config.settings.marks.route_mask}"])
        return len([line for line in output.splitlines() if line]) if ok else 0

    def run_once(self) -> None:
        observed: dict[str, TunnelHealth] = {}
        direct_transports = [
            transport for transport in ("bb", "lte")
            if self.config.transports[transport].internet_capable
        ]
        # Measure all paths in the same round. Serial probes exceeded the
        # six-second freshness budget, so early paths were stale before the
        # selector evaluated them.
        with ThreadPoolExecutor(
            max_workers=len(self.health) + len(direct_transports)
        ) as executor:
            overlay_futures = {
                name: executor.submit(self._probe, name) for name in self.health
            }
            direct_futures = {
                transport: executor.submit(self._direct_target, transport)
                for transport in direct_transports
            }
            for name, machine in self.health.items():
                try:
                    observed[name] = machine.observe(overlay_futures[name].result())
                except StaleMeasurement:
                    observed[name] = machine.health
            direct_targets = [
                direct_futures[transport].result() for transport in direct_transports
            ]
        candidates = self._targets(observed) + direct_targets
        self._run_sla_selection(candidates)
        profile = self.config.sites[self.site]
        for slot in self.manager.slots:
            current = self.manager.target(slot)
            current_health = observed[current.interface]
            if current_health.state is TunnelState.FAILED:
                try:
                    resolution = self.resolver.resolve(
                        slot=slot, ranked_transports=(slot, *(name for name in self.config.transports if name != slot)),
                        allowed_egress=(EgressMode.HUB_OVERLAY,), preferred_hub=profile.preferred_hub,
                        standby_hub=profile.standby_hub, targets=candidates,
                        current=next(item for item in candidates if item.interface == current.interface), hard_failure=True,
                    )
                except LookupError:
                    self._persist_status(slot, "DEGRADED", "no healthy local overlay replacement")
                    continue
                replacement = SlotTarget(str(resolution.target.hub), resolution.target.transport, resolution.target.interface, self.config.transports[slot].route_table)
                if replacement.interface != current.interface:
                    event = self.manager.emergency_remap(
                    event_id=str(uuid.uuid4()),
                    slot=slot,
                    replacement=replacement,
                    reason=resolution.reason,
                )
                    self.actuator.repoint(slot, replacement.interface)
                    self.agent.enqueue_event(event)
                    self._persist_status(slot, "FAILOVER", event.reason)
                continue
            if not self.manager.is_emergency(slot):
                self._persist_status(slot, current_health.state.value, f"active target {current.interface}")
                continue
            previous = self.manager.previous_target(slot)
            if observed[previous.interface].state is not TunnelState.HEALTHY:
                self.recovery_started.discard(slot)
                self._persist_status(slot, "DEGRADED", "previous target has not recovered")
                continue
            if slot not in self.recovery_started:
                self.manager.begin_recovery(slot)
                self.recovery_started.add(slot)
                self._persist_status(slot, "RECOVERING", "previous target met health threshold; waiting for drain")
                continue
            restored = self.manager.complete_recovery(slot, self._active_flow_count(slot))
            if restored is not None:
                self.actuator.repoint(slot, restored.interface)
                self.recovery_started.discard(slot)
                self._persist_status(slot, "FAILBACK", "drain completed; restored prior target")

    def serve_forever(self) -> None:
        while True:
            self.run_once()
            time.sleep(self.config.measurement.interval_seconds)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--site", required=True)
    parser.add_argument("--config", type=Path, default=Path("/opt/sdwan_v5/config/topology.core.yaml"))
    parser.add_argument("--site-profile", type=Path)
    parser.add_argument("--identity-root", type=Path, default=Path("/var/lib/sdwan"))
    parser.add_argument("--once", action="store_true")
    arguments = parser.parse_args()
    desired = json.loads((arguments.identity_root / "state" / "desired-state.json").read_text(encoding="utf-8"))
    profile = json.loads(arguments.site_profile.read_text(encoding="utf-8")) if arguments.site_profile and arguments.site_profile.is_file() else None
    config = overlay_site_profile(load_config(arguments.config), arguments.site, profile)
    runtime = LocalFailoverRuntime(arguments.site, config, desired, arguments.identity_root)
    runtime.run_once() if arguments.once else runtime.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
