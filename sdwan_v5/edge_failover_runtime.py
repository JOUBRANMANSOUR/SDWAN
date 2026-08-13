"""Spoke-local tunnel monitoring and failover actuation.

This process owns only local, cached-policy route changes.  It never makes a
packet-in, nDPI, or database decision.  Direct-SaaS routes are deliberately
outside its overlay-prefix replacement set.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import time
import uuid
from typing import Any, Mapping, Protocol

from .common.marks import EgressMode
from .common.model import TopologyConfig, load_config
from .edge_agent_v5 import CommandError, EdgeAgent, SystemRunner
from .hub_health import HubState, aggregate_hub
from .local_failover import LocalFailoverManager, SlotTarget
from .route_resolver import RouteResolver, Target
from .tunnel_health import StaleMeasurement, TunnelHealth, TunnelHealthMachine, TunnelSample, TunnelState


class Runner(Protocol):
    def run(self, command: list[str]) -> None: ...


class FailoverRouteActuator:
    """Applies an atomic route-table replacement for one SD-WAN slot."""

    def __init__(self, site: str, config: TopologyConfig, desired: Mapping[str, Any], runner: Runner):
        self.site, self.config, self.desired, self.runner = site, config, desired, runner
        if site not in config.sites:
            raise ValueError("local failover applies only to spokes")
        self._interfaces = {str(item["name"]): item for item in desired["interfaces"]}

    def repoint(self, slot: str, interface: str) -> None:
        if slot not in self.config.transports or interface not in self._interfaces:
            raise ValueError("unknown failover slot or interface")
        item = self._interfaces[interface]
        if int(item["transport_slot"]) <= 0:
            raise ValueError("desired interface is missing a transport slot")
        table = self.config.transports[slot].route_table
        # SaaS has an explicit direct-breakout route in table 102.  Do not
        # replace it with an overlay route while failing over corporate paths.
        for prefix in item["routes"]:
            if str(prefix) == str(self.config.saas_network):
                continue
            self.runner.run(["ip", "route", "replace", str(prefix), "dev", interface, "table", str(table)])


class LocalFailoverRuntime:
    """Periodic probe loop with local hysteresis, failover, and drain-based failback."""

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
        active = desired.get("active_target_by_slot", {})
        targets: dict[str, SlotTarget] = {}
        for slot, value in active.items():
            name = str(value["interface"])
            item = self.interfaces[name]
            targets[str(slot)] = SlotTarget(str(value["hub"]), self.transport_by_interface[name], name, config.transports[str(slot)].route_table)
        self.manager = LocalFailoverManager(site, targets, drain_timeout_s=config.settings.drain_timeout_s)
        self.health = {
            name: TunnelHealthMachine(
                suspect_failures=config.settings.suspect_failures,
                failed_failures=config.settings.failed_failures,
                recovery_successes=config.settings.recovery_successes,
                hold_down_s=config.settings.hold_down_s,
                stale_after_s=config.settings.stale_measurement_s,
            )
            for name in self.interfaces
        }
        self.sequence = 0
        self.recovery_started: set[str] = set()
        self._last_status: dict[str, tuple[str, str, int]] = {}

    def _check(self, command: list[str]) -> tuple[bool, str]:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False)
        return result.returncode == 0, result.stdout

    def _probe(self, name: str) -> TunnelSample:
        item = self.interfaces[name]
        hub = str(item["hub"])
        transport = self.transport_by_interface[name]
        self.sequence += 1
        now_wall, now_monotonic = time.time(), time.monotonic()
        link_up, _ = self._check(["ip", "link", "show", "dev", name, "up"])
        underlay_up, _ = self._check(["ping", "-I", f"{self.site}-{transport}", "-c", "1", "-W", "1", str(self.config.underlay_ip(hub, transport))])
        overlay_up, _ = self._check(["ping", "-I", name, "-c", "1", "-W", "1", str(self.config.overlay_ip(hub, hub, transport))])
        shown, output = self._check(["wg", "show", name, "latest-handshakes"])
        timestamps = [int(line.rsplit("\t", 1)[-1]) for line in output.splitlines() if "\t" in line and line.rsplit("\t", 1)[-1].isdigit()]
        age = (now_wall - max(timestamps)) if shown and timestamps and max(timestamps) else None
        return TunnelSample(
            site=self.site, hub=hub, transport=transport, interface=name,
            wall_timestamp=now_wall, monotonic_timestamp=now_monotonic,
            probe_sequence=self.sequence, source="edge-local-active-probe",
            link_up=link_up, underlay_reachable=underlay_up,
            wireguard_up=link_up, overlay_reachable=overlay_up,
            handshake_age_s=age,
        )

    def _targets(self, health: Mapping[str, TunnelHealth]) -> list[Target]:
        by_hub: dict[str, dict[str, TunnelHealth]] = {"hub1": {}, "hub2": {}}
        for name, item in self.interfaces.items():
            by_hub[str(item["hub"])][name] = health[name]
        hubs = {name: aggregate_hub(name, values).state for name, values in by_hub.items()}
        return [
            Target(
                hub=str(item["hub"]), transport=self.transport_by_interface[name], interface=name,
                egress_mode=EgressMode.HUB_OVERLAY, tunnel_state=health[name].state,
                hub_state=hubs[str(item["hub"])],
            )
            for name, item in self.interfaces.items()
        ]
    def _persist_status(self, slot: str, state: str, detail: str) -> None:
        record = (state, detail, self.manager.route_version)
        if self._last_status.get(slot) == record:
            return
        previous = self.agent.store.load_json("failover-status.json") or {}
        existing_slots = previous.get("slots") if isinstance(previous, dict) else {}
        slots = existing_slots if isinstance(existing_slots, dict) else {}
        status: dict[str, Any] = {"site": self.site, "slots": slots}
        slots[slot] = {
            "state": state, "detail": detail, "route_version": self.manager.route_version,
            "updated_monotonic": time.monotonic(),
        }
        status["site"] = self.site
        self.agent.store.persist_json("failover-status.json", status)
        self._last_status[slot] = record

    def _active_flow_count(self, slot: str) -> int:
        mark = self.config.transports[slot].route_slot
        ok, output = self._check(["conntrack", "-L", "-o", "extended", "--mark", f"{mark}/{self.config.settings.marks.route_mask}"])
        return len([line for line in output.splitlines() if line]) if ok else 0

    def run_once(self) -> None:
        observed: dict[str, TunnelHealth] = {}
        for name, machine in self.health.items():
            try:
                observed[name] = machine.observe(self._probe(name))
            except StaleMeasurement:
                observed[name] = machine.health
        candidates = self._targets(observed)
        profile = self.config.sites[self.site]
        for slot in self.manager.slots:
            current = self.manager.target(slot)
            current_health = observed[current.interface]
            if current_health.state is TunnelState.FAILED:
                try:
                    resolution = RouteResolver().resolve(
                        slot=slot,
                        ranked_transports=(slot, *(name for name in self.config.transports if name != slot)),
                        allowed_egress=(EgressMode.HUB_OVERLAY,),
                        preferred_hub=profile.preferred_hub, standby_hub=profile.standby_hub,
                        targets=candidates,
                        current=next(item for item in candidates if item.interface == current.interface),
                        hard_failure=True,
                    )
                except LookupError:
                    self._persist_status(slot, "DEGRADED", "no healthy local overlay replacement")
                    continue
                replacement = SlotTarget(
                    str(resolution.target.hub), resolution.target.transport,
                    resolution.target.interface, self.config.transports[slot].route_table,
                )
                if replacement.interface != current.interface:
                    event = self.manager.emergency_remap(
                        event_id=str(uuid.uuid4()), slot=slot, replacement=replacement,
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
            time.sleep(self.config.settings.probe_interval_s)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--site", required=True)
    parser.add_argument("--config", type=Path, default=Path("/opt/sdwan_v5/config/topology.yaml"))
    parser.add_argument("--identity-root", type=Path, default=Path("/var/lib/sdwan"))
    parser.add_argument("--once", action="store_true")
    arguments = parser.parse_args()
    desired_path = arguments.identity_root / "state" / "desired-state.json"
    desired = json.loads(desired_path.read_text(encoding="utf-8"))
    runtime = LocalFailoverRuntime(arguments.site, load_config(arguments.config), desired, arguments.identity_root)
    if arguments.once:
        runtime.run_once()
    else:
        runtime.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
