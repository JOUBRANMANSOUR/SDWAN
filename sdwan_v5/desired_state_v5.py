"""Canonical v5 desired-state construction and exact topology invariants."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Mapping

from .common.model import HUBS, TRANSPORTS, TopologyConfig


def canonical_digest(value: Mapping[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Peer:
    peer_id: str
    public_key: str
    endpoint: str | None
    allowed_ips: tuple[str, ...]
    keepalive_s: int


@dataclass(frozen=True)
class WireGuardInterface:
    name: str
    address: str
    listen_port: int
    route_table: int
    transport_slot: int
    hub: str | None
    peers: tuple[Peer, ...]
    routes: tuple[str, ...]


@dataclass(frozen=True)
class DesiredState:
    schema_version: int
    site: str
    generation: str
    desired_state_version: int
    route_version: int
    ownership_epoch: int
    preferred_hub: str | None
    standby_hub: str | None
    active_target_by_slot: Mapping[str, Mapping[str, str]]
    interfaces: tuple[WireGuardInterface, ...]
    route_ownership: tuple[Mapping[str, Any], ...]
    egress_policy: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["configuration_digest"] = canonical_digest(result)
        return result


def _all_remote_prefixes(config: TopologyConfig, site: str) -> tuple[str, ...]:
    prefixes = [str(item.lan_network) for name, item in config.sites.items() if name != site]
    prefixes.append(str(config.data_center_network))
    if config.cloud_vpc.enabled:
        prefixes.append(str(config.cloud_vpc.network))
    return tuple(sorted(prefixes))


def build_spoke_desired_state(
    config: TopologyConfig,
    site: str,
    public_keys: Mapping[str, str],
    *,
    generation: str,
    desired_state_version: int,
    route_version: int,
    ownership_epoch: int,
    active_target_by_slot: Mapping[str, Mapping[str, str]] | None = None,
) -> DesiredState:
    if site not in config.sites:
        raise ValueError("not a spoke")
    profile = config.sites[site]
    missing = set(HUBS) - set(public_keys)
    if missing:
        raise ValueError(f"missing hub public keys: {sorted(missing)}")
    routes = _all_remote_prefixes(config, site)
    interfaces: list[WireGuardInterface] = []
    for target in config.spoke_targets(site):
        remote_overlay = f"{config.overlay_ip(target.hub, target.hub, target.transport)}/32"
        endpoint = f"{config.underlay_ip(target.hub, target.transport)}:{config.wireguard_port(target.hub, target.hub, target.transport)}"
        peer = Peer(target.hub, public_keys[target.hub], endpoint, tuple(sorted((remote_overlay, *routes))), config.settings.persistent_keepalive_s)
        interfaces.append(WireGuardInterface(target.interface_name, f"{config.overlay_ip(site, target.hub, target.transport)}/{target.overlay_network.prefixlen}", config.wireguard_port(site, target.hub, target.transport), target.route_table, config.transports[target.transport].route_slot, target.hub, (peer,), routes))
    active = active_target_by_slot or {
        transport: {"hub": profile.preferred_hub, "interface": config.target(profile.preferred_hub, transport).interface_name}
        for transport in TRANSPORTS
    }
    state = DesiredState(5, site, generation, desired_state_version, route_version, ownership_epoch, profile.preferred_hub, profile.standby_hub, active, tuple(interfaces), (), {"private_prefixes": [str(item) for item in config.protected_private_prefixes]})
    validate_desired_state(state, config)
    return state


def build_hub_desired_state(
    config: TopologyConfig,
    hub: str,
    public_keys: Mapping[str, str],
    ownership: Mapping[str, Mapping[str, Any]],
    *,
    generation: str,
    desired_state_version: int,
    route_version: int,
    ownership_epoch: int,
) -> DesiredState:
    if hub not in config.hubs:
        raise ValueError("not a hub")
    other_hub = next(item for item in HUBS if item != hub)
    if other_hub not in public_keys:
        raise ValueError("missing opposite-hub public key")
    interfaces: list[WireGuardInterface] = []
    for transport in TRANSPORTS:
        peers: list[Peer] = []
        for site in config.sites:
            # Hub bootstrap precedes individual spoke enrollment. Unknown
            # spokes are deliberately absent until their public key is
            # registered; no placeholder peer is ever installed.
            if site not in public_keys:
                continue
            remote_overlay = f"{config.overlay_ip(site, hub, transport)}/32"
            allowed = (remote_overlay, str(config.sites[site].lan_network))
            peers.append(Peer(site, public_keys[site], None, allowed, config.settings.persistent_keepalive_s))
        interfaces.append(WireGuardInterface(f"wg-spokes-{transport}", f"{config.overlay_ip(hub, hub, transport)}/{config.target(hub, transport).overlay_network.prefixlen}", config.wireguard_port(hub, hub, transport), config.target(hub, transport).route_table, config.transports[transport].route_slot, hub, tuple(peers), tuple(str(item.lan_network) for item in config.sites.values())))
        other = next(item for item in HUBS if item != hub)
        network = config.interhub_networks[transport]
        peer = Peer(
            other, public_keys[other],
            f"{config.underlay_ip(other, transport)}:{config.interhub_port(other, transport)}",
            (f"{network.network_address + (2 if hub == 'hub1' else 1)}/32",),
            config.settings.persistent_keepalive_s,
        )
        interfaces.append(WireGuardInterface(f"wg-ih-{transport}", f"{network.network_address + (1 if hub == 'hub1' else 2)}/{network.prefixlen}", config.interhub_port(hub, transport), 2000 + HUBS.index(hub) * 10 + TRANSPORTS.index(transport), config.transports[transport].route_slot, other, (peer,), ()))
    state = DesiredState(5, hub, generation, desired_state_version, route_version, ownership_epoch, None, None, {}, tuple(interfaces), tuple(ownership.values()), {"private_prefixes": [str(item) for item in config.protected_private_prefixes]})
    validate_desired_state(state, config)
    return state


def validate_desired_state(state: DesiredState, config: TopologyConfig) -> None:
    if state.schema_version != 5:
        raise ValueError("desired state schema must be 5")
    names = [item.name for item in state.interfaces]
    if len(names) != len(set(names)):
        raise ValueError("desired-state interface names must be unique")
    ports = [item.listen_port for item in state.interfaces]
    if len(ports) != len(set(ports)):
        raise ValueError("desired-state listen ports must be unique")
    if state.site in config.sites:
        required = {f"wg-h{number}-{transport}" for number in (1, 2) for transport in TRANSPORTS}
        if set(names) != required:
            raise ValueError("a spoke must have exactly six hub-facing interfaces")
        if len({item.address for item in state.interfaces}) != 6:
            raise ValueError("spoke tunnel addresses must be unique")
        if set(state.active_target_by_slot) != set(TRANSPORTS):
            raise ValueError("every transport slot needs an active target")
    for interface in state.interfaces:
        for first, peer in enumerate(interface.peers):
            for allowed in peer.allowed_ips:
                for other in interface.peers[first + 1:]:
                    if allowed in other.allowed_ips:
                        raise ValueError(f"AllowedIPs collision on {interface.name}: {allowed}")
