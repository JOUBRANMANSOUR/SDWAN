"""Validated v5 topology, inventory, address, egress, and mark model."""
from __future__ import annotations

from dataclasses import dataclass, replace
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_interface, ip_network
from pathlib import Path
from typing import Any, Mapping

import yaml

from .marks import MarkLayout
from .path_selection import (
    ApplicationClass, ApplicationSLA, MeasurementTuning, NoEligibleAction,
    ScoreWeights, SelectionTuning,
)


class ConfigurationError(ValueError):
    """Raised before a network component is allowed to start."""


TRANSPORTS = ("mpls", "bb", "lte")
HUBS = ("hub1", "hub2")


@dataclass(frozen=True)
class Transport:
    name: str
    switch: str
    dpid: int
    network: IPv4Network
    bandwidth_mbps: float
    delay_ms: float
    jitter_ms: float
    loss_pct: float
    cost: float
    internet_capable: bool
    route_slot: int
    route_table: int


@dataclass(frozen=True)
class TunnelTarget:
    hub: str
    transport: str
    overlay_network: IPv4Network
    route_table: int

    @property
    def interface_name(self) -> str:
        return f"wg-{'h1' if self.hub == 'hub1' else 'h2'}-{self.transport}"


@dataclass(frozen=True)
class Hub:
    name: str
    address_id: int
    management_ip: IPv4Address


@dataclass(frozen=True)
class Site:
    name: str
    edge_node: str
    address_id: int
    management_ip: IPv4Address
    lan_network: IPv4Network
    lan_gateway: IPv4Address
    lan_switch: str
    lan_dpid: int
    host_name: str
    host_ip: IPv4Address
    preferred_hub: str
    standby_hub: str
    device_id: str
    wireguard_index: int = 0
    interface_suffix: str = ""


@dataclass(frozen=True)
class CloudVPC:
    enabled: bool
    switch: str
    app_name: str
    network: IPv4Network
    app_ip: IPv4Address
    gateway_count: int
    gateway_names: tuple[str, ...]
    gateway_ips: Mapping[str, IPv4Address]
    gateway_management_ips: Mapping[str, IPv4Address]
    gateway_address_ids: Mapping[str, int]
    transit_networks: Mapping[str, IPv4Network]

    def transit_network(self, hub: str, gateway: str) -> IPv4Network:
        try:
            return self.transit_networks[f"{hub}_{gateway}"]
        except KeyError as exc:
            raise ConfigurationError(f"missing Cloud transit network for {hub}/{gateway}") from exc

    def transit_ip(self, hub: str, gateway: str, endpoint: str) -> IPv4Address:
        network = self.transit_network(hub, gateway)
        if endpoint == hub:
            return IPv4Address(int(network.network_address) + 1)
        if endpoint == gateway:
            return IPv4Address(int(network.network_address) + 2)
        raise ConfigurationError(f"Cloud transit endpoint {endpoint} is not {hub} or {gateway}")

    @property
    def active_gateways(self) -> tuple[str, ...]:
        return self.gateway_names[:self.gateway_count]


@dataclass(frozen=True)
class Features:
    data_center: bool
    saas: bool
    cloud_vpc: bool


@dataclass(frozen=True)
class Settings:
    persistent_keepalive_s: int
    route_mark_mask: int
    terminal_mark_bit: int
    provisional_mark_bit: int
    emergency_mark_bit: int
    target_hub_mask: int
    hub1_bit: int
    hub2_bit: int
    egress_mask: int
    direct_internet_bit: int
    cloud_gateway_bit: int
    wireguard_port_start: int
    probe_interval_s: float
    suspect_failures: int
    failed_failures: int
    recovery_successes: int
    hold_down_s: float
    drain_timeout_s: float
    stale_measurement_s: float
    failback_mode: str

    @property
    def marks(self) -> MarkLayout:
        return MarkLayout(
            self.route_mark_mask, self.terminal_mark_bit, self.provisional_mark_bit,
            self.emergency_mark_bit, self.target_hub_mask, self.hub1_bit, self.hub2_bit,
            self.egress_mask, self.direct_internet_bit, self.cloud_gateway_bit,
        )


@dataclass(frozen=True)
class Controller:
    openflow_host: str
    openflow_port: int
    policy_port: int
    ztp_port: int
    edge_port: int
    management_address: str


@dataclass(frozen=True)
class TopologyConfig:
    source: Path
    edge_image: str
    host_image: str
    controller: Controller
    management_network: IPv4Network
    management_switch: str
    transports: Mapping[str, Transport]
    targets: Mapping[tuple[str, str], TunnelTarget]
    hubs: Mapping[str, Hub]
    sites: Mapping[str, Site]
    settings: Settings
    features: Features
    measurement: MeasurementTuning
    application_slas: Mapping[ApplicationClass, ApplicationSLA]
    path_scoring: Mapping[ApplicationClass, ScoreWeights]
    path_selection: SelectionTuning
    data_center_network: IPv4Network
    data_center_app_ip: IPv4Address
    data_center_switch: str
    data_center_app_name: str
    data_center_hub_ips: Mapping[str, IPv4Address]
    saas_network: IPv4Network
    saas_ip: IPv4Address
    saas_switch: str
    saas_app_name: str
    saas_gateway_name: str
    saas_gateway_ip: IPv4Address
    saas_transport_ips: Mapping[str, IPv4Address]
    cloud_vpc: CloudVPC
    interhub_networks: Mapping[str, IPv4Network]

    @property
    def site_names(self) -> tuple[str, ...]:
        """Logical control-plane site identifiers, plus hubs."""
        return tuple(self.hubs) + tuple(self.sites)

    @property
    def edge_nodes(self) -> tuple[str, ...]:
        """Actual Containernet WAN Edge node names."""
        return tuple(site.edge_node for site in self.sites.values())

    @property
    def runtime_node_names(self) -> tuple[str, ...]:
        return tuple(self.hubs) + self.edge_nodes

    def logical_site(self, value: str) -> str:
        if value in self.sites:
            return value
        matches = [site.name for site in self.sites.values() if site.edge_node == value]
        if len(matches) == 1:
            return matches[0]
        raise KeyError(value)

    def edge_node(self, site: str) -> str:
        if site in self.hubs:
            return site
        return self.sites[self.logical_site(site)].edge_node

    def with_sites(self, sites: Mapping[str, Site]) -> "TopologyConfig":
        """Return an immutable topology view backed by authoritative inventory."""
        candidate = replace(self, sites=dict(sites))
        validate_config(candidate)
        return candidate

    def target(self, hub: str, transport: str) -> TunnelTarget:
        try:
            return self.targets[(hub, transport)]
        except KeyError as exc:
            raise ConfigurationError(f"missing target for {hub}/{transport}") from exc

    def spoke_targets(self, site: str) -> tuple[TunnelTarget, ...]:
        self.logical_site(site)
        return tuple(self.target(hub, transport) for hub in HUBS for transport in TRANSPORTS)

    def underlay_ip(self, site: str, transport: str) -> IPv4Address:
        try:
            network = self.transports[transport].network
        except KeyError as exc:
            raise ConfigurationError(f"unknown transport: {transport}") from exc
        if site in self.hubs:
            address_id = self.hubs[site].address_id
        elif site in self.cloud_vpc.gateway_address_ids:
            address_id = self.cloud_vpc.gateway_address_ids[site]
        else:
            logical_site = self.logical_site(site)
            address_id = self.sites[logical_site].address_id
        return IPv4Address(int(network.network_address) + address_id)

    def underlay_gateway_ip(self, transport: str) -> IPv4Address:
        """Provider-facing next hop; endpoints never ARP for remote WAN sites."""
        try:
            network = self.transports[transport].network
        except KeyError as exc:
            raise ConfigurationError(f"unknown transport: {transport}") from exc
        return IPv4Address(int(network.broadcast_address) - 2)

    def underlay_interface_cidr(self, site: str, transport: str) -> str:
        """A provider attachment is a host route, not a shared Ethernet subnet."""
        address = self.saas_transport_ips[transport] if site == self.saas_gateway_name else self.underlay_ip(site, transport)
        return f"{address}/32"

    def underlay_mac(self, site: str, transport: str) -> str:
        """Stable topology-derived attachment identity for Ryu source validation."""
        if site == self.saas_gateway_name:
            identity = int(self.saas_transport_ips[transport]) & 0xffff
        elif site in self.hubs:
            identity = self.hubs[site].address_id
        else:
            site = self.logical_site(site)
            identity = self.sites[site].address_id
        return f"02:5a:{self.transports[transport].route_slot:02x}:{(identity >> 8) & 0xff:02x}:{identity & 0xff:02x}:01"

    def underlay_gateway_mac(self, transport: str) -> str:
        return f"02:5a:ff:{self.transports[transport].route_slot:02x}:00:01"

    def overlay_ip(self, site: str, hub: str, transport: str) -> IPv4Address:
        target = self.target(hub, transport)
        if site in self.hubs:
            return IPv4Address(int(target.overlay_network.network_address) + 1)
        site = self.logical_site(site)
        return IPv4Address(int(target.overlay_network.network_address) + self.sites[site].address_id)

    def wireguard_port(self, site: str, hub: str, transport: str) -> int:
        if site in self.hubs:
            offset = HUBS.index(site) * 64
            target_offset = TRANSPORTS.index(transport)
            return self.settings.wireguard_port_start + offset + target_offset
        site = self.logical_site(site)
        offset = self.sites[site].wireguard_index * 64
        target_offset = HUBS.index(hub) * len(TRANSPORTS) + TRANSPORTS.index(transport)
        return self.settings.wireguard_port_start + offset + target_offset

    def interhub_port(self, hub: str, transport: str) -> int:
        if hub not in self.hubs:
            raise KeyError(hub)
        return self.settings.wireguard_port_start + HUBS.index(hub) * 64 + len(TRANSPORTS) + TRANSPORTS.index(transport)

    @property
    def protected_private_prefixes(self) -> tuple[IPv4Network, ...]:
        prefixes = [site.lan_network for site in self.sites.values()]
        prefixes.append(self.data_center_network)
        if self.cloud_vpc.enabled:
            prefixes.append(self.cloud_vpc.network)
        return tuple(prefixes)


def _network(value: object, field: str) -> IPv4Network:
    try:
        return ip_network(str(value), strict=True)
    except ValueError as exc:
        raise ConfigurationError(f"invalid {field}: {value}") from exc


def _address(value: object, field: str) -> IPv4Address:
    try:
        return ip_address(str(value))
    except ValueError as exc:
        raise ConfigurationError(f"invalid {field}: {value}") from exc


def config_from_mapping(raw: Mapping[str, Any], source: Path = Path("<memory>")) -> TopologyConfig:
    required = {
        "schema_version", "edge_image", "host_image", "controller", "management_network", "management_switch",
        "settings", "transports", "hub_targets", "hubs", "spokes", "data_center",
        "saas", "cloud_vpc", "interhub_networks",
    }
    missing = required - set(raw)
    if missing:
        raise ConfigurationError(f"topology is missing: {', '.join(sorted(missing))}")
    if int(raw["schema_version"]) != 5:
        raise ConfigurationError("topology schema_version must be 5")
    _reject_plaintext_sensitive_values(raw)
    controller = Controller(**dict(raw["controller"]))
    settings = Settings(**dict(raw["settings"]))
    transports = {
        name: Transport(
            name=name, switch=str(item["switch"]), dpid=int(item["dpid"]),
            network=_network(item["network"], f"transports.{name}.network"),
            bandwidth_mbps=float(item["bandwidth_mbps"]), delay_ms=float(item["delay_ms"]),
            jitter_ms=float(item["jitter_ms"]), loss_pct=float(item["loss_pct"]),
            cost=float(item["cost"]), internet_capable=bool(item["internet_capable"]),
            route_slot=int(item["route_slot"]), route_table=int(item["route_table"]),
        ) for name, item in dict(raw["transports"]).items()
    }
    targets: dict[tuple[str, str], TunnelTarget] = {}
    for hub, by_transport in dict(raw["hub_targets"]).items():
        for transport, item in dict(by_transport).items():
            targets[(str(hub), str(transport))] = TunnelTarget(
                str(hub), str(transport), _network(item["overlay_network"], f"hub_targets.{hub}.{transport}.overlay_network"),
                int(item["route_table"]),
            )
    hubs = {
        name: Hub(name, int(item["address_id"]), _address(item["management_ip"], f"hubs.{name}.management_ip"))
        for name, item in dict(raw["hubs"]).items()
    }
    sites = {
        name: Site(
            name=name, edge_node=str(item.get("edge_node", name)), address_id=int(item["address_id"]),
            management_ip=_address(item["management_ip"], f"spokes.{name}.management_ip"),
            lan_network=_network(item["lan_network"], f"spokes.{name}.lan_network"),
            lan_gateway=_address(item["lan_gateway"], f"spokes.{name}.lan_gateway"),
            lan_switch=str(item["lan_switch"]), lan_dpid=int(item["lan_dpid"]),
            host_name=str(item["host_name"]), host_ip=_address(item["host_ip"], f"spokes.{name}.host_ip"),
            preferred_hub=str(item["preferred_hub"]), standby_hub=str(item["standby_hub"]),
            device_id=str(item["device_id"]),
            wireguard_index=int(item.get("wireguard_index", len(HUBS) + index)),
            interface_suffix=str(item.get("interface_suffix", f"n{index + 1}")),
        ) for index, (name, item) in enumerate(dict(raw["spokes"]).items())
    }
    data_center = dict(raw["data_center"])
    saas = dict(raw["saas"])
    cloud_raw = dict(raw["cloud_vpc"])
    feature_raw = dict(raw.get("features", {}))
    features = Features(
        data_center=bool(feature_raw.get("data_center", True)),
        saas=bool(feature_raw.get("saas", True)),
        cloud_vpc=bool(feature_raw.get("cloud_vpc", cloud_raw["enabled"])),
    )
    measurement_raw = dict(raw.get("measurement", {}))
    measurement = MeasurementTuning(
        interval_seconds=float(measurement_raw.get("interval_seconds", settings.probe_interval_s)),
        ewma_alpha=float(measurement_raw.get("ewma_alpha", 0.3)),
        stale_after_seconds=float(measurement_raw.get("stale_after_seconds", settings.stale_measurement_s)),
        loss_window_samples=int(measurement_raw.get("loss_window_samples", 10)),
    )
    sla_raw = raw.get("application_slas", {})
    score_raw = raw.get("path_scoring", {})
    if not isinstance(sla_raw, Mapping) or not isinstance(score_raw, Mapping):
        raise ConfigurationError("application_slas and path_scoring must be mappings")
    application_slas: dict[ApplicationClass, ApplicationSLA] = {}
    path_scoring: dict[ApplicationClass, ScoreWeights] = {}
    for application_class in ApplicationClass:
        if application_class.value not in sla_raw or application_class.value not in score_raw:
            raise ConfigurationError(f"missing SLA or scoring configuration for {application_class.value}")
        item = dict(sla_raw[application_class.value])
        application_slas[application_class] = ApplicationSLA(
            max_rtt_ms=float(item["max_rtt_ms"]) if item.get("max_rtt_ms") is not None else None,
            max_jitter_ms=float(item["max_jitter_ms"]) if item.get("max_jitter_ms") is not None else None,
            max_loss_pct=float(item["max_loss_pct"]) if item.get("max_loss_pct") is not None else None,
            min_estimated_available_bandwidth_mbps=float(item["min_estimated_available_bandwidth_mbps"])
            if item.get("min_estimated_available_bandwidth_mbps") is not None else None,
            no_eligible_action=NoEligibleAction(str(item["no_eligible_action"])),
        )
        weight = dict(score_raw[application_class.value])
        path_scoring[application_class] = ScoreWeights(
            rtt=float(weight.get("rtt", 0.0)), jitter=float(weight.get("jitter", 0.0)),
            loss=float(weight.get("loss", 0.0)),
            available_bandwidth=float(weight.get("available_bandwidth", 0.0)),
            transport_cost=float(weight.get("transport_cost", 0.0)),
        )
    selection_raw = dict(raw.get("path_selection", {}))
    path_selection = SelectionTuning(
        bad_samples_before_degraded=int(selection_raw.get("bad_samples_before_degraded", settings.failed_failures)),
        good_samples_before_recovered=int(selection_raw.get("good_samples_before_recovered", settings.recovery_successes)),
        minimum_improvement_percent=float(selection_raw.get("minimum_improvement_percent", 15.0)),
        hold_down_seconds=float(selection_raw.get("hold_down_seconds", settings.hold_down_s)),
    )
    config = TopologyConfig(
        source=source, edge_image=str(raw["edge_image"]), host_image=str(raw["host_image"]),
        controller=controller, management_network=_network(raw["management_network"], "management_network"),
        management_switch=str(raw["management_switch"]),
        data_center_switch=str(data_center["switch"]), data_center_app_name=str(data_center["app_name"]),
        saas_switch=str(saas["switch"]), saas_app_name=str(saas["app_name"]),
        saas_gateway_name=str(saas["gateway_name"]),
        saas_gateway_ip=_address(saas["gateway_ip"], "saas.gateway_ip"),
        saas_transport_ips={
            str(name): _address(value, f"saas.transport_ips.{name}")
            for name, value in dict(saas["transport_ips"]).items()
        },
        data_center_hub_ips={
            str(name): _address(value, f"data_center.hub_ips.{name}")
            for name, value in dict(data_center["hub_ips"]).items()
        },
        transports=transports, targets=targets, hubs=hubs, sites=sites, settings=settings,
        features=features, measurement=measurement, application_slas=application_slas,
        path_scoring=path_scoring, path_selection=path_selection,
        data_center_network=_network(data_center["network"], "data_center.network"),
        data_center_app_ip=_address(data_center["app_ip"], "data_center.app_ip"),
        saas_network=_network(saas["network"], "saas.network"), saas_ip=_address(saas["app_ip"], "saas.app_ip"),
        cloud_vpc=CloudVPC(
            enabled=features.cloud_vpc and bool(cloud_raw["enabled"]), switch=str(cloud_raw["switch"]),
            app_name=str(cloud_raw["app_name"]), network=_network(cloud_raw["network"], "cloud_vpc.network"),
            app_ip=_address(cloud_raw["app_ip"], "cloud_vpc.app_ip"), gateway_count=int(cloud_raw["gateway_count"]),
            gateway_names=tuple(str(name) for name in cloud_raw["gateway_names"]),
            gateway_ips={str(name): _address(value, f"cloud_vpc.gateway_ips.{name}") for name, value in dict(cloud_raw["gateway_ips"]).items()},
            gateway_management_ips={str(name): _address(value, f"cloud_vpc.gateway_management_ips.{name}") for name, value in dict(cloud_raw["gateway_management_ips"]).items()},
            gateway_address_ids={str(name): int(value) for name, value in dict(cloud_raw["gateway_address_ids"]).items()},
            transit_networks={str(name): _network(value, f"cloud_vpc.transit_networks.{name}") for name, value in dict(cloud_raw["transit_networks"]).items()},
        ),
        interhub_networks={name: _network(value, f"interhub_networks.{name}") for name, value in dict(raw["interhub_networks"]).items()},
    )
    validate_config(config)
    return config


def load_config(path: Path) -> TopologyConfig:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigurationError(f"cannot read topology configuration: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ConfigurationError("topology configuration must be a mapping")
    return config_from_mapping(raw, path)


def validate_config(config: TopologyConfig) -> None:
    if not config.edge_image or not config.host_image:
        raise ConfigurationError("edge and host Docker image names are required")
    controller_ports = (config.controller.openflow_port, config.controller.policy_port, config.controller.ztp_port, config.controller.edge_port)
    if any(port < 1 or port > 65535 for port in controller_ports):
        raise ConfigurationError("controller service ports must be between 1 and 65535")
    openflow_dpids = [item.dpid for item in config.transports.values()] + [item.lan_dpid for item in config.sites.values()]
    if any(dpid <= 0 for dpid in openflow_dpids) or len(openflow_dpids) != len(set(openflow_dpids)):
        raise ConfigurationError("OpenFlow datapaths require unique positive DPIDs")
    openflow_switches = [item.switch for item in config.transports.values()] + [item.lan_switch for item in config.sites.values()]
    if len(openflow_switches) != len(set(openflow_switches)):
        raise ConfigurationError("OpenFlow switch names must be unique")
    bridge_switches = (config.management_switch, config.data_center_switch, config.saas_switch, config.cloud_vpc.switch)
    if not all(bridge_switches) or len(set(bridge_switches)) != len(bridge_switches) or set(bridge_switches).intersection(openflow_switches):
        raise ConfigurationError("non-OpenFlow bridge names must be nonempty and distinct from OpenFlow switches")
    if tuple(config.transports) != TRANSPORTS:
        raise ConfigurationError("transports must be mpls, bb, lte in deterministic order")
    if tuple(config.hubs) != HUBS or not config.sites:
        raise ConfigurationError("topology requires hub1/hub2 and at least one seed branch")
    expected_targets = {(hub, transport) for hub in HUBS for transport in TRANSPORTS}
    if set(config.targets) != expected_targets:
        raise ConfigurationError("every hub/transport target must be configured")
    config.settings.marks.validate({name: transport.route_slot for name, transport in config.transports.items()})
    if [item.route_slot for item in config.transports.values()] != [1, 2, 3]:
        raise ConfigurationError("v4 transport ABI requires MPLS=1, Broadband=2, LTE=3")
    if [item.route_table for item in config.transports.values()] != [101, 102, 103]:
        raise ConfigurationError("transport route tables must remain 101, 102, 103")
    if config.settings.failback_mode not in {"manual", "after_drain", "after_timeout"}:
        raise ConfigurationError("baseline v5 supports manual, after_drain, or after_timeout failback")
    positive = (
        config.settings.persistent_keepalive_s, config.settings.wireguard_port_start,
        config.settings.probe_interval_s, config.settings.suspect_failures,
        config.settings.failed_failures, config.settings.recovery_successes,
        config.settings.hold_down_s, config.settings.drain_timeout_s, config.settings.stale_measurement_s,
    )
    if any(value <= 0 for value in positive):
        raise ConfigurationError("WireGuard, health, and recovery values must be positive")
    if config.settings.suspect_failures >= config.settings.failed_failures:
        raise ConfigurationError("suspect threshold must be lower than failed threshold")
    if not config.features.data_center or not config.features.saas:
        raise ConfigurationError("the core SD-WAN profile requires data_center and saas features")
    if not (0 < config.measurement.ewma_alpha <= 1):
        raise ConfigurationError("measurement.ewma_alpha must be in (0, 1]")
    if config.measurement.interval_seconds <= 0 or config.measurement.stale_after_seconds <= config.measurement.interval_seconds or config.measurement.loss_window_samples < 2:
        raise ConfigurationError("measurement interval/window/staleness values are invalid")
    if config.path_selection.bad_samples_before_degraded <= 0 or config.path_selection.good_samples_before_recovered <= 0 or config.path_selection.minimum_improvement_percent < 0 or config.path_selection.hold_down_seconds < 0:
        raise ConfigurationError("path_selection hysteresis values are invalid")
    for application_class in ApplicationClass:
        sla = config.application_slas[application_class]
        thresholds = (sla.max_rtt_ms, sla.max_jitter_ms, sla.max_loss_pct, sla.min_estimated_available_bandwidth_mbps)
        if any(value is not None and value < 0 for value in thresholds):
            raise ConfigurationError(f"negative SLA threshold for {application_class.value}")
        if sla.max_loss_pct is not None and sla.max_loss_pct > 100:
            raise ConfigurationError(f"loss SLA must be between 0 and 100 for {application_class.value}")
        if sla.min_estimated_available_bandwidth_mbps is not None and sla.min_estimated_available_bandwidth_mbps <= 0:
            raise ConfigurationError(f"bandwidth SLA must be positive for {application_class.value}")
        config.path_scoring[application_class].validate()
    if any(site.preferred_hub not in config.hubs or site.standby_hub not in config.hubs or site.preferred_hub == site.standby_hub for site in config.sites.values()):
        raise ConfigurationError("each spoke needs distinct known preferred and standby hubs")
    if len({site.edge_node for site in config.sites.values()}) != len(config.sites):
        raise ConfigurationError("physical WAN Edge node names must be unique")
    if any(not site.edge_node or site.edge_node in config.hubs for site in config.sites.values()):
        raise ConfigurationError("every logical site requires a distinct non-hub edge_node")
    if len({site.device_id for site in config.sites.values()}) != len(config.sites):
        raise ConfigurationError("device identities must be unique")
    if len({site.wireguard_index for site in config.sites.values()}) != len(config.sites):
        raise ConfigurationError("branch WireGuard allocation indices must be unique")
    for site in config.sites.values():
        if site.wireguard_index < len(HUBS):
            raise ConfigurationError("branch WireGuard allocation indices must follow hub indices")
        if site.lan_gateway not in site.lan_network or site.host_ip not in site.lan_network:
            raise ConfigurationError("site LAN gateway and host must be in the LAN prefix")
        if site.lan_gateway == site.host_ip or site.host_ip in {site.lan_network.network_address, site.lan_network.broadcast_address}:
            raise ConfigurationError("site LAN host must be a distinct usable address")
        if not site.lan_switch or not site.host_name:
            raise ConfigurationError("every spoke requires a LAN switch and branch host name")
    if len({site.host_name for site in config.sites.values()}) != len(config.sites):
        raise ConfigurationError("branch host names must be unique")
    if len({site.lan_switch for site in config.sites.values()}) != len(config.sites):
        raise ConfigurationError("branch LAN switch names must be unique")
    physical_names = [
        *config.runtime_node_names,
        *(site.host_name for site in config.sites.values()),
        config.management_switch,
        config.data_center_switch,
        config.data_center_app_name,
        config.saas_switch,
        config.saas_app_name,
        config.saas_gateway_name,
        config.cloud_vpc.switch,
        config.cloud_vpc.app_name,
        *config.cloud_vpc.gateway_names,
    ]
    if not all(physical_names) or len(physical_names) != len(set(physical_names)):
        raise ConfigurationError("physical node, application, and switch names must be nonempty and unique")
    application_endpoints = ((config.data_center_network, config.data_center_app_ip), (config.saas_network, config.saas_ip), (config.cloud_vpc.network, config.cloud_vpc.app_ip))
    if any(address not in network or address in {network.network_address, network.broadcast_address} for network, address in application_endpoints):
        raise ConfigurationError("application endpoints must be usable addresses in their configured network")
    if (config.saas_gateway_ip not in config.saas_network
            or config.saas_gateway_ip in {config.saas_network.network_address, config.saas_network.broadcast_address}
            or config.saas_gateway_ip == config.saas_ip):
        raise ConfigurationError("Internet gateway public address must be a distinct usable address in the SaaS network")
    if set(config.data_center_hub_ips) != set(HUBS):
        raise ConfigurationError("the Data Center LAN requires one configured address for each hub")
    dc_addresses = list(config.data_center_hub_ips.values()) + [config.data_center_app_ip]
    if (len(dc_addresses) != len(set(dc_addresses))
            or any(address not in config.data_center_network or address in {config.data_center_network.network_address, config.data_center_network.broadcast_address} for address in dc_addresses)):
        raise ConfigurationError("Data Center hub and application addresses must be unique usable addresses in the DC network")
    internet_transports = {name for name, item in config.transports.items() if item.internet_capable}
    if set(config.saas_transport_ips) != internet_transports:
        raise ConfigurationError("Internet gateway transport addresses must cover exactly the Internet-capable transports")
    for transport, address in config.saas_transport_ips.items():
        network = config.transports[transport].network
        if address not in network or address in {network.network_address, network.broadcast_address}:
            raise ConfigurationError("Internet gateway transport addresses must be usable underlay addresses")
    if config.cloud_vpc.gateway_count not in {1, 2}:
        raise ConfigurationError("cloud gateway count must be one or two")
    if len(config.cloud_vpc.gateway_names) != 2 or len(set(config.cloud_vpc.gateway_names)) != 2:
        raise ConfigurationError("cloud gateway inventory must define two unique gateway names")
    gateway_keys = set(config.cloud_vpc.gateway_names)
    if any(set(mapping) != gateway_keys for mapping in (config.cloud_vpc.gateway_ips, config.cloud_vpc.gateway_management_ips, config.cloud_vpc.gateway_address_ids)):
        raise ConfigurationError("cloud gateway address mappings must match the gateway inventory")
    expected_cloud_transits = {f"{hub}_{gateway}" for hub in HUBS for gateway in config.cloud_vpc.gateway_names}
    if set(config.cloud_vpc.transit_networks) != expected_cloud_transits:
        raise ConfigurationError("Cloud VPC requires exactly one dedicated transit network per hub/gateway pair")
    if any(network.prefixlen != 30 for network in config.cloud_vpc.transit_networks.values()):
        raise ConfigurationError("Cloud hub/gateway transit networks must be /30 point-to-point prefixes")
    cloud_ips = list(config.cloud_vpc.gateway_ips.values()) + [config.cloud_vpc.app_ip]
    if (len(cloud_ips) != len(set(cloud_ips))
            or any(address not in config.cloud_vpc.network or address in {config.cloud_vpc.network.network_address, config.cloud_vpc.network.broadcast_address} for address in cloud_ips)):
        raise ConfigurationError("Cloud VPC gateway and application addresses must be unique usable addresses in the VPC network")
    address_ids = [
        *(hub.address_id for hub in config.hubs.values()),
        *(site.address_id for site in config.sites.values()),
        *config.cloud_vpc.gateway_address_ids.values(),
    ]
    if any(value <= 0 for value in address_ids) or len(address_ids) != len(set(address_ids)):
        raise ConfigurationError("hub, spoke, and cloud gateway address IDs must be unique and positive")
    for transport_name, transport in config.transports.items():
        underlay_addresses = [config.underlay_ip(name, transport_name) for name in config.site_names]
        if transport.internet_capable:
            underlay_addresses.append(config.saas_transport_ips[transport_name])
        provider_gateway = config.underlay_gateway_ip(transport_name)
        if (len(underlay_addresses) != len(set(underlay_addresses))
                or any(address not in transport.network or address in {transport.network.network_address, transport.network.broadcast_address} for address in underlay_addresses)):
            raise ConfigurationError(f"underlay addresses for {transport_name} must be unique usable addresses")
        if provider_gateway in underlay_addresses or provider_gateway in {
            transport.network.network_address, transport.network.broadcast_address,
        }:
            raise ConfigurationError(
                f"provider gateway address for {transport_name} must be a unique usable underlay address"
            )
    if set(config.interhub_networks) != set(TRANSPORTS):
        raise ConfigurationError("every inter-hub transport must have a network")
    networks: list[IPv4Network] = [config.management_network, config.data_center_network, config.saas_network, config.cloud_vpc.network]
    networks.extend(item.network for item in config.transports.values())
    networks.extend(item.overlay_network for item in config.targets.values())
    networks.extend(config.interhub_networks.values())
    networks.extend(item.lan_network for item in config.sites.values())
    networks.extend(config.cloud_vpc.transit_networks.values())
    for index, left in enumerate(networks):
        for right in networks[index + 1:]:
            if left.overlaps(right):
                raise ConfigurationError(f"address spaces overlap: {left} and {right}")
    try:
        controller_management = ip_interface(config.controller.management_address)
    except ValueError as exc:
        raise ConfigurationError("controller management address is invalid") from exc
    all_addresses = [
        *(hub.management_ip for hub in config.hubs.values()),
        *(site.management_ip for site in config.sites.values()),
        *config.cloud_vpc.gateway_management_ips.values(),
        controller_management.ip,
    ]
    if (len(all_addresses) != len(set(all_addresses))
            or any(address not in config.management_network or address in {config.management_network.network_address, config.management_network.broadcast_address} for address in all_addresses)
            or controller_management.network != config.management_network):
        raise ConfigurationError("management addresses must be unique usable addresses in the configured management network")
    ports = [config.wireguard_port(site, target.hub, target.transport) for site in config.sites for target in config.spoke_targets(site)]
    ports.extend(config.wireguard_port(hub, hub, transport) for hub in HUBS for transport in TRANSPORTS)
    ports.extend(config.interhub_port(hub, transport) for hub in HUBS for transport in TRANSPORTS)
    if len(ports) != len(set(ports)) or any(port > 65535 for port in ports):
        raise ConfigurationError("WireGuard listen ports must be valid and unique per node/interface")
    target_tables = [target.route_table for target in config.targets.values()]
    if len(target_tables) != len(set(target_tables)):
        raise ConfigurationError("hub-specific route tables must be unique")
    if config.transports["mpls"].internet_capable:
        raise ConfigurationError("MPLS is not Internet-capable in the baseline experiment")


def _reject_plaintext_sensitive_values(raw: Mapping[str, Any]) -> None:
    def visit(value: Any, path: str = "") -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                lower = str(key).lower()
                if lower in {"private_key", "private_key_pem", "claim_secret", "shared_token", "password"}:
                    raise ConfigurationError(f"plaintext sensitive value is forbidden in configuration: {path}{key}")
                visit(item, f"{path}{key}.")
        elif isinstance(value, list):
            for item in value:
                visit(item, path)
    visit(raw)
