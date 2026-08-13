"""Configuration-derived Layer-3 underlay inventory and forwarding policy.

This module deliberately has no Ryu, packet-classification, WireGuard, route
selection, or shell dependency. It describes the provider-facing underlay
that Ryu realizes after an SD-WAN Edge has selected a transport.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Iterable

from .common.model import TopologyConfig


class UnderlayMode(str, Enum):
    DISABLED = "DISABLED"
    AUDIT = "AUDIT"
    ENFORCE = "ENFORCE"


class ServiceType(str, Enum):
    PRIVATE = "PRIVATE"
    INTERNET = "INTERNET"


@dataclass(frozen=True)
class UnderlayServiceProfile:
    transport: str
    service_type: ServiceType
    internet_access: bool


@dataclass(frozen=True)
class UnderlayAttachment:
    site: str
    transport: str
    switch: str
    port_name: str
    address: IPv4Address
    expected_mac: str
    role: str
    authorized: bool = True


@dataclass(frozen=True)
class FibRoute:
    transport: str
    source_site: str
    destination: IPv4Network
    egress_site: str
    reason: str


def service_profiles(config: TopologyConfig) -> dict[str, UnderlayServiceProfile]:
    return {
        name: UnderlayServiceProfile(
            transport=name,
            service_type=ServiceType.INTERNET if item.internet_capable else ServiceType.PRIVATE,
            internet_access=item.internet_capable,
        )
        for name, item in config.transports.items()
    }


def _short_attachment_name(config: TopologyConfig, site: str) -> str:
    if site == "hub1":
        return "h1"
    if site == "hub2":
        return "h2"
    if site == config.saas_gateway_name:
        return "inet"
    profile = config.sites.get(site)
    if profile is None:
        raise ValueError("unknown underlay attachment site: " + site)
    return profile.interface_suffix


class UnderlayRegistry:
    """Compile authoritative attachment bindings and service-reachability FIBs."""

    def __init__(self, config: TopologyConfig, *, authorized_sites: Iterable[str] | None = None):
        self.config = config
        self.authorized_sites = set(config.site_names if authorized_sites is None else authorized_sites)

    def attachments(self, transport: str) -> tuple[UnderlayAttachment, ...]:
        item = self.config.transports[transport]
        result: list[UnderlayAttachment] = []
        for site in self.config.site_names:
            result.append(
                UnderlayAttachment(
                    site=site,
                    transport=transport,
                    switch=item.switch,
                    port_name=item.switch + "-" + _short_attachment_name(self.config, site),
                    address=self.config.underlay_ip(site, transport),
                    expected_mac=self.config.underlay_mac(site, transport),
                    role="hub" if site in self.config.hubs else "spoke",
                    authorized=site in self.authorized_sites,
                )
            )
        if item.internet_capable:
            gateway = self.config.saas_gateway_name
            result.append(
                UnderlayAttachment(
                    site=gateway,
                    transport=transport,
                    switch=item.switch,
                    port_name=item.switch + "-inet",
                    address=self.config.saas_transport_ips[transport],
                    expected_mac=self.config.underlay_mac(gateway, transport),
                    role="internet_gateway",
                    authorized=True,
                )
            )
        return tuple(result)

    def source_networks(self, attachment: UnderlayAttachment) -> tuple[IPv4Network, ...]:
        """Return prefixes legitimately routed from one provider attachment."""
        networks = [IPv4Network(f"{attachment.address}/32")]
        if attachment.role == "spoke":
            networks.append(self.config.sites[attachment.site].lan_network)
        if attachment.role == "internet_gateway":
            networks.append(self.config.saas_network)
        return tuple(networks)

    def attachment(self, transport: str, site: str) -> UnderlayAttachment:
        for item in self.attachments(transport):
            if item.site == site:
                return item
        raise KeyError(site)

    def attachment_by_port(self, transport: str, port_name: str) -> UnderlayAttachment | None:
        return next((item for item in self.attachments(transport) if item.port_name == port_name), None)

    def fib(self, transport: str) -> tuple[FibRoute, ...]:
        profile = service_profiles(self.config)[transport]
        attachments = tuple(item for item in self.attachments(transport) if item.authorized)
        routes: list[FibRoute] = []
        for source in attachments:
            for target in attachments:
                if source.site == target.site:
                    continue
                if self._allowed_endpoint(profile, source, target):
                    routes.append(FibRoute(
                        transport=transport,
                        source_site=source.site,
                        destination=IPv4Network(str(target.address) + "/32"),
                        egress_site=target.site,
                        reason="PRIVATE_HUB_REACHABILITY" if profile.service_type is ServiceType.PRIVATE else "INTERNET_PROVIDER_REACHABILITY",
                    ))
                    if (
                        profile.internet_access
                        and source.role == "internet_gateway"
                        and target.role == "spoke"
                    ):
                        routes.append(FibRoute(
                            transport=transport, source_site=source.site,
                            destination=self.config.sites[target.site].lan_network,
                            egress_site=target.site, reason="DIRECT_INTERNET_RETURN",
                        ))
            if profile.internet_access and source.role != "internet_gateway":
                routes.append(FibRoute(
                    transport=transport,
                    source_site=source.site,
                    destination=self.config.saas_network,
                    egress_site=self.config.saas_gateway_name,
                    reason="DIRECT_INTERNET_BREAKOUT",
                ))
        return tuple(routes)

    @staticmethod
    def _allowed_endpoint(profile: UnderlayServiceProfile, source: UnderlayAttachment, target: UnderlayAttachment) -> bool:
        if profile.service_type is ServiceType.INTERNET:
            if source.role == "spoke":
                return target.role in {"hub", "internet_gateway"}
            if source.role == "hub":
                return target.role in {"spoke", "hub", "internet_gateway"}
            return target.role in {"spoke", "hub"}
        if source.role == "spoke":
            return target.role == "hub"
        if source.role == "hub":
            return target.role in {"spoke", "hub"}
        return False


def matching_fib_routes(routes: Iterable[FibRoute], source_site: str, destination: IPv4Address) -> tuple[FibRoute, ...]:
    return tuple(item for item in routes if item.source_site == source_site and destination in item.destination)
