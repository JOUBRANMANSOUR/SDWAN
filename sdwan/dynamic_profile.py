"""Dynamic site-profile overlay used by authenticated edge processes."""
from __future__ import annotations

import re
from typing import Any, Mapping

from .common.model import TopologyConfig
from .dynamic_control import InventorySite


def _legacy_profile(value: Mapping[str, Any], requested_site: str, config: TopologyConfig) -> dict[str, Any]:
    """Normalize pre-site/edge-node desired-state metadata."""
    raw = dict(value)
    profile_site = str(raw.get("site", requested_site))
    try:
        logical = config.logical_site(profile_site)
    except KeyError:
        match = re.fullmatch(r"node([1-9][0-9]*)", profile_site)
        if match:
            raw["site"] = "site" + match.group(1)
            raw.setdefault("edge_node", profile_site)
        else:
            raw.setdefault("edge_node", profile_site)
    else:
        raw["site"] = logical
        raw.setdefault("edge_node", config.edge_node(logical))
    return raw


def overlay_site_profile(config: TopologyConfig, site: str, value: Mapping[str, Any] | None) -> TopologyConfig:
    """Add an authenticated dynamic profile; static node aliases resolve first."""
    try:
        logical_site = config.logical_site(site)
    except KeyError:
        logical_site = site
    # Static topology members already have complete profiles; hubs do not
    # carry a dynamic inventory site_profile.
    if logical_site in config.sites or logical_site in config.hubs:
        return config
    if not isinstance(value, Mapping):
        raise ValueError("dynamic edge desired state does not include a site profile")
    # Dynamic edges may still have a historical enrollment name (node7).
    # The authenticated desired-state profile is the authoritative explicit
    # mapping, so resolve that runtime edge name through profile.edge_node.
    if str(value.get("edge_node", "")) == site:
        logical_site = str(value.get("site", logical_site))
    try:
        profile = InventorySite(**_legacy_profile(value, logical_site, config))
    except (TypeError, ValueError) as exc:
        raise ValueError("dynamic edge site profile is invalid") from exc
    if profile.site != logical_site or profile.lifecycle not in {"PROVISIONING", "PENDING_HUBS", "RECONCILING", "ACTIVE"}:
        raise ValueError("dynamic edge site profile is not provisionable")
    return config.with_sites({**config.sites, profile.site: profile.to_site()})


def overlay_inventory(config: TopologyConfig, values: object) -> TopologyConfig:
    """Overlay authenticated active/provisioning inventory for a hub or edge."""
    sites = dict(config.sites)
    for value in values if isinstance(values, list) else ():
        if not isinstance(value, Mapping):
            raise ValueError("desired-state inventory profile is invalid")
        try:
            profile = InventorySite(**_legacy_profile(value, str(value.get("site", "")), config))
        except (TypeError, ValueError) as exc:
            raise ValueError("desired-state inventory profile is invalid") from exc
        if profile.lifecycle in {"ZTP_STAGED", "ENROLLING", "ENROLLED", "REGISTERING", "PROVISIONING", "PENDING_HUBS", "RECONCILING", "ACTIVE"}:
            sites[profile.site] = profile.to_site()
    return config.with_sites(sites)
