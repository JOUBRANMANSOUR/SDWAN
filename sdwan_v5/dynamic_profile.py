"""Dynamic site-profile overlay used by authenticated edge processes.

The static topology profile provides shared hub, underlay, policy, and
measurement settings.  A newly enrolled edge receives only its own allocated
profile as authenticated desired-state metadata, then overlays that profile
locally.  No mutable inventory database is mounted into an edge container.
"""
from __future__ import annotations

from typing import Any, Mapping

from .common.model import TopologyConfig
from .dynamic_control import InventorySite


def overlay_site_profile(config: TopologyConfig, site: str, value: Mapping[str, Any] | None) -> TopologyConfig:
    """Add the authenticated allocated profile when ``site`` is dynamic."""
    if site in config.site_names:
        return config
    if not isinstance(value, Mapping):
        raise ValueError("dynamic edge desired state does not include a site profile")
    try:
        profile = InventorySite(**dict(value))
    except (TypeError, ValueError) as exc:
        raise ValueError("dynamic edge site profile is invalid") from exc
    if profile.site != site or profile.lifecycle not in {"PROVISIONING", "PENDING_HUBS", "RECONCILING", "ACTIVE"}:
        raise ValueError("dynamic edge site profile is not provisionable")
    return config.with_sites({**config.sites, profile.site: profile.to_site()})

def overlay_inventory(config: TopologyConfig, values: object) -> TopologyConfig:
    """Overlay authenticated active/provisioning inventory for a hub or edge."""
    sites = dict(config.sites)
    for value in values if isinstance(values, list) else ():
        if not isinstance(value, Mapping):
            raise ValueError("desired-state inventory profile is invalid")
        try:
            profile = InventorySite(**dict(value))
        except (TypeError, ValueError) as exc:
            raise ValueError("desired-state inventory profile is invalid") from exc
        if profile.lifecycle in {"ZTP_STAGED", "ENROLLING", "ENROLLED", "REGISTERING", "PROVISIONING", "PENDING_HUBS", "RECONCILING", "ACTIVE"}:
            sites[profile.site] = profile.to_site()
