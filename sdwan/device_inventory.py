"""Administrator-staged device-to-site inventory; device inputs never choose site."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml


class InventoryError(ValueError):
    pass


@dataclass(frozen=True)
class InventoryEntry:
    device_id: str
    role: str
    assigned_site: str


def load_inventory(path: Path) -> dict[str, InventoryEntry]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping) or int(raw.get("schema_version", 0)) != 5 or not isinstance(raw.get("devices"), Mapping):
        raise InventoryError("inventory must be a v5 devices mapping")
    result: dict[str, InventoryEntry] = {}
    sites: set[str] = set()
    for device_id, item in raw["devices"].items():
        if not isinstance(item, Mapping):
            raise InventoryError("inventory entries must be mappings")
        role, site = str(item.get("role")), str(item.get("assigned_site"))
        if role not in {"hub", "spoke", "cloud_gateway"} or not site or device_id in result or site in sites:
            raise InventoryError("duplicate or invalid inventory binding")
        result[str(device_id)] = InventoryEntry(str(device_id), role, site)
        sites.add(site)
    return result
