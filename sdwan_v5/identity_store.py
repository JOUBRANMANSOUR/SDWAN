"""Edge-local persistent private identity, WireGuard key and state storage."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Any


class IdentityStoreError(RuntimeError):
    pass


class IdentityStore:
    """Owns `/var/lib/sdwan`-style durable edge material, never a central DB."""

    def __init__(self, root: Path):
        self.root = root
        self.identity_dir = root / "identity"
        self.wireguard_dir = root / "wireguard"
        self.state_dir = root / "state"
        for directory in (self.identity_dir, self.wireguard_dir, self.state_dir):
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)

    @staticmethod
    def _write_private(path: Path, value: str) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(value, encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(path)
        os.chmod(path, 0o600)

    def private_key_path(self) -> Path:
        return self.identity_dir / "device-key.pem"

    def csr_path(self) -> Path:
        return self.identity_dir / "device.csr.pem"

    def certificate_path(self) -> Path:
        return self.identity_dir / "device-cert.pem"

    def store_certificate(self, certificate_pem: str, site: str, serial: str, fingerprint: str) -> None:
        self._write_private(self.certificate_path(), certificate_pem)
        self.persist_json("enrollment.json", {"site": site, "serial": serial, "fingerprint": fingerprint})

    def wireguard_private_key(self, interface: str) -> Path:
        if not interface.startswith("wg-") or "/" in interface:
            raise IdentityStoreError("invalid WireGuard interface name")
        return self.wireguard_dir / f"{interface}.key"

    def wireguard_device_private_key(self) -> Path:
        """One durable WireGuard key pair per edge device.

        The same public key is installed on the device's separate tunnel
        interfaces. Interface separation—not duplicate key material—provides
        the hub/transport cryptokey-routing separation in this lab.
        """
        return self.wireguard_dir / "device.key"

    def store_wireguard_device_private_key(self, value: str) -> Path:
        if not value.strip():
            raise IdentityStoreError("WireGuard private key is empty")
        path = self.wireguard_device_private_key()
        self._write_private(path, value.strip() + "\n")
        return path

    def persist_json(self, name: str, value: dict[str, Any]) -> None:
        if "/" in name or not name.endswith(".json"):
            raise IdentityStoreError("state name must be a simple JSON filename")
        self._write_private(self.state_dir / name, json.dumps(value, sort_keys=True, separators=(",", ":")))

    def load_json(self, name: str) -> dict[str, Any] | None:
        path = self.state_dir / name
        if not path.exists():
            return None
        self._assert_private(path)
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _assert_private(path: Path) -> None:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise IdentityStoreError(f"private state has unsafe permissions: {path}")
