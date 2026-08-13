"""Bounded local IPC for dynamic Containernet branch lifecycle operations.

The socket speaks only two typed operations (create_site/delete_site).  It is
not a command runner and cannot execute arbitrary shell or Docker input.
"""
from __future__ import annotations

from dataclasses import asdict
import os
import json
from pathlib import Path
import socket
import threading
from typing import Any, Callable

from .dynamic_control import InventorySite

def _bounded_error(value: str, limit: int = 800) -> str:
    value = value.strip()
    if len(value) <= limit:
        return value
    marker = "\n... error truncated ...\n"
    head = limit // 4
    return value[:head] + marker + value[-(limit - head - len(marker)):]



class TopologyControlClient:
    def __init__(self, socket_path: Path):
        self.socket_path = socket_path

    def _request(
        self,
        operation: str,
        site: InventorySite | None = None,
        bootstrap: dict[str, str] | None = None,
        target: str | None = None,
    ) -> dict[str, Any]:
        if not self.socket_path.exists():
            return {"available": False, "reason": "no active Containernet control socket"}
        payload_value: dict[str, Any] = {"operation": operation}
        if site is not None:
            payload_value["site"] = asdict(site)
        if target is not None:
            payload_value["target"] = target
        if bootstrap is not None:
            payload_value["bootstrap"] = bootstrap
        payload = json.dumps(payload_value, separators=(",", ":")).encode("utf-8")
        timeout_seconds = float(os.environ.get("SDWAN_TOPOLOGY_CONTROL_TIMEOUT_SECONDS", "90"))
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(timeout_seconds)
                client.connect(str(self.socket_path))
                client.sendall(payload + b"\n")
                response = client.recv(65536)
            value = json.loads(response.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("invalid topology response")
            return value
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return {"available": False, "reason": f"topology control unavailable: {_bounded_error(str(exc), 240)}"}

    def create_site(self, site: InventorySite) -> dict[str, Any]:
        return self._request("create_site", site)

    def delete_site(self, site: InventorySite) -> dict[str, Any]:
        return self._request("delete_site", site)

    def bootstrap_site(self, site: InventorySite, bootstrap: dict[str, str]) -> dict[str, Any]:
        return self._request("bootstrap_site", site, bootstrap)

    def reconcile_site(self, target: str, bootstrap: dict[str, str]) -> dict[str, Any]:
        return self._request("reconcile_site", bootstrap=bootstrap, target=target)


class TopologyControlServer:
    def __init__(self, socket_path: Path, create_site: Callable[[InventorySite], None], delete_site: Callable[[InventorySite], None], bootstrap_site: Callable[[InventorySite, dict[str, str]], dict[str, Any]] | None = None, reconcile_site: Callable[[str, dict[str, str]], dict[str, Any]] | None = None):
        self.socket_path, self.create_site, self.delete_site = socket_path, create_site, delete_site
        self.bootstrap_site, self.reconcile_site = bootstrap_site, reconcile_site
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @staticmethod
    def _record(value: dict[str, Any]) -> InventorySite:
        allowed = set(InventorySite.__dataclass_fields__)
        if set(value) != allowed:
            raise ValueError("invalid dynamic site record")
        return InventorySite(**value)

    def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.socket_path.unlink(missing_ok=True)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.socket_path))
        self.socket_path.chmod(0o600)
        owner_uid, owner_gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
        if owner_uid and owner_gid and owner_uid.isdigit() and owner_gid.isdigit():
            os.chown(self.socket_path, int(owner_uid), int(owner_gid))
        server.listen(8)
        server.settimeout(0.5)
        self._server = server
        self._thread = threading.Thread(target=self._serve, name="sdwan-topology-control", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._server is not None:
            self._server.close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self.socket_path.unlink(missing_ok=True)

    def _serve(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                connection, _ = self._server.accept()
            except (OSError, socket.timeout):
                continue
            with connection:
                try:
                    raw = connection.recv(65536)
                    request = json.loads(raw.decode("utf-8"))
                    if not isinstance(request, dict) or request.get("operation") not in {"create_site", "delete_site", "bootstrap_site", "reconcile_site"}:
                        raise ValueError("invalid topology operation")
                    operation = str(request["operation"])
                    record: InventorySite | None = None
                    if operation != "reconcile_site":
                        if not isinstance(request.get("site"), dict):
                            raise ValueError("invalid dynamic site record")
                        record = self._record(request["site"])
                    if operation == "create_site" and record is not None:
                        self.create_site(record); detail: dict[str, Any] = {}
                    elif operation == "delete_site" and record is not None:
                        self.delete_site(record); detail = {}
                    else:
                        bootstrap = request.get("bootstrap")
                        required = {"claim_id", "claim_secret", "bootstrap_ca_pem", "ztp_url", "policy_url", "management_host"} if operation == "bootstrap_site" else {"bootstrap_ca_pem", "policy_url", "management_host"}
                        if not isinstance(bootstrap, dict) or set(bootstrap) != required or not all(isinstance(value, str) and value for value in bootstrap.values()):
                            raise ValueError("invalid typed bootstrap request")
                        handler = self.bootstrap_site if operation == "bootstrap_site" else self.reconcile_site
                        if handler is None:
                            raise ValueError("topology does not support edge lifecycle operations")
                        if operation == "reconcile_site":
                            target = request.get("target")
                            if not isinstance(target, str) or not target or len(target) > 64:
                                raise ValueError("invalid reconcile target")
                            detail = handler(target, {key: str(value) for key, value in bootstrap.items()})
                            response_site = target
                        else:
                            assert record is not None
                            detail = handler(record, {key: str(value) for key, value in bootstrap.items()})
                            response_site = record.site
                    if operation in {"create_site", "delete_site"}:
                        assert record is not None
                        response_site = record.site
                    response = {"available": True, "operation": operation, "site": response_site, **detail}
                except Exception as exc:
                    response = {"available": False, "reason": _bounded_error(str(exc))}
                try:
                    connection.sendall(json.dumps(response, separators=(",", ":")).encode("utf-8"))
                except BrokenPipeError:
                    # A timed-out or cancelled client must not terminate the
                    # topology-control loop after the bounded operation ends.
                    continue
