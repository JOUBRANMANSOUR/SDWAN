"""Restore persistent dynamic branches into a newly started Containernet run."""
from __future__ import annotations

from dataclasses import fields
from pathlib import Path
import sqlite3
import threading
from typing import Any, Callable, Iterable, Protocol

from .dynamic_control import InventorySite


class ReconcileRuntime(Protocol):
    def reconcile_site(self, target: str, bootstrap: dict[str, str]) -> dict[str, Any]: ...


def load_active_dynamic_sites(
    database: Path,
    configured_sites: Iterable[str],
) -> tuple[InventorySite, ...]:
    """Read ACTIVE non-static sites without migrating or writing Policy state."""
    if not database.is_file():
        return ()
    connection = sqlite3.connect(f"file:{database.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='site_inventory'"
        ).fetchone()
        if table is None:
            return ()
        names = {field.name for field in fields(InventorySite)}
        static = set(configured_sites)
        records: list[InventorySite] = []
        for row in connection.execute(
            "SELECT * FROM site_inventory WHERE lifecycle='ACTIVE' ORDER BY site"
        ):
            values = dict(row)
            missing = names.difference(values)
            if missing:
                raise RuntimeError(
                    "persistent site inventory is missing required columns: "
                    + ", ".join(sorted(missing))
                )
            record = InventorySite(**{name: values[name] for name in names})
            if record.site not in static:
                record.to_site()
                records.append(record)
        return tuple(records)
    finally:
        connection.close()


def persistent_reconciliation_targets(
    hubs: Iterable[str],
    configured_sites: Iterable[str],
    restored_sites: Iterable[InventorySite],
) -> tuple[str, ...]:
    """Return dependency-ordered, de-duplicated startup targets."""
    return tuple(dict.fromkeys((
        *hubs, *configured_sites, *(record.site for record in restored_sites),
    )))


class PersistentSiteReconciler:
    """Reconcile hubs first, then static and restored branches until shutdown."""

    def __init__(
        self,
        runtime: ReconcileRuntime,
        targets: Iterable[str],
        bootstrap: dict[str, str],
        *,
        retry_seconds: float = 5.0,
        report: Callable[[str], None] = print,
    ):
        self.runtime = runtime
        self.targets = tuple(dict.fromkeys(targets))
        self.bootstrap = dict(bootstrap)
        self.retry_seconds = max(0.01, retry_seconds)
        self.report = report
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not self.targets or self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name="sdwan-persistent-site-reconcile",
            daemon=True,
        )
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(2.0, self.retry_seconds + 1.0))

    def _run(self) -> None:
        for target in self.targets:
            failures = 0
            while not self._stop.is_set():
                try:
                    result = self.runtime.reconcile_site(target, self.bootstrap)
                    state = str(result.get("state", "UNKNOWN"))
                    if state == "PENDING":
                        raise RuntimeError("desired state is pending")
                except Exception as exc:
                    failures += 1
                    if failures == 1 or failures % 12 == 0:
                        self.report(
                            f"Persistent reconciliation waiting for {target}: {exc}"
                        )
                    self._stop.wait(self.retry_seconds)
                    continue
                self.report(
                    f"Persistent reconciliation completed for {target}: {state}"
                )
                break
