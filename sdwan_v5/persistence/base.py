"""SQLite migration, transaction, audit, and backup primitives."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Iterator


class PersistenceError(RuntimeError):
    pass


class MigrationError(PersistenceError):
    pass


class VersionConflict(PersistenceError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class SQLiteStore:
    """One logical service owner for one SQLite database file.

    The store opens a new connection only for its owner process.  Cross-service
    writes go through an authenticated API/event in higher layers, never by
    opening the other service's database directly.
    """

    def __init__(self, path: Path, migration_dir: Path):
        self.path = path
        self.migration_dir = migration_dir
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.migrate()

    def close(self) -> None:
        self.connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            yield self.connection
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise
        else:
            self.connection.execute("COMMIT")

    def migrate(self) -> None:
        self.connection.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        applied = {int(row[0]) for row in self.connection.execute("SELECT version FROM schema_migrations")}
        files = sorted(self.migration_dir.glob("[0-9][0-9][0-9]_*.sql"))
        versions = [int(item.name.split("_", 1)[0]) for item in files]
        if applied and max(applied) > (max(versions) if versions else 0):
            raise MigrationError("database schema is newer than this running code")
        for path in files:
            version = int(path.name.split("_", 1)[0])
            if version in applied:
                continue
            sql = path.read_text(encoding="utf-8")
            try:
                applied_at = utc_now().replace("'", "''")
                self.connection.executescript(
                    "BEGIN IMMEDIATE;\n"
                    + sql
                    + f"\nINSERT INTO schema_migrations(version, applied_at) VALUES ({version}, '{applied_at}');\nCOMMIT;"
                )
            except sqlite3.DatabaseError as exc:
                if self.connection.in_transaction:
                    self.connection.execute("ROLLBACK")
                raise MigrationError(f"migration {path.name} failed: {exc}") from exc

    @property
    def schema_version(self) -> int:
        row = self.connection.execute("SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations").fetchone()
        return int(row["version"])

    def integrity_check(self) -> None:
        row = self.connection.execute("PRAGMA integrity_check").fetchone()
        if row is None or row[0] != "ok":
            raise PersistenceError(f"SQLite integrity check failed: {row[0] if row else 'no result'}")

    def backup_to(self, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        target = sqlite3.connect(str(destination))
        try:
            self.connection.backup(target)
        finally:
            target.close()
        probe = sqlite3.connect(str(destination))
        try:
            row = probe.execute("PRAGMA integrity_check").fetchone()
            if row is None or row[0] != "ok":
                raise PersistenceError("backup integrity check failed")
        finally:
            probe.close()
        return destination
