"""ZTP-owned transactional claim, enrollment, certificate and audit store."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path
import secrets
import sqlite3
from typing import Callable
from uuid import uuid4

from .base import PersistenceError, SQLiteStore, utc_now


class ClaimRejected(PersistenceError):
    pass


def _hash_secret(secret: str, salt: bytes | None = None) -> str:
    salt = secrets.token_bytes(16) if salt is None else salt
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 200_000)
    return f"pbkdf2_sha256$200000${salt.hex()}${digest.hex()}"


def _verify_secret(secret: str, stored: str) -> bool:
    algorithm, iterations, salt_hex, expected_hex = stored.split("$", 3)
    if algorithm != "pbkdf2_sha256" or iterations != "200000":
        return False
    actual = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)).hex()
    return hmac.compare_digest(actual, expected_hex)


def _nonce_fingerprint(nonce: str) -> str:
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()


class ZTPStore(SQLiteStore):
    def __init__(self, path: Path):
        super().__init__(path, Path(__file__).with_name("migrations") / "ztp")

    def stage_device(self, device_id: str, site: str, actor: str = "admin") -> None:
        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute("SELECT assigned_site, status FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if row and row["assigned_site"] != site:
                raise ClaimRejected("device is already staged for a different site")
            if not row:
                connection.execute("INSERT INTO devices(device_id, assigned_site, status, public_key_fingerprint, created_at, updated_at) VALUES (?, ?, 'STAGED', NULL, ?, ?)", (device_id, site, now, now))
            self._audit(connection, actor, "STAGE_DEVICE", device_id, "staged", "ok", "")

    def create_claim(self, device_id: str, site: str, *, lifetime_s: int, actor: str, maximum_uses: int = 1) -> tuple[str, str]:
        if lifetime_s <= 0 or maximum_uses != 1:
            raise ValueError("baseline claims must be single-use with a positive lifetime")
        claim_id, secret = str(uuid4()), secrets.token_urlsafe(32)
        created = datetime.now(timezone.utc)
        expires = created + timedelta(seconds=lifetime_s)
        with self.transaction() as connection:
            staged = connection.execute("SELECT assigned_site, status FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if staged is None or staged["assigned_site"] != site or staged["status"] not in {"STAGED", "REPLACED"}:
                raise ClaimRejected("device is not staged for this site")
            connection.execute(
                "INSERT INTO claims(claim_id, secret_hash, expected_device_id, assigned_site, created_at, expires_at, maximum_uses, current_uses, status, consumed_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'ACTIVE', NULL, ?)",
                (claim_id, _hash_secret(secret), device_id, site, created.isoformat(), expires.isoformat(), maximum_uses, actor),
            )
            self._audit(connection, actor, "CREATE_CLAIM", claim_id, "created", "ok", site)
        return claim_id, secret

    def cancel_claim(self, claim_id: str, actor: str, reason: str) -> None:
        with self.transaction() as connection:
            result = connection.execute("UPDATE claims SET status = 'CANCELLED' WHERE claim_id = ? AND status = 'ACTIVE'", (claim_id,))
            if result.rowcount != 1:
                raise ClaimRejected("only active claims can be cancelled")
            self._audit(connection, actor, "CANCEL_CLAIM", claim_id, "cancelled", "ok", reason)

    def consume_claim(
        self,
        claim_id: str,
        secret: str,
        device_id: str,
        nonce: str,
        issue_certificate: Callable[[str], tuple[str, str, str, str, str]],
        *,
        request_id: str,
    ) -> dict[str, str]:
        """Atomically consume a claim and persist an issuer-produced certificate.

        `issue_certificate` receives the assigned site and returns
        `(serial, fingerprint, not_before, not_after, certificate_pem)`.  Any
        exception rolls back the claim, nonce session, certificate and device
        update together.
        """
        nonce_hash = _nonce_fingerprint(nonce)
        try:
            with self.transaction() as connection:
                claim = connection.execute("SELECT * FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
                if claim is None:
                    raise ClaimRejected("unknown claim")
                if claim["expected_device_id"] != device_id:
                    raise ClaimRejected("claim device mismatch")
                if claim["status"] != "ACTIVE" or claim["current_uses"] >= claim["maximum_uses"]:
                    raise ClaimRejected("claim is not reusable")
                if datetime.fromisoformat(claim["expires_at"]) <= datetime.now(timezone.utc):
                    connection.execute("UPDATE claims SET status = 'EXPIRED' WHERE claim_id = ?", (claim_id,))
                    raise ClaimRejected("claim expired")
                if not _verify_secret(secret, claim["secret_hash"]):
                    raise ClaimRejected("claim secret rejected")
                duplicate = connection.execute("SELECT 1 FROM enrollment_sessions WHERE device_id = ? AND nonce = ?", (device_id, nonce)).fetchone()
                if duplicate:
                    raise ClaimRejected("enrollment nonce replay")
                serial, fingerprint, not_before, not_after, certificate_pem = issue_certificate(str(claim["assigned_site"]))
                now = utc_now()
                connection.execute("INSERT INTO enrollment_sessions(device_id, nonce, state, updated_at) VALUES (?, ?, 'AUTHENTICATED', ?)", (device_id, nonce, now))
                connection.execute("INSERT INTO certificates(serial, fingerprint, device_id, assigned_site, not_before, not_after, status, certificate_pem) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?)", (serial, fingerprint, device_id, claim["assigned_site"], not_before, not_after, certificate_pem))
                connection.execute("UPDATE claims SET current_uses = current_uses + 1, status = 'CONSUMED', consumed_at = ? WHERE claim_id = ?", (now, claim_id))
                connection.execute("UPDATE devices SET status = 'ACTIVE', public_key_fingerprint = ?, updated_at = ? WHERE device_id = ?", (fingerprint, now, device_id))
                connection.execute("INSERT INTO enrollment_attempts(device_id, claim_id, nonce_fingerprint, result, reason, created_at) VALUES (?, ?, ?, 'ACCEPTED', 'claim consumed', ?)", (device_id, claim_id, nonce_hash, now))
                self._audit(connection, device_id, "ENROLL", device_id, "accepted", "ok", request_id)
                return {"site": str(claim["assigned_site"]), "serial": serial, "fingerprint": fingerprint, "certificate_pem": certificate_pem}
        except ClaimRejected as exc:
            self.record_attempt(device_id, claim_id, nonce_hash, "REJECTED", str(exc))
            raise

    def record_attempt(self, device_id: str, claim_id: str | None, nonce_hash: str, result: str, reason: str) -> None:
        with self.transaction() as connection:
            connection.execute("INSERT INTO enrollment_attempts(device_id, claim_id, nonce_fingerprint, result, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)", (device_id, claim_id, nonce_hash, result, reason, utc_now()))

    def revoke_certificate(self, serial: str, actor: str, reason: str) -> None:
        with self.transaction() as connection:
            certificate = connection.execute("SELECT device_id FROM certificates WHERE serial = ?", (serial,)).fetchone()
            if certificate is None:
                raise ClaimRejected("unknown certificate")
            connection.execute("UPDATE certificates SET status = 'REVOKED' WHERE serial = ?", (serial,))
            connection.execute("INSERT OR REPLACE INTO revocations(serial, reason, revoked_at, actor) VALUES (?, ?, ?, ?)", (serial, reason, utc_now(), actor))
            connection.execute("UPDATE devices SET status = 'REVOKED', updated_at = ? WHERE device_id = ?", (utc_now(), certificate["device_id"]))
            self._audit(connection, actor, "REVOKE_CERTIFICATE", serial, "revoked", "ok", reason)

    def certificate_is_active(self, serial: str, site: str) -> bool:
        row = self.connection.execute("SELECT status, assigned_site FROM certificates WHERE serial = ?", (serial,)).fetchone()
        return bool(row and row["status"] == "ACTIVE" and row["assigned_site"] == site)

    @staticmethod
    def _audit(connection: sqlite3.Connection, actor: str, action: str, target: str, result: str, status: str, reason: str) -> None:
        connection.execute("INSERT INTO ztp_audit_events(actor, action, target, request_id, result, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (actor, action, target, status, result, reason, utc_now()))
