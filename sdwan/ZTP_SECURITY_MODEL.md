# ZTP security model

An unclaimed edge starts only with device UUID, a one-time claim file (`0600`), pinned bootstrap CA, generic ZTP URL, and mounted identity root. It does **not** receive trusted `--site`, a global shared token, or central private keys.

1. Administrator stages immutable device → site inventory.
2. Administrator creates a cryptographically random single-use, expiring claim. The API returns plaintext once; SQLite stores PBKDF2 hash only.
3. The edge creates and persists its own ED25519 identity key and CSR under `/var/lib/sdwan/identity` (`0700` directory, `0600` files).
4. HTTPS bootstrap validates server CA; ZTP validates claim/device/nonce/CSR proof and atomically consumes the claim with certificate issuance.
5. ZTP returns operational certificate bound to assigned site, records audit/session/certificate lifecycle, and informs Policy Service through its authenticated internal boundary.
6. Post-enrollment Edge ↔ Policy, service ↔ service, progress, reconciliation and sensitive operations use TLS 1.2+ with certificate verification. Admin endpoints require administrator mTLS.

Enrollment transitions are explicit: `UNCLAIMED → BOOTSTRAP_NETWORK_READY → DISCOVERED → ENROLLING → AUTHENTICATED → SITE_ASSIGNED → HUBS_PREPARING → EDGE_CONFIGURING → VERIFYING → ACTIVE`, with retry/pending/quarantine/failed/revoked paths. Both hubs must prepare and verify before a spoke becomes `ACTIVE`.

Replacement revokes/fences the old certificate first, stages a new device identity/claim, creates fresh local keys, prepares both hubs, transfers ownership under a new epoch, then retires old peers/leases. A revoked certificate cannot reconcile. This is a lightweight laboratory implementation inspired by RFC 8572/RFC 9646 principles; it does not claim complete RFC protocol compliance.
