# Persistent database design

Two SQLite files have one logical owner each and use WAL, foreign keys, busy timeout, transactions, versioned `001_initial.sql` migration, integrity checks, and SQLite backup API.

| Owner | File | Schema version | Principal durable entities |
|---|---|---:|---|
| ZTP Service | `ztp/ztp.db` | 1 | devices, claims, certificates, revocations, enrollment sessions/attempts, ZTP audit |
| Policy Service | `policy/policy.db` | 1 | sites, policies, leases, public keys, desired states/acks, route ownership, overrides, reconciliation, audit |

`claims.secret_hash` is PBKDF2-SHA256 with a random salt. Plaintext claim secrets, device private keys, WireGuard private keys, packets, NFQUEUE payloads, conntrack tables, and high-frequency probe samples are not stored centrally.

Desired state stores site, schema/generation, desired/route/ownership versions, canonical digest, attribution, delivery/applied/verification status and history. Repeating a version+digest is idempotent; equal version with different contents and older version are rejected. Route ownership contains prefix, spoke, preferred/standby/current/previous hub, monotonic epoch, policy/route versions, state, reason, timestamps, expiry and reconciliation flag.

Back up only while the owner service is healthy, for example:

```bash
source ~/ryu-venv38/bin/activate
PYTHONPATH=/mnt/data/sdwan-lab python -m sdwan_v5.persistence.migrate \
  --ztp-db /mnt/data/sdwan-state/ztp/ztp.db \
  --policy-db /mnt/data/sdwan-state/policy/policy.db --check
```

On corruption, stop new writes, preserve forwarding, report unhealthy state, and restore a verified backup. Never create a silent empty database.
