CREATE TABLE devices (
  device_id TEXT PRIMARY KEY,
  assigned_site TEXT UNIQUE,
  status TEXT NOT NULL CHECK(status IN ('STAGED','ACTIVE','REVOKED','REPLACED','QUARANTINED')),
  public_key_fingerprint TEXT UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE claims (
  claim_id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL,
  expected_device_id TEXT NOT NULL,
  assigned_site TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  maximum_uses INTEGER NOT NULL CHECK(maximum_uses > 0),
  current_uses INTEGER NOT NULL DEFAULT 0 CHECK(current_uses >= 0),
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','CONSUMED','CANCELLED','EXPIRED')),
  consumed_at TEXT,
  created_by TEXT NOT NULL
);
CREATE TABLE certificates (
  serial TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL UNIQUE,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  assigned_site TEXT NOT NULL,
  not_before TEXT NOT NULL,
  not_after TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','REVOKED','EXPIRED','RETIRED')),
  certificate_pem TEXT NOT NULL
);
CREATE TABLE revocations (
  serial TEXT PRIMARY KEY REFERENCES certificates(serial),
  reason TEXT NOT NULL,
  revoked_at TEXT NOT NULL,
  actor TEXT NOT NULL
);
CREATE TABLE enrollment_sessions (
  device_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  state TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(device_id, nonce)
);
CREATE TABLE enrollment_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  claim_id TEXT,
  nonce_fingerprint TEXT NOT NULL,
  result TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE ztp_audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  request_id TEXT NOT NULL,
  result TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX claims_expected_device_idx ON claims(expected_device_id, status);
CREATE INDEX certificates_device_idx ON certificates(device_id, status);
CREATE INDEX attempts_device_idx ON enrollment_attempts(device_id, created_at);
