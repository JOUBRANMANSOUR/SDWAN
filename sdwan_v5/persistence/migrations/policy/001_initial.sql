CREATE TABLE sites (
  site TEXT PRIMARY KEY,
  device_id TEXT NOT NULL UNIQUE,
  lan_prefix TEXT NOT NULL UNIQUE,
  preferred_hub TEXT NOT NULL,
  standby_hub TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE hubs (
  hub TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  capacity_mbps REAL NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE transport_profiles (
  transport TEXT PRIMARY KEY,
  route_slot INTEGER NOT NULL UNIQUE,
  route_table INTEGER NOT NULL UNIQUE,
  internet_capable INTEGER NOT NULL
);
CREATE TABLE application_policies (
  policy_id TEXT PRIMARY KEY,
  application_class TEXT NOT NULL,
  sla_class TEXT NOT NULL,
  allowed_egress_json TEXT NOT NULL,
  ranked_transports_json TEXT NOT NULL,
  generation INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);
CREATE TABLE failover_policies (
  policy_id TEXT PRIMARY KEY,
  policy_json TEXT NOT NULL,
  generation INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);
CREATE TABLE address_leases (
  address TEXT PRIMARY KEY,
  owner_site TEXT NOT NULL,
  hub TEXT NOT NULL,
  transport TEXT NOT NULL,
  interface_name TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(owner_site, hub, transport, interface_name)
);
CREATE TABLE port_leases (
  node TEXT NOT NULL,
  port INTEGER NOT NULL,
  owner_site TEXT NOT NULL,
  interface_name TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(node, port),
  UNIQUE(owner_site, interface_name)
);
CREATE TABLE wireguard_public_keys (
  site TEXT NOT NULL,
  interface_name TEXT NOT NULL,
  generation INTEGER NOT NULL,
  public_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(site, interface_name, generation),
  UNIQUE(site, interface_name, status)
);
CREATE TABLE desired_states (
  site TEXT NOT NULL,
  version INTEGER NOT NULL,
  digest TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  generation TEXT NOT NULL,
  route_version INTEGER NOT NULL,
  ownership_epoch INTEGER NOT NULL,
  contents_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  delivery_status TEXT NOT NULL,
  applied_status TEXT NOT NULL,
  verification_status TEXT NOT NULL,
  superseded_by INTEGER,
  PRIMARY KEY(site, version),
  UNIQUE(site, digest)
);
CREATE TABLE desired_state_acks (
  site TEXT NOT NULL,
  version INTEGER NOT NULL,
  digest TEXT NOT NULL,
  applied_route_version INTEGER NOT NULL,
  status TEXT NOT NULL,
  detail TEXT NOT NULL,
  acknowledged_at TEXT NOT NULL,
  PRIMARY KEY(site, version),
  FOREIGN KEY(site, version) REFERENCES desired_states(site, version)
);
CREATE TABLE route_ownership (
  prefix TEXT PRIMARY KEY,
  spoke TEXT NOT NULL UNIQUE,
  preferred_hub TEXT NOT NULL,
  standby_hub TEXT NOT NULL,
  current_owner_hub TEXT NOT NULL,
  previous_owner_hub TEXT,
  owner_epoch INTEGER NOT NULL,
  policy_version INTEGER NOT NULL,
  route_version INTEGER NOT NULL,
  state TEXT NOT NULL,
  reason TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  valid_until TEXT,
  pending_reconciliation INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE policy_versions (
  version INTEGER PRIMARY KEY,
  digest TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);
CREATE TABLE provisioning_runs (
  run_id TEXT PRIMARY KEY,
  site TEXT NOT NULL,
  state TEXT NOT NULL,
  desired_version INTEGER,
  detail TEXT NOT NULL,
  started_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE pending_reconciliation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site TEXT NOT NULL,
  owner_epoch INTEGER NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  UNIQUE(site, owner_epoch, reason)
);
CREATE TABLE manual_overrides (
  override_id TEXT PRIMARY KEY,
  site TEXT NOT NULL,
  scope TEXT NOT NULL,
  value_json TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE policy_audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  reason TEXT NOT NULL,
  request_id TEXT NOT NULL,
  result TEXT NOT NULL,
  before_version INTEGER,
  after_version INTEGER,
  created_at TEXT NOT NULL
);
CREATE INDEX desired_states_site_version_idx ON desired_states(site, version DESC);
CREATE INDEX route_ownership_epoch_idx ON route_ownership(owner_epoch DESC);
CREATE INDEX pending_reconciliation_site_idx ON pending_reconciliation(site, resolved_at);
