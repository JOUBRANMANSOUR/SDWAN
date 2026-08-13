CREATE TABLE site_inventory (
  site TEXT PRIMARY KEY,
  device_id TEXT NOT NULL UNIQUE,
  lifecycle TEXT NOT NULL CHECK(lifecycle IN ('REQUESTED','ALLOCATED','ZTP_STAGED','ENROLLING','PROVISIONING','ACTIVE','DECOMMISSIONING','REVOKED','DELETED','FAILED')),
  address_id INTEGER NOT NULL UNIQUE,
  wireguard_index INTEGER NOT NULL UNIQUE,
  management_ip TEXT NOT NULL UNIQUE,
  lan_prefix TEXT NOT NULL UNIQUE,
  lan_gateway TEXT NOT NULL UNIQUE,
  lan_switch TEXT NOT NULL UNIQUE,
  lan_dpid INTEGER NOT NULL UNIQUE,
  host_name TEXT NOT NULL UNIQUE,
  host_ip TEXT NOT NULL UNIQUE,
  interface_suffix TEXT NOT NULL UNIQUE,
  preferred_hub TEXT NOT NULL,
  standby_hub TEXT NOT NULL,
  runtime_status TEXT NOT NULL DEFAULT 'NOT_REQUESTED',
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);
CREATE TABLE administrative_intents (
  intent_id TEXT PRIMARY KEY,
  intent_type TEXT NOT NULL,
  target TEXT NOT NULL,
  contents_json TEXT NOT NULL,
  digest TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE control_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  subject TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE TABLE network_state_inputs (
  input_key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  digest TEXT NOT NULL,
  source TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE control_compilations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  trigger_event_id INTEGER,
  input_digest TEXT NOT NULL,
  output_digest TEXT NOT NULL,
  changed INTEGER NOT NULL,
  detail TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE hub_flow_events (
  flow_id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  hub_id TEXT NOT NULL,
  ingress_interface TEXT,
  egress_interface TEXT,
  source_site TEXT,
  destination_site TEXT,
  source_ip TEXT NOT NULL,
  destination_ip TEXT NOT NULL,
  protocol TEXT NOT NULL,
  source_port INTEGER,
  destination_port INTEGER,
  conntrack_state TEXT,
  mark TEXT,
  path_metadata_json TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  counters_json TEXT NOT NULL
);
CREATE INDEX site_inventory_lifecycle_idx ON site_inventory(lifecycle);
CREATE INDEX control_events_unconsumed_idx ON control_events(consumed_at, id);
CREATE INDEX hub_flow_events_query_idx ON hub_flow_events(hub_id, source_site, destination_site, timestamp DESC);
