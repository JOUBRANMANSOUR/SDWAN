PRAGMA foreign_keys=OFF;
ALTER TABLE site_inventory RENAME TO site_inventory_legacy;
CREATE TABLE site_inventory (
  site TEXT PRIMARY KEY,
  device_id TEXT NOT NULL UNIQUE,
  lifecycle TEXT NOT NULL CHECK(lifecycle IN ('ALLOCATING','TOPOLOGY_CREATED','ZTP_STAGED','ENROLLING','ENROLLED','REGISTERING','PROVISIONING','PENDING_HUBS','RECONCILING','ACTIVE','FAILED','DELETING','DELETED','REQUESTED','ALLOCATED','DECOMMISSIONING','REVOKED')),
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
  failure_stage TEXT,
  recoverable INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);
INSERT INTO site_inventory(site,device_id,lifecycle,address_id,wireguard_index,management_ip,lan_prefix,lan_gateway,lan_switch,lan_dpid,host_name,host_ip,interface_suffix,preferred_hub,standby_hub,runtime_status,last_error,failure_stage,recoverable,created_at,updated_at,deleted_at)
SELECT site,device_id,lifecycle,address_id,wireguard_index,management_ip,lan_prefix,lan_gateway,lan_switch,lan_dpid,host_name,host_ip,interface_suffix,preferred_hub,standby_hub,runtime_status,last_error,NULL,1,created_at,updated_at,deleted_at FROM site_inventory_legacy;
DROP TABLE site_inventory_legacy;
CREATE INDEX site_inventory_lifecycle_idx ON site_inventory(lifecycle);
CREATE TABLE site_operations (
  operation_id TEXT PRIMARY KEY,
  site TEXT NOT NULL,
  operation_type TEXT NOT NULL CHECK(operation_type IN ('CREATE','DELETE')),
  state TEXT NOT NULL,
  failure_stage TEXT,
  failure_reason TEXT,
  recoverable INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT
);
CREATE INDEX site_operations_site_idx ON site_operations(site, created_at DESC);
PRAGMA foreign_keys=ON;
