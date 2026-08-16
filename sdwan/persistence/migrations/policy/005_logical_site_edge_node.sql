ALTER TABLE site_inventory ADD COLUMN edge_node TEXT;
UPDATE site_inventory SET edge_node = site WHERE edge_node IS NULL;
CREATE UNIQUE INDEX site_inventory_edge_node_idx ON site_inventory(edge_node);
CREATE TEMP TABLE desired_state_acks_migration AS
SELECT site, version, digest, applied_route_version, status, detail, acknowledged_at
FROM desired_state_acks;
DROP TABLE desired_state_acks;
UPDATE sites SET site='site' || substr(site,5) WHERE site GLOB "node[0-9]*";
UPDATE site_inventory SET site='site' || substr(site,5) WHERE site GLOB "node[0-9]*";
UPDATE wireguard_public_keys SET site='site' || substr(site,5) WHERE site GLOB "node[0-9]*";
UPDATE desired_states SET site='site' || substr(site,5), contents_json=replace(contents_json, '"site":"node', '"site":"site') WHERE site GLOB 'node[0-9]*';
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
INSERT INTO desired_state_acks(site, version, digest, applied_route_version, status, detail, acknowledged_at)
SELECT CASE WHEN site GLOB "node[0-9]*" THEN 'site' || substr(site,5) ELSE site END,
       version, digest, applied_route_version, status, detail, acknowledged_at
FROM desired_state_acks_migration;
DROP TABLE desired_state_acks_migration;
UPDATE destination_policy_delivery SET site='site' || substr(site,5) WHERE site GLOB "node[0-9]*";
UPDATE address_leases SET owner_site='site' || substr(owner_site,5) WHERE owner_site GLOB "node[0-9]*";
UPDATE port_leases SET owner_site='site' || substr(owner_site,5) WHERE owner_site GLOB "node[0-9]*";
UPDATE route_ownership SET spoke='site' || substr(spoke,5) WHERE spoke GLOB "node[0-9]*";
UPDATE pending_reconciliation SET site='site' || substr(site,5) WHERE site GLOB "node[0-9]*";
UPDATE site_operations SET site='site' || substr(site,5) WHERE site GLOB "node[0-9]*";
UPDATE hub_flow_events SET source_site='site' || substr(source_site,5) WHERE source_site GLOB "node[0-9]*";
UPDATE hub_flow_events SET destination_site='site' || substr(destination_site,5) WHERE destination_site GLOB "node[0-9]*";
