CREATE TEMP TABLE logical_site_mapping AS
SELECT site AS old_site, 'site' || substr(edge_node, 5) AS new_site
FROM site_inventory
WHERE edge_node GLOB "node[0-9]*" AND site <> 'site' || substr(edge_node, 5);

CREATE TEMP TABLE desired_state_acks_normalization AS
SELECT site, version, digest, applied_route_version, status, detail, acknowledged_at FROM desired_state_acks;
DROP TABLE desired_state_acks;

UPDATE sites SET site = (SELECT new_site FROM logical_site_mapping WHERE old_site = sites.site) WHERE site IN (SELECT old_site FROM logical_site_mapping);
UPDATE site_inventory SET site = (SELECT new_site FROM logical_site_mapping WHERE old_site = site_inventory.site) WHERE site IN (SELECT old_site FROM logical_site_mapping);
UPDATE wireguard_public_keys SET site = (SELECT new_site FROM logical_site_mapping WHERE old_site = wireguard_public_keys.site) WHERE site IN (SELECT old_site FROM logical_site_mapping);
UPDATE desired_states SET site = (SELECT new_site FROM logical_site_mapping WHERE old_site = desired_states.site) WHERE site IN (SELECT old_site FROM logical_site_mapping);

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
SELECT COALESCE((SELECT new_site FROM logical_site_mapping WHERE old_site = a.site), a.site), version, digest, applied_route_version, status, detail, acknowledged_at FROM desired_state_acks_normalization AS a;
DROP TABLE desired_state_acks_normalization;

UPDATE destination_policy_delivery SET site = (SELECT new_site FROM logical_site_mapping WHERE old_site = destination_policy_delivery.site) WHERE site IN (SELECT old_site FROM logical_site_mapping);
UPDATE address_leases SET owner_site = (SELECT new_site FROM logical_site_mapping WHERE old_site = address_leases.owner_site) WHERE owner_site IN (SELECT old_site FROM logical_site_mapping);
UPDATE port_leases SET owner_site = (SELECT new_site FROM logical_site_mapping WHERE old_site = port_leases.owner_site) WHERE owner_site IN (SELECT old_site FROM logical_site_mapping);
UPDATE route_ownership SET spoke = (SELECT new_site FROM logical_site_mapping WHERE old_site = route_ownership.spoke) WHERE spoke IN (SELECT old_site FROM logical_site_mapping);
UPDATE pending_reconciliation SET site = (SELECT new_site FROM logical_site_mapping WHERE old_site = pending_reconciliation.site) WHERE site IN (SELECT old_site FROM logical_site_mapping);
UPDATE site_operations SET site = (SELECT new_site FROM logical_site_mapping WHERE old_site = site_operations.site) WHERE site IN (SELECT old_site FROM logical_site_mapping);
UPDATE hub_flow_events SET source_site = (SELECT new_site FROM logical_site_mapping WHERE old_site = hub_flow_events.source_site) WHERE source_site IN (SELECT old_site FROM logical_site_mapping);
UPDATE hub_flow_events SET destination_site = (SELECT new_site FROM logical_site_mapping WHERE old_site = hub_flow_events.destination_site) WHERE destination_site IN (SELECT old_site FROM logical_site_mapping);
DROP TABLE logical_site_mapping;
