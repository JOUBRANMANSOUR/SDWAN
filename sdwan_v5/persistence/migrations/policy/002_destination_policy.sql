CREATE TABLE destination_policy_versions (
  version INTEGER PRIMARY KEY,
  digest TEXT NOT NULL UNIQUE,
  contents_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);
CREATE TABLE destination_policy_activation (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  version INTEGER NOT NULL,
  activated_at TEXT NOT NULL,
  activated_by TEXT NOT NULL,
  FOREIGN KEY(version) REFERENCES destination_policy_versions(version)
);
CREATE TABLE destination_policy_delivery (
  site TEXT NOT NULL,
  policy_version INTEGER NOT NULL,
  desired_state_version INTEGER NOT NULL,
  applied_status TEXT NOT NULL,
  observed_status TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(site, policy_version),
  FOREIGN KEY(policy_version) REFERENCES destination_policy_versions(version)
);
CREATE INDEX destination_policy_delivery_site_idx
  ON destination_policy_delivery(site, policy_version DESC);
