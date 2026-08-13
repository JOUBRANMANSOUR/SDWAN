#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
state_root=${SDWAN_STATE_ROOT:-/mnt/data/sdwan-state}
source ~/ryu-venv38/bin/activate
topology_config=${SDWAN_TOPOLOGY_CONFIG:-"$root/sdwan/config/topology.core.yaml"}
destination_policy_config=${SDWAN_DESTINATION_POLICY_CONFIG:-"$root/sdwan/config/destination_policy.yaml"}
PYTHONPATH="$root" exec python -m sdwan.policy_http \
  --config "$topology_config" \
  --app-policy "$root/sdwan/config/app_policy.yaml" \
  --inventory "$root/sdwan/config/site_inventory.yaml" \
  --destination-policy "$destination_policy_config" \
  --database "$state_root/policy/policy.db" \
  --ca-bundle "$state_root/trust/ca-cert.pem" \
  --certificate "$state_root/trust/policy-cert.pem" \
  --private-key "$state_root/trust/policy-key.pem"
