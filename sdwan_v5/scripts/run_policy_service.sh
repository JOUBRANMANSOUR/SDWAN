#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
state_root=${SDWAN_STATE_ROOT:-/mnt/data/sdwan-state}
source ~/ryu-venv38/bin/activate
PYTHONPATH="$root" exec python -m sdwan_v5.policy_http \
  --config "$root/sdwan_v5/config/topology.yaml" \
  --app-policy "$root/sdwan_v5/config/app_policy.yaml" \
  --inventory "$root/sdwan_v5/config/site_inventory.yaml" \
  --database "$state_root/policy/policy.db" \
  --ca-bundle "$state_root/trust/ca-cert.pem" \
  --certificate "$state_root/trust/policy-cert.pem" \
  --private-key "$state_root/trust/policy-key.pem"
