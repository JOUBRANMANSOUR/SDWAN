#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
source ~/ryu-venv38/bin/activate
topology_config=${SDWAN_TOPOLOGY_CONFIG:-"$root/sdwan_v5/config/topology.core.yaml"}
state_root=${SDWAN_STATE_ROOT:-/mnt/data/sdwan-state}
PYTHONPATH="$root" SDWAN_TOPOLOGY_CONFIG="$topology_config" SDWAN_STATE_ROOT="$state_root" \
  exec ryu-manager "$root/sdwan_v5/controller_v5.py"
