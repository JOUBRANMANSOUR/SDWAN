#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
source ~/containernet-venv38/bin/activate
topology_config=${SDWAN_TOPOLOGY_CONFIG:-"$root/sdwan/config/topology.core.yaml"}
runtime_python="$VIRTUAL_ENV/bin/python"
exec sudo -E env PATH="$PATH" PYTHONPATH="$root" "$runtime_python" \
  -m sdwan.topology_v5 --config "$topology_config"


