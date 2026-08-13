#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
source ~/ryu-venv38/bin/activate
: "${SDWAN_MANAGEMENT_SECRET:?set SDWAN_MANAGEMENT_SECRET}"
: "${SDWAN_MANAGEMENT_USERS:?set SDWAN_MANAGEMENT_USERS}"
PYTHONPATH="$root" exec uvicorn sdwan.management.app:create_app --factory --host "${SDWAN_MANAGEMENT_HOST:-127.0.0.1}" --port "${SDWAN_MANAGEMENT_PORT:-8090}"
