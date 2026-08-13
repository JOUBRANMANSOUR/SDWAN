#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
source ~/ryu-venv38/bin/activate
PYTHONPATH="$root" exec ryu-manager "$root/sdwan_v5/controller_v5.py"
