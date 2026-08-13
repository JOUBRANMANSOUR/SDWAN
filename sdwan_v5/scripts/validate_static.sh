#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
source ~/ryu-venv38/bin/activate
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root" python -m unittest discover -s "$root/sdwan_v5/tests" -p 'test_*_v5.py' -v
sha256sum -c "$root/sdwan_v5/preservation/sdwan_v4.sha256"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$root" python -m sdwan_v5.topology_v5 --validate-config
