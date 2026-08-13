#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)

if [[ -n "${SDWAN_TEST_PYTHON:-}" ]]; then
  python_bin=${SDWAN_TEST_PYTHON}
elif [[ -x "$HOME/ryu-venv38/bin/python" ]]; then
  python_bin="$HOME/ryu-venv38/bin/python"
elif [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
  python_bin="$VIRTUAL_ENV/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  python_bin=$(command -v python3)
else
  echo "No usable Python interpreter found. Set SDWAN_TEST_PYTHON explicitly." >&2
  exit 1
fi

export PYTHONDONTWRITEBYTECODE=1
export PYTHONWARNINGS="${PYTHONWARNINGS:-error::ResourceWarning}"
export PYTHONPATH="$root"

"$python_bin" -m unittest discover \
  -s "$root/sdwan/tests" \
  -p 'test_*_v5.py' \
  -v

# Compile into a temporary cache so validation does not dirty the repository.
pycache_root=$(mktemp -d)
trap 'rm -rf "$pycache_root"' EXIT
PYTHONPYCACHEPREFIX="$pycache_root" "$python_bin" -m compileall -q "$root/sdwan"

"$python_bin" - "$root" <<'PYTHON'
from pathlib import Path
import ast
import sys
import yaml

root = Path(sys.argv[1])
package = root / "sdwan"
python_files = sorted(package.rglob("*.py"))
for path in python_files:
    ast.parse(
        path.read_text(encoding="utf-8"),
        filename=str(path),
        feature_version=(3, 8),
    )
print(f"validated Python 3.8 syntax for {len(python_files)} files")

files = sorted((package / "config").glob("*.yaml"))
for path in files:
    with path.open("r", encoding="utf-8") as stream:
        yaml.safe_load(stream)
print(f"validated {len(files)} YAML configuration files")
PYTHON

while IFS= read -r script; do
  bash -n "$script"
done < <(find "$root/sdwan" -type f -name '*.sh' -print | sort)

"$python_bin" -m sdwan.topology_v5 \
  --config "$root/sdwan/config/topology.core.yaml" \
  --validate-config
"$python_bin" -m sdwan.topology_v5 \
  --config "$root/sdwan/config/topology.cloud.yaml" \
  --validate-config

manifest="$root/sdwan/preservation/sdwan_v4.sha256"
if [[ -f "$manifest" ]]; then
  missing=0
  while IFS= read -r path; do
    if [[ ! -e "$path" ]]; then
      missing=1
      break
    fi
  done < <(sed -E 's/^[0-9a-fA-F]+  //' "$manifest")
  if [[ $missing -eq 0 ]]; then
    sha256sum -c "$manifest"
  else
    echo "SKIP: preserved v4 files are not mounted at the absolute paths recorded in $manifest"
  fi
fi
