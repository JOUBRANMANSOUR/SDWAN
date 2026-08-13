#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
docker build -f "$root/sdwan_v5/docker/Dockerfile.edge.v5" -t containernet-sdwan-edge-v5:latest "$root"
docker build -f "$root/sdwan_v5/docker/Dockerfile.host.v5" -t containernet-sdwan-host-v5:latest "$root"
