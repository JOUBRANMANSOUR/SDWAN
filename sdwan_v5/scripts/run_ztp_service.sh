#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
state_root=${SDWAN_STATE_ROOT:-/mnt/data/sdwan-state}
source ~/ryu-venv38/bin/activate
PYTHONPATH="$root" exec python -m sdwan_v5.ztp_service_v5 \
  --database "$state_root/ztp/ztp.db" \
  --ca-certificate "$state_root/trust/ca-cert.pem" \
  --ca-signing-key "$state_root/trust/ca-key.pem" \
  --tls-certificate "$state_root/trust/ztp-cert.pem" \
  --tls-private-key "$state_root/trust/ztp-key.pem" \
  --client-ca "$state_root/trust/ca-cert.pem"
