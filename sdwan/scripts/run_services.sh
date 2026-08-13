#!/usr/bin/env bash
# Start/stop the local SD-WAN control plane as one bounded service group.
# It never starts Docker/Containernet and never removes system resources.
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
project="$root/sdwan"
state_root=${SDWAN_STATE_ROOT:-/mnt/data/sdwan-state}
topology_config=${SDWAN_TOPOLOGY_CONFIG:-"$project/config/topology.core.yaml"}
runtime_dir="$state_root/run"
log_dir="$state_root/logs"
command=${1:-start}
target=${2:-all}
valid_targets="controller ztp policy management all"
[[ " $valid_targets " == *" $target "* ]] || { echo "unknown service: $target" >&2; exit 2; }

if [[ -f "$project/.env" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$project/.env"
  set +a
fi
export SDWAN_STATE_ROOT="$state_root"
export SDWAN_TOPOLOGY_CONFIG="$topology_config"
export SDWAN_MANAGEMENT_STATE=${SDWAN_MANAGEMENT_STATE:-"$state_root/management"}

require_file() {
  [[ -f "$1" ]] || { echo "missing required file: $1" >&2; exit 1; }
}

prepare() {
  [[ -x "$HOME/ryu-venv38/bin/python" ]] || { echo "missing virtual environment: $HOME/ryu-venv38" >&2; exit 1; }
  require_file "$topology_config"
  if [[ ! -f "$state_root/trust/ca-cert.pem" || ! -f "$state_root/trust/ca-key.pem" ]]; then
    cat >&2 <<EOF
Trust material is not initialized under $state_root/trust.
Run once:
  source "$HOME/ryu-venv38/bin/activate"
  PYTHONPATH="$root" python "$project/scripts/initialize_trust.py" --state-root "$state_root"
EOF
    exit 1
  fi
  : "${SDWAN_MANAGEMENT_SECRET:?set SDWAN_MANAGEMENT_SECRET in $project/.env}"
  : "${SDWAN_MANAGEMENT_USERS:?set SDWAN_MANAGEMENT_USERS in $project/.env}"
  mkdir -p "$runtime_dir" "$log_dir" "$SDWAN_MANAGEMENT_STATE"
}

pid_file() { printf '%s/%s.pid\n' "$runtime_dir" "$1"; }
is_running() {
  local name=$1 file pid
  file=$(pid_file "$name")
  [[ -f "$file" ]] || return 1
  pid=$(<"$file")
  kill -0 "$pid" 2>/dev/null
}
start_one() {
  local name=$1 script=$2 file
  file=$(pid_file "$name")
  if is_running "$name"; then
    echo "$name: already running (pid $(<"$file"))"
    return
  fi
  rm -f "$file"
  nohup env \
    SDWAN_STATE_ROOT="$SDWAN_STATE_ROOT" \
    SDWAN_TOPOLOGY_CONFIG="$SDWAN_TOPOLOGY_CONFIG" \
    SDWAN_MANAGEMENT_STATE="$SDWAN_MANAGEMENT_STATE" \
    SDWAN_MANAGEMENT_SECRET="$SDWAN_MANAGEMENT_SECRET" \
    SDWAN_MANAGEMENT_USERS="$SDWAN_MANAGEMENT_USERS" \
    SDWAN_MANAGEMENT_HOST="${SDWAN_MANAGEMENT_HOST:-127.0.0.1}" \
    SDWAN_MANAGEMENT_PORT="${SDWAN_MANAGEMENT_PORT:-8090}" \
    bash "$script" >"$log_dir/$name.log" 2>&1 < /dev/null &
  echo $! >"$file"
  echo "$name: started (pid $(<"$file")); log: $log_dir/$name.log"
}
stop_one() {
  local name=$1 file pid
  file=$(pid_file "$name")
  if ! is_running "$name"; then
    rm -f "$file"
    echo "$name: not running"
    return
  fi
  pid=$(<"$file")
  kill "$pid"
  for _ in 1 2 3 4 5; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo "$name: did not exit after 5 seconds; leaving it untouched (pid $pid)" >&2
    return 1
  fi
  rm -f "$file"
  echo "$name: stopped"
}
status_one() {
  local name=$1 file
  file=$(pid_file "$name")
  if is_running "$name"; then
    echo "$name: running (pid $(<"$file"))"
  else
    echo "$name: stopped"
  fi
}

case "$command" in
  start)
    prepare
    # Ryu first: topology requires its OpenFlow listener. Policy/ZTP precede
    # Management because a dynamic-site request invokes both automatically.
    if [[ "$target" == "all" || "$target" == "controller" ]]; then start_one controller "$project/scripts/run_controller.sh"; fi
    if [[ "$target" == "all" || "$target" == "ztp" ]]; then start_one ztp "$project/scripts/run_ztp_service.sh"; fi
    if [[ "$target" == "all" || "$target" == "policy" ]]; then start_one policy "$project/scripts/run_policy_service.sh"; fi
    if [[ "$target" == "all" || "$target" == "management" ]]; then start_one management "$project/scripts/run_management.sh"; fi
    echo "Control plane start requested. Check: $0 status; API: http://${SDWAN_MANAGEMENT_HOST:-127.0.0.1}:${SDWAN_MANAGEMENT_PORT:-8090}/docs"
    ;;
  stop)
    if [[ "$target" == "all" || "$target" == "management" ]]; then stop_one management || true; fi
    if [[ "$target" == "all" || "$target" == "policy" ]]; then stop_one policy || true; fi
    if [[ "$target" == "all" || "$target" == "ztp" ]]; then stop_one ztp || true; fi
    if [[ "$target" == "all" || "$target" == "controller" ]]; then stop_one controller || true; fi
    ;;
  restart)
    "$0" stop "$target"
    "$0" start "$target"
    ;;
  status)
    if [[ "$target" == "all" || "$target" == "controller" ]]; then status_one controller; fi
    if [[ "$target" == "all" || "$target" == "ztp" ]]; then status_one ztp; fi
    if [[ "$target" == "all" || "$target" == "policy" ]]; then status_one policy; fi
    if [[ "$target" == "all" || "$target" == "management" ]]; then status_one management; fi
    ;;
  logs)
    name=${2:-management}
    case "$name" in controller|ztp|policy|management) ;; *) echo "usage: $0 logs {controller|ztp|policy|management}" >&2; exit 2;; esac
    exec tail -n "${SDWAN_LOG_LINES:-80}" -f "$log_dir/$name.log"
    ;;
  *)
    echo "usage: $0 {start|stop|restart|status} [controller|ztp|policy|management|all] | $0 logs [controller|ztp|policy|management]" >&2
    exit 2
    ;;
esac
