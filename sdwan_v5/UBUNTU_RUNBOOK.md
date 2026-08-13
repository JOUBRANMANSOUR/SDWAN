# Ubuntu 24.04 runbook

Run from `/mnt/data/sdwan-lab`. VS Code/Codex should remain unprivileged. Containernet, OVS, namespaces, WireGuard, routes, `tc`, iptables, conntrack, and captures require `sudo` only during the live lab.

## 1. Clean and validate

```bash
cd /mnt/data/sdwan-lab
sudo mn -c
bash sdwan_v5/scripts/validate_static.sh
```

The validator checks unit tests with SQLite resource leaks treated as errors, Python compilation, all YAML files, all shell scripts, and both Core and optional Cloud topology plans.

Initialize trust and databases when starting from a new state root:

```bash
source ~/ryu-venv38/bin/activate
PYTHONPATH=$PWD python sdwan_v5/scripts/initialize_trust.py \
  --state-root /mnt/data/sdwan-state
PYTHONPATH=$PWD python -m sdwan_v5.persistence.migrate \
  --ztp-db /mnt/data/sdwan-state/ztp/ztp.db \
  --policy-db /mnt/data/sdwan-state/policy/policy.db --check
```

Build images after source or Dockerfile changes:

```bash
bash sdwan_v5/scripts/build_images.sh
```

## 2. Start the core profile

Use separate terminals.

Terminal A — Ryu:

```bash
cd /mnt/data/sdwan-lab
bash sdwan_v5/scripts/run_controller.sh
```

Terminal B — Policy Service:

```bash
cd /mnt/data/sdwan-lab
SDWAN_STATE_ROOT=/mnt/data/sdwan-state \
SDWAN_TOPOLOGY_CONFIG=$PWD/sdwan_v5/config/topology.core.yaml \
bash sdwan_v5/scripts/run_policy_service.sh
```

Terminal C — ZTP:

```bash
cd /mnt/data/sdwan-lab
SDWAN_STATE_ROOT=/mnt/data/sdwan-state \
bash sdwan_v5/scripts/run_ztp_service.sh
```

Terminal D — topology:

```bash
cd /mnt/data/sdwan-lab
SDWAN_TOPOLOGY_CONFIG=$PWD/sdwan_v5/config/topology.core.yaml \
bash sdwan_v5/scripts/run_topology.sh
```

Terminal E — enroll/reconcile after the topology is up:

```bash
cd /mnt/data/sdwan-lab
source ~/ryu-venv38/bin/activate
PYTHONPATH=$PWD python sdwan_v5/scripts/live_enroll.py \
  --state-root /mnt/data/sdwan-state \
  --inventory $PWD/sdwan_v5/config/site_inventory.yaml
```

The enrollment script resumes matching durable identities and reconciles desired state; it does not recreate certificates unnecessarily.

## 3. Optional management API

```bash
export SDWAN_MANAGEMENT_SECRET='replace-with-a-long-local-secret'
export SDWAN_MANAGEMENT_USERS='viewer:viewer-password:VIEWER,admin:admin-password:PLATFORM_ADMIN'
bash sdwan_v5/scripts/run_management.sh
```

Relevant read-only endpoints:

```text
GET /api/v1/paths
GET /api/v1/path-metrics
GET /api/v1/path-decisions
GET /api/v1/path-events
GET /api/v1/workloads
```

## 4. Physical smoke checks

Inside the Containernet CLI:

```text
node1_host ping -c 1 10.1.0.1
hub1 ping -c 1 10.100.0.10
dc_app curl -kfsS https://10.100.0.10:8443/healthz
public_saas curl -kfsS https://198.18.0.10/healthz
node1 ip rule show
node1 wg show
```

Cross-site acceptance is meaningful only after enrollment and reconciliation.

## 5. Workloads

### A. Real RTP/H.264 branch-to-branch

Start the receiver first:

```text
node2_host sh -c '/opt/sdwan_v5/workloads/rtp_receiver.sh /opt/sdwan_v5/workloads/rtp-video.sdp /tmp/received-video.mkv > /tmp/rtp-receiver.log 2>&1 &'
```

Start the sender:

```text
node1_host sh -c '/opt/sdwan_v5/workloads/rtp_sender.sh 10.2.0.10 5004 > /tmp/rtp-sender.log 2>&1 &'
```

Evidence:

```text
node1_host pgrep -af ffmpeg
node2_host pgrep -af ffmpeg
node2_host ls -lh /tmp/received-video.mkv
node2_host tail -n 30 /tmp/rtp-receiver.log
node1 tcpdump -ni any udp port 5004
```

Stop:

```text
node1_host pkill -f rtp_sender.sh; node1_host pkill -f ffmpeg
node2_host pkill -f rtp_receiver.sh; node2_host pkill -f ffmpeg
```

### B. Central backup

```text
node1_host python3 /opt/sdwan_v5/workloads/backup_client.py node1 --size-mib 64
```

The JSON result must include `sha256_verified: true`, byte count, job ID, elapsed time, and average throughput.

### C. Public SaaS interactive API

```text
node1_host python3 /opt/sdwan_v5/workloads/saas_client.py interactive --requests 30 --interval 0.2
```

### D. Public SaaS file transfer

Upload first, then download the same filename:

```text
node1_host python3 /opt/sdwan_v5/workloads/saas_client.py upload --file /tmp/saas-document.bin
node1_host python3 /opt/sdwan_v5/workloads/saas_client.py download --file /tmp/saas-document.bin
```

The client sets DSCP before `connect()`, so the TCP SYN and the connection use a consistent controlled class label.

## 6. Five demonstration scenarios

Print commands with:

```bash
bash sdwan_v5/scripts/failure_injection.sh <scenario>
```

Execute the printed commands inside the Containernet CLI.

### Scenario 1 — normal state

Expected initial behavior under the configured profiles:

- RTP normally prefers MPLS due to jitter/loss.
- Backup normally prefers Broadband due to available capacity.
- Public SaaS normally prefers Broadband and never appears on a WireGuard interface.

Inspect:

```text
node1 cat /var/lib/sdwan/state/path-decisions.json
node1 cat /var/lib/sdwan/state/path-metrics.json
node1 iptables -t mangle -nvL SDWAN_V5_MARK
```

### Scenario 2 — MPLS degradation while still up

```bash
bash sdwan_v5/scripts/failure_injection.sh degrade-node1-mpls
```

Wait for at least three bad measurement cycles plus processing time. RTP should move only after hysteresis, with an event such as `SLA_VIOLATION_JITTER` or `SLA_VIOLATION_LOSS`.

Rollback:

```bash
bash sdwan_v5/scripts/failure_injection.sh restore-node1-mpls
```

Recovery requires five good samples and hold-down before failback.

### Scenario 3 — node1 Broadband access-link congestion

```bash
bash sdwan_v5/scripts/failure_injection.sh congest-node1-bb
```

The printed command starts parallel `iperf3` flows from `node1_host` to the public SaaS endpoint. This is intentional: the available-bandwidth estimator is edge-local and reads counters from `node1-bb`, so traffic generated by another branch would not reduce node1's local estimate in the current topology.

Wait for several measurement cycles, then start a **new** backup or SaaS file-transfer connection. Existing TCP connections remain connmark-pinned and are not expected to migrate. Inspect:

```text
node1 ip -s link show node1-bb
node1 cat /var/lib/sdwan/state/path-metrics.json
node1 cat /var/lib/sdwan/state/path-decisions.json
node1_host cat /tmp/node1-bb-congestion.log
```

Stop the generator:

```bash
bash sdwan_v5/scripts/failure_injection.sh stop-congestion
```

### Scenario 4 — hub1 data-plane failure

```bash
bash sdwan_v5/scripts/failure_injection.sh hub1-down
```

The script disables hub1 transport-facing interfaces. Killing only the hub Edge Agent is not a valid data-plane failure because existing Linux/WireGuard forwarding can continue. New private flows should converge through hub2. Public SaaS should be unaffected.

Rollback:

```bash
bash sdwan_v5/scripts/failure_injection.sh hub1-up
```

### Scenario 5 — branch Broadband failure

```bash
bash sdwan_v5/scripts/failure_injection.sh broadband-down
```

Public SaaS should use LTE; private workloads should use another eligible overlay path. Roll back:

```bash
bash sdwan_v5/scripts/failure_injection.sh broadband-up
```

## 7. Evidence to retain

For every scenario retain:

- `path-metrics.json`, `path-decisions.json`, and `path-events.json`.
- workload client JSON and service logs.
- `ip rule`, relevant route tables, WireGuard counters, conntrack marks.
- packet captures on LAN, chosen WireGuard interface, and direct interface as appropriate.
- exact injection and rollback timestamps.

Do not claim one-way delay when only RTT is measured. Do not call the bandwidth estimate an exact capacity measurement.

## 8. Optional Cloud profile

Start Policy and topology with matching profiles:

```bash
SDWAN_STATE_ROOT=/mnt/data/sdwan-state \
SDWAN_TOPOLOGY_CONFIG=$PWD/sdwan_v5/config/topology.cloud.yaml \
SDWAN_DESTINATION_POLICY_CONFIG=$PWD/sdwan_v5/config/destination_policy.cloud.yaml \
bash sdwan_v5/scripts/run_policy_service.sh

SDWAN_TOPOLOGY_CONFIG=$PWD/sdwan_v5/config/topology.cloud.yaml \
bash sdwan_v5/scripts/run_topology.sh
```

This is an optional simulated Cloud VPC experiment. It is not part of the core workload acceptance and must not be mixed with core-profile results.
