# Privileged live acceptance checklist

This checklist is the boundary between statically verified code and claims that require the Ubuntu Containernet host. Run it from `/mnt/data/sdwan-lab` on branch `feature/sla-workload-testbed` after applying the completion patch.

Do not merge to `main` until the Core gates pass. The optional Cloud gates are separate and do not block the Core profile.

## Gate 0 — clean state and static validation

```bash
cd /mnt/data/sdwan-lab
git status --short
sudo mn -c
bash sdwan_v5/scripts/validate_static.sh
```

Expected ending:

```text
OK (skipped=1)
validated Python 3.8 syntax
validated 8 YAML configuration files
TopologyPlan(... cloud_nodes=())
TopologyPlan(... cloud_nodes=('cloud_gw1', 'cloud_gw2', 'cloud_app'))
```

The one skip is acceptable only when it says the Ryu controller test requires the controller virtual environment.

## Gate 1 — image build

```bash
cd /mnt/data/sdwan-lab
sudo docker build -f sdwan_v5/docker/Dockerfile.edge.v5 \
  -t containernet-sdwan-edge-v5:latest .
sudo docker build -f sdwan_v5/docker/Dockerfile.host.v5 \
  -t containernet-sdwan-host-v5:latest .
```

Retain the final 30 lines of both builds. The host image must include FFmpeg, FastAPI, Uvicorn, `iperf3`, and the workload files.

## Gate 2 — start the Core control plane

Use separate terminals.

### Terminal A — Ryu

```bash
cd /mnt/data/sdwan-lab
bash sdwan_v5/scripts/run_controller.sh
```

### Terminal B — ZTP

```bash
cd /mnt/data/sdwan-lab
SDWAN_STATE_ROOT=/mnt/data/sdwan-state \
  bash sdwan_v5/scripts/run_ztp_service.sh
```

### Terminal C — Policy Service

```bash
cd /mnt/data/sdwan-lab
SDWAN_STATE_ROOT=/mnt/data/sdwan-state \
SDWAN_TOPOLOGY_CONFIG=$PWD/sdwan_v5/config/topology.core.yaml \
SDWAN_DESTINATION_POLICY_CONFIG=$PWD/sdwan_v5/config/destination_policy.yaml \
  bash sdwan_v5/scripts/run_policy_service.sh
```

### Terminal D — Core topology

```bash
cd /mnt/data/sdwan-lab
SDWAN_TOPOLOGY_CONFIG=$PWD/sdwan_v5/config/topology.core.yaml \
  bash sdwan_v5/scripts/run_topology.sh
```

The topology must reach the Containernet prompt without `RTNETLINK`, interface-name, Docker, OVS, or workload-start errors.

At the Containernet prompt run:

```text
nodes
net
node1 ip -br link
hub1 ip -br link
node1_host ping -c 2 10.1.0.1
hub1 ping -c 2 10.100.0.10
node1_host curl -kfsS https://198.18.0.10/healthz
```

## Gate 3 — enroll and reconcile

From a fifth host terminal while the topology is running:

```bash
cd /mnt/data/sdwan-lab
source ~/containernet-venv38/bin/activate
sudo -E env PATH="$PATH" PYTHONPATH="$PWD" \
  "$VIRTUAL_ENV/bin/python" sdwan_v5/scripts/live_enroll.py \
  --state-root /mnt/data/sdwan-state \
  --inventory "$PWD/sdwan_v5/config/site_inventory.yaml"
```

Retain the complete output. It must not report a stale desired-state version, certificate mismatch, missing Cloud target in the Core profile, or failed hub acknowledgement.

Then at the Containernet prompt:

```text
node1 wg show
hub1 wg show
node1 ip rule show
node1 ip route show table 101
node1 ip route show table 102
node1 ip route show table 103
node1 iptables -t mangle -S SDWAN_V5_MARK
node1 iptables -t mangle -S SDWAN_V5_RPA_IN
hub1 iptables -t mangle -S SDWAN_V5_RPA_IN
hub1 iptables -t nat -S SDWAN_V5_HUB_NAT
```

## Gate 4 — workload health

At the Containernet prompt:

```text
dc_app curl -kfsS https://127.0.0.1:8443/healthz
public_saas curl -kfsS https://127.0.0.1/healthz
node1_host python3 /opt/sdwan_v5/workloads/backup_client.py node1 --size-mib 8
node1_host python3 /opt/sdwan_v5/workloads/saas_client.py interactive --requests 5 --interval 0.1
node1_host python3 /opt/sdwan_v5/workloads/saas_client.py upload --file /tmp/saas-document.bin
node1_host python3 /opt/sdwan_v5/workloads/saas_client.py download --file /tmp/saas-document.bin
```

Acceptance:

- Backup returns HTTP success and `sha256_verified: true`.
- SaaS interactive reports zero timeouts and zero HTTP failures.
- SaaS upload/download return HTTP success.

## Gate 5 — real RTP

At the Containernet prompt:

```text
node2_host sh -c '/opt/sdwan_v5/workloads/rtp_receiver.sh /opt/sdwan_v5/workloads/rtp-video.sdp /tmp/received-video.mkv >/tmp/rtp-receiver.log 2>&1 & echo $!'
node1_host sh -c '/opt/sdwan_v5/workloads/rtp_sender.sh 10.2.0.10 5004 >/tmp/rtp-sender.log 2>&1 & echo $!'
```

After 15 seconds:

```text
node1_host tail -30 /tmp/rtp-sender.log
node2_host tail -30 /tmp/rtp-receiver.log
node2_host ls -lh /tmp/received-video.mkv
node1 cat /var/lib/sdwan/state/path-decisions.json
```

Acceptance: the sender/receiver remain active, the output file grows, and the RTP decision selects a hub-overlay path.

## Gate 6 — MPLS degradation while still UP

From the host, print the injection command:

```bash
bash sdwan_v5/scripts/failure_injection.sh degrade-node1-mpls
```

Paste the printed commands into the Containernet prompt. Wait at least three measurement intervals plus processing time, then run:

```text
node1 ip link show node1-mpls
node1 tc -s qdisc show dev node1-mpls
node1 cat /var/lib/sdwan/state/path-decisions.json
node1 cat /var/lib/sdwan/state/path-events.json
```

Acceptance:

- `node1-mpls` remains UP.
- RTP stays on the original path for the first two bad samples.
- It changes only after the configured bad-sample threshold.
- The event reason is a concrete SLA reason such as `SLA_VIOLATION_JITTER` or `SLA_VIOLATION_LOSS`.

Restore:

```bash
bash sdwan_v5/scripts/failure_injection.sh restore-node1-mpls
```

Confirm that recovery waits for five good samples and hold-down.

## Gate 7 — node1 Broadband access-link congestion

Print and paste:

```bash
bash sdwan_v5/scripts/failure_injection.sh congest-node1-bb
```

The generator intentionally runs on `node1_host`, not `node3_host`, because the estimator reads node1-local interface counters.

After several intervals:

```text
node1 ip -s link show node1-bb
node1 cat /var/lib/sdwan/state/path-metrics.json
node1 cat /var/lib/sdwan/state/path-decisions.json
node1_host python3 /opt/sdwan_v5/workloads/backup_client.py node1 --size-mib 8
```

Acceptance: the measured estimate for node1 Broadband decreases. A new backup flow may select another eligible hub-overlay path; an already-established TCP transfer remains connmark-pinned.

Stop:

```bash
bash sdwan_v5/scripts/failure_injection.sh stop-congestion
```

## Gate 8 — hub1 data-plane failure

Print and paste:

```bash
bash sdwan_v5/scripts/failure_injection.sh hub1-down
```

Then create **new** private flows and inspect:

```text
node1_host ping -c 4 10.2.0.10
node1_host python3 /opt/sdwan_v5/workloads/backup_client.py node1 --size-mib 8
node1 cat /var/lib/sdwan/state/path-decisions.json
node1 cat /var/lib/sdwan/state/path-events.json
node1_host python3 /opt/sdwan_v5/workloads/saas_client.py interactive --requests 5
```

Acceptance: new private flows converge through hub2; direct SaaS remains available and is not switched because of the hub failure.

Restore:

```bash
bash sdwan_v5/scripts/failure_injection.sh hub1-up
```

## Gate 9 — node1 Broadband failure

Print and paste:

```bash
bash sdwan_v5/scripts/failure_injection.sh broadband-down
```

Inspect:

```text
node1 ip link show node1-bb
node1_host python3 /opt/sdwan_v5/workloads/saas_client.py interactive --requests 5
node1 cat /var/lib/sdwan/state/path-decisions.json
node1 cat /var/lib/sdwan/state/path-events.json
```

Acceptance: public SaaS uses LTE; private traffic uses another eligible overlay path.

Restore:

```bash
bash sdwan_v5/scripts/failure_injection.sh broadband-up
```

## Gate 10 — return-path evidence

Create a fresh backup connection, then inspect:

```text
node1 conntrack -L -p tcp --dport 8443 -o extended
node1 iptables -t mangle -nvL SDWAN_V5_RPA_IN
node1 iptables -t mangle -nvL SDWAN_V5_RPA_OUT
hub1 conntrack -L -p tcp --dport 8443 -o extended
hub1 iptables -t mangle -nvL SDWAN_V5_RPA_IN
hub1 iptables -t mangle -nvL SDWAN_V5_RPA_OUT
hub1 iptables -t nat -nvL SDWAN_V5_HUB_NAT
```

Acceptance: counters increase on the selected ingress/egress rules, conntrack carries the expected owned mark, and replies return through the same hub and transport for the connection.

## Optional Cloud gates

Run only after the Core profile passes. Start Policy and topology with both matching files:

```bash
SDWAN_TOPOLOGY_CONFIG=$PWD/sdwan_v5/config/topology.cloud.yaml \
SDWAN_DESTINATION_POLICY_CONFIG=$PWD/sdwan_v5/config/destination_policy.cloud.yaml \
SDWAN_STATE_ROOT=/mnt/data/sdwan-state \
  bash sdwan_v5/scripts/run_policy_service.sh

SDWAN_TOPOLOGY_CONFIG=$PWD/sdwan_v5/config/topology.cloud.yaml \
  bash sdwan_v5/scripts/run_topology.sh
```

Do not mix optional Cloud results with the Core workload results.

## Output bundle to send for review

Send these items after Gate 3 first, before running destructive scenarios:

1. The complete `validate_static.sh` ending.
2. The last 50 lines from Ryu, Policy, ZTP, and topology terminals.
3. Complete `live_enroll.py` output.
4. Output of `node1 wg show`, `node1 ip rule show`, and the four iptables chain listings from Gate 3.

After that baseline is verified, continue Gates 4–10 and send the JSON state files and workload outputs.
