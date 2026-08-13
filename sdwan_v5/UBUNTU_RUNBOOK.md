# Ubuntu 24.04 runbook

Run from `/mnt/data/sdwan-lab`. Do not run VS Code or Codex as root. The only privileged phase is the actual live lab, where `sudo` is required for Containernet, OVS, namespaces, WireGuard, iptables/NFQUEUE, routes, conntrack and captures.

## Unprivileged preparation

```bash
cd /mnt/data/sdwan-lab
source ~/ryu-venv38/bin/activate
PYTHONPATH=$PWD python -m sdwan_v5.persistence.migrate \
  --ztp-db /mnt/data/sdwan-state/ztp/ztp.db \
  --policy-db /mnt/data/sdwan-state/policy/policy.db --check
PYTHONPATH=$PWD python sdwan_v5/scripts/initialize_trust.py --state-root /mnt/data/sdwan-state
bash sdwan_v5/scripts/validate_static.sh
```

## Topology visualization

Graphviz is already installed on this Ubuntu lab. This unprivileged renderer
uses the same `build_live_plan()` configuration-derived topology as the live
launcher; it does not create containers, OVS bridges, or network namespaces.

```bash
cd /mnt/data/sdwan-lab
source ~/ryu-venv38/bin/activate
PYTHONPATH=$PWD python sdwan_v5/scripts/render_topology.py
xdg-open sdwan_v5/docs/topology-v5.svg
```

The default SVG is a readable logical architecture view: one Edge-to-fabric
line represents that router's three physical MPLS/Broadband/LTE attachments.
Use `--detail physical` only when you need every individual interface link.

Build containers on Ubuntu, not Windows:

```bash
cd /mnt/data/sdwan-lab
bash sdwan_v5/scripts/build_images.sh
```

## Startup order

1. Generate/verify trust material and initialize the two SQLite schemas.
2. In terminal A: `bash sdwan_v5/scripts/run_controller.sh` (uses `~/ryu-venv38`).
3. In terminal B: `SDWAN_STATE_ROOT=/mnt/data/sdwan-state bash sdwan_v5/scripts/run_policy_service.sh` (uses `~/ryu-venv38`).
4. In terminal C: `SDWAN_STATE_ROOT=/mnt/data/sdwan-state bash sdwan_v5/scripts/run_ztp_service.sh` (uses `~/ryu-venv38`).
5. In terminal D: `bash sdwan_v5/scripts/build_images.sh` if not already built.
6. In terminal E: `bash sdwan_v5/scripts/run_topology.sh` (uses `~/containernet-venv38` and asks sudo only for the live topology).
7. Run the protected incremental enrollment orchestrator below. It stages the declarative inventory through the ZTP administrator API, creates one-time claims without printing their secrets, enrolls hub1 then hub2, reconciles the inter-hub desired state, and enrolls each spoke only after both hubs acknowledge its peer update. No edge command accepts `--site`.
8. Verify exact peers/AllowedIPs, six spoke interfaces, slot and hub rules, certificates, desired/applied digest, and ownership before workloads.

## Incremental live enrollment

This is a privileged lab mutation: it creates WireGuard interfaces, policy rules,
and scoped NAT inside the running edge containers. It does not delete v4 data.
First rebuild the edge image after any v5 source change, then restart the Policy
and ZTP service processes so they load the current code. Leave Ryu running.

```bash
# Exit the existing Containernet CLI first; this cleans its v5 containers.
# containernet> exit

cd /mnt/data/sdwan-lab
sudo bash sdwan_v5/scripts/build_images.sh
```

Start the Policy Service and ZTP Service again in separate terminals, then start
the topology in the Containernet environment. When its CLI is ready, launch the
orchestrator from a separate terminal using the Ryu/control-plane environment:

```bash
cd /mnt/data/sdwan-lab
source ~/ryu-venv38/bin/activate
sudo -E env PATH="$PATH" PYTHONPATH="$PWD" "$VIRTUAL_ENV/bin/python" \
  sdwan_v5/scripts/live_enroll.py
```

The script prints a JSON summary containing sites, phases, and safe state
labels only. It never prints claim secrets, CSRs, certificates, or private keys.
A successful baseline ends with each spoke `reconcile-spoke` state `VERIFIED`.

Immediately validate the installed state from the Containernet CLI:

```text
node1 wg show
node1 ip rule show
node1 ip route show table 101
node1 ip route show table 102
node1 ip route show table 103
hub1 wg show
hub2 wg show
```

`node1` must show exactly `wg-h1-mpls`, `wg-h1-bb`, `wg-h1-lte`,
`wg-h2-mpls`, `wg-h2-bb`, and `wg-h2-lte`. Do not treat the script summary as
proof of end-to-end forwarding: WireGuard handshakes, routing, classifier,
conntrack affinity, Data Center/SaaS paths, and failure tests remain separate
Ubuntu live gates.

### Local failover monitor

Each reconciled spoke starts `sdwan_v5.edge_failover_runtime` from its durable
identity volume. It probes all six established tunnels every two seconds and
only repoints corporate overlay routes after the configured hard-failure
threshold. Direct SaaS is intentionally left on its specific direct route.

```text
node1 pgrep -af edge_failover_runtime
node1 cat /var/lib/sdwan/state/failover-status.json
node1 tail -n 30 /var/lib/sdwan/state/failover.log
```

A tunnel-down test requires three failed probes (about six seconds), followed
by three successful probes, a 20-second hold-down, and the configured flow
-drain period before baseline failback. Never use this monitor as a per-packet
load balancer.
### Metadata-only classifier observability

After rebuilding the Edge image and rerunning enrollment, the collector must be
running before the native classifier. It accepts only local Unix-datagram JSON
and writes bounded, root-readable JSONL; it explicitly removes any future
`payload` or `packet` field. It does not inspect WireGuard-encrypted traffic
and does not control routing, hub selection, SLA, or egress.

```text
node1 pgrep -af 'sdwan-classifier-v5|classifier_event_collector'
node1 ls -l /run/sdwan/classifier-events.sock /var/lib/sdwan/state/classifier-events.jsonl
node1_host curl --http1.0 -fsS --connect-timeout 10 http://198.18.0.10/healthz
sh sleep 20
node1 tail -n 30 /var/lib/sdwan/state/classifier-events.jsonl
```
Record a terminal `type:"flow"` event only after confirming it contains
application/category, destination, timing, and counters—never traffic payload.
separate live acceptance gate from nDPI process startup.


Cloud VPC remains disabled in `config/topology.yaml`. Use the separate `config/topology.cloud.yaml` profile only after baseline passes; it leaves the default configuration unchanged:

```bash
SDWAN_TOPOLOGY_CONFIG=/mnt/data/sdwan-lab/sdwan_v5/config/topology.cloud.yaml \
  bash sdwan_v5/scripts/run_topology.sh
```

## Physical-topology smoke checks

`run_topology.sh` now creates the physical lab and starts Nginx on `dc_app` and
`saas_nginx`. It does not enroll devices or create WireGuard interfaces/routes.
Therefore `pingall` is not an acceptance test at this stage and cross-site
traffic is expected to fail until the ZTP and Policy/Edge-Agent phases finish.

Inside the Containernet CLI, after Ryu has connected the eight OpenFlow switches,
these are safe physical checks:

```text
node1_host ping -c 1 10.1.0.1
hub1 ping -c 1 10.100.0.10
node1 ping -c 1 192.168.20.254
saas_nginx curl --fail http://198.18.0.10/sdwan-v5-test-file.txt -o /dev/null
```

## Workloads and captures

After ZTP has enrolled hubs and spokes and the Edge Agent reports the intended
desired state, run each client count:

```text
node1_host python3 /opt/sdwan_v5/workloads/http_load.py http://198.18.0.10/sdwan-v5-test-file.txt --clients 1
node1_host python3 /opt/sdwan_v5/workloads/http_load.py http://198.18.0.10/sdwan-v5-test-file.txt --clients 2
node1_host python3 /opt/sdwan_v5/workloads/http_load.py http://198.18.0.10/sdwan-v5-test-file.txt --clients 3
node1_host python3 /opt/sdwan_v5/workloads/http_load.py http://198.18.0.10/sdwan-v5-test-file.txt --clients 10
node1 tcpdump -ni node1-lan host 198.18.0.10
node1 tcpdump -ni wg-h1-bb host 198.18.0.10
node1 tcpdump -ni wg-h2-bb host 198.18.0.10
hub1 tcpdump -ni hub1-inet host 198.18.0.10
```

Direct breakout must not appear on WireGuard; hub backhaul must appear first on its selected hub WireGuard interface. Capture TCP/UDP forward and return paths plus `conntrack -L -o extended` to validate affinity.

## Failure injection and acceptance evidence

Print exact CLI commands with `bash sdwan_v5/scripts/failure_injection.sh <scenario>`. Required scenarios are single tunnel, blocked WireGuard UDP, spoke isolation, hub1/hub2 process failure, one/all inter-hub failure, Policy outage, Ryu outage, classifier outage, and Broadband/LTE outage. Record detection/convergence/loss/RTT/jitter/throughput/retransmissions/CPU/memory/WireGuard counters/route marks/owner epoch before claiming a result.

`sudo`-only live gates remain pending until executed and evidence is retained. Windows or static Linux tests do not prove these gates.

## Shutdown and rollback

Stop workloads, captures, ZTP, Policy and Ryu; leave the Containernet CLI to call `net.stop()`. Remove only v5 containers, volumes, interfaces/tables and evidence. Do not reuse v5 keys, IPs, conntrack state, databases, claims, CA/certificates, leases or ownership epochs in v4. Verify v4’s manifest, then start v4 from its separate directory/scripts only after clearing v5 runtime state.

## Cloud VPC and destination-specific SaaS validation

Cloud VPC remains disabled in the default profile. The separate Cloud profile is bind-mounted read-only into Edge containers, so it is reversible and does not require editing the default configuration. Rebuild images only when source has changed, restart the Policy Service using the same profile, then start a fresh topology and enroll again:

```bash
cd /mnt/data/sdwan-lab
sudo bash sdwan_v5/scripts/build_images.sh
SDWAN_TOPOLOGY_CONFIG=$PWD/sdwan_v5/config/topology.cloud.yaml \
  SDWAN_STATE_ROOT=/mnt/data/sdwan-state bash sdwan_v5/scripts/run_policy_service.sh
SDWAN_TOPOLOGY_CONFIG=$PWD/sdwan_v5/config/topology.cloud.yaml \
  bash sdwan_v5/scripts/run_topology.sh
```

The physical launcher installs Cloud Gateway `CONNMARK`, tables 3101/3102, scoped Cloud `SNAT`, and `ignore_routes_with_linkdown=1`. Spoke and Hub return-affinity chains are installed during their normal Edge reconciliation. After enrollment, use these Containernet checks:

```text
node1_host ping -c 3 10.200.0.10
node1_host curl -fsS --connect-timeout 10 http://10.200.0.10/healthz
hub1 ip route get 10.200.0.10
hub2 ip route get 10.200.0.10
cloud_gw1 ip route get 10.1.0.10
cloud_app ip route get 10.1.0.10
node1 iptables -t nat -nvL SDWAN_V5_DIRECT_NAT
node1 iptables -t mangle -nvL SDWAN_V5_RPA_IN
hub1 iptables -t mangle -nvL SDWAN_V5_RPA_IN
hub1 iptables -t nat -nvL SDWAN_V5_HUB_NAT
cloud_gw1 iptables -t mangle -nvL SDWAN_V5_CLOUD_RPA_IN
cloud_gw1 iptables -t nat -nvL SDWAN_V5_CLOUD_SNAT
cloud_gw1 ip rule show
cloud_gw1 ip route show table 3101
cloud_gw1 ip route show table 3102
```

For branch-originated Cloud traffic, `cloud_app` is expected to observe the selected gateway address (`10.200.0.1` or `10.200.0.2`) as the source. This is the mechanism that forces the reply to the same gateway; the direct-breakout chain on the spoke must still return `10.200.0.0/24` and must not masquerade it.

Validate gateway failover with a **new** connection after each state change:

```text
# Primary hub1 -> cloud_gw1 path.
node1_host curl -fsS --connect-timeout 5 http://10.200.0.10/healthz
cloud_gw1 iptables -t nat -nvL SDWAN_V5_CLOUD_SNAT

# Remove only hub1's primary Cloud link. hub1 must select cloud_gw2.
hub1 ip link set h1-c1 down
hub1 ip route get 10.200.0.10
node1_host curl -fsS --connect-timeout 5 http://10.200.0.10/healthz
cloud_gw2 iptables -t nat -nvL SDWAN_V5_CLOUD_SNAT
cloud_gw2 conntrack -L -p tcp --dport 80 -o extended

# Roll back.
hub1 ip link set h1-c1 up
```

The expected backup request is SNATed to `10.200.0.2`; its reply returns to `cloud_gw2`, restores the hub1/cloud mark, and uses table 3101 through `c2-h1`. Capture `h1-c2`, `c2-h1`, and `cloud_gw2-vpc` to retain proof.

Validate Spoke/Hub/Data-Center affinity separately:

```text
node1_host curl -fsS --connect-timeout 5 http://10.100.0.10/healthz
node1 conntrack -L -p tcp --dport 80 -o extended
hub1 conntrack -L -p tcp --dport 80 -o extended
hub1 iptables -t nat -nvL SDWAN_V5_HUB_NAT
node1 ip rule show
hub1 ip rule show
```

For this baseline, `dc_app` sees `10.100.0.1` or `10.100.0.2` as the source. Do not claim seamless migration of an existing TCP connection between hubs or Cloud Gateways: `conntrack` state is not synchronized between containers. Test failover with new connections unless `conntrackd` and shared VIP ownership are implemented in a later phase.

Destination-specific SaaS checks (the self-signed laboratory certificate requires `--insecure` only in this lab):

```text
# Trusted download: direct BB/LTE is allowed, with hub fallback.
node1_host python3 /opt/sdwan_v5/workloads/http_load.py http://198.18.0.10/sdwan-v5-test-file.txt --clients 1
node1_host python3 /opt/sdwan_v5/workloads/http_load.py http://198.18.0.10/sdwan-v5-test-file.txt --clients 10

# Sensitive HTTPS API/upload: hub overlay only and fail closed.
node1_host curl --insecure -fsS https://198.18.0.20/api/status
node1_host sh -c 'printf sensitive | curl --insecure -fsS -X POST --data-binary @- https://198.18.0.20/upload'

# Unknown generic TCP/UDP: hub overlay only and fail closed.
node1_host iperf3 -c 198.18.0.30 -p 9000 -t 5
node1_host iperf3 -u -c 198.18.0.30 -p 9001 -t 5
```

Capture both directions at the branch, selected WireGuard link, hub Internet interface, and SaaS interface. Keep classifier JSONL as metadata-only evidence. UDP/443 is generic unknown UDP only; the lab makes no QUIC-classification claim.

### Cloud failure injection (pending privileged live validation)

With the Cloud option enabled and an active Cloud flow, record the route, WireGuard counters, service result, and capture. Bring down exactly one hub-to-gateway transit interface, wait for the configured control-plane reconciliation window, then repeat all checks. Restore the interface and repeat for the other gateway and preferred hub. Record loss/convergence timing; do not claim a result until return traffic and the original branch source are observed.
