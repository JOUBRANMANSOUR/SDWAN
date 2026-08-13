# Test results and evidence status

## Executed safely on Ubuntu

| Phase | Exact command | Result |
|---|---|---|
| v4 preservation baseline | `sha256sum -c /mnt/data/sdwan-lab/sdwan_v5/preservation/sdwan_v4.sha256` | Passed: every manifest entry verified |
| Config/marks | `source ~/ryu-venv38/bin/activate; PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/mnt/data/sdwan-lab python -m unittest discover -s /mnt/data/sdwan-lab/sdwan_v5/tests -p test_config_v5.py -v` | Passed: 5 tests |
| Persistence/identity and topology lifecycle | same runner with `-p 'test_*_v5.py'` | Passed: 23 tests, including ZTP claims, CSR persistence, DB transactions, ownership, failover, policy intent, optional-cloud planning, and a fake-Containernet lifecycle test |
| Hub-first enrollment regression | `source ~/ryu-venv38/bin/activate; cd /mnt/data/sdwan-lab; python -m unittest discover -s sdwan_v5/tests -p 'test_*.py'` | Passed: 24 tests. Includes key registration, hub acknowledgements before spoke activation, six spoke interfaces, and initial ownership persistence. |
| Static gate | `bash /mnt/data/sdwan-lab/sdwan_v5/scripts/validate_static.sh` | Passed: 24 unit tests, v4 manifest, model/config validation, and the physical-topology plan |
| Local control-plane TLS | ZTP HTTPS health with pinned CA; Policy HTTPS health with administrator mTLS | Passed: both returned `{"status":"ok","schema_version":1}`. |
| Privileged physical underlay | `bash sdwan_v5/scripts/run_controller.sh`; `bash sdwan_v5/scripts/run_topology.sh`; `sh ovs-vsctl show` | Passed: Ryu loaded `SDWANV5UnderlayController`; all eight OpenFlow bridges reported `is_connected: true`. |
| Restart-safe and dataplane regression | `source ~/ryu-venv38/bin/activate; cd /mnt/data/sdwan-lab; PYTHONPATH=/mnt/data/sdwan-lab python -m unittest discover -s sdwan_v5/tests -p 'test_*.py'` | Passed: 28 tests. Covers kernel-state reapplication after restart, portable policy rules, Policy-to-Edge intent marks, NFQUEUE rules, direct SaaS route, hub return route and scoped NAT. |
| Privileged ZTP enrollment | `sudo -E env PATH="$PATH" PYTHONPATH="$PWD" "$VIRTUAL_ENV/bin/python" sdwan_v5/scripts/live_enroll.py` | Passed: hubs resumed/reconciled and all five spokes reached `VERIFIED` or idempotent `MATCHED` state. |
| Privileged WireGuard baseline | Containernet CLI `node1 wg show`; `node1 ip route show table 101/102/103` | Passed: six spoke interfaces had recent handshakes; all three policy tables contained their expected overlay routes. |
| Privileged physical smoke checks | Containernet CLI pings and SaaS health check | Passed: branch LAN, management bridge, Data Center, Broadband underlay, and the SaaS Nginx health endpoint were reachable. |
| Failover, metadata-observability, and renderer regression | `source ~/ryu-venv38/bin/activate; PYTHONPATH=/mnt/data/sdwan-lab python -m unittest discover -s /mnt/data/sdwan-lab/sdwan_v5/tests -p 'test_*_v5.py'` | Passed: 34 tests. Covers Docker creation-time policy-routing sysctls, emergency overlay-only route replacement, metadata-only Unix-datagram collection, and configuration-derived Graphviz topology rendering including the optional Cloud VPC. |
| Privileged concurrent SaaS downloads | Containernet workload client with 1, 2, 3, and 10 clients plus the fixture SHA-256 | Passed: every one of 16 downloads returned `fbd83f4b3f1032919420f29c391bf5f519d502bcab74a9196314f53003226889`. This proves concurrent fixture integrity, not capacity performance. |
| Privileged local tunnel failover and recovery | Containernet: down `wg-h1-bb`, wait 8 seconds, inspect table-102 marked route and SaaS, restore it, then wait 30 seconds | Passed: table 102 moved from `wg-h1-bb` to `wg-h2-bb` after failure while direct SaaS stayed healthy; after recovery it selected `wg-h1-bb` again. Hub-ownership migration remains unverified. |
| Privileged nDPI metadata-only flow event | Containernet: HTTP/1.0 SaaS health request, 20-second wait, then `tail` the Edge JSONL | Passed: terminal `type:"flow"` event identified HTTP/Web at `198.18.0.10:80` over TCP with nDPI confidence `DPI`, `event_drops:0`, and no payload field. |
| Unprivileged topology visualization | `PYTHONPATH=$PWD python sdwan_v5/scripts/render_topology.py` | Passed: rendered `docs/topology-v5.dot` and `docs/topology-v5.svg` from the canonical physical topology plan. |
| Cloud/SaaS source regression | `source ~/ryu-venv38/bin/activate; cd /mnt/data/sdwan-lab; PYTHONPATH=$PWD python -m unittest discover -s sdwan_v5/tests -p 'test_*.py' -v` | Passed: 40 tests. Includes validated Trusted/Sensitive/Unknown destination policies, immutable SQLite activation/restart persistence, Cloud transit overlap rejection, and Cloud physical-plan isolation from spoke transports. This is not a Docker/Containernet proof. |
| Privileged destination-policy SaaS validation | Containernet: route lookup with mark `4097`; `wg show wg-h1-mpls`; Sensitive HTTPS `curl`; Unknown TCP and UDP `iperf3` | Passed: `198.18.0.20/32` selected `wg-h1-mpls` table `1101`, its peer contained both `.20/32` and `.30/32`, Sensitive API returned `{"service":"sensitive_saas","status":"ok"}`, Unknown TCP delivered 768 KiB at 1.24 Mbit/s receiver rate, and UDP delivered 640 KiB with 0/479 datagrams lost. |
| Privileged Cloud VPC primary-path validation | Containernet: branch ping/curl, marked route lookup, hub/gateway/app return lookups, and direct-NAT chain | Passed: `node1_host` reached `10.200.0.10` by ICMP and HTTP; node1 selected `wg-h1-mpls` table 1101; hub1 selected `cloud_gw1` over `172.20.1.0/30`; gateway and Cloud application had the intended branch return routes; `10.200.0.0/24` hit the direct-NAT `RETURN` rule, not `MASQUERADE`. Cloud failure convergence is pending a separate live injection. |
Live conntrack-affinity evidence, cloud, and capacity-performance gates remain pending. Those privileged Ubuntu gates must be executed with the evidence described in [UBUNTU_RUNBOOK.md](UBUNTU_RUNBOOK.md); they are not claimed as passed by static tests.

## Return-path affinity revision (static verification)

| Phase | Exact command | Result |
|---|---|---|
| Spoke/Hub/Cloud return-affinity implementation | `cd /mnt/data/sdwan_v5_extract; python3 -m pytest -q sdwan_v5/tests` | Passed: 43 tests, 1 skipped. Covers six spoke ingress/egress paths, hub connmark and DC SNAT, Cloud Gateway connmark/SNAT and tables 3101/3102, policy-rule priority ordering, and creation-time linkdown sysctls. |

This is static/unit evidence. The privileged Containernet acceptance gate remains pending until the new code is rebuilt, enrolled/reconciled, and the primary/backup captures in `RETURN_PATH_AFFINITY.md` are retained.
