# SD-WAN  research testbed

This project is a Containernet-based, dual-hub SD-WAN laboratory for testing application-aware path selection, local failover, secure ZTP, policy reconciliation, and return-path correctness.

## Active core profile

The default profile is `config/topology.core.yaml`:

- Five branch edges and hosts.
- Two active SD-WAN hubs.
- Three emulated transport services: MPLS-like, Broadband-like, and LTE-like.
- A private Data Center central-backup workload.
- One public collaboration SaaS workload reached by direct Internet breakout.
- A real RTP/H.264 branch-to-branch workload.
- Cloud VPC code retained but disabled.

The three application paths are intentionally different:

```text
RTP video       : branch -> hub overlay -> branch
Central backup  : branch -> hub overlay -> Data Center
Public SaaS     : branch -> direct Broadband/LTE -> SaaS
```

The lab models transport-service behavior with OpenFlow-programmed OVS provider L3 forwarding and Linux `tc`/`netem`; it does not implement a carrier MPLS control plane or an LTE mobile core.

## Path selection

The Edge runtime combines destination policy, application class, and live measurements. It measures RTT, RTT-variation jitter, sliding-window loss, and an estimate of available bandwidth derived from configured capacity minus interface utilization. Metrics are EWMA-smoothed.

Selection includes:

- Mandatory egress and transport constraints.
- Per-application SLA eligibility.
- Normalized application-specific scoring.
- Consecutive bad/good sample thresholds.
- Minimum score improvement.
- Hold-down.
- Class-specific fail-closed rules for new flows when no path is eligible.
- Existing TCP flow pinning through conntrack; RTP/UDP can be re-steered.

## Start here

Read:

- [Architecture](sdwan/ARCHITECTURE.md)
- [Ryu L3 underlay](sdwan/docs/ryu_l3_underlay.md)
- [Ubuntu runbook](sdwan/UBUNTU_RUNBOOK.md)
- [Live acceptance checklist](sdwan/LIVE_ACCEPTANCE_CHECKLIST.md)
- [Test results](sdwan/TEST_RESULTS.md)
- [Migration notes](sdwan/MIGRATION.md)
- [Return-path affinity](sdwan/RETURN_PATH_AFFINITY.md)

Run the complete non-privileged validation from the repository root:

```bash
bash sdwan/scripts/validate_static.sh
```

The script validates tests, resource closure, Python compilation, YAML, shell syntax, and both Core and optional Cloud topology plans.

Privileged Containernet acceptance tests must be run on the Ubuntu lab; static tests do not prove live namespace, WireGuard, OVS, `tc`, conntrack, or failover behavior.

## Two-terminal local launch

Use the core profile without Cloud VPC. In the first terminal, start all control
plane services together (Ryu, ZTP, Policy, and Management):

```bash
cd /mnt/data/sdwan-lab
bash sdwan/scripts/run_services.sh start
```

Check or stop the group with `status`, `logs management`, `stop`, or restart a single service without touching the topology:

```bash
bash sdwan/scripts/run_services.sh status
bash sdwan/scripts/run_services.sh logs policy
bash sdwan/scripts/run_services.sh restart management
bash sdwan/scripts/run_services.sh stop
```

In the second terminal, start the interactive Containernet topology:

```bash
source ~/containernet-venv38/bin/activate
cd /mnt/data/sdwan-lab
SDWAN_TOPOLOGY_CONFIG=$PWD/sdwan/config/topology.core.yaml \
  bash sdwan/scripts/run_topology.sh
```

The launcher loads `sdwan/.env` when present, but does not generate trust
material automatically. If this is a new state directory, initialize trust once
using the exact command printed by the launcher.
