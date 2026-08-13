# Testing strategy

The test suite separates deterministic non-privileged validation from privileged live acceptance.

## Non-privileged

```bash
bash sdwan_v5/scripts/validate_static.sh
```

Coverage includes configuration, destination policy, desired state, route resolution, measurement windows, SLA scoring, hysteresis, fail-closed rules, topology plans, workloads, management REST, persistence, ZTP, and controller behavior.

## Privileged live acceptance

Run only on the Ubuntu Containernet host. Validate:

1. normal workload path selection;
2. MPLS degradation while link remains up;
3. node1 Broadband access-link congestion and new-flow behavior;
4. hub1 data-plane failure;
5. Broadband link failure.

Retain path state, iptables/rules/routes, conntrack, WireGuard counters, workload output, and packet captures. Static tests do not substitute for this evidence.
