# Test results and evidence status

## Completed in the non-privileged validation environment

| Gate | Result |
|---|---|
| Python tests under `sdwan/tests` | 96 passed, 1 skipped |
| Strict resource handling | Passed with `ResourceWarning` promoted to an error |
| Python module compilation | Passed for all project Python sources |
| YAML loading | Passed for all 8 configuration files |
| Core topology-plan construction | Passed |
| Optional Cloud topology-plan construction | Passed |
| Linux interface-name validation | Passed for Core and Cloud profiles; every generated name is at most 15 characters |
| Shell syntax validation | Passed for all project shell scripts |
| Failure-injection helper tests | Passed; scenarios print commands only and include rollback pairs |
| FastAPI backup workload tests | Passed: upload, size limit, byte count, SHA-256, status lookup |
| Public SaaS workload tests | Passed: messages, upload/download, unsafe filename and size-limit rejection |
| RTP sender/receiver loopback smoke test | Passed: produced a valid Matroska file containing H.264 video at 640×360 |
| Path-selector tests | Passed: policy constraints, scoring, three bad samples, five recovery samples, hold-down, minimum improvement, stale data, fail-closed/best-effort |
| Return-affinity command-generation tests | Passed for spoke, hub, Data Center SNAT, and optional Cloud gateway rules |
| Management REST tests | Passed: path metrics/decisions/events/workloads, one public SaaS, disabled Cloud status |

The single skipped test imports the Ryu controller and must run in the controller-specific environment, normally `~/ryu-venv38` on the Ubuntu VM.

## Not yet proven by this environment

The following require execution on the Ubuntu Containernet host and retained evidence:

- OVS connection to Ryu and real OpenFlow forwarding.
- Docker/Containernet node and interface creation.
- WireGuard creation, handshakes, encryption, and counters.
- Live route, `ip rule`, iptables, conntrack, and return-path behavior inside namespaces.
- Live RTP switching and interruption measurement.
- Live backup and SaaS path choice under `tc` degradation and node1 access-link congestion.
- `hub1` and Broadband failure convergence timing.
- Optional Cloud-profile live forwarding and failover.

These remain **privileged acceptance gates**, not passed results.

## Reproduce static validation

From the repository root:

```bash
bash sdwan/scripts/validate_static.sh
```

To force a particular interpreter:

```bash
SDWAN_TEST_PYTHON="$HOME/containernet-venv38/bin/python" \
  bash sdwan/scripts/validate_static.sh
```

The validator runs unit tests with `ResourceWarning` treated as an error, compiles the Python tree into a temporary cache, parses all YAML files, checks every shell script with `bash -n`, and validates both Core and Cloud topology plans. The preserved-v4 hash gate runs only when the recorded v4 paths are mounted.
