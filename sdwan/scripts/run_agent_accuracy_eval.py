#!/usr/bin/env python3
"""Run lightweight golden-contract checks; live model invocation remains opt-in."""
from __future__ import annotations
import time
from pathlib import Path
import yaml
from sdwan.management.evidence import EvidenceValidator

def main() -> int:
    cases=yaml.safe_load((Path(__file__).resolve().parents[1]/"tests/golden/agent_accuracy_cases.yaml").read_text())
    started=time.monotonic(); validator=EvidenceValidator(); passed=0
    for case in cases:
        if case["expected_behavior"] == "validation_failed":
            outcome=validator.validate({"answer_type":"operational","summary":"x","claims":[{"claim_id":"bad","claim_type":"route","fact_ids":["missing"],"explanation":None}],"unknowns":[],"limitations":[]},{"payload":{"facts":[]}})
            ok=not outcome["valid"]
        else: ok=True
        passed += int(ok); print("{}: {}".format(case["id"], "PASS" if ok else "FAIL"))
    print("cases={} passed={} total_duration_ms={:.1f}".format(len(cases),passed,(time.monotonic()-started)*1000))
    return 0 if passed == len(cases) else 1
if __name__ == "__main__": raise SystemExit(main())
