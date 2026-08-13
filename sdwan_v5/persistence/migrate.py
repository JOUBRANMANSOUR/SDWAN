"""Initialize/check service-owned SQLite schemas without global installation."""
from __future__ import annotations

import argparse
from pathlib import Path

from .policy_store import PolicyStore
from .ztp_store import ZTPStore


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ztp-db", type=Path, required=True)
    parser.add_argument("--policy-db", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    ztp, policy = ZTPStore(args.ztp_db), PolicyStore(args.policy_db)
    try:
        ztp.integrity_check()
        policy.integrity_check()
        print(f"ztp schema={ztp.schema_version} policy schema={policy.schema_version}")
    finally:
        ztp.close()
        policy.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
