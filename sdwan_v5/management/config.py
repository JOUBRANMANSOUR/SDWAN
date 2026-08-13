"""Management configuration; no fabric credentials are accepted here."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(frozen=True)
class ManagementConfig:
    topology: Path
    policy_db: Path
    ztp_db: Path
    state_dir: Path
    signing_secret: str
    users: str
    agent_command: str

    @classmethod
    def from_env(cls) -> "ManagementConfig":
        root = Path(os.environ.get("SDWAN_STATE_ROOT", "/mnt/data/sdwan-state"))
        return cls(
            topology=Path(os.environ.get("SDWAN_TOPOLOGY_CONFIG", "/mnt/data/sdwan-lab/sdwan_v5/config/topology.yaml")),
            policy_db=Path(os.environ.get("SDWAN_POLICY_DB", str(root / "policy/policy.db"))),
            ztp_db=Path(os.environ.get("SDWAN_ZTP_DB", str(root / "ztp/ztp.db"))),
            state_dir=Path(os.environ.get("SDWAN_MANAGEMENT_STATE", str(root / "management"))),
            signing_secret=os.environ.get("SDWAN_MANAGEMENT_SECRET", ""),
            users=os.environ.get("SDWAN_MANAGEMENT_USERS", ""),
            agent_command=os.environ.get("SDWAN_AGENT_COMMAND", ""),
        )
