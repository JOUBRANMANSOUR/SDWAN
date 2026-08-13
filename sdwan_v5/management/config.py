"""Configuration for the read-only web management plane."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import os
@dataclass(frozen=True)
class ManagementConfig:
    topology: Path; policy_db: Path; ztp_db: Path; state_dir: Path; signing_secret: str; users: str; agent_command: str = ""
    project_root: Path = Path("/mnt/data/sdwan-lab/sdwan_v5"); ollama_executable: str = "/usr/local/bin/ollama"; ollama_model: str = "gpt-oss:20b-cloud"; claude_home: str = "/home/joubran"; agent_path: str = "/home/joubran/.local/bin:/usr/local/bin:/usr/bin:/bin"; claude_timeout_seconds: int = 120; claude_max_output_bytes: int = 262144; mcp_config: Path = Path("/mnt/data/sdwan-lab/sdwan_v5/config/mcp.sdwan.json"); claude_settings: Path = Path("/mnt/data/sdwan-lab/sdwan_v5/config/claude.sdwan.settings.json"); agent_context_audience: str = "sdwan-mcp-stdio"; agent_context_ttl_seconds: int = 120; ztp_url: str = "https://ztp:8443"; policy_url: str = "https://policy:8080"; management_connect_host: str = "172.30.0.254"

    @property
    def topology_control_socket(self) -> Path:
        return Path(os.environ.get("SDWAN_TOPOLOGY_CONTROL_SOCKET", str(self.state_dir / "topology-control.sock")))

    @classmethod
    def from_env(cls):
        project = Path(os.environ.get("SDWAN_PROJECT_ROOT", "/mnt/data/sdwan-lab/sdwan_v5")); root = Path(os.environ.get("SDWAN_STATE_ROOT", "/mnt/data/sdwan-state"))
        return cls(Path(os.environ.get("SDWAN_TOPOLOGY_CONFIG", str(project / "config/topology.yaml"))), Path(os.environ.get("SDWAN_POLICY_DB", str(root / "policy/policy.db"))), Path(os.environ.get("SDWAN_ZTP_DB", str(root / "ztp/ztp.db"))), Path(os.environ.get("SDWAN_MANAGEMENT_STATE", str(root / "management"))), os.environ.get("SDWAN_MANAGEMENT_SECRET", ""), os.environ.get("SDWAN_MANAGEMENT_USERS", ""), project_root=project, ollama_executable=os.environ.get("OLLAMA_EXECUTABLE", "/usr/local/bin/ollama"), ollama_model=os.environ.get("OLLAMA_MODEL", "gpt-oss:20b-cloud"), claude_home=os.environ.get("AGENT_HOME", "/home/joubran"), agent_path=os.environ.get("AGENT_SUBPROCESS_PATH", "/home/joubran/.local/bin:/usr/local/bin:/usr/bin:/bin"), claude_timeout_seconds=int(os.environ.get("CLAUDE_TIMEOUT_SECONDS", "120")), claude_max_output_bytes=int(os.environ.get("CLAUDE_MAX_OUTPUT_BYTES", "262144")), mcp_config=Path(os.environ.get("SDWAN_MCP_CONFIG_PATH", str(project / "config/mcp.sdwan.json"))), claude_settings=Path(os.environ.get("CLAUDE_SETTINGS_PATH", str(project / "config/claude.sdwan.settings.json"))), agent_context_audience=os.environ.get("AGENT_CONTEXT_AUDIENCE", "sdwan-mcp-stdio"), agent_context_ttl_seconds=int(os.environ.get("AGENT_CONTEXT_TTL_SECONDS", "120")), ztp_url=os.environ.get("SDWAN_ZTP_URL", "https://ztp:8443"), policy_url=os.environ.get("SDWAN_POLICY_URL", "https://policy:8080"), management_connect_host=os.environ.get("SDWAN_MANAGEMENT_CONNECT_HOST", "172.30.0.254"))
