from __future__ import annotations
from enum import Enum
from typing import List, Optional, Literal
from pydantic import BaseModel, ConfigDict, Field

class AnswerType(str, Enum):
    conceptual = "conceptual"
    operational = "operational"
    mixed = "mixed"

class AnswerClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim_id: str = Field(min_length=1, max_length=128)
    claim_type: Literal["system_health", "topology", "endpoint", "endpoint_route", "flow_route", "transport", "site_status", "hub_status", "cloud_gateway", "data_center", "saas", "tunnel_status", "runtime_interfaces", "failover_status", "classifier_status", "routing_rule", "routing_table", "route", "next_hop", "output_interface", "selected_hub", "selected_transport", "route_ownership", "desired_state", "policy_version", "destination_policy", "device_enrollment", "state_comparison", "event", "limitation"]
    fact_ids: List[str] = Field(default_factory=list, max_length=64)
    explanation: Optional[str] = Field(default=None, max_length=1000)

class AgentAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer_type: AnswerType
    summary: str = Field(min_length=1, max_length=2000)
    claims: List[AnswerClaim] = Field(default_factory=list, max_length=64)
    unknowns: List[str] = Field(default_factory=list, max_length=64)
    limitations: List[str] = Field(default_factory=list, max_length=64)
