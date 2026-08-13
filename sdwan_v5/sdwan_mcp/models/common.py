"""Typed evidence contracts shared by local stdio MCP tools and FastAPI."""
from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

class StateKind(str, Enum):
    configured = "configured"
    desired = "desired"
    applied = "applied"
    observed = "observed"
    derived = "derived"

class UnknownField(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str
    reason: str

class EvidenceSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str
    source_type: str
    description: str
    observed_at: Optional[datetime] = None

class OperationalFact(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fact_id: str
    fact_kind: str
    state_kind: StateKind
    value: Any
    source_ids: List[str] = Field(min_length=1)
    observed_at: Optional[datetime] = None

class OperationalResultMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"
    request_id: str
    available: bool
    observed_at: Optional[datetime] = None
    freshness_seconds: Optional[float] = Field(default=None, ge=0)
    stale: bool = False
    source_kind: str
    sources: List[EvidenceSource]
    unknowns: List[UnknownField] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

class OperationalResult(BaseModel):
    """Stable structured MCP result. Payload values are duplicated as facts."""
    model_config = ConfigDict(extra="forbid")
    meta: OperationalResultMeta
    facts: List[OperationalFact] = Field(default_factory=list, max_length=512)
    payload: Dict[str, Any] = Field(default_factory=dict)
    truncated: bool = False
    returned_count: Optional[int] = Field(default=None, ge=0)
    total_count: Optional[int] = Field(default=None, ge=0)
    next_cursor: Optional[str] = Field(default=None, max_length=256)

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def result_from_payload(tool: str, payload: Dict[str, Any], source_type: str, state_kind: StateKind, *, available: bool = True, limitations: Optional[List[str]] = None, warnings: Optional[List[str]] = None, unknowns: Optional[List[UnknownField]] = None, request_id: Optional[str] = None) -> OperationalResult:
    request_id = request_id or uuid4().hex
    observed_at = utcnow() if source_type in {"runtime_command", "linux_namespace", "wireguard", "routing_table", "audit_log"} else None
    source = EvidenceSource(source_id="{}:source".format(request_id), source_type=source_type, description="{} result".format(tool), observed_at=observed_at)
    facts: List[OperationalFact] = []
    for index, (field, value) in enumerate(payload.items()):
        if field in {"meta", "facts"}:
            continue
        facts.append(OperationalFact(fact_id="{}:fact:{:03d}".format(request_id, index), fact_kind=field, state_kind=state_kind, value=value, source_ids=[source.source_id], observed_at=observed_at))
    return OperationalResult(meta=OperationalResultMeta(request_id=request_id, available=available, observed_at=observed_at, freshness_seconds=0.0 if observed_at else None, stale=False, source_kind=source_type, sources=[source], unknowns=unknowns or [], limitations=limitations or [], warnings=warnings or []), facts=facts, payload=payload, returned_count=len(facts), total_count=len(facts))
