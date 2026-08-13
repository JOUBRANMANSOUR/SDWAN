from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

class SiteInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    site: str = Field(min_length=1, max_length=64)

class HubInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hub: str = Field(min_length=1, max_length=64)

class RouteDecisionInput(SiteInput):
    destination: IPvAnyAddress
    source: Optional[IPvAnyAddress] = None
    fwmark: Optional[int] = Field(default=None, ge=0)
