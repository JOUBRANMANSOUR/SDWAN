"""Canonical, intent-oriented Management write routes.

No endpoint in this module accepts a shell command or writes Edge/Ryu/Linux
forwarding state.  Dynamic-site provisioning is one orchestration request.
"""
from __future__ import annotations
from typing import Any, Callable, Dict, Literal, Optional
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from ..dynamic_control import InventoryError
from .auth import Principal
from .service import ManagementService

class SiteCreateRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    site_id: str = Field(min_length=1, max_length=32, alias="site")
    role: Literal["spoke"] = "spoke"
    device_id: Optional[str] = Field(default=None, max_length=128)
    preferred_hub: str = "hub1"
    standby_hub: str = "hub2"

class IntentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intent_id: str = Field(min_length=1, max_length=128)
    intent_type: str
    target: str = Field(min_length=1, max_length=128)
    contents: Dict[str, Any] = Field(default_factory=dict)

def _error(error: InventoryError) -> HTTPException:
    return HTTPException(404 if str(error) == "unknown site" else 409, detail=str(error))

def install_management_write_routes(app: FastAPI, service: ManagementService, require: Callable[[str], Callable[..., Principal]]) -> None:
    @app.post("/api/v1/sites", status_code=202)
    def create_site(value: SiteCreateRequest, user: Principal = Depends(require("site:write"))):
        try:
            return service.create_site(site=value.site_id, device_id=value.device_id or f"{value.site_id}-edge", preferred_hub=value.preferred_hub, standby_hub=value.standby_hub, actor=user.subject)
        except InventoryError as exc:
            raise _error(exc) from exc

    @app.delete("/api/v1/sites/{site}", status_code=202)
    def delete_site(site: str, user: Principal = Depends(require("site:write"))):
        try:
            return service.delete_site(site, actor=user.subject)
        except InventoryError as exc:
            raise _error(exc) from exc

    @app.get("/api/v1/operations/{operation_id}")
    def operation(operation_id: str, user: Principal = Depends(require("site:read"))):
        value = service.operation(operation_id)
        if value is None:
            raise HTTPException(404, "operation not found")
        return value

    @app.get("/api/v1/intents")
    def intents(user: Principal = Depends(require("policy:read"))):
        return {"items": service.administrative_intents()}

    @app.post("/api/v1/intents", status_code=202)
    @app.put("/api/v1/intents/{intent_id}", status_code=202)
    def upsert_intent(value: IntentRequest, intent_id: Optional[str] = None, user: Principal = Depends(require("policy:write"))):
        if intent_id is not None and intent_id != value.intent_id:
            raise HTTPException(422, "intent_id path and body must match")
        try:
            return service.upsert_intent(intent_id=value.intent_id, intent_type=value.intent_type, target=value.target, contents=value.contents, actor=user.subject)
        except InventoryError as exc:
            raise HTTPException(422, detail=str(exc)) from exc

    @app.delete("/api/v1/intents/{intent_id}", status_code=202)
    def delete_intent(intent_id: str, user: Principal = Depends(require("policy:write"))):
        if not service.delete_intent(intent_id, actor=user.subject):
            raise HTTPException(404, "intent not found")
        return {"intent_id": intent_id, "status": "DELETED"}
