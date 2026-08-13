"""Laboratory authentication and signed short-lived agent contexts."""
from __future__ import annotations
import time, uuid
from dataclasses import dataclass
from typing import Dict, Tuple
from itsdangerous import BadData, SignatureExpired, URLSafeTimedSerializer
ROLES = {"VIEWER", "NETWORK_OPERATOR", "ADMIN"}
ROLE_SCOPES = {
    "VIEWER": {
        "network:read", "site:read", "policy:read", "ztp:read", "mcp:read",
    },
    "NETWORK_OPERATOR": {
        "network:read", "network:operate", "site:read", "site:write", "policy:read", "policy:write", "ztp:read", "ztp:operate", "audit:read",
        "mcp:read", "mcp:operate",
    },
    "ADMIN": {
        "*",
    },
}
@dataclass(frozen=True)
class Principal:
    subject: str
    role: str
    scopes: Tuple[str, ...]
def parse_users(value: str) -> Dict[str, Tuple[str, str]]:
    users = {}
    for item in filter(None, value.split(",")):
        parts = item.split(":")
        if len(parts) != 3 or parts[2] not in ROLES: raise ValueError("SDWAN_MANAGEMENT_USERS must use user:password:ROLE")
        users[parts[0]] = (parts[1], parts[2])
    return users
def scopes_for(role: str) -> Tuple[str, ...]: return tuple(sorted(ROLE_SCOPES.get(role, set())))
def _serializer(secret: str, purpose: str) -> URLSafeTimedSerializer:
    if not secret: raise ValueError("SDWAN_MANAGEMENT_SECRET is required")
    return URLSafeTimedSerializer(secret_key=secret, salt="sdwan-v5-" + purpose)
def issue(secret: str, principal: Principal, lifetime_s: int = 3600) -> str:
    return _serializer(secret, "access").dumps({"sub": principal.subject, "role": principal.role, "scopes": list(principal.scopes), "exp": int(time.time()) + lifetime_s})
def verify(secret: str, token: str) -> Principal:
    try: payload = _serializer(secret, "access").loads(token)
    except (BadData, SignatureExpired) as exc: raise ValueError("invalid token") from exc
    if int(payload.get("exp", 0)) < time.time() or payload.get("role") not in ROLES: raise ValueError("expired token")
    scopes = tuple(str(x) for x in payload.get("scopes", []))
    if not set(scopes).issubset(ROLE_SCOPES.get(payload["role"], set())): raise ValueError("invalid scopes")
    return Principal(str(payload["sub"]), str(payload["role"]), scopes)
def issue_agent_context(secret: str, principal: Principal, session_id: str, audience: str, lifetime_s: int = 120) -> str:
    return _serializer(secret, "agent-context").dumps({"sub": principal.subject, "role": principal.role, "scopes": list(principal.scopes), "sid": str(session_id), "aud": audience, "iat": int(time.time()), "jti": str(uuid.uuid4())})
def verify_agent_context(secret: str, token: str, session_id: str, audience: str, max_age: int = 120) -> Principal:
    try: payload = _serializer(secret, "agent-context").loads(token, max_age=max_age)
    except (BadData, SignatureExpired) as exc: raise ValueError("invalid agent context") from exc
    if payload.get("aud") != audience or str(payload.get("sid")) != str(session_id): raise ValueError("agent context audience or session mismatch")
    principal = Principal(str(payload.get("sub", "")), str(payload.get("role", "")), tuple(str(x) for x in payload.get("scopes", [])))
    if not principal.subject or principal.role not in ROLES or not set(principal.scopes).issubset(ROLE_SCOPES.get(principal.role, set())): raise ValueError("invalid agent context")
    return principal
def allowed(principal: Principal, required: str) -> bool:
    return (
        principal.role == "ADMIN"
        or "*" in principal.scopes
        or required in principal.scopes
    )