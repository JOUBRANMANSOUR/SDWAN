"""Small local-token RBAC implementation for the laboratory UI/API."""
from __future__ import annotations

import base64, hashlib, hmac, json, time
from dataclasses import dataclass
from typing import Iterable

ROLES = {"VIEWER", "NETWORK_ADMIN", "AUDITOR", "PLATFORM_ADMIN"}
ROLE_SCOPES = {
    "VIEWER": {"read:topology", "read:operations", "read:health"},
    "NETWORK_ADMIN": {"read:topology", "read:operations", "read:health", "read:routes", "read:tunnels", "read:events"},
    "AUDITOR": {"read:topology", "read:operations", "read:health", "read:audit", "read:events"},
    "PLATFORM_ADMIN": {"read:*", "chat:use"},
}

@dataclass(frozen=True)
class Principal:
    subject: str
    role: str
    scopes: tuple[str, ...]

def parse_users(value: str) -> dict[str, tuple[str, str]]:
    """`user:password:ROLE,user2:password:ROLE`; suitable only for local labs."""
    users = {}
    for item in filter(None, value.split(",")):
        parts = item.split(":")
        if len(parts) != 3 or parts[2] not in ROLES:
            raise ValueError("SDWAN_MANAGEMENT_USERS must use user:password:ROLE")
        users[parts[0]] = (parts[1], parts[2])
    return users

def scopes_for(role: str) -> tuple[str, ...]:
    return tuple(sorted(ROLE_SCOPES[role]))

def issue(secret: str, principal: Principal, lifetime_s: int = 3600) -> str:
    if not secret:
        raise ValueError("SDWAN_MANAGEMENT_SECRET is required")
    payload = {"sub": principal.subject, "role": principal.role, "scopes": principal.scopes, "exp": int(time.time()) + lifetime_s}
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=")
    sig = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest().encode()
    return raw.decode() + "." + sig.decode()

def verify(secret: str, token: str) -> Principal:
    raw, signature = token.encode().split(b".", 1)
    expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest().encode()
    if not hmac.compare_digest(expected, signature): raise ValueError("invalid token")
    payload = json.loads(base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4)))
    if int(payload["exp"]) < time.time() or payload["role"] not in ROLES: raise ValueError("expired token")
    return Principal(str(payload["sub"]), str(payload["role"]), tuple(payload["scopes"]))

def allowed(principal: Principal, required: str) -> bool:
    return "read:*" in principal.scopes or required in principal.scopes
