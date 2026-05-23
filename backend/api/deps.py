"""
api/deps.py — Shared auth and rate-limiting dependencies.

Extracted here to break the circular import that occurred when
email_intel.py and search.py imported from api.main while main.py
was still being loaded, causing intermittent ImportError / 404 responses.
"""
from __future__ import annotations

import base64 as _base64
import hashlib as _hashlib
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt as _bcrypt
import jwt as pyjwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from slowapi import Limiter
from starlette.requests import Request

# ─── Rate limiter ─────────────────────────────────────────────────────────────

def _real_ip(request: Request) -> str:
    # Use X-Real-IP (set by Traefik to the actual client IP, not spoofable by the client).
    # Fall back to the rightmost X-Forwarded-For entry added by the trusted proxy,
    # then to the direct connection address.
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Rightmost entry is appended by the trusted Traefik proxy and cannot be spoofed.
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"

limiter = Limiter(
    key_func=_real_ip,
    storage_uri=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
    default_limits=["300/minute"],
)

# ─── JWT config ───────────────────────────────────────────────────────────────

SECRET_KEY       = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")
JWT_ALGORITHM    = "HS256"
JWT_EXPIRE_HOURS = 12

def create_jwt(user_id: str, tenant_id: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    return pyjwt.encode(
        {"sub": user_id, "tid": tenant_id, "role": role, "exp": exp},
        SECRET_KEY, algorithm=JWT_ALGORITHM,
    )

def decode_jwt(token: str) -> dict:
    return pyjwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])

# ─── Password hashing ─────────────────────────────────────────────────────────

def _prepare_pw(password: str) -> bytes:
    digest = _hashlib.sha256(password.encode("utf-8")).digest()
    return _base64.b64encode(digest)

def hash_pw(password: str) -> str:
    return _bcrypt.hashpw(_prepare_pw(password), _bcrypt.gensalt()).decode("utf-8")

def verify_pw(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(_prepare_pw(plain), hashed.encode("utf-8"))
    except Exception:
        return False

# ─── Auth context ─────────────────────────────────────────────────────────────

class AuthContext:
    def __init__(self, user_id: str, tenant_id: str, role: str):
        self.user_id   = user_id
        self.tenant_id = tenant_id
        self.role      = role

    def assert_own_tenant(self, tenant_id: str) -> None:
        if self.role in ("mssp_admin", "mssp_analyst"):
            return
        if self.tenant_id != tenant_id:
            raise HTTPException(status_code=403, detail="Zugriff verweigert.")

bearer = HTTPBearer(auto_error=False)

async def get_auth(
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
) -> AuthContext:
    if not cred:
        raise HTTPException(status_code=401, detail="Authentifizierung erforderlich.")
    try:
        payload = decode_jwt(cred.credentials)
        return AuthContext(payload["sub"], payload.get("tid", ""), payload["role"])
    except Exception:
        raise HTTPException(status_code=401, detail="Ungültiger oder abgelaufener Token.")
