from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from hmac import compare_digest
from typing import Any, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

from .config import (
    ACCESS_TOKEN_TTL_MINUTES,
    JWT_ALGORITHM,
    JWT_AUTH_ENABLED,
    JWT_SECRET,
)

PUBLIC_PATHS = {"/health", "/metrics"}

# ──────────────────────────────────────────────────────────────────────────────
# Rate limiting (pre-existing; unchanged)
# ──────────────────────────────────────────────────────────────────────────────
_REQUESTS: dict[str, deque[float]] = defaultdict(deque)


def _enabled(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def auth_enabled() -> bool:
    return _enabled("API_AUTH_ENABLED", False)


def rate_limit_enabled() -> bool:
    return _enabled("API_RATE_LIMIT_ENABLED", True)


def rate_limit_per_minute() -> int:
    return max(int(os.getenv("API_RATE_LIMIT_PER_MINUTE", "120")), 1)


def expected_api_key() -> str:
    return os.getenv("API_KEY", "")


def is_public_path(path: str) -> bool:
    return (
        path in PUBLIC_PATHS
        or path.startswith("/docs")
        or path.startswith("/openapi")
        or path.startswith("/auth")  # auth endpoints are self-guarding
    )


async def require_api_key(request: Request) -> None:
    if not auth_enabled() or is_public_path(request.url.path):
        return

    configured_key = expected_api_key()
    provided_key = request.headers.get("x-api-key") or ""
    if not configured_key or not compare_digest(provided_key, configured_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )


def enforce_rate_limit(request: Request) -> None:
    if not rate_limit_enabled() or is_public_path(request.url.path):
        return

    client_host = request.client.host if request.client else "unknown"
    now = time.monotonic()
    window_start = now - 60
    bucket = _REQUESTS[client_host]

    while bucket and bucket[0] < window_start:
        bucket.popleft()

    if len(bucket) >= rate_limit_per_minute():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )

    bucket.append(now)


def clear_rate_limit_state() -> None:
    _REQUESTS.clear()


# ──────────────────────────────────────────────────────────────────────────────
# Password hashing  (Phase 7A)
# ──────────────────────────────────────────────────────────────────────────────
# passlib[bcrypt] verifies both $2a$ (from pgcrypto) and $2b$ (from Python)
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_context.verify(plain, hashed)


def hash_password(plain: str) -> str:
    return _pwd_context.hash(plain)


# ──────────────────────────────────────────────────────────────────────────────
# JWT helpers  (Phase 7A)
# ──────────────────────────────────────────────────────────────────────────────

def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return int(value.timestamp())
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _sign_jwt_message(message: str) -> str:
    signature = hmac.new(JWT_SECRET.encode("utf-8"), message.encode("ascii"), hashlib.sha256).digest()
    return _b64url_encode(signature)


def create_access_token(data: dict[str, Any]) -> str:
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)
    payload["exp"] = expire
    payload["iat"] = datetime.now(timezone.utc)
    payload["type"] = "access"
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64url_encode(
        json.dumps(payload, default=_json_default, separators=(",", ":")).encode("utf-8")
    )
    message = f"{encoded_header}.{encoded_payload}"
    return f"{message}.{_sign_jwt_message(message)}"


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        encoded_header, encoded_payload, provided_signature = token.split(".")
        message = f"{encoded_header}.{encoded_payload}"
        expected_signature = _sign_jwt_message(message)
        if not compare_digest(provided_signature, expected_signature):
            raise ValueError("Invalid token signature")

        header = json.loads(_b64url_decode(encoded_header))
        if header.get("alg") != JWT_ALGORITHM or header.get("typ") != "JWT":
            raise ValueError("Invalid token header")

        payload = json.loads(_b64url_decode(encoded_payload))
        exp = payload.get("exp")
        if not isinstance(exp, (int, float)) or datetime.now(timezone.utc).timestamp() >= float(exp):
            raise ValueError("Token expired")

        if payload.get("type") != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        return payload
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError, binascii.Error) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from exc


# Optional Bearer extractor — does NOT raise if token is absent
_bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> Optional[dict[str, Any]]:
    """
    Returns the decoded JWT payload, or None when JWT auth is disabled.
    Raises 401 when JWT auth is enabled and the token is missing/invalid.
    """
    if not JWT_AUTH_ENABLED:
        return None

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return decode_access_token(credentials.credentials)


async def require_authenticated(
    current_user: Optional[dict[str, Any]] = Depends(get_current_user),
) -> Optional[dict[str, Any]]:
    """Use this on endpoints that need JWT when JWT_AUTH_ENABLED=true."""
    return current_user


async def require_soc_auth(
    request: Request,
    current_user: Optional[dict[str, Any]] = Depends(get_current_user),
) -> Optional[dict[str, Any]]:
    """
    Production SOC auth gate.

    JWT_AUTH_ENABLED=true:
      - require a valid Bearer JWT and return its claims.

    JWT_AUTH_ENABLED=false:
      - preserve the existing local/demo API-key behavior.
    """
    if JWT_AUTH_ENABLED:
        if current_user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer token required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return current_user

    await require_api_key(request)
    return current_user
