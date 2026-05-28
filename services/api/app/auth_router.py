"""
Phase 7A – Authentication router  (security-hardened)
======================================================
Endpoints
─────────
POST /auth/login           – email + password → access_token; refresh token in httpOnly cookie
POST /auth/refresh         – rotate refresh token (cookie) → new access_token + fresh cookie
POST /auth/logout          – revoke refresh token and clear cookie
GET  /auth/me              – current user from Bearer token
GET  /auth/ws-ticket       – short-lived single-use WebSocket upgrade ticket

Security hardening (Phase 7A):
  • Refresh token stored in httpOnly "soc_rt" cookie — not accessible from JS
  • token_prefix (first 16 chars) used for O(1) DB lookup before bcrypt verify
  • Per-account login lockout: 5 failures → 5 min lock, 10 failures → 1 h lock
  • Cookie takes priority over request body (backwards-compatible for mobile clients)
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .config import (
    ACCESS_TOKEN_TTL_MINUTES,
    COOKIE_NAME,
    COOKIE_SAMESITE,
    COOKIE_SECURE,
    REFRESH_TOKEN_TTL_DAYS,
    WS_TICKET_TTL_SECONDS,
)
from .db import get_conn
from .metrics import AUTH_LOGIN_TOTAL, AUTH_REFRESH_TOTAL
from .security import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# ──────────────────────────────────────────────────────────────────────────────
# Lockout thresholds
# ──────────────────────────────────────────────────────────────────────────────
_LOCKOUT_SOFT_ATTEMPTS = 5      # → 5-minute lock
_LOCKOUT_SOFT_MINUTES  = 5
_LOCKOUT_HARD_ATTEMPTS = 10     # → 60-minute lock
_LOCKOUT_HARD_MINUTES  = 60


# ──────────────────────────────────────────────────────────────────────────────
# Request schemas
# ──────────────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


class RefreshRequest(BaseModel):
    """Body is optional — cookie takes priority."""
    refresh_token: Optional[str] = None


class LogoutRequest(BaseModel):
    """Body is optional — cookie takes priority."""
    refresh_token: Optional[str] = None


# ──────────────────────────────────────────────────────────────────────────────
# Cookie helper
# ──────────────────────────────────────────────────────────────────────────────

def _set_refresh_cookie(response: Response, raw_token: str, expires_at: datetime) -> None:
    """Attach the httpOnly refresh-token cookie to *response*."""
    max_age = int((expires_at - datetime.now(timezone.utc)).total_seconds())
    response.set_cookie(
        key=COOKIE_NAME,
        value=raw_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,   # type: ignore[arg-type]
        max_age=max_age,
        path="/auth",               # restrict cookie to /auth/* only
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=COOKIE_NAME, path="/auth")


# ──────────────────────────────────────────────────────────────────────────────
# Internal DB helpers
# ──────────────────────────────────────────────────────────────────────────────

def _get_user_by_email(conn: Any, email: str) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT user_id, email, role, display_name, password_hash, is_active, "
            "       failed_attempts, locked_until "
            "FROM auth.users WHERE email = %s",
            (email,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {
        "user_id":         row[0],
        "email":           row[1],
        "role":            row[2],
        "display_name":    row[3],
        "password_hash":   row[4],
        "is_active":       row[5],
        "failed_attempts": row[6],
        "locked_until":    row[7],
    }


def _get_user_by_id(conn: Any, user_id: str) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT user_id, email, role, display_name, is_active "
            "FROM auth.users WHERE user_id = %s",
            (user_id,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {
        "user_id":      row[0],
        "email":        row[1],
        "role":         row[2],
        "display_name": row[3],
        "is_active":    row[4],
    }


def _record_failed_attempt(conn: Any, user_id: str, current_attempts: int) -> None:
    """Increment failed_attempts and apply lockout if thresholds are crossed."""
    new_attempts = current_attempts + 1
    locked_until: datetime | None = None

    if new_attempts >= _LOCKOUT_HARD_ATTEMPTS:
        locked_until = datetime.now(timezone.utc) + timedelta(minutes=_LOCKOUT_HARD_MINUTES)
    elif new_attempts >= _LOCKOUT_SOFT_ATTEMPTS:
        locked_until = datetime.now(timezone.utc) + timedelta(minutes=_LOCKOUT_SOFT_MINUTES)

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE auth.users SET failed_attempts = %s, locked_until = %s "
            "WHERE user_id = %s",
            (new_attempts, locked_until, user_id),
        )
    conn.commit()


def _reset_failed_attempts(conn: Any, user_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE auth.users SET failed_attempts = 0, locked_until = NULL "
            "WHERE user_id = %s",
            (user_id,),
        )
    conn.commit()


def _issue_refresh_token(conn: Any, user_id: str) -> tuple[str, datetime, str]:
    """
    Creates a refresh token, stores its bcrypt hash + first-16-char prefix in
    the DB, and returns the raw (unhashed) token string.

    The token_prefix enables an O(1) indexed pre-filter before the bcrypt verify,
    preventing a full table scan on every /auth/refresh call.
    """
    raw_token   = secrets.token_urlsafe(48)
    token_prefix = raw_token[:16]
    token_hash   = hash_password(raw_token)
    expires_at   = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_TTL_DAYS)

    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO auth.refresh_tokens (user_id, token_hash, token_prefix, expires_at) "
            "VALUES (%s, %s, %s, %s) RETURNING token_id",
            (user_id, token_hash, token_prefix, expires_at),
        )
        token_id = cur.fetchone()[0]
    conn.commit()
    return raw_token, expires_at, str(token_id)


def _verify_and_rotate_refresh_token(
    conn: Any, raw_token: str
) -> dict[str, Any] | None:
    """
    Fast-path lookup:
      1. Filter by token_prefix (first 16 chars) — hits the partial index, O(1)
      2. bcrypt-verify the single matching row
      3. Revoke it so the next /auth/refresh gets a fresh token (rotation)

    Returns the user dict on success, None on failure.
    """
    prefix = raw_token[:16]

    with conn.cursor() as cur:
        cur.execute(
            "SELECT token_id, user_id, token_hash "
            "FROM auth.refresh_tokens "
            "WHERE token_prefix = %s "
            "  AND expires_at > now() "
            "  AND revoked_at IS NULL "
            "LIMIT 5",                      # prefix collision is astronomically rare
            (prefix,),
        )
        rows = cur.fetchall()

    matched_row: tuple | None = None
    for row in rows:
        if verify_password(raw_token, row[2]):
            matched_row = row
            break

    if not matched_row:
        return None

    token_id, user_id = matched_row[0], matched_row[1]

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE auth.refresh_tokens SET revoked_at = now() WHERE token_id = %s",
            (token_id,),
        )
    conn.commit()

    user = _get_user_by_id(conn, user_id)
    if user:
        user["refresh_token_id"] = str(token_id)
    return user


def _revoke_refresh_token(conn: Any, raw_token: str) -> bool:
    """Revoke a single refresh token using the prefix fast-path."""
    prefix = raw_token[:16]

    with conn.cursor() as cur:
        cur.execute(
            "SELECT token_id, token_hash FROM auth.refresh_tokens "
            "WHERE token_prefix = %s "
            "  AND expires_at > now() "
            "  AND revoked_at IS NULL "
            "LIMIT 5",
            (prefix,),
        )
        rows = cur.fetchall()

    for token_id, token_hash in rows:
        if verify_password(raw_token, token_hash):
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE auth.refresh_tokens SET revoked_at = now() WHERE token_id = %s",
                    (token_id,),
                )
            conn.commit()
            return True
    return False


def _resolve_refresh_token(cookie_token: str | None, body_token: str | None) -> str | None:
    """Cookie takes priority; body is accepted as fallback (e.g. mobile clients)."""
    return cookie_token or body_token


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/login")
def login(body: LoginRequest, response: Response) -> JSONResponse:
    with get_conn() as conn:
        user = _get_user_by_email(conn, body.email)

        # Constant-time-ish path: always fail with the same message regardless
        # of whether the email exists, to prevent user enumeration.
        if not user or not user["is_active"]:
            AUTH_LOGIN_TOTAL.labels("failure").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        # ── Lockout check ──────────────────────────────────────────────────
        locked_until = user.get("locked_until")
        if locked_until is not None:
            now = datetime.now(timezone.utc)
            # locked_until may be naive (no tzinfo) from psycopg2 — normalise it
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            if now < locked_until:
                retry_after = int((locked_until - now).total_seconds())
                AUTH_LOGIN_TOTAL.labels("locked").inc()
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Account temporarily locked. Retry after {retry_after} seconds.",
                    headers={"Retry-After": str(retry_after)},
                )

        # ── Password verify ────────────────────────────────────────────────
        if not verify_password(body.password, user["password_hash"]):
            _record_failed_attempt(conn, user["user_id"], user["failed_attempts"])
            AUTH_LOGIN_TOTAL.labels("failure").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        # ── Success: reset lockout counter ─────────────────────────────────
        _reset_failed_attempts(conn, user["user_id"])

        access_token = create_access_token({
            "sub":          user["user_id"],
            "email":        user["email"],
            "role":         user["role"],
            "display_name": user["display_name"],
        })
        access_expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)
        raw_refresh, expires_at, _refresh_token_id = _issue_refresh_token(conn, user["user_id"])

    AUTH_LOGIN_TOTAL.labels("success").inc()
    resp = JSONResponse({
        "access_token":      access_token,
        "token_type":        "bearer",
        "access_expires_at": access_expires_at.isoformat(),
        "refresh_expires_at": expires_at.isoformat(),
        "user": {
            "user_id":      user["user_id"],
            "email":        user["email"],
            "role":         user["role"],
            "display_name": user["display_name"],
        },
    })
    _set_refresh_cookie(resp, raw_refresh, expires_at)
    return resp


@router.post("/refresh")
def refresh(
    response: Response,
    body: RefreshRequest = RefreshRequest(),
    soc_rt: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
) -> JSONResponse:
    raw_token = _resolve_refresh_token(soc_rt, body.refresh_token)
    if not raw_token:
        AUTH_REFRESH_TOTAL.labels("failure").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided",
        )

    with get_conn() as conn:
        user = _verify_and_rotate_refresh_token(conn, raw_token)
        if not user or not user.get("is_active"):
            _clear_refresh_cookie(response)
            AUTH_REFRESH_TOTAL.labels("failure").inc()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )

        access_token = create_access_token({
            "sub":          user["user_id"],
            "email":        user["email"],
            "role":         user["role"],
            "display_name": user["display_name"],
        })
        access_expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)
        new_refresh, expires_at, new_refresh_id = _issue_refresh_token(conn, user["user_id"])
        old_refresh_id = user.get("refresh_token_id")
        if old_refresh_id:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE auth.refresh_tokens SET rotated_by = %s WHERE token_id = %s",
                    (new_refresh_id, old_refresh_id),
                )
            conn.commit()

    AUTH_REFRESH_TOTAL.labels("success").inc()
    resp = JSONResponse({
        "access_token":      access_token,
        "token_type":        "bearer",
        "access_expires_at": access_expires_at.isoformat(),
        "refresh_expires_at": expires_at.isoformat(),
        "user": {
            "user_id":      user["user_id"],
            "email":        user["email"],
            "role":         user["role"],
            "display_name": user["display_name"],
        },
    })
    _set_refresh_cookie(resp, new_refresh, expires_at)
    return resp


@router.post("/logout")
def logout(
    response: Response,
    body: LogoutRequest = LogoutRequest(),
    soc_rt: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
) -> JSONResponse:
    raw_token = _resolve_refresh_token(soc_rt, body.refresh_token)
    if raw_token:
        with get_conn() as conn:
            _revoke_refresh_token(conn, raw_token)
    _clear_refresh_cookie(response)
    return JSONResponse({"detail": "Logged out"})


@router.get("/me")
def me(current_user: Optional[dict] = Depends(get_current_user)) -> dict:
    if current_user is None:
        # JWT auth is disabled; return a demo identity
        return {
            "user_id":      "demo",
            "email":        "demo@soc.internal",
            "role":         "soc_manager",
            "display_name": "Demo User",
        }
    return {
        "user_id":      current_user.get("sub"),
        "email":        current_user.get("email"),
        "role":         current_user.get("role"),
        "display_name": current_user.get("display_name"),
    }


@router.get("/ws-ticket")
def get_ws_ticket(current_user: Optional[dict] = Depends(get_current_user)) -> dict:
    """
    Issues a short-lived (WS_TICKET_TTL_SECONDS), single-use ticket the
    frontend passes as ?ticket=... when opening the WebSocket connection.
    This avoids sending the Bearer token in the WS URL (visible in server logs).
    """
    user_id = (current_user or {}).get("sub", "anon")
    role    = (current_user or {}).get("role", "l1")

    ticket     = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=WS_TICKET_TTL_SECONDS)

    # Only persist to DB when JWT auth is active — the WS endpoint validates the
    # ticket against this table, but ignores it entirely when JWT_AUTH_ENABLED=false.
    # Persisting with user_id="anon" would violate the FK constraint on auth.users.
    if current_user is not None:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO auth.ws_tickets (ticket, user_id, role, expires_at) "
                    "VALUES (%s, %s, %s, %s)",
                    (ticket, user_id, role, expires_at),
                )
            conn.commit()

    return {
        "ticket":      ticket,
        "expires_at":  expires_at.isoformat(),
        "ttl_seconds": WS_TICKET_TTL_SECONDS,
    }
