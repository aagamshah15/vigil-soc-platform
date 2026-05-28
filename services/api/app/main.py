from __future__ import annotations

import secrets
import time
from typing import Any, Generator, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .auth_router import router as auth_router
from .config import API_CORS_ORIGINS, API_TRUSTED_HOSTS, APP_NAME, APP_VERSION, MAX_STREAM_LAG_MINUTES
from .db import get_conn
from .incident_router import router as incident_router
from .metrics import REQUEST_COUNT, REQUEST_LATENCY, prometheus_response, update_pipeline_metrics, update_soc_metrics
from .repository import AnalyticsRepository
from .security import enforce_rate_limit, require_api_key, require_soc_auth
from .ws import manager as ws_manager
from .ws import soc_stream_handler, ws_lifespan


# ──────────────────────────────────────────────────────────────────────────────
# Application with lifespan (starts/stops the PGLISTEN background task)
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=ws_lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=API_CORS_ORIGINS,
    allow_credentials=True,  # required for Authorization header in CORS pre-flight
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["content-type", "x-api-key", "authorization", "if-match"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=API_TRUSTED_HOSTS)

app.include_router(auth_router)
app.include_router(incident_router)


# ──────────────────────────────────────────────────────────────────────────────
# Middleware
# ──────────────────────────────────────────────────────────────────────────────

@app.middleware("http")
async def phase5_controls(request: Request, call_next):
    start = time.perf_counter()
    route_path = request.url.path
    try:
        enforce_rate_limit(request)
        response = await call_next(request)
    except HTTPException as exc:
        response = JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    except Exception:
        response = JSONResponse(status_code=500, content={"detail": "Internal server error"})

    elapsed = time.perf_counter() - start
    REQUEST_COUNT.labels(request.method, route_path, str(response.status_code)).inc()
    REQUEST_LATENCY.labels(request.method, route_path).observe(elapsed)
    return response


# ──────────────────────────────────────────────────────────────────────────────
# Dependency: sync DB connection
# ──────────────────────────────────────────────────────────────────────────────

def get_repository() -> Generator[AnalyticsRepository, None, None]:
    with get_conn() as conn:
        yield AnalyticsRepository(conn)


# ──────────────────────────────────────────────────────────────────────────────
# Health + metrics
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/health")
def health(repo: AnalyticsRepository = Depends(get_repository)) -> dict[str, Any]:
    db = repo.health()
    return {
        "status": "ok" if db["db_ok"] else "degraded",
        "ws_clients": ws_manager.count,
        "ws_listener_ok": ws_manager.listener_ok,
        **db,
    }


@app.get("/metrics")
def metrics(repo: AnalyticsRepository = Depends(get_repository)):
    summary = repo.pipeline_summary()
    update_pipeline_metrics(summary, max_lag_minutes=MAX_STREAM_LAG_MINUTES)
    update_soc_metrics(repo.soc_metrics_summary())
    return prometheus_response()


# ──────────────────────────────────────────────────────────────────────────────
# Phase 7A: WebSocket endpoint
# ──────────────────────────────────────────────────────────────────────────────

@app.websocket("/v1/soc/stream")
async def soc_stream(
    websocket: WebSocket,
    ticket: Optional[str] = Query(default=None),
):
    """
    Real-time SOC event stream.

    Authentication
    ──────────────
    Pass a short-lived ticket obtained from GET /auth/ws-ticket as the
    `?ticket=` query parameter.  When JWT_AUTH_ENABLED=false the ticket is
    optional and any connection is accepted (dev/demo mode).

    The server validates the ticket against auth.ws_tickets, marks it as
    used, then upgrades the connection.  Subsequent messages from Postgres
    NOTIFY channels are broadcast to all connected clients.

    Client → server messages
    ────────────────────────
    {"type": "pong"}  — reply to keepalive pings

    Server → client messages
    ────────────────────────
    {"type": "soc_event",            "data": {...}}
    {"type": "incident_state_change", "data": {...}}
    {"type": "ping",                  "ts":   "..."}
    {"type": "error",                 "detail": "..."}
    """
    from .config import JWT_AUTH_ENABLED

    if JWT_AUTH_ENABLED:
        if not ticket:
            await websocket.close(code=4001, reason="ticket required")
            return

        # Validate ticket in DB
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT user_id, role, used_at FROM auth.ws_tickets "
                    "WHERE ticket = %s AND expires_at > now()",
                    (ticket,),
                )
                row = cur.fetchone()

            if not row:
                await websocket.close(code=4001, reason="invalid or expired ticket")
                return
            if row[2] is not None:
                await websocket.close(code=4001, reason="ticket already used")
                return

            # Mark ticket as used (single-use guarantee)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE auth.ws_tickets SET used_at = now() WHERE ticket = %s",
                    (ticket,),
                )
            conn.commit()

        client_id = f"{row[0]}:{secrets.token_hex(8)}"
    else:
        client_id = f"anon:{secrets.token_hex(8)}"

    await soc_stream_handler(websocket, client_id)


# ──────────────────────────────────────────────────────────────────────────────
# Existing analytics endpoints (unchanged)
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/v1/pipeline/summary")
def pipeline_summary(
    _: None = Depends(require_api_key),
    repo: AnalyticsRepository = Depends(get_repository),
) -> dict[str, Any]:
    return repo.pipeline_summary()


@app.get("/v1/trends/threat-events")
def threat_event_trends(
    days: int = Query(default=14, ge=1, le=90),
    _: None = Depends(require_api_key),
    repo: AnalyticsRepository = Depends(get_repository),
) -> dict[str, Any]:
    return {"days": days, "series": repo.threat_event_trends(days=days)}


@app.get("/v1/risk/kev-summary")
def kev_risk_summary(
    _: None = Depends(require_api_key),
    repo: AnalyticsRepository = Depends(get_repository),
) -> dict[str, Any]:
    return repo.kev_risk_summary()


@app.get("/v1/trends/stream-lag")
def stream_lag_trends(
    hours: int = Query(default=24, ge=1, le=168),
    _: None = Depends(require_api_key),
    repo: AnalyticsRepository = Depends(get_repository),
) -> dict[str, Any]:
    return {"hours": hours, "series": repo.stream_lag_trends(hours=hours)}


@app.get("/v1/threat/top-hosts")
def top_hosts(
    days: int = Query(default=7, ge=1, le=30),
    limit: int = Query(default=10, ge=1, le=100),
    _: None = Depends(require_api_key),
    repo: AnalyticsRepository = Depends(get_repository),
) -> dict[str, Any]:
    return {"days": days, "limit": limit, "rows": repo.top_malicious_hosts(days=days, limit=limit)}


@app.get("/v1/soc/risk/entities")
def soc_risk_entities(
    limit: int = Query(default=20, ge=1, le=100),
    min_score: int = Query(default=0, ge=0, le=100),
    entity_type: Optional[str] = Query(default=None),
    _user: Optional[dict[str, Any]] = Depends(require_soc_auth),
    repo: AnalyticsRepository = Depends(get_repository),
) -> dict[str, Any]:
    return {
        "limit": limit,
        "min_score": min_score,
        "entity_type": entity_type,
        "rows": repo.soc_risk_entities(limit=limit, min_score=min_score, entity_type=entity_type),
    }


@app.get("/v1/soc/entities/{entity_id}/timeline")
def soc_entity_timeline(
    entity_id: str,
    _user: Optional[dict[str, Any]] = Depends(require_soc_auth),
    repo: AnalyticsRepository = Depends(get_repository),
) -> dict[str, Any]:
    return repo.soc_entity_timeline(entity_id=entity_id)


@app.get("/v1/soc/incidents")
def soc_incidents(
    limit: int = Query(default=20, ge=1, le=100),
    _user: Optional[dict[str, Any]] = Depends(require_soc_auth),
    repo: AnalyticsRepository = Depends(get_repository),
) -> dict[str, Any]:
    return {"limit": limit, "rows": repo.soc_incidents(limit=limit)}


@app.get("/v1/soc/incidents/{incident_id}/triage-report")
def soc_triage_report(
    incident_id: str,
    _user: Optional[dict[str, Any]] = Depends(require_soc_auth),
    repo: AnalyticsRepository = Depends(get_repository),
) -> dict[str, Any]:
    report = repo.soc_triage_report(incident_id=incident_id)
    if not report:
        return JSONResponse(status_code=404, content={"detail": "Incident not found"})
    return report


@app.get("/v1/soc/qna/templates")
def soc_qna_templates(
    _user: Optional[dict[str, Any]] = Depends(require_soc_auth),
    repo: AnalyticsRepository = Depends(get_repository),
) -> dict[str, Any]:
    return {"templates": repo.soc_qna_templates()}


@app.get("/v1/soc/qna/{question_id}")
def soc_qna_answer(
    question_id: str,
    _user: Optional[dict[str, Any]] = Depends(require_soc_auth),
    repo: AnalyticsRepository = Depends(get_repository),
) -> dict[str, Any]:
    answer = repo.soc_qna_answer(question_id=question_id)
    if not answer:
        return JSONResponse(status_code=404, content={"detail": "Question not found"})
    return answer


@app.get("/v1/soc/compliance/{framework}")
def soc_compliance(
    framework: str,
    _user: Optional[dict[str, Any]] = Depends(require_soc_auth),
    repo: AnalyticsRepository = Depends(get_repository),
) -> dict[str, Any]:
    return repo.soc_compliance(framework=framework)


# ──────────────────────────────────────────────────────────────────────────────
# Unhandled exception handler
# ──────────────────────────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def unhandled_error_handler(_request, exc: Exception):
    _ = exc
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
