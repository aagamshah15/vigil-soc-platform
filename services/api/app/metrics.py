from __future__ import annotations

from typing import Any

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from starlette.responses import Response

REQUEST_COUNT = Counter(
    "threat_risk_api_requests_total",
    "Total API requests by method, path, and status.",
    ["method", "path", "status"],
)

REQUEST_LATENCY = Histogram(
    "threat_risk_api_request_duration_seconds",
    "API request duration in seconds.",
    ["method", "path"],
    buckets=(0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)

STREAM_INGEST_LAG = Gauge(
    "threat_risk_stream_ingest_lag_minutes",
    "Minutes since the latest raw stream event was ingested.",
)

CONSUMER_HEARTBEAT_LAG = Gauge(
    "threat_risk_consumer_heartbeat_lag_minutes",
    "Minutes since the latest consumer-written stream event.",
)

PIPELINE_SUCCESS = Gauge(
    "threat_risk_pipeline_success_ratio",
    "Derived local pipeline health: 1 when database is healthy and stream lag is within threshold, otherwise 0.",
)

SOC_EVENT_FRESHNESS = Gauge(
    "threat_risk_soc_event_freshness_minutes",
    "Minutes since the latest SOC security event was ingested.",
)

SOC_HIGH_RISK_ENTITIES = Gauge(
    "threat_risk_soc_high_risk_entities",
    "Current SOC entities with high or critical risk bands.",
)

SOC_CRITICAL_INCIDENTS = Gauge(
    "threat_risk_soc_critical_incidents",
    "Current SOC incidents marked critical.",
)

WS_CONNECTED_CLIENTS = Gauge(
    "threat_risk_ws_connected_clients",
    "Currently connected SOC WebSocket clients.",
)

WS_BROADCAST_TOTAL = Counter(
    "threat_risk_ws_broadcast_total",
    "Total WebSocket messages broadcast to connected SOC clients.",
    ["message_type"],
)

WS_BROADCAST_FAILURES = Counter(
    "threat_risk_ws_broadcast_failures_total",
    "Total failed WebSocket client sends.",
    ["message_type"],
)

WS_RECONNECTS = Counter(
    "threat_risk_ws_reconnects_total",
    "Total SOC WebSocket client connections accepted.",
)

INCIDENT_ACTION_TOTAL = Counter(
    "threat_risk_incident_action_total",
    "Total SOC incident workflow actions recorded.",
    ["action_type"],
)

AUTH_LOGIN_TOTAL = Counter(
    "threat_risk_auth_login_total",
    "Total auth login attempts.",
    ["status"],
)

AUTH_REFRESH_TOTAL = Counter(
    "threat_risk_auth_refresh_total",
    "Total auth refresh attempts.",
    ["status"],
)


def _pipeline_success(summary: dict[str, Any], max_lag_minutes: float) -> float:
    stream_rows = int(summary.get("stream_events_total") or 0)
    lag = float(summary.get("stream_ingest_lag_minutes") or 1e9)
    return 1.0 if stream_rows > 0 and lag <= max_lag_minutes else 0.0


def update_pipeline_metrics(summary: dict[str, Any], max_lag_minutes: float) -> None:
    STREAM_INGEST_LAG.set(float(summary.get("stream_ingest_lag_minutes") or 0.0))
    CONSUMER_HEARTBEAT_LAG.set(float(summary.get("consumer_heartbeat_lag_minutes") or 0.0))
    PIPELINE_SUCCESS.set(_pipeline_success(summary, max_lag_minutes))


def update_soc_metrics(summary: dict[str, Any]) -> None:
    SOC_EVENT_FRESHNESS.set(float(summary.get("soc_event_freshness_minutes") or 0.0))
    SOC_HIGH_RISK_ENTITIES.set(float(summary.get("soc_high_risk_entities") or 0.0))
    SOC_CRITICAL_INCIDENTS.set(float(summary.get("soc_critical_incidents") or 0.0))


def prometheus_response() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
