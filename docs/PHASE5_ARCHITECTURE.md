# Phase 5 Architecture: Production Readiness + Governance

Phase 5 keeps the platform local-first and additive. The existing Phase 1-4 stack remains intact, and `infra/monitoring/docker-compose.phase5.yml` layers production-readiness services on top.

## Additive Stack

```text
FastAPI /metrics
  -> Prometheus
  -> Grafana dashboard
  -> Alertmanager
  -> local alert-log webhook
```

Phase 5 services:

- `prometheus`: scrapes API and derived pipeline metrics every 15 seconds.
- `grafana`: provisions a checked-in dashboard from `infra/monitoring/grafana/dashboards/phase5-slos.json`.
- `alertmanager`: routes local alerts to the log sink.
- `alert-log`: tiny Python HTTP service that prints alert payloads to container logs.

## SLOs

| SLO | Initial Target | Measurement |
| --- | --- | --- |
| API availability | >= 99.5% non-5xx over rolling windows | `threat_risk_api_requests_total` |
| API p95 latency | <= 750ms | `threat_risk_api_request_duration_seconds` histogram |
| Stream freshness | latest ingest <= 15 minutes old | `threat_risk_stream_ingest_lag_minutes` |
| Pipeline run success | >= 99% derived health over 30 minutes | `threat_risk_pipeline_success_ratio` |

Pipeline success is intentionally derived from local signals: stream rows exist and ingest lag is within the configured threshold. This avoids coupling the demo to Prefect internals while still surfacing an operationally meaningful health signal.

## Alerts

Prometheus rules live in `infra/monitoring/prometheus/rules/phase5-alerts.yml`.

- `HighApi5xxRate`: warning when 5xx responses exceed 5% for 2 minutes.
- `ApiP95LatencyHigh`: warning when p95 latency exceeds 750ms for 5 minutes.
- `StreamIngestLagHigh`: warning when stream lag exceeds 15 minutes for 5 minutes.

Alerts flow to Alertmanager and then to `alert-log`; inspect with:

```bash
docker compose -f docker-compose.yml -f infra/streaming/docker-compose.phase2.yml -f infra/orchestration/docker-compose.phase3.yml -f infra/consumption/docker-compose.phase4.yml -f infra/monitoring/docker-compose.phase5.yml logs alert-log
```

## Security Defaults

- `/health` and `/metrics` remain public for health checks and Prometheus.
- Protected API routes require `x-api-key` only when `API_AUTH_ENABLED=true`.
- Rate limiting is enabled by default at `API_RATE_LIMIT_PER_MINUTE=120`.
- Unhandled API exceptions return generic HTTP 500 responses.
- The API container runs as a non-root user with `read_only` and `no-new-privileges` in the Phase 5 overlay.

## Governance

dbt now documents key mart models and columns, declares exposures for the API and Streamlit dashboard, and includes conservative stream recency/anomaly tests.

## Resilience

Local backup and replay utilities are exposed through Make targets:

- `make backup-postgres`
- `make restore-postgres BACKUP_FILE=...`
- `make backup-minio`
- `make restore-minio BACKUP_DIR=...`
- `make replay-bronze-p5`
