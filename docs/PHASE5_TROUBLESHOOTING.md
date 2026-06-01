# Phase 5 Troubleshooting

## Prometheus cannot scrape the API

Check API health:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/metrics
```

Check container status:

```bash
docker compose -f docker-compose.yml -f infra/streaming/docker-compose.phase2.yml -f infra/orchestration/docker-compose.phase3.yml -f infra/consumption/docker-compose.phase4.yml -f infra/monitoring/docker-compose.phase5.yml ps
```

If `/metrics` fails, inspect API logs:

```bash
make logs-p5
```

## Grafana dashboard is empty

Run `make verify-p5` to generate fresh API and Prometheus requests. Grafana panels depend on Prometheus samples, so a new stack may need 30-60 seconds before data appears.

## Secure API calls return 401

Confirm `.env` has:

```bash
API_AUTH_ENABLED=true
API_KEY=your-local-key
```

Call protected routes with:

```bash
curl -H "x-api-key: your-local-key" http://localhost:8000/v1/pipeline/summary
```

## Rate limit returns 429

Raise the local limit or disable it for demo debugging:

```bash
API_RATE_LIMIT_PER_MINUTE=300
API_RATE_LIMIT_ENABLED=false
```

Restart the stack after changing `.env`.

## Failure drill: consumer down

Detection:

1. Open Grafana and watch `Stream freshness`.
2. Confirm Prometheus has `threat_risk_stream_ingest_lag_minutes > 15`.
3. Check Alertmanager for `StreamIngestLagHigh`.
4. Inspect the local alert sink with `make logs-p5`.

Inject failure:

```bash
docker stop threat-consumer
```

Recovery:

```bash
docker start threat-consumer
make replay-bronze-p5
make run-p5
```

Validation:

```bash
curl http://localhost:8000/v1/pipeline/summary
curl http://localhost:8000/metrics | grep threat_risk_stream_ingest_lag_minutes
```

If secure mode is enabled, include the `x-api-key` header for `/v1/pipeline/summary`.
