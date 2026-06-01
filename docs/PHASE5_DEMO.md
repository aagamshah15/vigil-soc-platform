# Phase 5 Demo

## One-command demo

```bash
cp .env.example .env
make demo-p5
```

## URLs

- Prefect UI: http://localhost:4200
- Redpanda UI: http://localhost:8080
- API docs: http://localhost:8000/docs
- Streamlit dashboard: http://localhost:8501
- Prometheus: http://localhost:9090
- Alertmanager: http://localhost:9093
- Grafana: http://localhost:3000

Grafana defaults to `admin/admin` unless `GRAFANA_ADMIN_USER` and `GRAFANA_ADMIN_PASSWORD` are changed in `.env`.

## Secure API mode

Set these in `.env`:

```bash
API_AUTH_ENABLED=true
API_KEY=replace-with-local-secret
```

Then restart Phase 5:

```bash
make down-p5
make up-p5
```

Protected API call:

```bash
curl -H "x-api-key: replace-with-local-secret" http://localhost:8000/v1/pipeline/summary
```

Health and metrics remain public:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/metrics
```

## Validation

```bash
make verify-p5
pytest -q services/api/tests
docker compose -f docker-compose.yml -f infra/streaming/docker-compose.phase2.yml -f infra/orchestration/docker-compose.phase3.yml -f infra/consumption/docker-compose.phase4.yml -f infra/monitoring/docker-compose.phase5.yml config
```

## Backup, restore, and replay

```bash
make backup-postgres
make backup-minio
make replay-bronze-p5
```

Restore examples:

```bash
make restore-postgres BACKUP_FILE=backups/postgres/threat_risk_YYYYMMDDTHHMMSSZ.sql
make restore-minio BACKUP_DIR=backups/minio/YYYYMMDDTHHMMSSZ
```
