# Threat & Risk Analytics Platform

**Local-first cyber threat intelligence, SOC risk analytics, and operational observability platform.**

![Build Status](https://img.shields.io/badge/build-GitHub%20Actions-blue)
![Local First](https://img.shields.io/badge/runtime-local--first-success)
![Docker](https://img.shields.io/badge/docker-compose-2496ED)
![Python](https://img.shields.io/badge/python-3.11-3776AB)
![React](https://img.shields.io/badge/react-18-61DAFB)
![FastAPI](https://img.shields.io/badge/api-FastAPI-009688)
![dbt](https://img.shields.io/badge/transform-dbt-FF694B)

This project is a production-style data engineering and SOC analytics platform that runs locally with Docker and zero cloud cost. It combines public cyber threat feeds, synthetic SOC telemetry, live GitHub activity, IOC enrichment, batch ELT, streaming ingestion, dbt marts, FastAPI, Streamlit, a React SOC command center, JWT-ready auth, WebSockets, Prometheus, Grafana, Alertmanager, and backup/replay utilities.

The README is optimized as the GitHub front door for people evaluating or running the project. The deeper phase docs remain under [docs](docs).

## What You Can Demo

- Launch the full Phase 8 stack with one command: `make demo-up`.
- Open the React SOC Command Center and inspect entity risk, incidents, triage evidence, compliance evidence, and analyst workflow state.
- Explore the FastAPI docs, authenticated SOC routes, WebSocket stream, and health/metrics endpoints.
- View operational telemetry in Grafana and Prometheus.
- Inspect the warehouse in Postgres, immutable Bronze objects in MinIO, and dbt models/tests.
- Stop the stack without deleting data using `make demo-down`.

## Screenshots

Core architecture and product views:

![Architecture](docs/architecture.png)

![React SOC Command Center](docs/screenshots/react-soc-command-center.png)

![Grafana SLO Dashboard](docs/screenshots/grafana-slo-dashboard.png)

![FastAPI OpenAPI Docs](docs/screenshots/fastapi-openapi.png)

![Redpanda Topics](docs/screenshots/redpanda-topics.png)

![dbt Model](docs/screenshots/dbt-docs-model.png)

![dbt Lineage](docs/screenshots/dbt-docs-lineage.png)

## Quick Start

### Prerequisites

- Docker and Docker Compose
- GNU Make
- Git
- Optional: `GITHUB_TOKEN`, `GITHUB_USERNAME`, and `OTX_API_KEY` for live Phase 8 producers

### Run the full demo

```bash
cp .env.example .env
make demo-up
```

`make demo-up` starts the full Phase 8 stack, applies the Phase 7 and Phase 8 SQL migrations, runs SOC dbt models, and prints the main service URLs.

### Stop the stack

```bash
make demo-down
```

This stops containers and preserves Docker volumes. To wipe data for a clean start, use the relevant reset target, such as `make reset-p8`.

### Demo authentication defaults

Local demo mode keeps the portfolio experience easy to run:

```bash
JWT_AUTH_ENABLED=false
SEED_DEMO_USERS=true
PRODUCTION_MODE=false
COOKIE_SECURE=false
```

For production-like auth hardening, set:

```bash
JWT_AUTH_ENABLED=true
PRODUCTION_MODE=true
JWT_SECRET=<strong value from openssl rand -hex 32>
COOKIE_SECURE=true
API_CORS_ORIGINS=https://your-ui.example.com
SEED_DEMO_USERS=false
```

When demo users are seeded, the local accounts use password `changeme`:

| Role | Email |
| --- | --- |
| L1 Analyst | `l1@soc.internal` |
| L2 Analyst | `l2@soc.internal` |
| SOC Manager | `manager@soc.internal` |
| CISO | `ciso@soc.internal` |
| Compliance Officer | `compliance@soc.internal` |

## Main URLs

| Service | URL | Purpose |
| --- | --- | --- |
| React SOC UI | http://localhost:8600 | Primary command center for the SOC demo |
| FastAPI docs | http://localhost:8000/docs | Interactive API documentation |
| Streamlit dashboard | http://localhost:8501 | Lightweight analytics and SOC dashboard |
| Grafana | http://localhost:3000 | SLO and operational dashboards |
| Prometheus | http://localhost:9090 | Metrics and alert rule inspection |
| Alertmanager | http://localhost:9093 | Alert routing |
| Alert log | http://localhost:9094/alerts | Local webhook sink for alert payloads |
| Prefect | http://localhost:4200 | Orchestration UI |
| Redpanda UI | http://localhost:8080 | Kafka-compatible topic inspection |
| MinIO API | http://localhost:9000 | S3-compatible object storage API |
| MinIO console | http://localhost:9001 | Bronze lake object browser |

## Architecture

### Data Flow

Public threat intelligence and demo SOC telemetry land in an additive local data platform:

1. Python ELT jobs fetch public datasets such as CISA KEV and URLhaus.
2. Streaming producers publish URLhaus, synthetic SOC, and GitHub-derived security events to Redpanda.
3. Consumers write append-only JSONL batches to MinIO Bronze and upsert normalized rows into Postgres raw tables.
4. Phase 8 threat intelligence producers enrich Postgres with IOC reference data.
5. dbt builds staging models, dimensions, facts, SOC risk marts, incident timelines, compliance evidence, and analyst Q&A outputs.

### Serving Flow

Curated marts are exposed through multiple user-facing surfaces:

- FastAPI serves pipeline, threat, risk, SOC, auth, incident state, and WebSocket endpoints.
- Streamlit provides a lightweight dashboard for demos and data checks.
- React plus nginx serves the SOC Command Center on port `8600` and proxies same-origin API traffic through `/api`.
- The React app can fall back to deterministic demo data for `INC-PAYMENT-001` if the API is unavailable.

### Operational Flow

The platform includes local production-readiness patterns:

- Prefect orchestrates batch, streaming health checks, dbt builds, and observability artifacts.
- Prometheus scrapes API and pipeline metrics.
- Grafana provisions SLO dashboards.
- Alertmanager routes alerts to a local alert sink.
- Backup, restore, and replay scripts support Postgres, MinIO, and Bronze stream event recovery.
- CI validates Python services, API tests, dbt models, React build/lint, monitoring config, and security checks.

## Tech Stack

| Layer | Tools |
| --- | --- |
| Ingestion | Python, URLhaus, CISA KEV, GitHub Events API, OTX/ThreatFox/Feodo-style IOC feeds |
| Streaming | Redpanda, Kafka-compatible producers and consumers |
| Lake and warehouse | MinIO, Postgres |
| Transformation | dbt Core, staging models, marts, tests, exposures |
| Orchestration | Prefect |
| APIs | FastAPI, JWT-ready auth, API key mode, WebSockets |
| User interfaces | React, nginx, Streamlit |
| Observability | Prometheus, Grafana, Alertmanager, local alert sink |
| Quality and CI | pytest, ruff, Bandit, pip-audit, npm lint/build, dbt tests |
| Runtime | Docker Compose, Make |

## Platform Evolution

| Phase | Capability |
| --- | --- |
| Phase 1 | Batch ELT from public threat feeds into MinIO Bronze, Postgres raw tables, and dbt marts |
| Phase 2 | Redpanda streaming, URLhaus producer/consumer, idempotent raw upserts, incremental dbt model |
| Phase 3 | Prefect orchestration, backfills, streaming health checks, run artifacts |
| Phase 4 | FastAPI serving layer, Streamlit dashboard, stronger contracts, CI gates |
| Phase 5 | Prometheus, Grafana, Alertmanager, SLOs, API key auth toggle, rate limits, backup/restore/replay |
| Phase 6 | Synthetic financial SOC scenario, entity risk scoring, incident timelines, compliance evidence |
| Phase 7 | JWT-gated SOC APIs, single-use WebSocket tickets, incident workflow state, Postgres notifications |
| Phase 8 | Live GitHub activity producer and IOC enrichment producer while preserving synthetic replay |

## Public Interfaces

### Core API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Service, database, and WebSocket listener health |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/v1/pipeline/summary` | Pipeline freshness and row-count summary |
| `GET` | `/v1/trends/threat-events` | Threat event trend series |
| `GET` | `/v1/trends/stream-lag` | Streaming ingest lag trend series |
| `GET` | `/v1/threat/top-hosts` | Top malicious hosts |
| `GET` | `/v1/risk/kev-summary` | KEV risk summary |

### SOC API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/soc/risk/entities` | Current entity risk scores |
| `GET` | `/v1/soc/entities/{entity_id}/timeline` | Entity event timeline |
| `GET` | `/v1/soc/incidents` | Incident list |
| `GET` | `/v1/soc/incidents/{incident_id}/triage-report` | Deterministic triage report |
| `GET` | `/v1/soc/qna/templates` | Analyst Q&A templates |
| `GET` | `/v1/soc/qna/{question_id}` | Analyst Q&A answer |
| `GET` | `/v1/soc/compliance/{framework}` | Compliance evidence |
| `GET` | `/v1/soc/incidents/{incident_id}/state` | Incident workflow state |
| `PATCH` | `/v1/soc/incidents/{incident_id}/state` | Update incident state with optimistic locking |
| `GET` | `/v1/soc/incidents/{incident_id}/actions` | Incident action history |
| `POST` | `/v1/soc/incidents/{incident_id}/actions` | Add incident action |

### Auth and Realtime

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/auth/login` | Login and issue access token plus refresh cookie |
| `POST` | `/auth/refresh` | Refresh access token |
| `POST` | `/auth/logout` | Clear refresh cookie |
| `GET` | `/auth/me` | Current authenticated user |
| `GET` | `/auth/ws-ticket` | Single-use WebSocket ticket |
| `WS` | `/v1/soc/stream` | Realtime SOC event and incident state stream |

## Data Model

### Raw Layer

- `raw.kev`
- `raw.urlhaus_recent`
- `raw.urlhaus_events`
- `raw.security_events`
- `raw.iocs`

### Staging

- `stg_kev`
- `stg_urlhaus`
- `stg_urlhaus_events`
- SOC staging models under `dbt/models/staging/soc`

### Marts

- `dim_date`
- `dim_vendor`
- `dim_product`
- `dim_url`
- `fact_kev`
- `fact_url_events`
- `fct_urlhaus_threat_events`
- `mart_soc_entity_risk_current`
- `mart_soc_incident_timelines`
- `mart_soc_risk_events`
- `mart_soc_qna_results`
- `mart_soc_compliance_evidence`

See [docs/DATA_DICTIONARY.md](docs/DATA_DICTIONARY.md) and [docs/SOC_DATA_DICTIONARY.md](docs/SOC_DATA_DICTIONARY.md) for column-level detail.

## Repository Layout

```text
.
|-- dbt/                       # dbt project, staging models, marts, tests, docs config
|-- docs/                      # architecture notes, demo guides, data dictionaries
|-- elt/                       # batch ELT loaders and public threat feed sources
|-- infra/                     # additive Docker Compose overlays by phase
|-- orchestration/             # Prefect flows
|-- scripts/                   # backup, restore, replay, and alert sink utilities
|-- services/
|   |-- api/                   # FastAPI app, auth, metrics, SOC routes, WebSocket
|   |-- dashboard/             # Streamlit dashboard
|   |-- web/                   # React SOC Command Center served by nginx
|   |-- consumer/              # URLhaus stream consumer
|   |-- producer/              # URLhaus stream producer
|   |-- soc_consumer/          # SOC event consumer
|   |-- soc_producer/          # Synthetic SOC event producer
|   |-- github_producer/       # GitHub activity producer
|   `-- threat_intel_producer/ # IOC enrichment producer
|-- sql/init/                  # Postgres schema and auth/SOC/IOC migrations
|-- docker-compose.yml         # Phase 1 base stack
|-- Makefile                   # Main local workflow entrypoint
`-- README.md
```

## Environment Variables

Start with:

```bash
cp .env.example .env
```

Important settings:

| Variable | Default | Notes |
| --- | --- | --- |
| `POSTGRES_DB` | `threat_risk` | Local warehouse database |
| `POSTGRES_USER` | `app` | Local database user |
| `POSTGRES_PASSWORD` | `app` | Local demo password |
| `MINIO_ROOT_USER` | `minioadmin` | MinIO root user |
| `MINIO_ROOT_PASSWORD` | `minioadmin123` | MinIO root password |
| `MINIO_BUCKET` | `lake` | Bronze bucket |
| `RUN_DATE` | `2026-01-19` | Deterministic batch run date |
| `API_AUTH_ENABLED` | `false` | API key enforcement toggle for Phase 5 controls |
| `API_KEY` | `change-me-local-demo-key` | Local API key when key auth is enabled |
| `JWT_AUTH_ENABLED` | `false` | Enforce JWT auth on SOC endpoints when true |
| `JWT_SECRET` | insecure placeholder | Must be replaced when JWT auth is enabled |
| `PRODUCTION_MODE` | `false` | Enables stricter startup secret checks |
| `COOKIE_SECURE` | `false` | Set true behind HTTPS |
| `SEED_DEMO_USERS` | `true` | Seeds local demo users during auth init |
| `API_CORS_ORIGINS` | localhost origins | Comma-separated allowed UI origins |
| `SOC_TOPIC` | `security.events` | SOC Redpanda topic |
| `SOC_SCENARIO` | `financial_attack_chain` | Synthetic SOC scenario |
| `GITHUB_TOKEN` | unset | Optional for live GitHub producer |
| `GITHUB_USERNAME` | unset | Optional GitHub activity filter |
| `OTX_API_KEY` | unset | Optional for live threat intel producer |

## Secrets and Local Credentials

Do not commit `.env` or real credentials. `.env.example` contains placeholders only; copy it to `.env` and keep local values private.

Rotate any exposed GitHub token, OTX API key, JWT secret, API key, or reused local password immediately. See [SECURITY.md](SECURITY.md) for reporting and secret-handling guidance.

## Common Commands

### Full stack

```bash
make demo-up
make demo-down
make logs-p8
make reset-p8
```

### Phase-specific workflows

```bash
make run
make run-p2
make demo-p3
make demo-p4
make demo-p5
make demo-p6
make demo-web
```

### Validation and inspection

```bash
make verify-p2
make verify-p3
make verify-p4
make verify-p5
make verify-p6
make verify-web
make verify-p7
make verify-p8
make psql
```

### dbt docs

```bash
make docs
make docs-serve
```

After `make docs-serve`, open http://localhost:8080.

Note: the full Phase 8 stack also uses port `8080` for Redpanda UI. Stop the stack or change the docs server port before serving dbt docs.

### Backup, restore, and replay

```bash
make backup-postgres
make restore-postgres BACKUP_FILE=backups/postgres/<file>.sql
make backup-minio
make restore-minio BACKUP_DIR=backups/minio/<directory>
make replay-bronze-p5
```

## CI and Quality

The GitHub Actions workflow validates the project with:

- Python setup on 3.11 and Node setup on 22.
- `ruff` checks for API, dashboard, SOC producer, and SOC consumer services.
- Bandit and pip-audit security checks.
- Postgres schema bootstrap for raw, SOC, auth, state, notification, and IOC schemas.
- `dbt build`, source freshness, and focused dbt tests.
- FastAPI unit and integration tests.
- React SOC UI `npm ci`, lint, and production build.
- Monitoring YAML/JSON validation and Docker Compose config validation through Phase 8.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Containers fail to start | Confirm Docker is running and ports `3000`, `4200`, `5432`, `8000`, `8080`, `8501`, `8600`, `9000`, `9001`, `9090`, `9093`, and `9094` are free |
| API returns degraded health | Run `make logs-p7` or `make logs-p8`, then inspect Postgres and API logs |
| React UI has no live data | Confirm `make demo-up` completed, then visit `http://localhost:8000/health` and `http://localhost:8600/api/health` |
| JWT startup fails | Replace `JWT_SECRET`, set `COOKIE_SECURE=true`, disable seeded users, and use explicit CORS origins when `PRODUCTION_MODE=true` |
| Grafana is empty | Run `make verify-p5` or `make verify-p7` and confirm Prometheus targets are up |
| dbt models are stale | Run the relevant `run-p*` target or inspect the `dbt-refresh` container in Phase 7 |
| Need a clean local reset | Use a phase reset target such as `make reset-p8`; reset targets remove Docker volumes |

## Documentation Index

- [Phase 3 Architecture](docs/PHASE3_ARCHITECTURE.md)
- [Phase 3 Demo](docs/PHASE3_DEMO.md)
- [Phase 4 Architecture](docs/PHASE4_ARCHITECTURE.md)
- [Phase 4 Demo](docs/PHASE4_DEMO.md)
- [Phase 4 Troubleshooting](docs/PHASE4_TROUBLESHOOTING.md)
- [Phase 5 Architecture](docs/PHASE5_ARCHITECTURE.md)
- [Phase 5 Demo](docs/PHASE5_DEMO.md)
- [Phase 5 Troubleshooting](docs/PHASE5_TROUBLESHOOTING.md)
- [Phase 6 Architecture](docs/PHASE6_ARCHITECTURE.md)
- [Phase 6 Demo](docs/PHASE6_DEMO.md)
- [Phase 6 Troubleshooting](docs/PHASE6_TROUBLESHOOTING.md)
- [React SOC Command Center](docs/REACT_SOC_COMMAND_CENTER.md)
- [Data Dictionary](docs/DATA_DICTIONARY.md)
- [SOC Data Dictionary](docs/SOC_DATA_DICTIONARY.md)
- [SOC Scoring Rubric](docs/SOC_SCORING_RUBRIC.md)
- [Security Policy](SECURITY.md)
- [Contributing Guide](CONTRIBUTING.md)

Additional Word-format project artifacts are available under `docs/`:

- `docs/Vigil_APIDocumentation.docx`
- `docs/Vigil_PRD.docx`
- `docs/Vigil_SystemArchitecture.docx`
- `docs/Vigil_UserStories.docx`
- `docs/Vigil_Wireframes_UX.docx`

## License

This project is licensed under the [MIT License](LICENSE).
