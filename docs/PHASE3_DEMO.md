# Phase 3 Recruiter Demo Path

## Goal
Show end-to-end orchestration and observability for the Threat & Risk Analytics Platform.

## 1) Start stack
```bash
cp .env.example .env
make up-p3
```

Expected:
- Postgres, MinIO, Redpanda, producer, consumer are running
- Prefect server UI is available at `http://localhost:4200`

## 2) Optional smoke test (hello flow)
```bash
make run-p3-hello
```

In Prefect UI, verify flow run:
- flow name: `p3-hello-flow`
- state: `Completed`

## 3) Trigger full Phase 3 pipeline
```bash
make run-p3
```

What this run executes:
1. Batch ELT for current run date
2. Streaming checks:
   - topic exists
   - Kafka lag threshold
   - ingest freshness and consumer recency
3. dbt build + dbt test
4. Row-count guardrails and run summary artifact creation

You can tune checks directly from Make variables:
```bash
make run-p3 RUN_DATE=2026-02-22 MAX_KAFKA_LAG=5000 MAX_INGEST_LAG_MINUTES=20 MIN_ROWS_PER_RUN_DATE=1 MAX_DAILY_CHANGE_RATIO=20
```

## 4) Show observability outputs

### Prefect UI
Open `http://localhost:4200` and show:
- Flow graph with task dependencies
- Task retries and logs
- Completed run status

### Local artifacts
```bash
make verify-p3
```

Then open latest artifact directory in:
- `artifacts/p3_runs/`

Show files:
- `summary.json`
- `summary.md`

Quickly print latest summary:
```bash
make show-p3-latest
```

## 5) Optional backfill run
```bash
make run-p3-backfill BACKFILL_START=2026-02-15 BACKFILL_END=2026-02-17
```

## 6) Shutdown
```bash
make down-p3
```

Use `make reset-p3` only when you want to remove volumes.

## Known Issues + Tuning

- `unknown flag: --profile`:
  - Cause: older Docker Compose CLI.
  - Resolution: already handled in current `Makefile` (no action needed).

- Flow fails on row-count anomaly:
  - Cause: sudden traffic spike/drop compared with previous day.
  - Resolution: raise tolerance for demo runs.
  - Example: `make run-p3 MAX_DAILY_CHANGE_RATIO=30`

- Flow fails on stream freshness:
  - Cause: consumer temporarily behind or no recent events.
  - Resolution: relax freshness threshold.
  - Example: `make run-p3 MAX_INGEST_LAG_MINUTES=30`

- Flow fails because stream lag too high:
  - Cause: backlog in Kafka topic for consumer group.
  - Resolution: increase lag threshold for local demos.
  - Example: `make run-p3 MAX_KAFKA_LAG=50000`
