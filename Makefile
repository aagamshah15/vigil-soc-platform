# Compose files
COMPOSE_BASE = -f docker-compose.yml
COMPOSE_P2   = -f docker-compose.yml -f infra/streaming/docker-compose.phase2.yml
COMPOSE_P3   = -f docker-compose.yml -f infra/streaming/docker-compose.phase2.yml -f infra/orchestration/docker-compose.phase3.yml
COMPOSE_P4   = -f docker-compose.yml -f infra/streaming/docker-compose.phase2.yml -f infra/orchestration/docker-compose.phase3.yml -f infra/consumption/docker-compose.phase4.yml
COMPOSE_P5   = -f docker-compose.yml -f infra/streaming/docker-compose.phase2.yml -f infra/orchestration/docker-compose.phase3.yml -f infra/consumption/docker-compose.phase4.yml -f infra/monitoring/docker-compose.phase5.yml
COMPOSE_P6   = -f docker-compose.yml -f infra/streaming/docker-compose.phase2.yml -f infra/orchestration/docker-compose.phase3.yml -f infra/consumption/docker-compose.phase4.yml -f infra/monitoring/docker-compose.phase5.yml -f infra/soc/docker-compose.phase6.yml
COMPOSE_WEB  = -f docker-compose.yml -f infra/streaming/docker-compose.phase2.yml -f infra/orchestration/docker-compose.phase3.yml -f infra/consumption/docker-compose.phase4.yml -f infra/monitoring/docker-compose.phase5.yml -f infra/soc/docker-compose.phase6.yml -f infra/web/docker-compose.web.yml
COMPOSE_P7   = -f docker-compose.yml -f infra/streaming/docker-compose.phase2.yml -f infra/orchestration/docker-compose.phase3.yml -f infra/consumption/docker-compose.phase4.yml -f infra/monitoring/docker-compose.phase5.yml -f infra/soc/docker-compose.phase6.yml -f infra/soc/docker-compose.phase7.yml -f infra/web/docker-compose.web.yml
COMPOSE_P8   = -f docker-compose.yml -f infra/streaming/docker-compose.phase2.yml -f infra/orchestration/docker-compose.phase3.yml -f infra/consumption/docker-compose.phase4.yml -f infra/monitoring/docker-compose.phase5.yml -f infra/soc/docker-compose.phase6.yml -f infra/soc/docker-compose.phase7.yml -f infra/soc/docker-compose.phase8.yml -f infra/web/docker-compose.web.yml

.PHONY: up run run-p2 up-p2 dbt dbt-p2 verify verify-p2 logs logs-p2 down down-p2 reset reset-p2 psql docs docs-serve up-p3 init-p3 run-p3-hello run-p3 run-p3-backfill verify-p3 show-p3-latest logs-p3 down-p3 reset-p3 demo-p3 up-p4 init-p4 run-p4 verify-p4 logs-p4 down-p4 reset-p4 demo-p4 up-p5 init-p5 run-p5 verify-p5 logs-p5 down-p5 reset-p5 demo-p5 backup-postgres restore-postgres backup-minio restore-minio replay-bronze-p5 validate-monitoring-p5 up-p6 init-p6 run-p6 verify-p6 logs-p6 down-p6 reset-p6 demo-p6 up-web verify-web logs-web down-web demo-web up-p7 init-p7 verify-p7 logs-p7 down-p7 reset-p7 up-p8 init-p8 verify-p8 logs-p8 down-p8 reset-p8 demo-up demo-down

RUN_DATE ?= $(shell date +%F)
MAX_KAFKA_LAG ?= 10000
MAX_INGEST_LAG_MINUTES ?= 15
MIN_ROWS_PER_RUN_DATE ?= 1
MAX_DAILY_CHANGE_RATIO ?= 20.0

# ----------------------------
# Phase 1 (batch) targets
# ----------------------------

up:
	docker compose $(COMPOSE_BASE) up -d --build

run:
	docker compose $(COMPOSE_BASE) up -d --build
	docker compose $(COMPOSE_BASE) run --rm elt
	docker compose $(COMPOSE_BASE) run --rm dbt

dbt:
	docker compose $(COMPOSE_BASE) run --rm dbt dbt build

verify:
	@echo "== Postgres marts tables =="
	docker exec -it threat-risk-platform-postgres-1 psql -U app -d threat_risk -c "\dt marts.*"
	@echo "== Row counts (marts) =="
	docker exec -it threat-risk-platform-postgres-1 psql -U app -d threat_risk -c "select 'fact_kev' as table, count(*) from marts.fact_kev union all select 'fact_url_events', count(*) from marts.fact_url_events;"
	@echo "== Sample checks =="
	docker exec -it threat-risk-platform-postgres-1 psql -U app -d threat_risk -c "select vendor_project, count(*) cnt from marts.dim_vendor group by 1 order by 2 desc limit 10;"
	@echo "== dbt test (fast) =="
	docker compose $(COMPOSE_BASE) run --rm dbt dbt test

docs:
	docker compose $(COMPOSE_BASE) run --rm dbt dbt docs generate
	@echo "dbt docs generated under dbt/target (local)."

# Safe down (keeps volumes)
down:
	docker compose $(COMPOSE_BASE) down

# Destructive reset (wipes volumes)
reset:
	docker compose $(COMPOSE_BASE) down -v


# ----------------------------
# Phase 2 (streaming + incremental) targets
# ----------------------------

up-p2:
	docker compose $(COMPOSE_P2) up -d --build

run-p2:
	docker compose $(COMPOSE_P2) up -d --build
	docker compose $(COMPOSE_P2) run --rm elt
	docker compose $(COMPOSE_P2) run --rm dbt dbt build

dbt-p2:
	docker compose $(COMPOSE_P2) run --rm dbt dbt build

verify-p2:
	@echo "== Postgres raw table (streaming) =="
	docker exec -it threat-risk-platform-postgres-1 psql -U app -d threat_risk -c "\dt raw.*"
	@echo "== Row counts (raw + incremental fact) =="
	docker exec -it threat-risk-platform-postgres-1 psql -U app -d threat_risk -c "select 'raw.urlhaus_events' as table, count(*) from raw.urlhaus_events union all select 'marts.fct_urlhaus_threat_events', count(*) from marts.fct_urlhaus_threat_events;"
	@echo "== Latest ingested_at =="
	docker exec -it threat-risk-platform-postgres-1 psql -U app -d threat_risk -c "select max(ingested_at) as latest_ingested_at from raw.urlhaus_events;"
	@echo "== dbt test =="
	docker compose $(COMPOSE_P2) run --rm dbt dbt test

logs:
	docker compose $(COMPOSE_BASE) logs -f --tail=100

logs-p2:
	docker compose $(COMPOSE_P2) logs -f --tail=100

down-p2:
	docker compose $(COMPOSE_P2) down

reset-p2:
	docker compose $(COMPOSE_P2) down -v


# ----------------------------
# Phase 3 (orchestration + observability) targets
# ----------------------------

up-p3:
	docker compose $(COMPOSE_P3) up -d --build

init-p3:
	docker compose $(COMPOSE_P3) run --rm prefect-cli prefect work-pool create local-process --type process || true

run-p3-hello:
	docker compose $(COMPOSE_P3) run --rm prefect-cli python orchestration/flows/hello_flow.py

run-p3:
	docker compose $(COMPOSE_P3) run --rm prefect-cli python -c "from orchestration.flows.p3_pipeline_flow import p3_pipeline_flow; p3_pipeline_flow(run_date='$(RUN_DATE)', max_kafka_lag=int('$(MAX_KAFKA_LAG)'), max_ingest_lag_minutes=int('$(MAX_INGEST_LAG_MINUTES)'), min_rows_per_run_date=int('$(MIN_ROWS_PER_RUN_DATE)'), max_daily_change_ratio=float('$(MAX_DAILY_CHANGE_RATIO)'))"

run-p3-backfill:
ifndef BACKFILL_START
	$(error BACKFILL_START is not set. Use: make run-p3-backfill BACKFILL_START=YYYY-MM-DD BACKFILL_END=YYYY-MM-DD)
endif
ifndef BACKFILL_END
	$(error BACKFILL_END is not set. Use: make run-p3-backfill BACKFILL_START=YYYY-MM-DD BACKFILL_END=YYYY-MM-DD)
endif
	docker compose $(COMPOSE_P3) run --rm prefect-cli python -c "from orchestration.flows.p3_pipeline_flow import p3_pipeline_flow; p3_pipeline_flow(backfill_start='$(BACKFILL_START)', backfill_end='$(BACKFILL_END)', run_date='$(BACKFILL_START)', max_kafka_lag=int('$(MAX_KAFKA_LAG)'), max_ingest_lag_minutes=int('$(MAX_INGEST_LAG_MINUTES)'), min_rows_per_run_date=int('$(MIN_ROWS_PER_RUN_DATE)'), max_daily_change_ratio=float('$(MAX_DAILY_CHANGE_RATIO)'))"

verify-p3:
	@echo "== Prefect UI =="
	@echo "http://localhost:4200"
	@echo "== Prefect services =="
	docker compose $(COMPOSE_P3) ps prefect-server prefect-worker
	@echo "== Recent artifacts =="
	ls -lah artifacts/p3_runs || true

show-p3-latest:
	@latest_dir=$$(ls -1dt artifacts/p3_runs/* 2>/dev/null | head -n 1); \
	if [ -z "$$latest_dir" ]; then \
	  echo "No Phase 3 artifacts found."; \
	  exit 0; \
	fi; \
	echo "Latest artifact: $$latest_dir"; \
	if [ -f "$$latest_dir/summary.md" ]; then \
	  echo "== summary.md =="; \
	  cat "$$latest_dir/summary.md"; \
	else \
	  echo "summary.md not found in $$latest_dir"; \
	fi

logs-p3:
	docker compose $(COMPOSE_P3) logs -f --tail=100 prefect-server prefect-worker

down-p3:
	docker compose $(COMPOSE_P3) down

reset-p3:
	docker compose $(COMPOSE_P3) down -v

demo-p3: up-p3 init-p3 run-p3
	@echo "Open Prefect UI: http://localhost:4200"

# ----------------------------
# Phase 4 (consumption + reliability hardening)
# ----------------------------

up-p4:
	docker compose $(COMPOSE_P4) up -d --build

init-p4:
	docker compose $(COMPOSE_P4) run --rm prefect-cli prefect work-pool create local-process --type process || true

run-p4:
	docker compose $(COMPOSE_P4) run --rm prefect-cli python -c "from orchestration.flows.p3_pipeline_flow import p3_pipeline_flow; p3_pipeline_flow(run_date='$(RUN_DATE)', max_kafka_lag=int('$(MAX_KAFKA_LAG)'), max_ingest_lag_minutes=int('$(MAX_INGEST_LAG_MINUTES)'), min_rows_per_run_date=int('$(MIN_ROWS_PER_RUN_DATE)'), max_daily_change_ratio=float('$(MAX_DAILY_CHANGE_RATIO)'))"

verify-p4:
	@echo "== Phase 4 URLs =="
	@echo "Prefect UI:   http://localhost:4200"
	@echo "Redpanda UI:  http://localhost:8080"
	@echo "API docs:     http://localhost:8000/docs"
	@echo "Dashboard:    http://localhost:8501"
	@echo "== API health =="
	curl -s http://localhost:8000/health || true

logs-p4:
	docker compose $(COMPOSE_P4) logs -f --tail=100 api dashboard prefect-server prefect-worker

down-p4:
	docker compose $(COMPOSE_P4) down

reset-p4:
	docker compose $(COMPOSE_P4) down -v

demo-p4: up-p4 init-p4 run-p4 verify-p4
	@echo "Open dashboard: http://localhost:8501"

# ----------------------------
# Phase 5 (production readiness + governance)
# ----------------------------

up-p5:
	docker compose $(COMPOSE_P5) up -d --build

init-p5:
	docker compose $(COMPOSE_P5) run --rm prefect-cli prefect work-pool create local-process --type process || true

run-p5:
	docker compose $(COMPOSE_P5) run --rm prefect-cli python -c "from orchestration.flows.p3_pipeline_flow import p3_pipeline_flow; p3_pipeline_flow(run_date='$(RUN_DATE)', max_kafka_lag=int('$(MAX_KAFKA_LAG)'), max_ingest_lag_minutes=int('$(MAX_INGEST_LAG_MINUTES)'), min_rows_per_run_date=int('$(MIN_ROWS_PER_RUN_DATE)'), max_daily_change_ratio=float('$(MAX_DAILY_CHANGE_RATIO)'))"

verify-p5: validate-monitoring-p5
	@echo "== Phase 5 URLs =="
	@echo "Prefect UI:    http://localhost:4200"
	@echo "Redpanda UI:   http://localhost:8080"
	@echo "API docs:      http://localhost:8000/docs"
	@echo "Dashboard:     http://localhost:8501"
	@echo "Prometheus:    http://localhost:9090"
	@echo "Alertmanager:  http://localhost:9093"
	@echo "Alert log:     http://localhost:9094/alerts"
	@echo "Grafana:       http://localhost:3000"
	@echo "== API health =="
	curl -s http://localhost:8000/health || true
	@echo "\n== API metrics sample =="
	curl -s http://localhost:8000/metrics | head -n 20 || true
	@echo "\n== Prometheus targets =="
	curl -s http://localhost:9090/api/v1/targets | head -c 1200 || true

validate-monitoring-p5:
	@echo "== Validate monitoring YAML/JSON syntax =="
	python3 -c "import json, pathlib; [json.load(open(p)) for p in pathlib.Path('infra/monitoring/grafana/dashboards').glob('*.json')]; print('dashboard json ok')"
	python3 -c "import importlib.util; spec=importlib.util.find_spec('yaml'); exec(\"import yaml; [yaml.safe_load(open(p)) for p in ['infra/monitoring/prometheus/prometheus.yml','infra/monitoring/prometheus/rules/phase5-alerts.yml','infra/monitoring/alertmanager.yml']]; print('monitoring yaml ok')\" if spec else \"print('PyYAML unavailable; skipping direct YAML parse')\")"
	docker compose $(COMPOSE_P5) config >/dev/null

logs-p5:
	docker compose $(COMPOSE_P5) logs -f --tail=100 api prometheus alertmanager alert-log grafana

down-p5:
	docker compose $(COMPOSE_P5) down

reset-p5:
	docker compose $(COMPOSE_P5) down -v

demo-p5: up-p5 init-p5 run-p5 verify-p5
	@echo "Open Grafana: http://localhost:3000 (admin/admin unless overridden)"

backup-postgres:
	scripts/backup_postgres.sh

restore-postgres:
ifndef BACKUP_FILE
	$(error BACKUP_FILE is not set. Use: make restore-postgres BACKUP_FILE=backups/postgres/file.sql)
endif
	scripts/restore_postgres.sh "$(BACKUP_FILE)"

backup-minio:
	scripts/backup_minio.sh

restore-minio:
ifndef BACKUP_DIR
	$(error BACKUP_DIR is not set. Use: make restore-minio BACKUP_DIR=backups/minio/YYYYMMDDTHHMMSSZ)
endif
	scripts/restore_minio.sh "$(BACKUP_DIR)"

replay-bronze-p5:
	docker compose $(COMPOSE_P5) run --rm -v $(PWD)/scripts:/scripts consumer python /scripts/replay_bronze_to_raw.py

# ----------------------------
# Phase 6 (SOC threat correlation + risk scoring)
# ----------------------------

up-p6:
	docker compose $(COMPOSE_P6) up -d --build

init-p6:
	docker exec -i $$(docker compose $(COMPOSE_BASE) ps -q postgres) psql -U $${POSTGRES_USER:-app} -d $${POSTGRES_DB:-threat_risk} -f /docker-entrypoint-initdb.d/002_soc_schema.sql
	docker compose $(COMPOSE_P6) run --rm prefect-cli prefect work-pool create local-process --type process || true

run-p6: init-p6
	docker compose $(COMPOSE_P6) run --rm soc-producer
	sleep 4
	docker compose $(COMPOSE_P6) run --rm dbt dbt build --select path:models/staging/soc path:models/marts/soc

verify-p6: validate-monitoring-p5
	@echo "== Phase 6 URLs =="
	@echo "SOC API docs:  http://localhost:8000/docs"
	@echo "SOC dashboard: http://localhost:8501"
	@echo "Grafana:       http://localhost:3000"
	@echo "== SOC risk sample =="
	curl -s http://localhost:8000/v1/soc/risk/entities?limit=5 || true
	@echo "\n== SOC incidents sample =="
	curl -s http://localhost:8000/v1/soc/incidents || true

logs-p6:
	docker compose $(COMPOSE_P6) logs -f --tail=100 soc-producer soc-consumer api dashboard prometheus grafana

down-p6:
	docker compose $(COMPOSE_P6) down

reset-p6:
	docker compose $(COMPOSE_P6) down -v

demo-p6: up-p6 run-p6 verify-p6
	@echo "Open SOC dashboard: http://localhost:8501"

# ----------------------------
# React SOC Command Center
# ----------------------------

up-web:
	docker compose $(COMPOSE_WEB) up -d --build web

verify-web:
	@echo "== React SOC Command Center =="
	@echo "React UI:      http://localhost:8600"
	@echo "Streamlit UI:  http://localhost:8501"
	@echo "API docs:      http://localhost:8000/docs"
	@echo "== Web HTML smoke check =="
	curl -fsS http://localhost:8600 >/dev/null
	@echo "web html ok"
	@echo "== Same-origin API proxy health =="
	curl -fsS http://localhost:8600/api/health >/dev/null
	@echo "api proxy ok"

logs-web:
	docker compose $(COMPOSE_WEB) logs -f --tail=100 web api

down-web:
	docker compose $(COMPOSE_WEB) down

demo-web: demo-p6 up-web verify-web
	@echo "Open React SOC Command Center: http://localhost:8600"


# ----------------------------
# Phase 7 (WebSocket + JWT auth + incident state)
# ----------------------------

up-p7:
	docker compose $(COMPOSE_P7) up -d --build api web soc-producer dbt-refresh

init-p7:
	@echo "== Applying Phase 7 SQL migrations =="
	docker exec -i $$(docker compose $(COMPOSE_BASE) ps -q postgres) \
	  psql -U $${POSTGRES_USER:-app} -d $${POSTGRES_DB:-threat_risk} \
	  -f /docker-entrypoint-initdb.d/003_auth_schema.sql
	@if [ "$${SEED_DEMO_USERS:-true}" = "true" ]; then \
	  docker exec -e SEED_DEMO_USERS=true -i $$(docker compose $(COMPOSE_BASE) ps -q postgres) \
	    sh /docker-entrypoint-initdb.d/003b_auth_demo_seed.sh; \
	else \
	  echo "== Skipping demo users (SEED_DEMO_USERS=$${SEED_DEMO_USERS}) =="; \
	fi
	docker exec -i $$(docker compose $(COMPOSE_BASE) ps -q postgres) \
	  psql -U $${POSTGRES_USER:-app} -d $${POSTGRES_DB:-threat_risk} \
	  -f /docker-entrypoint-initdb.d/004_soc_state.sql
	docker exec -i $$(docker compose $(COMPOSE_BASE) ps -q postgres) \
	  psql -U $${POSTGRES_USER:-app} -d $${POSTGRES_DB:-threat_risk} \
	  -f /docker-entrypoint-initdb.d/005_notify_triggers.sql
	docker exec -i $$(docker compose $(COMPOSE_BASE) ps -q postgres) \
	  psql -U $${POSTGRES_USER:-app} -d $${POSTGRES_DB:-threat_risk} \
	  -f /docker-entrypoint-initdb.d/006_auth_hardening.sql

verify-p7:
	@echo "== Phase 7 service URLs =="
	@echo "SOC UI:        http://localhost:8600"
	@echo "API docs:      http://localhost:8000/docs"
	@echo "Grafana:       http://localhost:3000"
	@echo "Prefect:       http://localhost:4200"
	@echo "Redpanda:      http://localhost:8080"
	@echo ""
	@echo "== API health =="
	@curl -fsS http://localhost:8000/health | python3 -m json.tool || true
	@echo ""
	@echo "== Auth routes registered =="
	@curl -s http://localhost:8000/openapi.json | \
	  python3 -c "import json,sys; paths=json.load(sys.stdin)['paths']; [print(' ', p) for p in sorted(paths) if p.startswith('/auth') or 'state' in p]" || true
	@echo ""
	@echo "== Demo credentials =="
	@echo "  manager@soc.internal / changeme"
	@echo "  l1@soc.internal      / changeme"
	@echo "  l2@soc.internal      / changeme"
	@echo "  ciso@soc.internal    / changeme"

logs-p7:
	docker compose $(COMPOSE_P7) logs -f --tail=100 api web soc-consumer soc-producer dbt-refresh

down-p7:
	docker compose $(COMPOSE_P7) down

reset-p7:
	docker compose $(COMPOSE_P7) down -v

# ----------------------------
# Phase 8 (Live data: GitHub + Threat Intel)
# ----------------------------

up-p8:
	docker compose $(COMPOSE_P8) up -d --build threat-intel-producer github-producer

init-p8:
	@echo "== Applying Phase 8 SQL migrations =="
	docker exec -i $$(docker compose $(COMPOSE_BASE) ps -q postgres) \
	  psql -U $${POSTGRES_USER:-app} -d $${POSTGRES_DB:-threat_risk} \
	  -f /docker-entrypoint-initdb.d/007_ioc_schema.sql

verify-p8:
	@echo "== Phase 8 producer status =="
	docker compose $(COMPOSE_P8) ps threat-intel-producer github-producer
	@echo ""
	@echo "== IOC rows ingested =="
	docker exec -i $$(docker compose $(COMPOSE_BASE) ps -q postgres) \
	  psql -U $${POSTGRES_USER:-app} -d $${POSTGRES_DB:-threat_risk} \
	  -c "SELECT source, ioc_type, count(*) FROM raw.iocs GROUP BY 1,2 ORDER BY 3 DESC;" || true
	@echo ""
	@echo "== GitHub events in raw.security_events =="
	docker exec -i $$(docker compose $(COMPOSE_BASE) ps -q postgres) \
	  psql -U $${POSTGRES_USER:-app} -d $${POSTGRES_DB:-threat_risk} \
	  -c "SELECT event_type, count(*) FROM raw.security_events WHERE source_system='github' GROUP BY 1 ORDER BY 2 DESC;" || true

logs-p8:
	docker compose $(COMPOSE_P8) logs -f --tail=100 threat-intel-producer github-producer

down-p8:
	docker compose $(COMPOSE_P8) down

reset-p8:
	docker compose $(COMPOSE_P8) down -v

# ── Single-command demo entry point ──────────────────────────────────────────
# Starts the full Phase 8 stack (all phases), applies all migrations, and prints URLs.
# Use this when showing the project to someone for the first time.
demo-up:
	@echo "==> Starting threat-risk-platform (Phase 8 — full stack) ..."
	docker compose $(COMPOSE_P8) up -d
	@echo "==> Waiting for Postgres to be healthy ..."
	@until docker compose $(COMPOSE_P8) ps postgres | grep -q "healthy"; do sleep 2; done
	@echo "==> Applying all migrations (idempotent) ..."
	@$(MAKE) init-p7 --no-print-directory
	@$(MAKE) init-p8 --no-print-directory
	@echo "==> Running dbt SOC models ..."
	docker compose $(COMPOSE_P8) run --rm dbt dbt build --select tag:soc --no-partial-parse -q
	@echo ""
	@$(MAKE) verify-p7 --no-print-directory
	@echo ""
	@echo "==> Phase 8 producer status =="
	docker compose $(COMPOSE_P8) ps threat-intel-producer github-producer
	@echo ""
	@echo "==> Stack is ready. Live GitHub events and IOC enrichment are active."

demo-down:
	docker compose $(COMPOSE_P8) down
	@echo "Stack stopped. Volumes preserved — run 'make reset-p8' to wipe data."


# ----------------------------
# Utilities
# ----------------------------

psql:
	docker exec -it $$(docker compose $(COMPOSE_BASE) ps -q postgres) psql -U $${POSTGRES_USER} -d $${POSTGRES_DB}

docs-serve:
	python3 -m http.server 8080 --directory dbt/target
