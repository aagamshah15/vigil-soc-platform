from __future__ import annotations

import os

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.main import app


def _dsn() -> str:
    return os.getenv("API_TEST_DATABASE_URL") or os.getenv("DATABASE_URL") or ""


def _seed_api_fixture(dsn: str) -> None:
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("create schema if not exists raw")
            cur.execute("create schema if not exists marts")
            cur.execute(
                """
                create table if not exists raw.urlhaus_events (
                  event_id text primary key,
                  event_time timestamptz,
                  ingested_at timestamptz,
                  source text,
                  url text,
                  feed text,
                  payload jsonb,
                  _consumer_ingested_at timestamptz,
                  _kafka_topic text,
                  _kafka_partition int,
                  _kafka_offset bigint,
                  inserted_at timestamptz default now()
                )
                """
            )
            cur.execute(
                """
                create table if not exists marts.fct_urlhaus_threat_events (
                  event_id text,
                  event_time timestamptz,
                  ingested_at timestamptz,
                  source text,
                  url text,
                  feed text
                )
                """
            )
            cur.execute(
                """
                create table if not exists marts.fact_kev (
                  cve_id text,
                  date_day date,
                  date_added date
                )
                """
            )
            cur.execute(
                """
                create table if not exists marts.mart_soc_entity_risk_current (
                  entity_id text,
                  entity_type text,
                  display_name text,
                  risk_score int,
                  risk_band text,
                  last_seen_at timestamptz,
                  top_risk_reasons json,
                  recommended_action text
                )
                """
            )
            cur.execute(
                """
                create table if not exists marts.mart_soc_incident_timelines (
                  incident_id text,
                  severity text,
                  summary text,
                  started_at timestamptz,
                  last_seen_at timestamptz,
                  entities_involved text[],
                  target_assets text[],
                  mitre_techniques text[],
                  timeline json,
                  recommended_next_steps text[]
                )
                """
            )
            cur.execute(
                """
                create table if not exists marts.mart_soc_qna_results (
                  question_id text,
                  question text,
                  answer_rows json
                )
                """
            )
            cur.execute(
                """
                create table if not exists marts.mart_soc_compliance_evidence (
                  framework text,
                  control_id text,
                  control_name text,
                  evidence_count int,
                  latest_evidence_at timestamptz,
                  lineage text
                )
                """
            )
            cur.execute("truncate raw.urlhaus_events")
            cur.execute("truncate marts.fct_urlhaus_threat_events")
            cur.execute("truncate marts.fact_kev")
            cur.execute("truncate marts.mart_soc_entity_risk_current")
            cur.execute("truncate marts.mart_soc_incident_timelines")
            cur.execute("truncate marts.mart_soc_qna_results")
            cur.execute("truncate marts.mart_soc_compliance_evidence")

            cur.execute(
                """
                insert into raw.urlhaus_events (
                  event_id, event_time, ingested_at, source, url, feed, payload,
                  _consumer_ingested_at, _kafka_topic, _kafka_partition, _kafka_offset
                )
                values (
                  'evt-1', now() - interval '2 minutes', now() - interval '1 minute',
                  'urlhaus', 'http://mal.example', 'urlhaus', '{}'::jsonb,
                  now() - interval '1 minute', 'threat.urlhaus.events', 0, 10
                )
                """
            )
            cur.execute(
                """
                insert into marts.fct_urlhaus_threat_events
                  (event_id, event_time, ingested_at, source, url, feed)
                values
                  ('evt-1', now() - interval '2 minutes', now() - interval '1 minute', 'urlhaus', 'http://mal.example', 'urlhaus')
                """
            )
            cur.execute(
                """
                insert into marts.fact_kev (cve_id, date_day, date_added)
                values ('CVE-2099-0001', current_date, current_date)
                """
            )
            cur.execute(
                """
                insert into marts.mart_soc_entity_risk_current
                  (entity_id, entity_type, display_name, risk_score, risk_band, last_seen_at, top_risk_reasons, recommended_action)
                values
                  ('user:jsmith', 'user', 'Jordan Smith', 100, 'critical', now(), '["Privilege escalation observed"]'::json, 'Isolate entity')
                """
            )
            cur.execute(
                """
                insert into marts.mart_soc_incident_timelines
                  (incident_id, severity, summary, started_at, last_seen_at, entities_involved, target_assets, mitre_techniques, timeline, recommended_next_steps)
                values
                  ('INC-PAYMENT-001', 'critical', 'Demo incident', now() - interval '10 minutes', now(),
                   array['user:jsmith'], array['Payment Processing Database'], array['T1078'],
                   '[{"event_id":"evt-1"}]'::json, array['Disable sessions'])
                """
            )
            cur.execute(
                """
                insert into marts.mart_soc_qna_results (question_id, question, answer_rows)
                values ('critical_entities_now', 'Which entities are critical risk right now?', '[]'::json)
                """
            )
            cur.execute(
                """
                insert into marts.mart_soc_compliance_evidence
                  (framework, control_id, control_name, evidence_count, latest_evidence_at, lineage)
                values ('PCI-DSS', '10.2', 'Track access', 1, now(), 'demo')
                """
            )
        conn.commit()


def test_health_and_summary_against_real_postgres() -> None:
    dsn = _dsn()
    if not dsn:
        pytest.skip("Set API_TEST_DATABASE_URL or DATABASE_URL to run integration test.")

    _seed_api_fixture(dsn)

    client = TestClient(app)

    health = client.get("/health")
    summary = client.get("/v1/pipeline/summary")

    assert health.status_code == 200
    assert health.json()["db_ok"] is True

    assert summary.status_code == 200
    body = summary.json()
    assert body["stream_events_total"] >= 1
    assert body["kev_rows_total"] >= 1
    assert body["threat_rows_total"] >= 1


def test_secure_mode_protected_api_access_against_real_postgres(monkeypatch) -> None:
    dsn = _dsn()
    if not dsn:
        pytest.skip("Set API_TEST_DATABASE_URL or DATABASE_URL to run integration test.")

    _seed_api_fixture(dsn)
    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    monkeypatch.setenv("API_KEY", "integration-key")
    client = TestClient(app)

    unauthorized = client.get("/v1/pipeline/summary")
    authorized = client.get("/v1/pipeline/summary", headers={"x-api-key": "integration-key"})

    assert unauthorized.status_code == 401
    assert authorized.status_code == 200


def test_soc_api_contract_against_real_postgres() -> None:
    dsn = _dsn()
    if not dsn:
        pytest.skip("Set API_TEST_DATABASE_URL or DATABASE_URL to run integration test.")

    _seed_api_fixture(dsn)
    client = TestClient(app)

    risk = client.get("/v1/soc/risk/entities")
    report = client.get("/v1/soc/incidents/INC-PAYMENT-001/triage-report")

    assert risk.status_code == 200
    assert risk.json()["rows"][0]["risk_band"] == "critical"
    assert report.status_code == 200
    assert report.json()["recommended_next_steps"] == ["Disable sessions"]
