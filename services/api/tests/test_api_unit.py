from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import config
from app import security
from app.main import app, get_repository
from app.security import clear_rate_limit_state


class FakeRepo:
    def health(self) -> dict[str, Any]:
        return {"db_ok": True}

    def pipeline_summary(self) -> dict[str, Any]:
        return {
            "stream_events_total": 12,
            "latest_stream_ingested_at": "2026-02-22T12:00:00+00:00",
            "stream_ingest_lag_minutes": 1.2,
            "consumer_heartbeat_lag_minutes": 0.8,
            "rows_with_kafka_metadata": 12,
            "kev_rows_total": 20,
            "kev_unique_cves": 20,
            "latest_kev_date": "2026-02-22",
            "threat_rows_total": 12,
            "latest_event_time": "2026-02-22T11:58:00+00:00",
        }

    def threat_event_trends(self, days: int) -> list[dict[str, Any]]:
        return [{"day": "2026-02-21", "event_count": days, "unique_urls": 2}]

    def kev_risk_summary(self) -> dict[str, Any]:
        return {
            "kev_total": 20,
            "unique_cves": 20,
            "first_added": "2026-01-01",
            "latest_added": "2026-02-22",
            "overdue_count": 3,
            "top_vendors": [{"vendor": "apache", "cve_count": 4}],
        }

    def top_malicious_hosts(self, days: int, limit: int) -> list[dict[str, Any]]:
        return [{"host": "evil.example", "event_count": limit + days}]

    def stream_lag_trends(self, hours: int) -> list[dict[str, Any]]:
        return [{"bucket_hour": "2026-02-22T12:00:00+00:00", "avg_event_delay_seconds": 9.5, "samples": hours}]

    def soc_risk_entities(
        self,
        limit: int = 20,
        min_score: int = 0,
        entity_type: str | None = None,
    ) -> list[dict[str, Any]]:
        _ = (limit, min_score, entity_type)
        return [
            {
                "entity_id": "user:jsmith",
                "entity_type": "user",
                "display_name": "Jordan Smith",
                "risk_score": 100,
                "risk_band": "critical",
                "last_seen_at": "2026-02-22T12:00:00+00:00",
                "top_risk_reasons": ["Privilege escalation observed"],
                "recommended_action": "Isolate entity.",
            }
        ]

    def soc_entity_timeline(self, entity_id: str) -> dict[str, Any]:
        return {"entity_id": entity_id, "timeline": [{"event_id": "evt-1"}]}

    def soc_incidents(self, limit: int = 20) -> list[dict[str, Any]]:
        _ = limit
        return [{"incident_id": "INC-PAYMENT-001", "severity": "critical", "summary": "Demo incident"}]

    def soc_triage_report(self, incident_id: str) -> dict[str, Any] | None:
        if incident_id != "INC-PAYMENT-001":
            return None
        return {
            "incident_id": incident_id,
            "severity": "critical",
            "summary": "Demo incident",
            "target_assets": ["Payment Processing Database"],
            "entities_involved": ["user:jsmith"],
            "timeline": [{"event_id": "evt-1"}],
            "mitre_techniques": ["T1078"],
            "evidence": {"event_count": 1},
            "recommended_next_steps": ["Disable sessions"],
        }

    def soc_qna_templates(self) -> list[dict[str, str]]:
        return [{"question_id": "critical_entities_now", "question": "Which entities are critical risk right now?"}]

    def soc_qna_answer(self, question_id: str) -> dict[str, Any] | None:
        if question_id != "critical_entities_now":
            return None
        return {"question_id": question_id, "question": "Which entities are critical risk right now?", "answer_rows": []}

    def soc_compliance(self, framework: str) -> dict[str, Any]:
        return {"framework": framework, "controls": [{"control_id": "10.2", "evidence_count": 3}]}

    def soc_metrics_summary(self) -> dict[str, Any]:
        return {"soc_event_freshness_minutes": 1.0, "soc_high_risk_entities": 1, "soc_critical_incidents": 1}


def _override_repo():
    yield FakeRepo()


def test_health_endpoint() -> None:
    app.dependency_overrides[get_repository] = _override_repo
    client = TestClient(app)
    resp = client.get("/health")
    app.dependency_overrides.clear()

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["db_ok"] is True
    assert "ws_clients" in body
    assert "ws_listener_ok" in body


def test_pipeline_summary_contract() -> None:
    app.dependency_overrides[get_repository] = _override_repo
    client = TestClient(app)
    resp = client.get("/v1/pipeline/summary")
    app.dependency_overrides.clear()

    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {
        "stream_events_total",
        "latest_stream_ingested_at",
        "stream_ingest_lag_minutes",
        "consumer_heartbeat_lag_minutes",
        "rows_with_kafka_metadata",
        "kev_rows_total",
        "kev_unique_cves",
        "latest_kev_date",
        "threat_rows_total",
        "latest_event_time",
    }


def test_trends_query_param_validation() -> None:
    app.dependency_overrides[get_repository] = _override_repo
    client = TestClient(app)
    valid = client.get("/v1/trends/threat-events?days=30")
    invalid = client.get("/v1/trends/threat-events?days=0")
    app.dependency_overrides.clear()

    assert valid.status_code == 200
    assert valid.json()["days"] == 30
    assert invalid.status_code == 422


def test_protected_endpoint_allows_dev_mode_without_api_key(monkeypatch) -> None:
    monkeypatch.setenv("API_AUTH_ENABLED", "false")
    app.dependency_overrides[get_repository] = _override_repo
    client = TestClient(app)
    resp = client.get("/v1/pipeline/summary")
    app.dependency_overrides.clear()

    assert resp.status_code == 200


def test_protected_endpoint_requires_api_key_in_secure_mode(monkeypatch) -> None:
    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    monkeypatch.setenv("API_KEY", "local-demo-key")
    app.dependency_overrides[get_repository] = _override_repo
    client = TestClient(app)

    missing = client.get("/v1/pipeline/summary")
    wrong = client.get("/v1/pipeline/summary", headers={"x-api-key": "wrong"})
    valid = client.get("/v1/pipeline/summary", headers={"x-api-key": "local-demo-key"})
    app.dependency_overrides.clear()

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert valid.status_code == 200


def test_health_and_metrics_remain_public_in_secure_mode(monkeypatch) -> None:
    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    monkeypatch.setenv("API_KEY", "local-demo-key")
    app.dependency_overrides[get_repository] = _override_repo
    client = TestClient(app)

    health = client.get("/health")
    metrics = client.get("/metrics")
    app.dependency_overrides.clear()

    assert health.status_code == 200
    assert metrics.status_code == 200
    assert "threat_risk_stream_ingest_lag_minutes" in metrics.text


def test_rate_limit_returns_429(monkeypatch) -> None:
    monkeypatch.setenv("API_AUTH_ENABLED", "false")
    monkeypatch.setenv("API_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("API_RATE_LIMIT_PER_MINUTE", "2")
    clear_rate_limit_state()
    app.dependency_overrides[get_repository] = _override_repo
    client = TestClient(app)

    assert client.get("/v1/pipeline/summary").status_code == 200
    assert client.get("/v1/pipeline/summary").status_code == 200
    assert client.get("/v1/pipeline/summary").status_code == 429
    clear_rate_limit_state()
    app.dependency_overrides.clear()


def test_soc_risk_entities_contract() -> None:
    app.dependency_overrides[get_repository] = _override_repo
    client = TestClient(app)
    resp = client.get("/v1/soc/risk/entities?limit=5&min_score=80")
    app.dependency_overrides.clear()

    assert resp.status_code == 200
    row = resp.json()["rows"][0]
    assert row["entity_id"] == "user:jsmith"
    assert row["risk_band"] == "critical"
    assert row["top_risk_reasons"]


def test_soc_triage_report_contract() -> None:
    app.dependency_overrides[get_repository] = _override_repo
    client = TestClient(app)
    resp = client.get("/v1/soc/incidents/INC-PAYMENT-001/triage-report")
    missing = client.get("/v1/soc/incidents/INC-NOPE/triage-report")
    app.dependency_overrides.clear()

    assert resp.status_code == 200
    body = resp.json()
    assert body["incident_id"] == "INC-PAYMENT-001"
    assert body["evidence"]["event_count"] == 1
    assert missing.status_code == 404


def test_soc_endpoints_require_api_key_in_secure_mode(monkeypatch) -> None:
    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    monkeypatch.setenv("API_KEY", "local-demo-key")
    app.dependency_overrides[get_repository] = _override_repo
    client = TestClient(app)

    missing = client.get("/v1/soc/risk/entities")
    valid = client.get("/v1/soc/risk/entities", headers={"x-api-key": "local-demo-key"})
    app.dependency_overrides.clear()

    assert missing.status_code == 401
    assert valid.status_code == 200


def test_soc_endpoints_require_jwt_when_enabled(monkeypatch) -> None:
    monkeypatch.setattr(security, "JWT_AUTH_ENABLED", True)
    monkeypatch.setattr(security, "JWT_SECRET", "x" * 48)
    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    monkeypatch.setenv("API_KEY", "local-demo-key")

    token = security.create_access_token(
        {
            "sub": "user_manager",
            "email": "manager@soc.internal",
            "role": "soc_manager",
            "display_name": "SOC Manager",
        }
    )

    app.dependency_overrides[get_repository] = _override_repo
    client = TestClient(app)

    missing = client.get("/v1/soc/risk/entities")
    api_key_only = client.get("/v1/soc/risk/entities", headers={"x-api-key": "local-demo-key"})
    bearer = client.get("/v1/soc/risk/entities", headers={"Authorization": f"Bearer {token}"})
    app.dependency_overrides.clear()

    assert missing.status_code == 401
    assert api_key_only.status_code == 401
    assert bearer.status_code == 200


def test_soc_websocket_requires_ticket_when_jwt_enabled(monkeypatch) -> None:
    monkeypatch.setattr(config, "JWT_AUTH_ENABLED", True)
    client = TestClient(app)

    try:
        with client.websocket_connect("/v1/soc/stream"):
            raise AssertionError("WebSocket connection unexpectedly opened without a ticket")
    except WebSocketDisconnect as exc:
        assert exc.code == 4001


def test_vite_dev_origin_is_allowed_by_cors() -> None:
    client = TestClient(app)
    resp = client.options(
        "/v1/soc/risk/entities",
        headers={
            "origin": "http://localhost:5173",
            "access-control-request-method": "GET",
            "access-control-request-headers": "x-api-key",
        },
    )

    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "x-api-key" in resp.headers["access-control-allow-headers"].lower()
