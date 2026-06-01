from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class AnalyticsRepository:
    conn: Any

    def health(self) -> dict[str, Any]:
        with self.conn.cursor() as cur:
            cur.execute("select 1 as ok")
            row = cur.fetchone()
        return {"db_ok": bool(row and row[0] == 1)}

    def pipeline_summary(self) -> dict[str, Any]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                with stream as (
                  select
                    count(*) as stream_events_total,
                    max(ingested_at) as latest_stream_ingested_at,
                    extract(epoch from (now() - max(ingested_at))) / 60.0 as stream_ingest_lag_minutes,
                    extract(epoch from (now() - max(_consumer_ingested_at))) / 60.0 as consumer_heartbeat_lag_minutes,
                    coalesce(sum(case when _kafka_offset is not null then 1 else 0 end), 0) as rows_with_kafka_metadata
                  from raw.urlhaus_events
                ),
                kev as (
                  select
                    count(*) as kev_rows_total,
                    count(distinct cve_id) as kev_unique_cves,
                    max(date_day) as latest_kev_date
                  from marts.fact_kev
                ),
                threats as (
                  select
                    count(*) as threat_rows_total,
                    max(event_time) as latest_event_time
                  from marts.fct_urlhaus_threat_events
                )
                select
                  stream.stream_events_total,
                  stream.latest_stream_ingested_at,
                  round(coalesce(stream.stream_ingest_lag_minutes, 1e9)::numeric, 2) as stream_ingest_lag_minutes,
                  round(coalesce(stream.consumer_heartbeat_lag_minutes, 1e9)::numeric, 2) as consumer_heartbeat_lag_minutes,
                  stream.rows_with_kafka_metadata,
                  kev.kev_rows_total,
                  kev.kev_unique_cves,
                  kev.latest_kev_date,
                  threats.threat_rows_total,
                  threats.latest_event_time
                from stream, kev, threats
                """
            )
            row = cur.fetchone()

        return {
            "stream_events_total": int(row[0] or 0),
            "latest_stream_ingested_at": row[1].isoformat() if row[1] else None,
            "stream_ingest_lag_minutes": float(row[2] or 0.0),
            "consumer_heartbeat_lag_minutes": float(row[3] or 0.0),
            "rows_with_kafka_metadata": int(row[4] or 0),
            "kev_rows_total": int(row[5] or 0),
            "kev_unique_cves": int(row[6] or 0),
            "latest_kev_date": row[7].isoformat() if row[7] else None,
            "threat_rows_total": int(row[8] or 0),
            "latest_event_time": row[9].isoformat() if row[9] else None,
        }

    def threat_event_trends(self, days: int) -> list[dict[str, Any]]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                select
                  date_trunc('day', event_time)::date as day,
                  count(*) as event_count,
                  count(distinct url) as unique_urls
                from marts.fct_urlhaus_threat_events
                where event_time >= now() - (%s || ' days')::interval
                group by 1
                order by 1
                """,
                (days,),
            )
            rows = cur.fetchall()

        return [
            {
                "day": row[0].isoformat(),
                "event_count": int(row[1]),
                "unique_urls": int(row[2]),
            }
            for row in rows
        ]

    def kev_risk_summary(self) -> dict[str, Any]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                with base as (
                  select
                    count(*) as kev_total,
                    count(distinct cve_id) as unique_cves,
                    min(date_added) as first_added,
                    max(date_added) as latest_added,
                    count(*) filter (where due_date < current_date) as overdue_count
                  from marts.fact_kev
                ),
                top_vendors as (
                  select coalesce(dp.vendor_project, 'unknown') as vendor, count(*) as cve_count
                  from marts.fact_kev fk
                  left join marts.dim_product dp on fk.product_key = dp.product_key
                  group by dp.vendor_project
                  order by 2 desc, 1
                  limit 5
                )
                select
                  base.kev_total,
                  base.unique_cves,
                  base.first_added,
                  base.latest_added,
                  base.overdue_count,
                  coalesce(
                    json_agg(json_build_object('vendor', top_vendors.vendor, 'cve_count', top_vendors.cve_count))
                      filter (where top_vendors.vendor is not null),
                    '[]'::json
                  ) as top_vendors
                from base
                left join top_vendors on true
                group by 1,2,3,4,5
                """
            )
            row = cur.fetchone()

        return {
            "kev_total": int(row[0] or 0),
            "unique_cves": int(row[1] or 0),
            "first_added": row[2].isoformat() if row[2] else None,
            "latest_added": row[3].isoformat() if row[3] else None,
            "overdue_count": int(row[4] or 0),
            "top_vendors": row[5] or [],
        }

    def top_malicious_hosts(self, days: int, limit: int) -> list[dict[str, Any]]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                select
                  coalesce(
                    nullif(
                      split_part(regexp_replace(url, '^https?://', ''), '/', 1),
                      ''
                    ),
                    'unknown'
                  ) as host,
                  count(*) as event_count
                from marts.fct_urlhaus_threat_events
                where event_time >= now() - (%s || ' days')::interval
                group by 1
                order by 2 desc, 1
                limit %s
                """,
                (days, limit),
            )
            rows = cur.fetchall()

        return [{"host": row[0], "event_count": int(row[1])} for row in rows]

    def stream_lag_trends(self, hours: int) -> list[dict[str, Any]]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                select
                  date_trunc('hour', ingested_at) as bucket_hour,
                  round(avg(extract(epoch from (ingested_at - event_time)))::numeric, 2) as avg_event_delay_seconds,
                  count(*) as samples
                from raw.urlhaus_events
                where ingested_at >= now() - (%s || ' hours')::interval
                group by 1
                order by 1
                """,
                (hours,),
            )
            rows = cur.fetchall()

        return [
            {
                "bucket_hour": row[0].isoformat(),
                "avg_event_delay_seconds": float(row[1] or 0.0),
                "samples": int(row[2]),
            }
            for row in rows
        ]

    def soc_risk_entities(
        self,
        limit: int = 20,
        min_score: int = 0,
        entity_type: str | None = None,
    ) -> list[dict[str, Any]]:
        with self.conn.cursor() as cur:
            if entity_type:
                cur.execute(
                    """
                    select entity_id, entity_type, display_name, risk_score, risk_band,
                           last_seen_at, top_risk_reasons, recommended_action
                    from marts.mart_soc_entity_risk_current
                    where risk_score >= %s
                      and entity_type = %s
                    order by risk_score desc, last_seen_at desc
                    limit %s
                    """,
                    (min_score, entity_type, limit),
                )
            else:
                cur.execute(
                    """
                    select entity_id, entity_type, display_name, risk_score, risk_band,
                           last_seen_at, top_risk_reasons, recommended_action
                    from marts.mart_soc_entity_risk_current
                    where risk_score >= %s
                    order by risk_score desc, last_seen_at desc
                    limit %s
                    """,
                    (min_score, limit),
                )
            rows = cur.fetchall()

        return [
            {
                "entity_id": row[0],
                "entity_type": row[1],
                "display_name": row[2],
                "risk_score": int(row[3] or 0),
                "risk_band": row[4],
                "last_seen_at": row[5].isoformat() if row[5] else None,
                "top_risk_reasons": row[6] or [],
                "recommended_action": row[7],
            }
            for row in rows
        ]

    def soc_entity_timeline(self, entity_id: str) -> dict[str, Any]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                select event_id, event_time, source_system, event_type, action, severity,
                       asset_id, asset_name, src_ip, dest_ip, mitre_technique
                from marts.mart_soc_risk_events
                where entity_id = %s
                order by event_time
                """,
                (entity_id,),
            )
            rows = cur.fetchall()

        return {
            "entity_id": entity_id,
            "timeline": [
                {
                    "event_id": row[0],
                    "event_time": row[1].isoformat() if row[1] else None,
                    "source_system": row[2],
                    "event_type": row[3],
                    "action": row[4],
                    "severity": row[5],
                    "asset_id": row[6],
                    "asset_name": row[7],
                    "src_ip": row[8],
                    "dest_ip": row[9],
                    "mitre_technique": row[10],
                }
                for row in rows
            ],
        }

    def soc_incidents(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                select incident_id, severity, summary, started_at, last_seen_at,
                       entities_involved, target_assets, mitre_techniques
                from marts.mart_soc_incident_timelines
                order by last_seen_at desc
                limit %s
                """,
                (limit,),
            )
            rows = cur.fetchall()

        return [
            {
                "incident_id": row[0],
                "severity": row[1],
                "summary": row[2],
                "started_at": row[3].isoformat() if row[3] else None,
                "last_seen_at": row[4].isoformat() if row[4] else None,
                "entities_involved": row[5] or [],
                "target_assets": row[6] or [],
                "mitre_techniques": row[7] or [],
            }
            for row in rows
        ]

    def soc_triage_report(self, incident_id: str) -> dict[str, Any] | None:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                select incident_id, severity, summary, target_assets, entities_involved,
                       timeline, mitre_techniques, recommended_next_steps
                from marts.mart_soc_incident_timelines
                where incident_id = %s
                """,
                (incident_id,),
            )
            row = cur.fetchone()

        if not row:
            return None

        timeline = [
            self._normalize_triage_event(event, index)
            for index, event in enumerate(row[5] or [], start=1)
            if isinstance(event, dict)
        ]

        return {
            "incident_id": row[0],
            "severity": row[1],
            "summary": row[2],
            "target_assets": row[3] or [],
            "entities_involved": row[4] or [],
            "timeline": timeline,
            "mitre_techniques": row[6] or [],
            "evidence": {
                "event_count": len(timeline),
                "lineage": "raw.security_events -> stg_soc_security_events -> mart_soc_incident_timelines",
            },
            "recommended_next_steps": row[7] or [],
        }

    @staticmethod
    def _normalize_triage_event(event: dict[str, Any], index: int) -> dict[str, Any]:
        asset = event.get("asset")
        asset_id = event.get("asset_id") or asset
        return {
            "event_id": event.get("event_id") or f"triage-event-{index}",
            "event_time": event.get("event_time"),
            "source_system": event.get("source_system"),
            "event_type": event.get("event_type"),
            "entity_id": event.get("entity_id"),
            "display_name": event.get("display_name"),
            "action": event.get("action"),
            "severity": event.get("severity"),
            "asset": asset,
            "asset_id": asset_id,
            "asset_name": event.get("asset_name") or asset,
            "src_ip": event.get("src_ip"),
            "dest_ip": event.get("dest_ip"),
            "mitre_technique": event.get("mitre_technique"),
            "rule_explanation": event.get("rule_explanation"),
        }

    def soc_qna_templates(self) -> list[dict[str, str]]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                select question_id, question
                from marts.mart_soc_qna_results
                order by question_id
                """
            )
            rows = cur.fetchall()

        return [{"question_id": row[0], "question": row[1]} for row in rows]

    def soc_qna_answer(self, question_id: str) -> dict[str, Any] | None:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                select question_id, question, coalesce(answer_rows, '[]'::json) as answer_rows
                from marts.mart_soc_qna_results
                where question_id = %s
                """,
                (question_id,),
            )
            row = cur.fetchone()

        if not row:
            return None
        return {"question_id": row[0], "question": row[1], "answer_rows": row[2] or []}

    def soc_compliance(self, framework: str) -> dict[str, Any]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                select framework, control_id, control_name, evidence_count,
                       latest_evidence_at, lineage
                from marts.mart_soc_compliance_evidence
                where replace(replace(lower(framework), ' ', ''), '-', '') =
                      replace(replace(lower(%s), ' ', ''), '-', '')
                order by control_id
                """,
                (framework,),
            )
            rows = cur.fetchall()

        return {
            "framework": framework,
            "controls": [
                {
                    "framework": row[0],
                    "control_id": row[1],
                    "control_name": row[2],
                    "evidence_count": int(row[3] or 0),
                    "latest_evidence_at": row[4].isoformat() if row[4] else None,
                    "lineage": row[5],
                }
                for row in rows
            ],
        }

    def soc_metrics_summary(self) -> dict[str, Any]:
        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    """
                    select
                      round(coalesce(extract(epoch from (now() - max(ingested_at))) / 60.0, 0)::numeric, 2),
                      (select count(*) from marts.mart_soc_entity_risk_current where risk_band in ('high', 'critical')),
                      (select count(*) from marts.mart_soc_incident_timelines where severity = 'critical')
                    from raw.security_events
                    """
                )
                row = cur.fetchone()
        except Exception:
            return {
                "soc_event_freshness_minutes": 0.0,
                "soc_high_risk_entities": 0,
                "soc_critical_incidents": 0,
            }

        return {
            "soc_event_freshness_minutes": float(row[0] or 0.0),
            "soc_high_risk_entities": int(row[1] or 0),
            "soc_critical_incidents": int(row[2] or 0),
        }
