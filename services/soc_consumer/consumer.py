from __future__ import annotations

import io
import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import psycopg2
from kafka import KafkaConsumer
from minio import Minio
from psycopg2.extras import execute_values

BOOTSTRAP = os.getenv("BOOTSTRAP_SERVERS", "redpanda:9092")
TOPIC = os.getenv("SOC_TOPIC", "security.events")
GROUP_ID = os.getenv("SOC_GROUP_ID", "soc-risk-consumer")

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "lake")
MINIO_PREFIX = os.getenv("SOC_MINIO_PREFIX", "soc/security_events")

PG_HOST = os.getenv("POSTGRES_HOST", "postgres")
PG_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
PG_DB = os.getenv("POSTGRES_DB", "threat_risk")
PG_USER = os.getenv("POSTGRES_USER", "app")
PG_PASSWORD = os.getenv("POSTGRES_PASSWORD", "app")

BATCH_SIZE = int(os.getenv("SOC_EVENT_BATCH_SIZE", "200"))
BATCH_SECONDS = int(os.getenv("SOC_BATCH_SECONDS", "2"))

UPSERT_SQL = """
INSERT INTO raw.security_events (
  event_id, event_time, ingested_at, source_system, event_type,
  entity_id, entity_type, display_name, user_id, device_id, src_ip, dest_ip,
  asset_id, action, severity, mitre_technique, payload,
  _consumer_ingested_at, _kafka_topic, _kafka_partition, _kafka_offset
)
VALUES %s
ON CONFLICT (event_id) DO UPDATE SET
  event_time = EXCLUDED.event_time,
  ingested_at = EXCLUDED.ingested_at,
  source_system = EXCLUDED.source_system,
  event_type = EXCLUDED.event_type,
  entity_id = EXCLUDED.entity_id,
  entity_type = EXCLUDED.entity_type,
  display_name = EXCLUDED.display_name,
  user_id = EXCLUDED.user_id,
  device_id = EXCLUDED.device_id,
  src_ip = EXCLUDED.src_ip,
  dest_ip = EXCLUDED.dest_ip,
  asset_id = EXCLUDED.asset_id,
  action = EXCLUDED.action,
  severity = EXCLUDED.severity,
  mitre_technique = EXCLUDED.mitre_technique,
  payload = EXCLUDED.payload,
  _consumer_ingested_at = EXCLUDED._consumer_ingested_at,
  _kafka_topic = EXCLUDED._kafka_topic,
  _kafka_partition = EXCLUDED._kafka_partition,
  _kafka_offset = EXCLUDED._kafka_offset
;
"""


def pg_connect():
    return psycopg2.connect(host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASSWORD)


def ensure_schema() -> None:
    with pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("create schema if not exists raw")
            cur.execute(
                """
                create table if not exists raw.security_events (
                  event_id text primary key,
                  event_time timestamptz not null,
                  ingested_at timestamptz not null default now(),
                  source_system text not null,
                  event_type text not null,
                  entity_id text not null,
                  entity_type text not null,
                  display_name text,
                  user_id text,
                  device_id text,
                  src_ip text,
                  dest_ip text,
                  asset_id text,
                  action text not null,
                  severity text not null,
                  mitre_technique text,
                  payload jsonb not null default '{}'::jsonb,
                  _consumer_ingested_at timestamptz,
                  _kafka_topic text,
                  _kafka_partition integer,
                  _kafka_offset bigint,
                  inserted_at timestamptz not null default now()
                )
                """
            )
            cur.execute("create index if not exists idx_raw_security_events_event_time on raw.security_events (event_time)")
            cur.execute("create index if not exists idx_raw_security_events_entity on raw.security_events (entity_id)")
        conn.commit()


def ensure_bucket(minio: Minio, bucket: str) -> None:
    if not minio.bucket_exists(bucket):
        minio.make_bucket(bucket)
        print(f"[soc-consumer] created bucket: {bucket}")


def write_jsonl_to_minio(minio: Minio, records: list[dict[str, Any]]) -> str:
    now = datetime.now(timezone.utc)
    key = f"{MINIO_PREFIX}/dt={now:%Y-%m-%d}/hour={now:%H}/batch_{uuid.uuid4().hex}.jsonl"
    for record in records:
        record["_consumer_ingested_at"] = now.isoformat()
    data = ("\n".join(json.dumps(record) for record in records) + "\n").encode("utf-8")
    minio.put_object(MINIO_BUCKET, key, io.BytesIO(data), length=len(data), content_type="application/json")
    return key


def normalize(record: dict[str, Any]) -> tuple:
    payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
    now = datetime.now(timezone.utc).isoformat()
    return (
        record.get("event_id"),
        record.get("event_time") or now,
        record.get("ingested_at") or now,
        record.get("source_system") or "unknown",
        record.get("event_type") or "unknown",
        record.get("entity_id") or "unknown",
        record.get("entity_type") or "unknown",
        record.get("display_name"),
        record.get("user_id"),
        record.get("device_id"),
        record.get("src_ip"),
        record.get("dest_ip"),
        record.get("asset_id"),
        record.get("action") or "unknown",
        record.get("severity") or "low",
        record.get("mitre_technique"),
        json.dumps(payload),
        record.get("_consumer_ingested_at") or now,
        record.get("_kafka_topic"),
        record.get("_kafka_partition"),
        record.get("_kafka_offset"),
    )


def upsert_to_postgres(records: list[dict[str, Any]]) -> None:
    with pg_connect() as conn:
        with conn.cursor() as cur:
            execute_values(cur, UPSERT_SQL, [normalize(record) for record in records], page_size=1000)
        conn.commit()


print(f"[soc-consumer] starting | bootstrap={BOOTSTRAP} topic={TOPIC} group={GROUP_ID}")
ensure_schema()
minio = Minio(MINIO_ENDPOINT, access_key=MINIO_ACCESS_KEY, secret_key=MINIO_SECRET_KEY, secure=False)
ensure_bucket(minio, MINIO_BUCKET)

consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers=BOOTSTRAP,
    group_id=GROUP_ID,
    auto_offset_reset="earliest",
    enable_auto_commit=False,
    value_deserializer=lambda b: json.loads(b.decode("utf-8")),
)

buffer: list[dict[str, Any]] = []
last_flush = time.time()

while True:
    msg_pack = consumer.poll(timeout_ms=1000)
    now = time.time()
    for _tp, messages in msg_pack.items():
        for message in messages:
            value = message.value
            value["_kafka_topic"] = message.topic
            value["_kafka_partition"] = message.partition
            value["_kafka_offset"] = message.offset
            buffer.append(value)

    if len(buffer) >= BATCH_SIZE or (buffer and now - last_flush >= BATCH_SECONDS):
        try:
            key = write_jsonl_to_minio(minio, buffer)
            upsert_to_postgres(buffer)
            consumer.commit()
            print(f"[soc-consumer] wrote {len(buffer)} -> s3://{MINIO_BUCKET}/{key}; committed offsets")
            buffer.clear()
            last_flush = now
        except Exception as exc:
            print(f"[soc-consumer] ERROR during flush: {type(exc).__name__}: {exc}")
            time.sleep(2)
