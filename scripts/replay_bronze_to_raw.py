from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from minio import Minio
import psycopg2
from psycopg2.extras import execute_values

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "lake")
MINIO_PREFIX = os.getenv("MINIO_PREFIX", "urlhaus/events")
REPLAY_LIMIT = int(os.getenv("REPLAY_LIMIT", "0"))

PG_HOST = os.getenv("POSTGRES_HOST", "postgres")
PG_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
PG_DB = os.getenv("POSTGRES_DB", "threat_risk")
PG_USER = os.getenv("POSTGRES_USER", "app")
PG_PASSWORD = os.getenv("POSTGRES_PASSWORD", "app")

UPSERT_SQL = """
INSERT INTO raw.urlhaus_events (
  event_id, event_time, ingested_at, source, url, feed, payload,
  _consumer_ingested_at, _kafka_topic, _kafka_partition, _kafka_offset
)
VALUES %s
ON CONFLICT (event_id) DO UPDATE SET
  ingested_at = EXCLUDED.ingested_at,
  payload = EXCLUDED.payload,
  _consumer_ingested_at = EXCLUDED._consumer_ingested_at,
  _kafka_topic = EXCLUDED._kafka_topic,
  _kafka_partition = EXCLUDED._kafka_partition,
  _kafka_offset = EXCLUDED._kafka_offset
;
"""


def normalize(record: dict) -> tuple:
    payload = record.get("payload", {})
    if not isinstance(payload, dict):
        payload = {}
    now = datetime.now(timezone.utc).isoformat()
    return (
        record.get("event_id"),
        record.get("event_time") or record.get("ingested_at") or now,
        record.get("ingested_at") or now,
        record.get("source") or "urlhaus",
        payload.get("url") or record.get("url"),
        payload.get("feed") or record.get("feed"),
        json.dumps(payload),
        record.get("_consumer_ingested_at") or now,
        record.get("_kafka_topic"),
        record.get("_kafka_partition"),
        record.get("_kafka_offset"),
    )


def main() -> None:
    minio = Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False,
    )
    rows = []
    objects = minio.list_objects(MINIO_BUCKET, prefix=MINIO_PREFIX, recursive=True)
    for obj in objects:
        if not obj.object_name.endswith(".jsonl"):
            continue
        response = minio.get_object(MINIO_BUCKET, obj.object_name)
        try:
            for line in response.stream(32 * 1024):
                for item in line.decode("utf-8").splitlines():
                    if item.strip():
                        rows.append(normalize(json.loads(item)))
                        if REPLAY_LIMIT and len(rows) >= REPLAY_LIMIT:
                            break
                if REPLAY_LIMIT and len(rows) >= REPLAY_LIMIT:
                    break
        finally:
            response.close()
            response.release_conn()
        if REPLAY_LIMIT and len(rows) >= REPLAY_LIMIT:
            break

    if not rows:
        print("No bronze stream events found to replay.")
        return

    with psycopg2.connect(host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASSWORD) as conn:
        with conn.cursor() as cur:
            execute_values(cur, UPSERT_SQL, rows, page_size=1000)
        conn.commit()

    print(f"Replayed {len(rows)} bronze events into raw.urlhaus_events.")


if __name__ == "__main__":
    main()
