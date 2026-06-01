import json
import os
import subprocess
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import psycopg2
from kafka import KafkaAdminClient, KafkaConsumer, TopicPartition
from prefect import flow, get_run_logger, task
from prefect.context import get_run_context


PROJECT_ROOT = Path("/opt/project")
ELT_DIR = PROJECT_ROOT / "elt"
DBT_DIR = PROJECT_ROOT / "dbt"
ARTIFACT_ROOT = PROJECT_ROOT / "artifacts" / "p3_runs"


@dataclass
class StreamHealth:
    topic: str
    partitions: int
    kafka_lag: int
    ingest_lag_minutes: float
    consumer_seen_recently: bool


def _env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def _base_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("POSTGRES_HOST", "postgres")
    env.setdefault("POSTGRES_PORT", "5432")
    env.setdefault("POSTGRES_DB", "threat_risk")
    env.setdefault("POSTGRES_USER", "app")
    env.setdefault("POSTGRES_PASSWORD", "app")
    env.setdefault("MINIO_ENDPOINT", "http://minio:9000")
    env.setdefault("MINIO_ACCESS_KEY", "minioadmin")
    env.setdefault("MINIO_SECRET_KEY", "minioadmin123")
    env.setdefault("MINIO_BUCKET", "lake")
    env.setdefault("BOOTSTRAP_SERVERS", "redpanda:9092")
    env.setdefault("TOPIC", "threat.urlhaus.events")
    env.setdefault("GROUP_ID", "threat-risk-consumer")
    env.setdefault("DBT_PROFILES_DIR", str(DBT_DIR))
    return env


def _pg_connect():
    return psycopg2.connect(
        host=_env("POSTGRES_HOST", "postgres"),
        port=int(_env("POSTGRES_PORT", "5432")),
        dbname=_env("POSTGRES_DB", "threat_risk"),
        user=_env("POSTGRES_USER", "app"),
        password=_env("POSTGRES_PASSWORD", "app"),
    )


def _run_cmd(cmd: list[str], cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, env=env, check=True, text=True, capture_output=True)


def _date_range(run_date: str, backfill_start: str | None, backfill_end: str | None) -> list[str]:
    if not backfill_start and not backfill_end:
        return [run_date]

    if not backfill_start or not backfill_end:
        raise ValueError("backfill_start and backfill_end must both be set for a backfill run")

    start = date.fromisoformat(backfill_start)
    end = date.fromisoformat(backfill_end)
    if start > end:
        raise ValueError("backfill_start cannot be after backfill_end")

    current = start
    dates: list[str] = []
    while current <= end:
        dates.append(current.isoformat())
        current += timedelta(days=1)
    return dates


@task(name="phase1-batch-elt", retries=2, retry_delay_seconds=30)
def run_batch_elt(run_dates: list[str]) -> dict[str, Any]:
    logger = get_run_logger()
    env = _base_env()
    outputs: list[dict[str, Any]] = []

    for run_date in run_dates:
        env["RUN_DATE"] = run_date
        logger.info("Running batch ELT for run_date=%s", run_date)
        result = _run_cmd(["python", "run.py"], cwd=ELT_DIR, env=env)
        output = result.stdout.strip()
        parsed = None
        if output:
            try:
                parsed = json.loads(output)
            except json.JSONDecodeError:
                parsed = {"raw_output": output}

        outputs.append({"run_date": run_date, "result": parsed})
        logger.info("Batch ELT completed for run_date=%s", run_date)

    return {"processed_dates": run_dates, "results": outputs}


@task(name="stream-topic-check", retries=2, retry_delay_seconds=15)
def check_stream_topic_exists() -> dict[str, Any]:
    logger = get_run_logger()
    topic = _env("TOPIC", "threat.urlhaus.events")
    bootstrap = _env("BOOTSTRAP_SERVERS", "redpanda:9092")

    admin = KafkaAdminClient(bootstrap_servers=bootstrap, client_id="p3-topic-check")
    try:
        topics = set(admin.list_topics())
    finally:
        admin.close()

    if topic not in topics:
        raise RuntimeError(f"Topic '{topic}' does not exist")

    logger.info("Topic check passed: %s exists", topic)
    return {"topic": topic, "exists": True}


@task(name="stream-health-check", retries=2, retry_delay_seconds=15)
def check_stream_health(max_kafka_lag: int, max_ingest_lag_minutes: int) -> dict[str, Any]:
    logger = get_run_logger()
    topic = _env("TOPIC", "threat.urlhaus.events")
    group_id = _env("GROUP_ID", "threat-risk-consumer")
    bootstrap = _env("BOOTSTRAP_SERVERS", "redpanda:9092")

    consumer = KafkaConsumer(bootstrap_servers=bootstrap, group_id=group_id, enable_auto_commit=False)
    try:
        partitions = consumer.partitions_for_topic(topic)
        if not partitions:
            raise RuntimeError(f"No partitions found for topic '{topic}'")

        topic_partitions = [TopicPartition(topic, p) for p in partitions]
        end_offsets = consumer.end_offsets(topic_partitions)
        committed = {tp: (consumer.committed(tp) or 0) for tp in topic_partitions}
        kafka_lag = sum(max(0, end_offsets[tp] - committed[tp]) for tp in topic_partitions)
    finally:
        consumer.close()

    with _pg_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                  extract(epoch from (now() - max(ingested_at))) / 60.0 as ingest_lag_minutes,
                  extract(epoch from (now() - max(_consumer_ingested_at))) / 60.0 as consumer_seen_minutes
                from raw.urlhaus_events
                """
            )
            row = cur.fetchone()

    ingest_lag = float(row[0]) if row and row[0] is not None else float("inf")
    consumer_seen_minutes = float(row[1]) if row and row[1] is not None else float("inf")
    consumer_seen_recently = consumer_seen_minutes <= max_ingest_lag_minutes

    if kafka_lag > max_kafka_lag:
        raise RuntimeError(f"Kafka lag {kafka_lag} exceeds threshold {max_kafka_lag}")
    if ingest_lag > max_ingest_lag_minutes:
        raise RuntimeError(
            f"Streaming ingest lag {ingest_lag:.2f} minutes exceeds threshold {max_ingest_lag_minutes}"
        )
    if not consumer_seen_recently:
        raise RuntimeError(
            f"Consumer heartbeat lag {consumer_seen_minutes:.2f} minutes exceeds threshold {max_ingest_lag_minutes}"
        )

    health = StreamHealth(
        topic=topic,
        partitions=len(partitions),
        kafka_lag=kafka_lag,
        ingest_lag_minutes=ingest_lag,
        consumer_seen_recently=consumer_seen_recently,
    )

    logger.info(
        "Stream health passed | partitions=%s kafka_lag=%s ingest_lag_minutes=%.2f",
        health.partitions,
        health.kafka_lag,
        health.ingest_lag_minutes,
    )

    return {
        "topic": health.topic,
        "partitions": health.partitions,
        "kafka_lag": health.kafka_lag,
        "ingest_lag_minutes": round(health.ingest_lag_minutes, 2),
        "consumer_seen_recently": health.consumer_seen_recently,
    }


@task(name="dbt-build", retries=1, retry_delay_seconds=20)
def run_dbt_build() -> dict[str, Any]:
    logger = get_run_logger()
    env = _base_env()
    result = _run_cmd(["dbt", "build"], cwd=DBT_DIR, env=env)
    logger.info("dbt build completed")
    return {"stdout": result.stdout[-4000:], "stderr": result.stderr[-4000:]}


@task(name="dbt-test", retries=1, retry_delay_seconds=20)
def run_dbt_test() -> dict[str, Any]:
    logger = get_run_logger()
    env = _base_env()
    result = subprocess.run(
        ["dbt", "test"],
        cwd=DBT_DIR,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )

    run_results_path = DBT_DIR / "target" / "run_results.json"
    summary = {
        "total": 0,
        "pass": 0,
        "warn": 0,
        "error": 0,
        "failures": [],
    }

    if run_results_path.exists():
        with run_results_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        results = data.get("results", [])
        summary["total"] = len(results)

        for item in results:
            status = item.get("status", "unknown")
            unique_id = item.get("unique_id", "unknown")
            if status == "pass":
                summary["pass"] += 1
            elif status == "warn":
                summary["warn"] += 1
            else:
                summary["error"] += 1
                summary["failures"].append(unique_id)

    logger.info(
        "dbt test summary | total=%s pass=%s warn=%s error=%s",
        summary["total"],
        summary["pass"],
        summary["warn"],
        summary["error"],
    )
    if summary["failures"] or result.returncode != 0:
        logger.error("Failing dbt tests: %s", ", ".join(summary["failures"]))
        raise RuntimeError("dbt tests reported failures")

    return {
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
        "summary": summary,
    }


@task(name="row-count-guardrails")
def run_row_count_guardrails(run_dates: list[str], min_rows_per_run_date: int, max_daily_change_ratio: float) -> dict[str, Any]:
    logger = get_run_logger()
    checks: dict[str, Any] = {}

    with _pg_connect() as conn:
        with conn.cursor() as cur:
            for run_date in run_dates:
                cur.execute("select count(*) from raw.kev where run_date = %s", (run_date,))
                kev_count = int(cur.fetchone()[0])
                if kev_count < min_rows_per_run_date:
                    raise RuntimeError(f"raw.kev rows for {run_date} below threshold: {kev_count}")

                cur.execute("select count(*) from raw.urlhaus_recent where run_date = %s", (run_date,))
                urlhaus_count = int(cur.fetchone()[0])
                if urlhaus_count < min_rows_per_run_date:
                    raise RuntimeError(f"raw.urlhaus_recent rows for {run_date} below threshold: {urlhaus_count}")

                checks[run_date] = {
                    "raw_kev_count": kev_count,
                    "raw_urlhaus_recent_count": urlhaus_count,
                }

            cur.execute(
                """
                with daily as (
                  select date_trunc('day', ingested_at)::date as d, count(*) as c
                  from raw.urlhaus_events
                  group by 1
                ), ranked as (
                  select d, c, lag(c) over (order by d) as prev_c
                  from daily
                )
                select d, c, prev_c
                from ranked
                where prev_c is not null
                order by d desc
                limit 1
                """
            )
            latest = cur.fetchone()

    if latest:
        day, current_count, previous_count = latest
        if previous_count and previous_count > 0:
            ratio = float(current_count) / float(previous_count)
            min_ratio = 1.0 / max_daily_change_ratio
            max_ratio = max_daily_change_ratio
            if ratio < min_ratio or ratio > max_ratio:
                raise RuntimeError(
                    "Daily stream row count anomaly detected: "
                    f"{current_count} vs {previous_count} ({ratio:.2f}x), "
                    f"allowed range [{min_ratio:.2f}x, {max_ratio:.2f}x]"
                )
            checks["latest_daily_stream_ratio"] = {
                "date": str(day),
                "current": int(current_count),
                "previous": int(previous_count),
                "ratio": round(ratio, 2),
            }

    logger.info("Row-count guardrails passed")
    return checks


@task(name="write-observability-artifacts")
def write_observability_artifacts(
    flow_run_id: str,
    run_dates: list[str],
    batch_result: dict[str, Any],
    topic_result: dict[str, Any],
    stream_result: dict[str, Any],
    dbt_build_result: dict[str, Any],
    dbt_test_result: dict[str, Any],
    row_count_result: dict[str, Any],
) -> dict[str, str]:
    logger = get_run_logger()
    run_id = flow_run_id or datetime.now(timezone.utc).strftime("manual-%Y%m%d%H%M%S")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = ARTIFACT_ROOT / f"{timestamp}_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "run_id": run_id,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "run_dates": run_dates,
        "batch": batch_result,
        "stream_topic": topic_result,
        "stream_health": stream_result,
        "dbt_test_summary": dbt_test_result.get("summary", {}),
        "row_count_guardrails": row_count_result,
    }

    summary_json_path = out_dir / "summary.json"
    with summary_json_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    md_lines = [
        "# Phase 3 Run Summary",
        "",
        f"- run_id: `{run_id}`",
        f"- generated_at_utc: `{summary['generated_at_utc']}`",
        f"- run_dates: `{', '.join(run_dates)}`",
        "",
        "## Streaming",
        f"- topic: `{stream_result.get('topic')}`",
        f"- partitions: `{stream_result.get('partitions')}`",
        f"- kafka_lag: `{stream_result.get('kafka_lag')}`",
        f"- ingest_lag_minutes: `{stream_result.get('ingest_lag_minutes')}`",
        "",
        "## dbt Tests",
        f"- total: `{dbt_test_result.get('summary', {}).get('total', 0)}`",
        f"- pass: `{dbt_test_result.get('summary', {}).get('pass', 0)}`",
        f"- warn: `{dbt_test_result.get('summary', {}).get('warn', 0)}`",
        f"- error: `{dbt_test_result.get('summary', {}).get('error', 0)}`",
        "",
        "## Row Count Guardrails",
        "```json",
        json.dumps(row_count_result, indent=2),
        "```",
    ]

    summary_md_path = out_dir / "summary.md"
    summary_md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    logger.info("Observability artifacts written to %s", out_dir)
    return {"summary_json": str(summary_json_path), "summary_md": str(summary_md_path)}


@flow(name="p3-threat-risk-pipeline")
def p3_pipeline_flow(
    run_date: str = date.today().isoformat(),
    backfill_start: str | None = None,
    backfill_end: str | None = None,
    max_kafka_lag: int = 10000,
    max_ingest_lag_minutes: int = 15,
    min_rows_per_run_date: int = 1,
    max_daily_change_ratio: float = 20.0,
) -> dict[str, Any]:
    logger = get_run_logger()
    flow_context = get_run_context()
    current_flow_run_id = str(flow_context.flow_run.id) if flow_context and flow_context.flow_run else ""
    run_dates = _date_range(run_date, backfill_start, backfill_end)

    logger.info("Starting Phase 3 pipeline | run_dates=%s", run_dates)

    batch_result = run_batch_elt(run_dates)

    topic_result = check_stream_topic_exists()
    stream_result = check_stream_health(max_kafka_lag=max_kafka_lag, max_ingest_lag_minutes=max_ingest_lag_minutes)

    dbt_build_result = run_dbt_build(wait_for=[batch_result, topic_result, stream_result])
    dbt_test_result = run_dbt_test(wait_for=[dbt_build_result])

    row_count_result = run_row_count_guardrails(
        run_dates=run_dates,
        min_rows_per_run_date=min_rows_per_run_date,
        max_daily_change_ratio=max_daily_change_ratio,
        wait_for=[dbt_test_result],
    )

    artifact_result = write_observability_artifacts(
        flow_run_id=current_flow_run_id,
        run_dates=run_dates,
        batch_result=batch_result,
        topic_result=topic_result,
        stream_result=stream_result,
        dbt_build_result=dbt_build_result,
        dbt_test_result=dbt_test_result,
        row_count_result=row_count_result,
        wait_for=[row_count_result],
    )

    logger.info("Phase 3 pipeline completed successfully")
    return {
        "run_dates": run_dates,
        "artifacts": artifact_result,
        "dbt_test_summary": dbt_test_result.get("summary", {}),
    }


if __name__ == "__main__":
    p3_pipeline_flow()
