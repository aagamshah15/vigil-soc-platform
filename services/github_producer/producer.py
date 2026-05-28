"""
Phase 8A – GitHub Events Producer
====================================
Polls the GitHub Events API for the authenticated user and maps real activity
into the SOC security.events schema. Publishes to Redpanda (Kafka) so events
flow through the full pipeline: Kafka → soc-consumer → raw.security_events → dbt.

Event mappings (GitHub type → SOC event_type / severity):
  PushEvent          → code_push           low
  PullRequestEvent   → pr_activity         low
  CreateEvent        → asset_created       low      (branch, tag, or repo)
  DeleteEvent        → asset_deleted       medium   (branch/tag removed)
  ForkEvent          → repo_forked         high     (data exfiltration risk)
  PublicEvent        → repo_exposed        critical (private → public)
  MemberEvent        → member_change       high     (collaborator added/removed)
  ReleaseEvent       → release_published   low
  IssuesEvent        → issue_activity      low
  WatchEvent         → (skipped — star events, no security value)

State: last processed event_id persisted to raw.producer_offsets in Postgres
to avoid re-emitting events across restarts and container replacements.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

import psycopg2
import requests
from kafka import KafkaProducer

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("github_producer")

# ── Config ────────────────────────────────────────────────────────────────────
GH_TOKEN       = os.getenv("GITHUB_TOKEN", "")
GH_USERNAME    = os.getenv("GITHUB_USERNAME", "")
BOOTSTRAP      = os.getenv("BOOTSTRAP_SERVERS", "redpanda:9092")
TOPIC          = os.getenv("SOC_TOPIC", "security.events")
POLL_SECONDS   = int(os.getenv("GITHUB_POLL_SECONDS", "60"))
POSTGRES_HOST  = os.getenv("POSTGRES_HOST", "postgres")
POSTGRES_PORT  = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB    = os.getenv("POSTGRES_DB", "threat_risk")
POSTGRES_USER  = os.getenv("POSTGRES_USER", "app")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "app")

GH_API         = "https://api.github.com"
SESSION        = requests.Session()
SESSION.headers.update({
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "threat-risk-platform/8a",
})
if GH_TOKEN:
    SESSION.headers["Authorization"] = f"Bearer {GH_TOKEN}"

# ── Event type mapping ────────────────────────────────────────────────────────
# (soc_event_type, severity, mitre_technique | None)
_TYPE_MAP: dict[str, tuple[str, str, str | None]] = {
    "PushEvent":         ("code_push",          "low",      "T1505"),
    "PullRequestEvent":  ("pr_activity",         "low",      None),
    "CreateEvent":       ("asset_created",        "low",      None),
    "DeleteEvent":       ("asset_deleted",        "medium",   "T1485"),
    "ForkEvent":         ("repo_forked",          "high",     "T1213"),
    "PublicEvent":       ("repo_exposed",         "critical", "T1213"),
    "MemberEvent":       ("member_change",        "high",     "T1136"),
    "ReleaseEvent":      ("release_published",    "low",      None),
    "IssuesEvent":       ("issue_activity",       "low",      None),
    "PullRequestReviewEvent": ("pr_review",       "low",      None),
}

_SKIP_TYPES = {"WatchEvent", "StarEvent", "GollumEvent"}


# ── State persistence ─────────────────────────────────────────────────────────

def _connect_pg():
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
    )


def _ensure_offsets_table(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS raw.producer_offsets (
                source       TEXT NOT NULL,
                stream_id    TEXT NOT NULL,
                last_seen_id TEXT NOT NULL,
                updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
                PRIMARY KEY (source, stream_id)
            )
            """
        )
    conn.commit()


def _load_last_id(conn, username: str) -> str | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT last_seen_id FROM raw.producer_offsets WHERE source = 'github' AND stream_id = %s",
            (username,),
        )
        row = cur.fetchone()
    return row[0] if row else None


def _save_last_id(conn, username: str, event_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO raw.producer_offsets (source, stream_id, last_seen_id, updated_at)
            VALUES ('github', %s, %s, now())
            ON CONFLICT (source, stream_id) DO UPDATE
            SET last_seen_id = EXCLUDED.last_seen_id,
                updated_at = now()
            """,
            (username, event_id),
        )
    conn.commit()


# ── Event normalisation ───────────────────────────────────────────────────────

def _map_event(event: dict[str, Any], username: str) -> dict[str, Any] | None:
    gh_type = event.get("type", "")
    if gh_type in _SKIP_TYPES:
        return None

    mapping = _TYPE_MAP.get(gh_type)
    if mapping is None:
        return None   # unmapped type — skip rather than emit noise

    soc_type, severity, mitre = mapping
    repo    = event.get("repo", {})
    actor   = event.get("actor", {})
    payload = event.get("payload", {})
    created = event.get("created_at", datetime.now(timezone.utc).isoformat())

    repo_name  = repo.get("name", "unknown")          # "owner/repo"
    repo_short = repo_name.split("/")[-1]
    actor_login = actor.get("login", username)

    # Build the action string from the payload (richer than the GH type alone)
    action = _action_from_payload(gh_type, payload)

    # Boost severity for direct pushes to main/master/protected branches
    if gh_type == "PushEvent":
        ref = payload.get("ref", "")
        if any(b in ref for b in ("main", "master", "prod", "release")):
            severity = "medium"
            mitre    = "T1505"
        if payload.get("forced"):
            severity = "high"
            action   = "force_push"

    entity_id   = f"repo:{repo_name}"
    entity_type = "repository"

    return {
        "schema_version": 1,
        "event_id":     f"github-{event['id']}",
        "event_time":   created,
        "ingested_at":  datetime.now(timezone.utc).isoformat(),
        "source_system": "github",
        "event_type":   soc_type,
        "entity_id":    entity_id,
        "entity_type":  entity_type,
        "display_name": repo_short,
        "user_id":      actor_login,
        "device_id":    None,
        "src_ip":       None,
        "dest_ip":      None,
        "asset_id":     repo_name,
        "action":       action,
        "severity":     severity,
        "mitre_technique": mitre,
        "payload": {
            "incident_id":  "GH-LIVE",
            "scenario":     "github_activity",
            "gh_type":      gh_type,
            "repo":         repo_name,
            "actor":        actor_login,
            "ref":          payload.get("ref"),
            "pr_number":    payload.get("number"),
            "forced":       payload.get("forced", False),
            "commits":      payload.get("size"),           # PushEvent commit count
            "action":       payload.get("action"),
        },
    }


def _action_from_payload(gh_type: str, payload: dict) -> str:
    sub = payload.get("action", "")
    return {
        "PushEvent":         "push",
        "PullRequestEvent":  f"pr_{sub}" if sub else "pr_activity",
        "CreateEvent":       f"create_{payload.get('ref_type','ref')}",
        "DeleteEvent":       f"delete_{payload.get('ref_type','ref')}",
        "ForkEvent":         "fork",
        "PublicEvent":       "made_public",
        "MemberEvent":       f"member_{sub}" if sub else "member_change",
        "ReleaseEvent":      "release",
        "IssuesEvent":       f"issue_{sub}" if sub else "issue_activity",
        "PullRequestReviewEvent": f"pr_review_{sub}" if sub else "pr_review",
    }.get(gh_type, "unknown")


# ── Fetch + publish ───────────────────────────────────────────────────────────

def poll_and_publish(producer: KafkaProducer, username: str) -> int:
    with _connect_pg() as conn:
        _ensure_offsets_table(conn)
        last_id = _load_last_id(conn, username)

    try:
        resp = SESSION.get(
            f"{GH_API}/users/{username}/events",
            params={"per_page": 100},
            timeout=20,
        )
        resp.raise_for_status()
        events = resp.json()
    except Exception as exc:
        log.warning("[github] fetch failed: %s", exc)
        return 0

    if not isinstance(events, list):
        log.warning("[github] unexpected response: %s", type(events))
        return 0

    # Events arrive newest-first; process in reverse so we publish in
    # chronological order and the last_id is the most recent.
    new_events = []
    for evt in reversed(events):
        if last_id and evt["id"] <= last_id:
            continue
        mapped = _map_event(evt, username)
        if mapped:
            new_events.append((evt["id"], mapped))

    for event_id, soc_event in new_events:
        producer.send(TOPIC, soc_event)

    producer.flush()

    if new_events:
        with _connect_pg() as conn:
            _save_last_id(conn, username, new_events[-1][0])
        log.info("[github] published %d new events (last_id=%s)", len(new_events), new_events[-1][0])
    else:
        log.debug("[github] no new events")

    return len(new_events)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    if not GH_TOKEN:
        log.error("GITHUB_TOKEN not set — exiting")
        return
    if not GH_USERNAME:
        log.error("GITHUB_USERNAME not set — exiting")
        return

    log.info("github_producer starting | user=%s topic=%s poll=%ds", GH_USERNAME, TOPIC, POLL_SECONDS)

    producer = KafkaProducer(
        bootstrap_servers=BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
        retries=5,
    )

    while True:
        try:
            poll_and_publish(producer, GH_USERNAME)
        except Exception as exc:
            log.error("poll error: %s", exc)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
