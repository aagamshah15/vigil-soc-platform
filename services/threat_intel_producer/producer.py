"""
Phase 8A – Threat Intelligence Producer
=========================================
Sources (all free / no-cost tier):
  OTX (AlienVault)   – subscribed pulse IOCs with MITRE technique IDs
  ThreatFox          – recent malware IOCs (IPs, domains, URLs, hashes)
  Feodo Tracker      – active C2 botnet IP blocklist (Emotet, Trickbot, etc.)

Writes directly to raw.iocs in PostgreSQL — IOCs are reference/enrichment
data, not event-stream data, so Kafka is not needed here.

Runs on a configurable interval (INTEL_LOOP_SECONDS, default 900 = 15 min).
"""

from __future__ import annotations

import csv
import io
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

import psycopg2
import psycopg2.extras
import requests

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("threat_intel_producer")

# ── Config ────────────────────────────────────────────────────────────────────
OTX_API_KEY    = os.getenv("OTX_API_KEY", "")
THREATFOX_KEY  = os.getenv("THREATFOX_API_KEY", "")  # optional; abuse.ch auth key
OTX_BASE       = "https://otx.alienvault.com/api/v1"
THREATFOX_URL  = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_URL      = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
LOOP_SECONDS   = int(os.getenv("INTEL_LOOP_SECONDS", "900"))

PG_DSN = (
    f"host={os.getenv('POSTGRES_HOST','postgres')} "
    f"port={os.getenv('POSTGRES_PORT','5432')} "
    f"dbname={os.getenv('POSTGRES_DB','threat_risk')} "
    f"user={os.getenv('POSTGRES_USER','app')} "
    f"password={os.getenv('POSTGRES_PASSWORD','app')}"
)

UPSERT_SQL = """
INSERT INTO raw.iocs
    (ioc_id, source, ioc_type, ioc_value, malware_family,
     confidence, tags, mitre_techniques, first_seen, last_seen, ingested_at)
VALUES %s
ON CONFLICT (ioc_id) DO UPDATE SET
    malware_family  = EXCLUDED.malware_family,
    confidence      = EXCLUDED.confidence,
    tags            = EXCLUDED.tags,
    mitre_techniques = EXCLUDED.mitre_techniques,
    last_seen       = EXCLUDED.last_seen,
    ingested_at     = EXCLUDED.ingested_at
"""

SESSION = requests.Session()
SESSION.headers["User-Agent"] = "threat-risk-platform/8a (portfolio project)"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _upsert(conn: Any, rows: list[tuple]) -> int:
    if not rows:
        return 0
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(cur, UPSERT_SQL, rows, page_size=500)
    conn.commit()
    return len(rows)


# ── OTX ───────────────────────────────────────────────────────────────────────

def fetch_otx(conn: Any) -> int:
    if not OTX_API_KEY:
        log.warning("[otx] OTX_API_KEY not set – skipping")
        return 0

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    rows: list[tuple] = []
    page = 1

    while True:
        try:
            resp = SESSION.get(
                f"{OTX_BASE}/pulses/subscribed",
                headers=headers,
                params={"limit": 20, "page": page},
                timeout=60,
            )
            resp.raise_for_status()
        except Exception as exc:
            log.warning("[otx] request failed: %s", exc)
            break

        data = resp.json()
        pulses = data.get("results", [])
        if not pulses:
            break

        for pulse in pulses:
            pulse_id   = pulse.get("id", "")
            tags       = pulse.get("tags", [])
            attack_ids = pulse.get("attack_ids", [])  # MITRE techniques — may be str or dict
            mitre_ttps = []
            for a in attack_ids:
                if isinstance(a, dict):
                    name = a.get("display_name") or a.get("id") or ""
                    if name:
                        mitre_ttps.append(name)
                elif isinstance(a, str) and a:
                    mitre_ttps.append(a)

            for ind in pulse.get("indicators", []):
                ioc_type  = _otx_type(ind.get("type", ""))
                ioc_value = ind.get("indicator", "").strip()
                if not ioc_type or not ioc_value:
                    continue

                rows.append((
                    f"otx:{pulse_id}:{ioc_value}",  # ioc_id
                    "otx",                           # source
                    ioc_type,
                    ioc_value,
                    pulse.get("name"),               # malware_family (pulse name)
                    None,                            # confidence (OTX doesn't score per-IOC)
                    tags or None,
                    mitre_ttps or None,
                    _parse_ts(ind.get("created")),
                    _parse_ts(ind.get("modified") or ind.get("created")),
                    _now(),
                ))

        if not data.get("next"):
            break
        page += 1
        if page > 5:          # cap at 5 pages / 100 pulses to stay reasonable
            break

    return _upsert(conn, rows)


def _otx_type(raw: str) -> str | None:
    return {
        "IPv4": "ip", "IPv6": "ip",
        "domain": "domain", "hostname": "domain",
        "URL": "url",
        "FileHash-MD5": "md5", "FileHash-SHA256": "sha256",
    }.get(raw)


# ── ThreatFox ─────────────────────────────────────────────────────────────────

def fetch_threatfox(conn: Any) -> int:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if THREATFOX_KEY:
        headers["Auth-Key"] = THREATFOX_KEY
    try:
        resp = SESSION.post(
            THREATFOX_URL,
            json={"query": "get_iocs", "days": 1},
            headers=headers,
            timeout=30,
        )
        if resp.status_code == 401:
            log.warning("[threatfox] 401 Unauthorized — set THREATFOX_API_KEY in .env to enable (skipping)")
            return 0
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log.warning("[threatfox] request failed: %s", exc)
        return 0

    rows: list[tuple] = []
    for ioc in data.get("data") or []:
        ioc_type  = _tf_type(ioc.get("ioc_type", ""))
        ioc_value = ioc.get("ioc", "").strip()
        if not ioc_type or not ioc_value:
            continue

        # ThreatFox returns ip:port for network IOCs — strip the port
        if ioc_type == "ip" and ":" in ioc_value:
            ioc_value = ioc_value.split(":")[0]

        tags    = ioc.get("tags") or []
        malware = ioc.get("malware") or ioc.get("malware_printable")
        mitre   = [ioc["mitre_tactics"]] if ioc.get("mitre_tactics") else None

        rows.append((
            f"threatfox:{ioc.get('id', ioc_value)}",
            "threatfox",
            ioc_type,
            ioc_value,
            malware,
            ioc.get("confidence_level"),
            tags or None,
            mitre,
            _parse_ts(ioc.get("first_seen")),
            _parse_ts(ioc.get("last_seen") or ioc.get("first_seen")),
            _now(),
        ))

    return _upsert(conn, rows)


def _tf_type(raw: str) -> str | None:
    return {
        "ip:port": "ip", "domain": "domain",
        "url": "url", "md5_hash": "md5", "sha256_hash": "sha256",
    }.get(raw)


# ── Feodo Tracker ─────────────────────────────────────────────────────────────

def fetch_feodo(conn: Any) -> int:
    try:
        resp = SESSION.get(FEODO_URL, timeout=30)
        resp.raise_for_status()
    except Exception as exc:
        log.warning("[feodo] request failed: %s", exc)
        return 0

    rows: list[tuple] = []
    reader = csv.DictReader(
        io.StringIO(resp.text),
        fieldnames=["first_seen", "dst_ip", "dst_port", "c2_status", "last_online", "malware"],
    )
    for row in reader:
        if row.get("first_seen", "").startswith("#"):
            continue
        ip = (row.get("dst_ip") or "").strip()
        if not ip:
            continue

        malware  = (row.get("malware") or "").strip() or None
        ioc_id   = f"feodo:{ip}"
        tags     = ["c2", "botnet", malware.lower()] if malware else ["c2", "botnet"]

        rows.append((
            ioc_id,
            "feodo",
            "ip",
            ip,
            malware,
            90,           # Feodo is high-confidence — active C2 blocklist
            tags,
            None,
            _parse_ts(row.get("first_seen")),
            _parse_ts(row.get("last_online") or row.get("first_seen")),
            _now(),
        ))

    return _upsert(conn, rows)


# ── Utility ───────────────────────────────────────────────────────────────────

def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ── Main loop ─────────────────────────────────────────────────────────────────

def run_once() -> None:
    conn = psycopg2.connect(PG_DSN)
    try:
        n_otx  = fetch_otx(conn)
        n_tf   = fetch_threatfox(conn)
        n_feod = fetch_feodo(conn)
        log.info(
            "upserted iocs: otx=%d  threatfox=%d  feodo=%d  total=%d",
            n_otx, n_tf, n_feod, n_otx + n_tf + n_feod,
        )
    finally:
        conn.close()


if __name__ == "__main__":
    log.info("threat_intel_producer starting | loop=%ds", LOOP_SECONDS)
    iteration = 0
    while True:
        iteration += 1
        log.info("--- iteration %d ---", iteration)
        try:
            run_once()
        except Exception as exc:
            log.error("run_once failed: %s", exc)

        if LOOP_SECONDS <= 0:
            break
        log.info("sleeping %ds until next fetch", LOOP_SECONDS)
        time.sleep(LOOP_SECONDS)
