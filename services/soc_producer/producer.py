from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone

from kafka import KafkaProducer

BOOTSTRAP = os.getenv("BOOTSTRAP_SERVERS", "redpanda:9092")
TOPIC = os.getenv("SOC_TOPIC", "security.events")
SCENARIO = os.getenv("SOC_SCENARIO", "financial_attack_chain")


def _ts(minutes_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


def _event(
    suffix: str,
    minutes_ago: int,
    source_system: str,
    event_type: str,
    entity_id: str,
    entity_type: str,
    display_name: str,
    action: str,
    severity: str,
    user_id: str | None = None,
    device_id: str | None = None,
    src_ip: str | None = None,
    dest_ip: str | None = None,
    asset_id: str | None = None,
    mitre_technique: str | None = None,
    payload: dict | None = None,
) -> dict:
    event_time = _ts(minutes_ago)
    payload = payload or {}
    payload.setdefault("incident_id", "INC-PAYMENT-001")
    payload.setdefault("scenario", SCENARIO)
    return {
        "schema_version": 1,
        "event_id": f"{SCENARIO}-{suffix}",
        "event_time": event_time,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "source_system": source_system,
        "event_type": event_type,
        "entity_id": entity_id,
        "entity_type": entity_type,
        "display_name": display_name,
        "user_id": user_id,
        "device_id": device_id,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "asset_id": asset_id,
        "action": action,
        "severity": severity,
        "mitre_technique": mitre_technique,
        "payload": payload,
    }


def scenario_events() -> list[dict]:
    return [
        _event(
            "001-vendor-login",
            18,
            "sentinel",
            "iam_login",
            "vendor:paylink-admin",
            "vendor",
            "PayLink contractor admin",
            "login_success",
            "medium",
            user_id="paylink_admin",
            src_ip="198.51.100.77",
            asset_id="vpn-gateway-01",
            mitre_technique="T1078",
            payload={"user_role": "vendor_admin", "outside_business_hours": True, "country": "NL"},
        ),
        _event(
            "002-failed-burst",
            16,
            "active_directory",
            "auth_failed_burst",
            "user:jsmith",
            "user",
            "Jordan Smith",
            "failed_login_burst",
            "medium",
            user_id="jsmith",
            src_ip="198.51.100.77",
            asset_id="ad-prod-01",
            mitre_technique="T1110",
            payload={"failed_attempts_15m": 7, "user_role": "developer"},
        ),
        _event(
            "003-priv-esc",
            14,
            "active_directory",
            "privilege_change",
            "user:jsmith",
            "user",
            "Jordan Smith",
            "privilege_escalation",
            "high",
            user_id="jsmith",
            src_ip="10.20.14.31",
            asset_id="ad-prod-01",
            mitre_technique="T1098",
            payload={"new_group": "Domain Admins", "user_role": "developer", "privileged": True},
        ),
        _event(
            "004-badge-mismatch",
            13,
            "badge_system",
            "badge_anomaly",
            "user:jsmith",
            "user",
            "Jordan Smith",
            "badge_digital_mismatch",
            "medium",
            user_id="jsmith",
            src_ip="10.20.14.31",
            mitre_technique="T1078",
            payload={"badge_location": "Austin HQ", "vpn_geo": "Amsterdam", "mismatch": True},
        ),
        _event(
            "005-payment-access",
            11,
            "splunk",
            "payment_access",
            "user:jsmith",
            "user",
            "Jordan Smith",
            "read_payment_records",
            "high",
            user_id="jsmith",
            device_id="WS-04821",
            src_ip="10.20.14.31",
            dest_ip="10.44.2.10",
            asset_id="paydb-prod-01",
            mitre_technique="T1005",
            payload={
                "asset_name": "Payment Processing Database",
                "asset_criticality": "critical",
                "data_domain": "cardholder_data",
                "outside_business_hours": True,
                "user_role": "developer",
                "privileged": True,
            },
        ),
        _event(
            "006-endpoint-alert",
            9,
            "crowdstrike",
            "endpoint_alert",
            "device:WS-04821",
            "device",
            "WS-04821",
            "suspicious_powershell",
            "critical",
            user_id="jsmith",
            device_id="WS-04821",
            src_ip="10.20.14.31",
            asset_id="WS-04821",
            mitre_technique="T1059.001",
            payload={"process": "powershell.exe", "command": "encoded download cradle", "malware": True},
        ),
        _event(
            "007-lateral",
            7,
            "zeek",
            "lateral_movement",
            "device:WS-04821",
            "device",
            "WS-04821",
            "remote_admin_connection",
            "high",
            user_id="jsmith",
            device_id="WS-04821",
            src_ip="10.20.14.31",
            dest_ip="10.44.2.10",
            asset_id="paydb-prod-01",
            mitre_technique="T1021",
            payload={"chain_minutes": 4, "asset_criticality": "critical", "asset_name": "Payment Processing Database"},
        ),
        _event(
            "008-c2-outbound",
            5,
            "netflow",
            "network_connection",
            "device:WS-04821",
            "device",
            "WS-04821",
            "outbound_connection",
            "critical",
            user_id="jsmith",
            device_id="WS-04821",
            src_ip="10.44.2.10",
            dest_ip="203.0.113.66",
            asset_id="paydb-prod-01",
            mitre_technique="T1105",
            payload={
                "asset_criticality": "critical",
                "threat_intel_match": True,
                "indicator": "203.0.113.66",
                "indicator_source": "dark_web_watchlist",
            },
        ),
        _event(
            "009-benign-dba",
            4,
            "splunk",
            "payment_access",
            "user:agarcia",
            "user",
            "Avery Garcia",
            "read_payment_records",
            "low",
            user_id="agarcia",
            src_ip="10.20.8.12",
            asset_id="paydb-prod-01",
            payload={"asset_criticality": "critical", "outside_business_hours": False, "user_role": "dba", "privileged": True},
        ),
    ]


# SOC_LOOP_SECONDS: re-emit events on this interval so the dashboard always
# shows recent timestamps.  Set to 0 (default) to run once and exit.
LOOP_SECONDS = int(os.getenv("SOC_LOOP_SECONDS", "0"))

print(f"[soc-producer] starting | bootstrap={BOOTSTRAP} topic={TOPIC} scenario={SCENARIO} loop={LOOP_SECONDS}s")

producer = KafkaProducer(
    bootstrap_servers=BOOTSTRAP,
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
)

iteration = 0
while True:
    events = scenario_events()
    for event in events:
        producer.send(TOPIC, event)
    producer.flush()
    iteration += 1
    print(f"[soc-producer] iteration {iteration}: emitted {len(events)} events (timestamps refreshed to now)")

    if LOOP_SECONDS <= 0:
        break
    time.sleep(LOOP_SECONDS)

producer.close()
