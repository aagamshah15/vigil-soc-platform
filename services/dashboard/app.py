from __future__ import annotations

import os
from typing import Any

import pandas as pd
import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8000")
TIMEOUT_SECONDS = float(os.getenv("API_TIMEOUT_SECONDS", "5"))
API_KEY = os.getenv("API_KEY", "")
DASHBOARD_PHASE_LABEL = os.getenv("DASHBOARD_PHASE_LABEL", "Phase 4: Consumption + Reliability Hardening")

st.set_page_config(page_title="Threat & Risk Demo", layout="wide")


@st.cache_data(ttl=30)
def api_get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    url = f"{API_BASE_URL}{path}"
    headers = {"x-api-key": API_KEY} if API_KEY else None
    resp = requests.get(url, params=params, headers=headers, timeout=TIMEOUT_SECONDS)
    resp.raise_for_status()
    return resp.json()


def render_pipeline_health() -> None:
    st.subheader("Pipeline Health")
    summary = api_get("/v1/pipeline/summary")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Stream Events", summary["stream_events_total"])
    col2.metric("Threat Events (Mart)", summary["threat_rows_total"])
    col3.metric("KEV Rows", summary["kev_rows_total"])
    col4.metric("Ingest Lag (min)", summary["stream_ingest_lag_minutes"])

    st.caption(f"Latest stream ingest: {summary['latest_stream_ingested_at']}")
    st.caption(f"Consumer heartbeat lag (min): {summary['consumer_heartbeat_lag_minutes']}")


def render_stream_freshness_lag() -> None:
    st.subheader("Stream Freshness / Lag Trends")
    lag = api_get("/v1/trends/stream-lag", params={"hours": 24})
    df = pd.DataFrame(lag["series"])
    if df.empty:
        st.info("No stream lag data yet.")
        return

    df["bucket_hour"] = pd.to_datetime(df["bucket_hour"])
    df = df.sort_values("bucket_hour")

    st.line_chart(df.set_index("bucket_hour")[["avg_event_delay_seconds"]])
    st.dataframe(df, use_container_width=True)


def render_top_malicious_hosts() -> None:
    st.subheader("Top Malicious URLs/Hosts")
    top = api_get("/v1/threat/top-hosts", params={"days": 7, "limit": 10})
    rows = pd.DataFrame(top["rows"])
    if rows.empty:
        st.info("No threat host data yet.")
        return

    st.bar_chart(rows.set_index("host")[["event_count"]])
    st.dataframe(rows, use_container_width=True)


def render_kev_highlights() -> None:
    st.subheader("KEV Highlights")
    kev = api_get("/v1/risk/kev-summary")

    col1, col2, col3 = st.columns(3)
    col1.metric("KEV Total", kev["kev_total"])
    col2.metric("Unique CVEs", kev["unique_cves"])
    col3.metric("Overdue", kev["overdue_count"])

    st.caption(f"First Added: {kev['first_added']} | Latest Added: {kev['latest_added']}")

    vendors = pd.DataFrame(kev.get("top_vendors", []))
    if not vendors.empty:
        st.bar_chart(vendors.set_index("vendor")[["cve_count"]])
        st.dataframe(vendors, use_container_width=True)


def render_soc_risk_entities() -> None:
    st.subheader("SOC Entity Risk")
    risk = api_get("/v1/soc/risk/entities", params={"limit": 20, "min_score": 0})
    rows = pd.DataFrame(risk["rows"])
    if rows.empty:
        st.info("No SOC risk rows yet. Run `make demo-p6` to seed the attack-chain scenario.")
        return

    col1, col2, col3 = st.columns(3)
    col1.metric("Entities", len(rows))
    col2.metric("Critical", int((rows["risk_band"] == "critical").sum()))
    col3.metric("Max Score", int(rows["risk_score"].max()))

    st.dataframe(
        rows[
            [
                "risk_score",
                "risk_band",
                "entity_type",
                "display_name",
                "entity_id",
                "top_risk_reasons",
                "recommended_action",
            ]
        ],
        use_container_width=True,
    )


def render_soc_incident_timeline() -> None:
    st.subheader("SOC Incident Timeline")
    incidents = api_get("/v1/soc/incidents")["rows"]
    if not incidents:
        st.info("No incidents yet.")
        return

    selected = st.selectbox("Incident", [item["incident_id"] for item in incidents])
    report = api_get(f"/v1/soc/incidents/{selected}/triage-report")

    col1, col2 = st.columns(2)
    col1.metric("Severity", report["severity"])
    col2.metric("Evidence Events", report["evidence"]["event_count"])
    st.write(report["summary"])

    timeline = pd.DataFrame(report["timeline"])
    if not timeline.empty:
        st.dataframe(timeline, use_container_width=True)

    st.subheader("Recommended Next Steps")
    for step in report["recommended_next_steps"]:
        st.write(f"- {step}")


def render_soc_qna() -> None:
    st.subheader("Analyst Q&A")
    templates = api_get("/v1/soc/qna/templates")["templates"]
    if not templates:
        st.info("No Q&A templates available.")
        return

    by_label = {item["question"]: item["question_id"] for item in templates}
    question = st.selectbox("Question", list(by_label.keys()))
    answer = api_get(f"/v1/soc/qna/{by_label[question]}")
    st.caption(answer["question_id"])
    rows = pd.DataFrame(answer.get("answer_rows") or [])
    if rows.empty:
        st.info("No matching rows.")
    else:
        st.dataframe(rows, use_container_width=True)


def render_soc_compliance() -> None:
    st.subheader("Compliance Evidence")
    framework = st.selectbox("Framework", ["PCI-DSS", "SOC 2"])
    evidence = api_get(f"/v1/soc/compliance/{framework}")
    rows = pd.DataFrame(evidence["controls"])
    if rows.empty:
        st.info("No compliance evidence rows yet.")
    else:
        st.dataframe(rows, use_container_width=True)


def main() -> None:
    st.title("Threat & Risk Analytics Platform")
    st.caption(DASHBOARD_PHASE_LABEL)

    try:
        health = api_get("/health")
        st.success(f"API status: {health['status']}")
    except Exception as exc:
        st.error(f"API unavailable: {exc}")
        st.stop()

    page = st.sidebar.radio(
        "Demo Pages",
        [
            "SOC Entity Risk",
            "SOC Incident Timeline",
            "SOC Analyst Q&A",
            "SOC Compliance Evidence",
            "Pipeline Health",
            "Stream Freshness/Lag Trends",
            "Top Malicious URLs/Hosts",
            "KEV Highlights",
        ],
    )

    if page == "SOC Entity Risk":
        render_soc_risk_entities()
    elif page == "SOC Incident Timeline":
        render_soc_incident_timeline()
    elif page == "SOC Analyst Q&A":
        render_soc_qna()
    elif page == "SOC Compliance Evidence":
        render_soc_compliance()
    elif page == "Pipeline Health":
        render_pipeline_health()
    elif page == "Stream Freshness/Lag Trends":
        render_stream_freshness_lag()
    elif page == "Top Malicious URLs/Hosts":
        render_top_malicious_hosts()
    else:
        render_kev_highlights()


if __name__ == "__main__":
    main()
