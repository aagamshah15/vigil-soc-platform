# Phase 6 Architecture: SOC Threat Correlation + Risk Scoring

Phase 6 adds a local SOC analytics product on top of the existing platform without replacing the URLhaus/KEV pipeline.

## Flow

```text
soc-producer -> Redpanda security.events -> soc-consumer
  -> MinIO Bronze JSONL
  -> Postgres raw.security_events
  -> dbt SOC staging/marts
  -> FastAPI SOC endpoints
  -> Streamlit SOC dashboard
  -> Prometheus SOC metrics
```

## Demo Scenario

The deterministic financial-institution scenario simulates:

1. PayLink vendor account logs in from an unusual location.
2. Jordan Smith experiences a failed-login burst.
3. Jordan Smith receives privileged access.
4. Badge and VPN location conflict.
5. Jordan accesses the payment processing database after hours.
6. Endpoint detection flags suspicious PowerShell on `WS-04821`.
7. Lateral movement reaches `paydb-prod-01`.
8. Payment database makes an outbound connection to a threat-intel IP.

The resulting answer for leadership is visible through ranked SOC risk, incident timeline, triage report, Q&A, and compliance views.

## Scoring

Risk score is capped at `100`. Rules are intentionally explainable:

| Rule | Points |
| --- | ---: |
| Privilege escalation | 25 |
| Critical/high asset access | 20 |
| Outside business hours | 15 |
| Failed-login burst | 15 |
| Endpoint malware-like alert | 25 |
| Lateral movement | 30 |
| Threat-intel outbound connection | 30 |
| Vendor sensitive access | 20 |
| Badge/digital mismatch | 20 |

Risk bands:

- `low`: `< 30`
- `medium`: `30-59`
- `high`: `60-79`
- `critical`: `>= 80`

## Key Marts

- `marts.mart_soc_risk_events`: one row per event/rule hit.
- `marts.mart_soc_entity_risk_current`: ranked entity risk with reasons and actions.
- `marts.mart_soc_incident_timelines`: incident chain and triage context.
- `marts.mart_soc_qna_results`: deterministic analyst questions mapped to SQL results.
- `marts.mart_soc_compliance_evidence`: PCI-DSS and SOC 2 audit evidence.
