# SOC Data Dictionary

## raw.security_events

Normalized raw security stream written by the SOC consumer.

| Column | Meaning |
| --- | --- |
| `event_id` | Stable event identifier. |
| `event_time` | Security event timestamp. |
| `source_system` | Tool or feed: Sentinel, AD, CrowdStrike, Zeek, Netflow, badge system. |
| `event_type` | Normalized event category. |
| `entity_id` | User, device, vendor, or IP risk entity. |
| `entity_type` | Entity class. |
| `user_id`, `device_id` | Identity and endpoint references when present. |
| `src_ip`, `dest_ip` | Network source and destination. |
| `asset_id` | Target asset reference. |
| `action` | Normalized action. |
| `severity` | Low, medium, high, or critical. |
| `mitre_technique` | MITRE ATT&CK technique ID when matched. |
| `payload` | Source-specific context retained as JSON. |

## marts.mart_soc_entity_risk_current

Current ranked entity risk view for analysts.

| Column | Meaning |
| --- | --- |
| `entity_id` | User/device/vendor identifier. |
| `risk_score` | Explainable score capped at 100. |
| `risk_band` | Low, medium, high, or critical. |
| `top_risk_reasons` | JSON list of rule reasons. |
| `recommended_action` | Analyst next step. |

## marts.mart_soc_incident_timelines

Auto-constructed incident chain.

| Column | Meaning |
| --- | --- |
| `incident_id` | Incident grouping key. |
| `severity` | Incident severity. |
| `timeline` | Ordered JSON event sequence. |
| `entities_involved` | Users/devices/vendors in the chain. |
| `target_assets` | Assets touched by the chain. |
| `recommended_next_steps` | Triage actions. |
