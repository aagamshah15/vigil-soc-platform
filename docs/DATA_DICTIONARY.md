# Data Dictionary

## raw.urlhaus_events

Streaming landing table populated by the Redpanda consumer and replay utility.

| Column | Meaning |
| --- | --- |
| `event_id` | Unique event identifier used for idempotent upserts. |
| `event_time` | Source event timestamp. |
| `ingested_at` | Platform ingestion timestamp. |
| `source` | Source feed, currently `urlhaus`. |
| `url` | Malicious URL from the payload. |
| `feed` | Feed name from the payload. |
| `payload` | Original JSON payload. |
| `_consumer_ingested_at` | Timestamp written by the consumer after durable sink writes. |
| `_kafka_topic`, `_kafka_partition`, `_kafka_offset` | Kafka lineage and replay metadata. |

## marts.fct_urlhaus_threat_events

Incremental fact table used by the API, dashboard, and SLO metrics.

| Column | Meaning |
| --- | --- |
| `event_id` | Unique event identifier. |
| `event_time` | Source event timestamp. |
| `ingested_at` | Platform ingestion timestamp. |
| `source` | Source feed. |
| `url` | Malicious URL. |
| `feed` | Feed label. |

## marts.fact_kev

Curated CISA KEV facts used for vulnerability risk summaries.

| Column | Meaning |
| --- | --- |
| `cve_key` | Stable hash key for the CVE. |
| `product_key` | Stable hash key for vendor/product. |
| `date_day` | Batch run date. |
| `cve_id` | CVE identifier. |
| `vulnerability_name` | Source vulnerability label. |
| `date_added` | Date CISA added the CVE to KEV. |
| `due_date` | CISA remediation due date. |
| `required_action` | Required remediation action. |

## marts.dim_product

Product dimension for grouping KEV risk.

| Column | Meaning |
| --- | --- |
| `product_key` | Stable product key. |
| `vendor_key` | Stable vendor key. |
| `vendor_project` | Vendor or project name. |
| `product` | Product name. |

## marts.fact_url_events

Batch URLhaus URL observation table for historical analytics.

| Column | Meaning |
| --- | --- |
| `url_key` | Stable URL key. |
| `date_day` | Batch run date. |
| `url_status` | URLhaus status. |
| `threat` | Threat classification. |
| `tags` | Source tags. |
