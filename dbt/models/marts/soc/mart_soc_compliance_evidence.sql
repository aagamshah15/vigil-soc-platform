{{ config(tags=['soc']) }}

select
  'PCI-DSS' as framework,
  '10.2' as control_id,
  'Track and monitor all access to cardholder data' as control_name,
  count(*) as evidence_count,
  max(event_time) as latest_evidence_at,
  'raw.security_events -> mart_soc_incident_timelines' as lineage
from {{ ref('stg_soc_security_events') }}
where asset_id = 'paydb-prod-01'

union all

select
  'PCI-DSS' as framework,
  '12.10' as control_id,
  'Maintain incident response evidence for payment-system threats' as control_name,
  count(*) as evidence_count,
  max(event_time) as latest_evidence_at,
  'raw.security_events -> mart_soc_incident_timelines' as lineage
from {{ ref('stg_soc_security_events') }}
where severity in ('high', 'critical')
  and asset_id in ('paydb-prod-01', 'payapp-prod-02')

union all

select
  'SOC 2',
  'CC7.2',
  'Monitor system components for anomalies and security events',
  count(*),
  max(event_time),
  'raw.security_events -> mart_soc_entity_risk_current'
from {{ ref('stg_soc_security_events') }}
where severity in ('high', 'critical')

union all

select
  'SOC 2',
  'CC7.4',
  'Document incident response actions and supporting evidence',
  count(*),
  max(event_time),
  'raw.security_events -> mart_soc_incident_timelines'
from {{ ref('stg_soc_security_events') }}
where mitre_technique is not null
