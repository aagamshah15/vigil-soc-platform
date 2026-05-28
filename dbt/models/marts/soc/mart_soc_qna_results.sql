{{ config(tags=['soc']) }}

select
  'privileged_payment_after_hours' as question_id,
  'Show me privileged accounts that accessed payment systems outside business hours this week' as question,
  json_agg(
    json_build_object(
      'event_time', event_time,
      'user_id', user_id,
      'entity_id', entity_id,
      'display_name', display_name,
      'asset_id', asset_id,
      'asset_name', asset_name,
      'src_ip', src_ip,
      'severity', severity
    )
    order by event_time desc
  ) filter (where event_id is not null) as answer_rows
from {{ ref('stg_soc_security_events') }}
where asset_id = 'paydb-prod-01'
  and outside_business_hours
  and privileged

union all

select
  'critical_entities_now',
  'Which entities are critical risk right now?',
  json_agg(
    json_build_object(
      'entity_id', entity_id,
      'display_name', display_name,
      'risk_score', risk_score,
      'risk_band', risk_band,
      'top_risk_reasons', top_risk_reasons
    )
    order by risk_score desc
  ) filter (where entity_id is not null)
from {{ ref('mart_soc_entity_risk_current') }}
where risk_band = 'critical'

union all

select
  'vendor_sensitive_access',
  'Show vendor accounts that touched sensitive assets',
  json_agg(
    json_build_object(
      'event_time', event_time,
      'entity_id', entity_id,
      'display_name', display_name,
      'asset_id', asset_id,
      'asset_name', asset_name,
      'action', action
    )
    order by event_time desc
  ) filter (where event_id is not null)
from {{ ref('stg_soc_security_events') }}
where entity_type = 'vendor'
  and asset_criticality in ('critical', 'high')
