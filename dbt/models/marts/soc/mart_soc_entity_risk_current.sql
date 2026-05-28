{{ config(tags=['soc']) }}

with scored as (
  select
    entity_id,
    entity_type,
    display_name,
    max(event_time) as last_seen_at,
    least(sum(risk_points), 100) as risk_score,
    array_agg(distinct reason) as top_risk_reasons,
    array_agg(distinct mitre_technique) filter (where mitre_technique is not null) as mitre_techniques
  from {{ ref('mart_soc_risk_events') }}
  group by 1, 2, 3
)
select
  entity_id,
  entity_type,
  display_name,
  risk_score,
  case
    when risk_score >= 80 then 'critical'
    when risk_score >= 60 then 'high'
    when risk_score >= 30 then 'medium'
    else 'low'
  end as risk_band,
  last_seen_at,
  to_json(top_risk_reasons) as top_risk_reasons,
  to_json(coalesce(mitre_techniques, array[]::text[])) as mitre_techniques,
  case
    when risk_score >= 80 then 'Isolate entity, disable active sessions, and open a priority incident.'
    when risk_score >= 60 then 'Escalate to security analyst and validate the event chain.'
    when risk_score >= 30 then 'Review account and asset activity during the last 24 hours.'
    else 'Monitor for additional signals.'
  end as recommended_action
from scored
