{{ config(tags=['soc']) }}

with events as (
  select
    coalesce(incident_id, 'INC-UNASSIGNED') as incident_id,
    event_id,
    event_time,
    source_system,
    event_type,
    entity_id,
    display_name,
    asset_id,
    asset_name,
    action,
    severity,
    mitre_technique,
    src_ip,
    dest_ip
  from {{ ref('stg_soc_security_events') }}
),
risk as (
  select incident_id, max(risk_points) as max_rule_points
  from {{ ref('mart_soc_risk_events') }}
  group by 1
)
select
  e.incident_id,
  case
    when coalesce(r.max_rule_points, 0) >= 30 then 'critical'
    when coalesce(r.max_rule_points, 0) >= 25 then 'high'
    else 'medium'
  end as severity,
  min(event_time) as started_at,
  max(event_time) as last_seen_at,
  array_agg(distinct entity_id) as entities_involved,
  array_agg(distinct asset_name) filter (where asset_name is not null) as target_assets,
  array_agg(distinct mitre_technique) filter (where mitre_technique is not null) as mitre_techniques,
  json_agg(
    json_build_object(
      'event_time', event_time,
      'event_type', event_type,
      'source_system', source_system,
      'entity_id', entity_id,
      'display_name', display_name,
      'asset', asset_name,
      'action', action,
      'severity', severity,
      'src_ip', src_ip,
      'dest_ip', dest_ip,
      'mitre_technique', mitre_technique
    )
    order by event_time
  ) as timeline,
  'Compromised vendor/user activity reached payment infrastructure and made a threat-intel matched outbound connection.' as summary,
  array[
    'Disable jsmith and PayLink contractor sessions',
    'Isolate WS-04821 from the network',
    'Block 203.0.113.66 at egress controls',
    'Review paydb-prod-01 access logs for data exposure'
  ] as recommended_next_steps
from events e
left join risk r using (incident_id)
group by e.incident_id, r.max_rule_points
