{{ config(tags=['soc']) }}

with events as (
  select * from {{ ref('stg_soc_security_events') }}
),
rules as (
  select event_id, entity_id, event_time, 25 as risk_points, 'privilege_escalation' as rule_name,
         'Privilege escalation observed' as reason
  from events
  where action = 'privilege_escalation'

  union all
  select event_id, entity_id, event_time, 20, 'critical_asset_access',
         'Accessed critical payment or identity asset'
  from events
  where asset_criticality in ('critical', 'high') and asset_id is not null

  union all
  select event_id, entity_id, event_time, 15, 'outside_business_hours',
         'Activity occurred outside expected business hours'
  from events
  where outside_business_hours

  union all
  select event_id, entity_id, event_time, 15, 'failed_login_burst',
         'Five or more failed logins in a 15 minute window'
  from events
  where event_type = 'auth_failed_burst' or action = 'failed_login_burst'

  union all
  select event_id, entity_id, event_time, 25, 'endpoint_malware_alert',
         'Endpoint detection flagged suspicious malware-like behavior'
  from events
  where event_type = 'endpoint_alert' and severity in ('high', 'critical')

  union all
  select event_id, entity_id, event_time, 30, 'lateral_movement',
         'Lateral movement pattern observed within the incident chain'
  from events
  where event_type = 'lateral_movement'

  union all
  select event_id, entity_id, event_time, 30, 'threat_intel_outbound',
         'Outbound connection matched threat intelligence indicator'
  from events
  where threat_intel_match

  union all
  select event_id, entity_id, event_time, 20, 'vendor_sensitive_access',
         'Vendor account accessed a sensitive asset'
  from events
  where entity_type = 'vendor' and asset_criticality in ('critical', 'high')

  union all
  select event_id, entity_id, event_time, 20, 'badge_digital_mismatch',
         'Physical badge location conflicts with digital access location'
  from events
  where event_type = 'badge_anomaly'

  -- ── Phase 8A: GitHub live event rules ──────────────────────────────────────
  union all
  select event_id, entity_id, event_time, 40, 'repo_exposed',
         'Private repository was made public — potential data exposure'
  from events
  where event_type = 'repo_exposed'

  union all
  select event_id, entity_id, event_time, 25, 'force_push',
         'Force push detected — history rewrite on a protected branch'
  from events
  where source_system = 'github' and action = 'force_push'

  union all
  select event_id, entity_id, event_time, 20, 'repo_forked',
         'Repository forked — possible data exfiltration vector'
  from events
  where event_type = 'repo_forked'

  union all
  select event_id, entity_id, event_time, 15, 'member_change',
         'Repository collaborator added or removed'
  from events
  where event_type = 'member_change'

  -- ── Phase 8A: Live IOC match boost ─────────────────────────────────────────
  union all
  select event_id, entity_id, event_time,
         -- scale points 20-35 by confidence bucket (null confidence → 20 pts)
         case
           when ioc_confidence >= 80 then 35
           when ioc_confidence >= 50 then 28
           else 20
         end,
         'live_ioc_match',
         coalesce(
           'IP matched threat-intel feed: ' || ioc_malware_family,
           'IP matched threat-intel feed'
         )
  from events
  where ioc_matched
    and not coalesce((payload->>'threat_intel_match')::boolean, false)
    -- avoid double-counting events already flagged by payload threat_intel_match
)
select
  r.event_id,
  e.incident_id,
  r.entity_id,
  e.entity_type,
  e.display_name,
  e.user_id,
  e.device_id,
  e.src_ip,
  e.dest_ip,
  e.asset_id,
  e.asset_name,
  e.event_type,
  e.action,
  e.severity,
  e.mitre_technique,
  r.event_time,
  r.rule_name,
  r.risk_points,
  r.reason
from rules r
join events e using (event_id, entity_id)
