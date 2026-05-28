{{ config(tags=['soc']) }}

select
  event_id,
  event_time,
  ingested_at,
  source_system,
  event_type,
  entity_id,
  entity_type,
  coalesce(display_name, entity_id) as display_name,
  user_id,
  device_id,
  src_ip,
  dest_ip,
  asset_id,
  action,
  lower(severity) as severity,
  mitre_technique,
  payload,
  payload->>'incident_id' as incident_id,
  payload->>'user_role' as user_role,
  coalesce((payload->>'outside_business_hours')::boolean, false) as outside_business_hours,
  coalesce((payload->>'privileged')::boolean, false) as privileged,
  coalesce(payload->>'asset_criticality', sa.criticality, 'unknown') as asset_criticality,
  coalesce(payload->>'asset_name', sa.asset_name, asset_id) as asset_name,
  -- threat_intel_match: payload flag OR live IOC hit on src/dest IP
  coalesce((payload->>'threat_intel_match')::boolean, false)
    or (ioc_src.ioc_value  is not null)
    or (ioc_dest.ioc_value is not null)                              as threat_intel_match,
  payload->>'indicator' as threat_indicator,
  -- IOC enrichment columns (populated when src_ip or dest_ip is in raw.iocs)
  (ioc_src.ioc_value is not null or ioc_dest.ioc_value is not null) as ioc_matched,
  coalesce(ioc_src.malware_family, ioc_dest.malware_family)         as ioc_malware_family,
  greatest(ioc_src.confidence, ioc_dest.confidence)                 as ioc_confidence,
  coalesce(ioc_src.ioc_mitre,  ioc_dest.ioc_mitre)                  as ioc_mitre_techniques,
  coalesce(ioc_src.ioc_source, ioc_dest.ioc_source)                 as ioc_source,
  _consumer_ingested_at,
  _kafka_topic,
  _kafka_partition,
  _kafka_offset
from {{ source('raw', 'security_events') }} se
left join {{ source('raw', 'soc_assets') }} sa using (asset_id)
-- Phase 8A: enrich with live IOC matches (src_ip or dest_ip in raw.iocs)
left join (
    select ioc_value, malware_family, confidence,
           array_to_string(mitre_techniques, ',') as ioc_mitre,
           source as ioc_source
    from {{ source('raw', 'iocs') }}
    where ioc_type = 'ip'
) ioc_src  on ioc_src.ioc_value  = se.src_ip
left join (
    select ioc_value, malware_family, confidence,
           array_to_string(mitre_techniques, ',') as ioc_mitre,
           source as ioc_source
    from {{ source('raw', 'iocs') }}
    where ioc_type = 'ip'
) ioc_dest on ioc_dest.ioc_value = se.dest_ip
