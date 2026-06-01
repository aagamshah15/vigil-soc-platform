select 1
where not exists (
  select 1
  from {{ source('raw', 'security_events') }}
  where ingested_at >= now() - interval '2 hours'
)
