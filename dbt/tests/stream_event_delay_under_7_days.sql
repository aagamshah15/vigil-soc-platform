select *
from raw.urlhaus_events
where ingested_at >= now() - interval '7 days'
  and event_time is not null
  and ingested_at - event_time > interval '7 days'
