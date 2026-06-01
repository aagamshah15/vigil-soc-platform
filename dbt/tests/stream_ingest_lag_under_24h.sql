select *
from raw.urlhaus_events
where ingested_at < now() - interval '24 hours'
  and inserted_at >= now() - interval '24 hours'
