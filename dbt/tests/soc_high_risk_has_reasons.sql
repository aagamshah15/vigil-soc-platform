select *
from {{ ref('mart_soc_entity_risk_current') }}
where risk_band in ('high', 'critical')
  and (
    top_risk_reasons is null
    or top_risk_reasons::text in ('[]', 'null')
  )
