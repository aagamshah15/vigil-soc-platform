select *
from {{ ref('mart_soc_entity_risk_current') }}
where risk_score < 0 or risk_score > 100
