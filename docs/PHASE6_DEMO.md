# Phase 6 Demo

## Run

```bash
cp .env.example .env
make demo-p6
```

## Open

- SOC dashboard: http://localhost:8501
- API docs: http://localhost:8000/docs
- Grafana: http://localhost:3000
- Prometheus: http://localhost:9090

## API Examples

```bash
curl http://localhost:8000/v1/soc/risk/entities?limit=5
curl http://localhost:8000/v1/soc/incidents
curl http://localhost:8000/v1/soc/incidents/INC-PAYMENT-001/triage-report
curl http://localhost:8000/v1/soc/qna/templates
curl http://localhost:8000/v1/soc/qna/critical_entities_now
curl http://localhost:8000/v1/soc/compliance/PCI-DSS
```

If secure mode is enabled:

```bash
curl -H "x-api-key: $API_KEY" http://localhost:8000/v1/soc/risk/entities
```

## Expected Demo Outcome

The dashboard should show at least one `critical` entity, a payment-system attack chain, and a triage report recommending session disablement, workstation isolation, egress blocking, and payment database log review.
