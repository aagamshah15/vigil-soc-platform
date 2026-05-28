# Phase 6 Troubleshooting

## No SOC risk rows

Run the producer and dbt build again:

```bash
make run-p6
```

Then check raw events:

```bash
docker exec -it threat-risk-platform-postgres-1 psql -U app -d threat_risk -c "select count(*), max(ingested_at) from raw.security_events;"
```

## SOC consumer is not writing rows

Check logs:

```bash
make logs-p6
```

Confirm Redpanda is healthy and the `security.events` topic has messages in Redpanda Console at http://localhost:8080.

## API returns 500 for SOC endpoints

The SOC marts may not exist yet. Run:

```bash
make run-p6
```

## Secure mode returns 401

Use the configured key:

```bash
curl -H "x-api-key: $API_KEY" http://localhost:8000/v1/soc/risk/entities
```

## Failure drill: analyst sees critical risk

Detection:

1. Open SOC dashboard and view `SOC Entity Risk`.
2. Confirm `user:jsmith` or `device:WS-04821` is critical.
3. Open `SOC Incident Timeline`.
4. Read the triage report for `INC-PAYMENT-001`.

Recovery actions:

1. Disable `jsmith` and PayLink contractor sessions.
2. Isolate `WS-04821`.
3. Block `203.0.113.66`.
4. Review `paydb-prod-01` audit logs.

Validation:

```bash
curl http://localhost:8000/v1/soc/incidents/INC-PAYMENT-001/triage-report
```
