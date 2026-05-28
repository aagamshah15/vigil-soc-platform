# Phase 3 Architecture (Orchestration + Observability)

```mermaid
flowchart LR
  subgraph "Local Stack"
    PServer["Prefect Server UI/API"]
    PWorker["Prefect Worker"]
    RP["Redpanda"]
    PG["Postgres"]
    MI["MinIO"]
  end

  subgraph "Flow Tasks"
    T1["Batch ELT"]
    T2["Stream Health Checks"]
    T3["dbt build + test"]
    T4["Observability Summary"]
  end

  PServer --> PWorker
  PWorker --> T1
  PWorker --> T2
  PWorker --> T3
  T3 --> T4
  T2 --> T4

  T1 --> MI
  T1 --> PG
  T2 --> RP
  T2 --> PG
  T3 --> PG
```

## Notes
- Phase 1/2 components are unchanged and still runnable with existing Make targets.
- Phase 3 runs flow code from `orchestration/flows/` and writes run summaries to `artifacts/p3_runs/`.
- Prefect UI is local at `http://localhost:4200`.
