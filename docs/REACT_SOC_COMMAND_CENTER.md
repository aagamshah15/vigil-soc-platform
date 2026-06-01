# React SOC Command Center

Phase 6 includes a hosted-ready React command center at `services/web`.

## Purpose

The UI is the primary SOC command surface for the financial-institution attack chain. It answers:

- Are we under attack right now?
- Who is targeted?
- How far did the attacker get?
- What should the analyst do next?

It consumes the existing FastAPI SOC endpoints through an nginx same-origin proxy:

- Browser: `http://localhost:8600`
- UI calls: `/api/v1/soc/...`
- nginx forwards to: `http://api:8000/v1/soc/...`

Streamlit remains available at `http://localhost:8501`.

## Local Commands

```bash
make demo-web
make verify-web
make logs-web
make down-web
```

For Vite development:

```bash
cd services/web
npm install
npm run dev
```

The FastAPI service allows local CORS origins through `API_CORS_ORIGINS`, defaulting to:

```text
http://localhost:5173,http://localhost:8600
```

## API Key Handling

The static app never embeds secrets. If secure API mode is enabled, enter the API key in the UI. It is stored only in browser `localStorage` and sent as the `x-api-key` header.

## Offline Mode

If the API is unavailable, the app enters offline mode and renders the last known seeded incident state for `INC-PAYMENT-001`. This keeps the interface usable while the backend is starting or temporarily unreachable.

The UI surfaces the connection error reason in the page header, so an operator can distinguish auth failures from network or server errors.

## Role Profiles

The login screen provides five local operating profiles:

- L1 Analyst: Overview, Timeline, and Entity Risk with read-only actions.
- L2 Analyst: all views, acknowledge, and mark-investigated actions.
- SOC Manager: all views, assignment, incident status, and compliance export.
- CISO: executive Overview only.
- Compliance Officer: Overview and Evidence with export access.

## Analyst Workflow

The command center includes local analyst controls:

- Acknowledge the active incident.
- Assign the incident to a named analyst.
- Filter, sort, and search the entity-risk queue.
- Mark an entity as investigated.
- Auto-refresh live data every 60 seconds, with manual refresh still available.

These workflow actions are intentionally browser-local for Phase 6. Incident acknowledgement, entity investigation state, and assignee are persisted in browser `localStorage` so demo state survives a hard refresh, but they do not mutate the warehouse or FastAPI state.
