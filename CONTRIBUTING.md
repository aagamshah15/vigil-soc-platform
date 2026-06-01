# Contributing

Thanks for helping improve Threat & Risk Analytics Platform. Keep contributions focused, documented, and safe to run locally.

## Local Setup

```bash
cp .env.example .env
make demo-up
```

When finished:

```bash
make demo-down
```

`make demo-down` preserves Docker volumes. Use phase-specific reset targets, such as `make reset-p8`, only when you intentionally want to remove local data.

## Development Guidelines

- Keep pull requests small and scoped.
- Do not commit `.env`, real credentials, local tokens, API keys, database dumps, or private logs.
- Update `README.md`, docs, and screenshots when user-facing behavior changes.
- Prefer existing Make targets, Docker Compose overlays, service patterns, and dbt conventions.
- Keep demo defaults runnable without external identity infrastructure.

## Suggested Validation

Run the checks that match the change:

```bash
make verify-p8
```

For API changes:

```bash
pytest -q services/api/tests
```

For React SOC UI changes:

```bash
cd services/web
npm ci
npm run lint
npm run build
```

For dbt model changes:

```bash
docker compose -f docker-compose.yml run --rm dbt dbt build
```

For docs-only changes, verify that README links resolve, documented Make targets exist, and Markdown passes whitespace checks.

## Security Notes

Use placeholders in committed examples. If a real token or secret is exposed, rotate it immediately and remove it from the repository history if it was committed.
