# Security Policy

## Project Scope

Threat & Risk Analytics Platform is a local-first demo and portfolio project. It is designed to show production-style security, data engineering, SOC analytics, observability, and operational patterns in a local Docker environment.

This repository is not a managed production service and does not provide a formal support SLA.

## Reporting Security Issues

Please report security issues through GitHub issues.

Do not include secrets, API keys, access tokens, exploit payloads, private logs, customer data, or other sensitive material in a public issue. Describe the affected component, expected impact, and high-level reproduction steps instead.

If a report requires sensitive details, open a minimal public issue first asking for a private coordination path.

## Secrets and Credentials

Committed examples must use placeholders only. Real values must stay in local, ignored files such as `.env`.

Rotate any credential immediately if it is exposed, including:

- GitHub tokens
- OTX or threat-intel API keys
- JWT secrets
- API keys
- Database, MinIO, Grafana, or demo passwords reused outside local development

## Demo Defaults

The default configuration favors local demo ergonomics over production hardening. For production-like testing, enable JWT auth, set a strong `JWT_SECRET`, use explicit CORS origins, disable seeded demo users, and require secure cookies behind HTTPS.

See `README.md` and `.env.example` for the current local configuration defaults.
