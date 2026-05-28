from __future__ import annotations

import os


def _build_dsn(scheme: str = "postgresql") -> str:
    host = os.getenv("POSTGRES_HOST", "postgres")
    port = os.getenv("POSTGRES_PORT", "5432")
    db = os.getenv("POSTGRES_DB", "threat_risk")
    user = os.getenv("POSTGRES_USER", "app")
    password = os.getenv("POSTGRES_PASSWORD", "app")
    return f"{scheme}://{user}:{password}@{host}:{port}/{db}"


# Sync DSN for psycopg (existing data access)
DB_DSN = os.getenv("DATABASE_URL", _build_dsn("postgresql"))

# Async DSN for asyncpg (LISTEN/NOTIFY + WebSocket fan-out)
ASYNC_DB_DSN = os.getenv("ASYNC_DATABASE_URL", _build_dsn("postgresql"))

APP_NAME = "Threat & Risk API"
APP_VERSION = "0.3.0"  # Phase 7A
MAX_STREAM_LAG_MINUTES = float(os.getenv("MAX_STREAM_LAG_MINUTES", "15"))
API_CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("API_CORS_ORIGINS", "http://localhost:5173,http://localhost:8600").split(",")
    if origin.strip()
]

# ──────────────────────────────────────────────────────────────────────────────
# JWT / Auth  (Phase 7A)
# ──────────────────────────────────────────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE-ME-IN-PRODUCTION-use-openssl-rand-hex-32")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL_MINUTES = int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "15"))
REFRESH_TOKEN_TTL_DAYS = int(os.getenv("REFRESH_TOKEN_TTL_DAYS", "7"))

# Short-lived WebSocket upgrade tickets (seconds)
WS_TICKET_TTL_SECONDS = int(os.getenv("WS_TICKET_TTL_SECONDS", "30"))

# When False the /auth/* endpoints still work but JWT is not required on
# existing data endpoints (backward-compatible with API_KEY mode).
JWT_AUTH_ENABLED = os.getenv("JWT_AUTH_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
PRODUCTION_MODE = os.getenv("PRODUCTION_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}
SEED_DEMO_USERS = os.getenv("SEED_DEMO_USERS", "false").strip().lower() in {"1", "true", "yes", "on"}

# ──────────────────────────────────────────────────────────────────────────────
# Cookie settings for httpOnly refresh tokens  (Phase 7A security hardening)
# ──────────────────────────────────────────────────────────────────────────────
# Set COOKIE_SECURE=true in production (requires HTTPS).
COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}
# "lax" works for same-site SPAs behind a reverse proxy.
# Override to "strict" if your deploy has no cross-site navigation needs.
COOKIE_SAMESITE: str = os.getenv("COOKIE_SAMESITE", "lax")
COOKIE_NAME = "soc_rt"

# ──────────────────────────────────────────────────────────────────────────────
# Startup secret validation
# ──────────────────────────────────────────────────────────────────────────────
# Known-insecure sentinel; startup validation rejects it when JWT auth is enabled.
_DEFAULT_JWT_SECRET = "CHANGE-ME-IN-PRODUCTION-use-openssl-rand-hex-32"  # nosec B105


def validate_secrets() -> None:
    """
    Raise RuntimeError at startup if critical secrets are still set to their
    known-insecure defaults.  Called from the FastAPI lifespan so the process
    refuses to start rather than silently accepting forgeable tokens.
    """
    if JWT_AUTH_ENABLED:
        if JWT_SECRET == _DEFAULT_JWT_SECRET:
            raise RuntimeError(
                "CRITICAL: JWT_AUTH_ENABLED=true but JWT_SECRET is the insecure built-in "
                "default.  Generate a strong secret with:\n"
                "    openssl rand -hex 32\n"
                "then set JWT_SECRET=<value> in your environment."
            )
        if len(JWT_SECRET) < 32:
            raise RuntimeError(
                f"CRITICAL: JWT_SECRET is only {len(JWT_SECRET)} characters — minimum 32 required."
            )

    if PRODUCTION_MODE:
        if not JWT_AUTH_ENABLED:
            raise RuntimeError("CRITICAL: PRODUCTION_MODE=true requires JWT_AUTH_ENABLED=true.")
        if not COOKIE_SECURE:
            raise RuntimeError("CRITICAL: PRODUCTION_MODE=true requires COOKIE_SECURE=true.")
        if SEED_DEMO_USERS:
            raise RuntimeError("CRITICAL: PRODUCTION_MODE=true cannot run with SEED_DEMO_USERS=true.")

    # Guard against accidentally opening CORS to all origins with credentials
    for origin in API_CORS_ORIGINS:
        if origin.strip() == "*":
            raise RuntimeError(
                "CRITICAL: API_CORS_ORIGINS contains '*' (wildcard) while "
                "allow_credentials=True.  Browsers reject this combination and it "
                "creates a CSRF surface.  Use explicit origin(s) instead."
            )
