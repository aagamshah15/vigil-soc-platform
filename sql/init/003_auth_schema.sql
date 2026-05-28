-- Phase 7A: Authentication schema
-- Requires pgcrypto for bcrypt password hashing in seed data
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS auth;

-- ──────────────────────────────────────────────────────────────────────────────
-- Users
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth.users (
  user_id      TEXT PRIMARY KEY,
  email        TEXT UNIQUE NOT NULL,
  role         TEXT NOT NULL DEFAULT 'l1',  -- l1 | l2 | soc_manager | ciso | compliance
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  is_active    BOOLEAN NOT NULL DEFAULT true,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ──────────────────────────────────────────────────────────────────────────────
-- Refresh tokens (stored; rotated on every use)
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth.refresh_tokens (
  token_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      TEXT NOT NULL REFERENCES auth.users(user_id) ON DELETE CASCADE,
  -- We store a bcrypt hash of the opaque token string so the DB is not
  -- a credential store if exfiltrated.
  token_hash   TEXT NOT NULL UNIQUE,
  issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,
  revoked_at   TIMESTAMPTZ,
  -- Forms a linked-list of rotations for audit purposes
  rotated_by   UUID REFERENCES auth.refresh_tokens(token_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_user_id ON auth.refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_hash   ON auth.refresh_tokens(token_hash);

-- ──────────────────────────────────────────────────────────────────────────────
-- WebSocket tickets (short-lived, single-use; in-memory in single-node deploy;
-- stored here for multi-replica correctness)
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth.ws_tickets (
  ticket      TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES auth.users(user_id) ON DELETE CASCADE,
  role        TEXT NOT NULL,
  issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_auth_ws_tickets_expires ON auth.ws_tickets(expires_at);

-- Demo users are seeded by 003_auth_demo_seed.sh only when
-- SEED_DEMO_USERS=true. Production deploys should leave that flag disabled.
