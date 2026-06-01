-- Phase 7A security hardening
-- Run against an already-initialised database (idempotent).
-- Applies after 003_auth_schema.sql.

-- ──────────────────────────────────────────────────────────────────────────────
-- 1. Token prefix for fast O(1) refresh-token lookup before bcrypt verify.
--    Stores the first 16 characters of the raw (pre-hash) token string.
--    A colliding prefix still requires a successful bcrypt verify, so it
--    adds no credential exposure.
-- ──────────────────────────────────────────────────────────────────────────────
ALTER TABLE auth.refresh_tokens
  ADD COLUMN IF NOT EXISTS token_prefix TEXT;

CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_prefix
  ON auth.refresh_tokens(token_prefix)
  WHERE revoked_at IS NULL;

-- ──────────────────────────────────────────────────────────────────────────────
-- 2. Per-account login lockout
--    failed_attempts – consecutive bad-password counter (reset on success)
--    locked_until    – when the account becomes unlockable again
-- ──────────────────────────────────────────────────────────────────────────────
ALTER TABLE auth.users
  ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0;

ALTER TABLE auth.users
  ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;

-- ──────────────────────────────────────────────────────────────────────────────
-- 3. Seed users get a clean slate
-- ──────────────────────────────────────────────────────────────────────────────
UPDATE auth.users SET failed_attempts = 0, locked_until = NULL
WHERE failed_attempts IS NULL OR locked_until IS NOT NULL;
