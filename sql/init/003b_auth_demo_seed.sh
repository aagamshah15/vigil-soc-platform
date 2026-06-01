#!/bin/sh
set -eu

if [ "${SEED_DEMO_USERS:-false}" != "true" ]; then
  echo "[auth-demo-seed] SEED_DEMO_USERS is not true; skipping demo users"
  exit 0
fi

echo "[auth-demo-seed] seeding local demo users (password: changeme)"
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-app}" --dbname "${POSTGRES_DB:-threat_risk}" <<'SQL'
INSERT INTO auth.users (user_id, email, role, display_name, password_hash) VALUES
  ('user_l1',         'l1@soc.internal',         'l1',          'Alex Turner (L1)',          crypt('changeme', gen_salt('bf', 12))),
  ('user_l2',         'l2@soc.internal',         'l2',          'Morgan Patel (L2)',          crypt('changeme', gen_salt('bf', 12))),
  ('user_manager',    'manager@soc.internal',    'soc_manager', 'Riley Johnson (SOC Mgr)',   crypt('changeme', gen_salt('bf', 12))),
  ('user_ciso',       'ciso@soc.internal',       'ciso',        'Jordan Kim (CISO)',          crypt('changeme', gen_salt('bf', 12))),
  ('user_compliance', 'compliance@soc.internal', 'compliance',  'Avery Chen (Compliance)',   crypt('changeme', gen_salt('bf', 12)))
ON CONFLICT (user_id) DO NOTHING;
SQL
