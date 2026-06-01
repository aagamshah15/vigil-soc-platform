CREATE SCHEMA IF NOT EXISTS raw;

CREATE TABLE IF NOT EXISTS raw.security_events (
  event_id TEXT PRIMARY KEY,
  event_time TIMESTAMPTZ NOT NULL,
  ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  source_system TEXT NOT NULL,
  event_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  display_name TEXT,
  user_id TEXT,
  device_id TEXT,
  src_ip TEXT,
  dest_ip TEXT,
  asset_id TEXT,
  action TEXT NOT NULL,
  severity TEXT NOT NULL,
  mitre_technique TEXT,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  _consumer_ingested_at TIMESTAMPTZ,
  _kafka_topic TEXT,
  _kafka_partition INTEGER,
  _kafka_offset BIGINT,
  inserted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_raw_security_events_event_time
  ON raw.security_events (event_time);

CREATE INDEX IF NOT EXISTS idx_raw_security_events_entity
  ON raw.security_events (entity_id);

CREATE TABLE IF NOT EXISTS raw.soc_entities (
  entity_id TEXT PRIMARY KEY,
  entity_type TEXT NOT NULL,
  display_name TEXT NOT NULL,
  business_role TEXT,
  home_location TEXT,
  is_privileged BOOLEAN NOT NULL DEFAULT false,
  is_vendor BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS raw.soc_assets (
  asset_id TEXT PRIMARY KEY,
  asset_name TEXT NOT NULL,
  asset_type TEXT NOT NULL,
  criticality TEXT NOT NULL,
  data_domain TEXT,
  compliance_scope TEXT
);

CREATE TABLE IF NOT EXISTS raw.soc_threat_indicators (
  indicator TEXT PRIMARY KEY,
  indicator_type TEXT NOT NULL,
  source_name TEXT NOT NULL,
  severity TEXT NOT NULL,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS raw.soc_physical_access (
  access_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  badge_time TIMESTAMPTZ NOT NULL,
  location TEXT NOT NULL,
  result TEXT NOT NULL
);

INSERT INTO raw.soc_entities (entity_id, entity_type, display_name, business_role, home_location, is_privileged, is_vendor)
VALUES
  ('user:jsmith', 'user', 'Jordan Smith', 'developer', 'Austin HQ', false, false),
  ('user:agarcia', 'user', 'Avery Garcia', 'dba', 'Austin HQ', true, false),
  ('device:WS-04821', 'device', 'WS-04821', 'developer workstation', 'Austin HQ', false, false),
  ('vendor:paylink-admin', 'vendor', 'PayLink contractor admin', 'vendor_admin', 'external', true, true)
ON CONFLICT (entity_id) DO UPDATE SET
  display_name = EXCLUDED.display_name,
  business_role = EXCLUDED.business_role,
  is_privileged = EXCLUDED.is_privileged,
  is_vendor = EXCLUDED.is_vendor;

INSERT INTO raw.soc_assets (asset_id, asset_name, asset_type, criticality, data_domain, compliance_scope)
VALUES
  ('paydb-prod-01', 'Payment Processing Database', 'database', 'critical', 'cardholder_data', 'PCI-DSS'),
  ('ad-prod-01', 'Production Active Directory', 'identity', 'critical', 'identity', 'SOC 2'),
  ('vpn-gateway-01', 'Vendor VPN Gateway', 'network', 'high', 'remote_access', 'SOC 2'),
  ('WS-04821', 'Developer Workstation WS-04821', 'endpoint', 'medium', 'workstation', 'SOC 2')
ON CONFLICT (asset_id) DO UPDATE SET
  asset_name = EXCLUDED.asset_name,
  criticality = EXCLUDED.criticality,
  compliance_scope = EXCLUDED.compliance_scope;

INSERT INTO raw.soc_threat_indicators (indicator, indicator_type, source_name, severity)
VALUES ('203.0.113.66', 'ip', 'dark_web_watchlist', 'critical')
ON CONFLICT (indicator) DO UPDATE SET
  source_name = EXCLUDED.source_name,
  severity = EXCLUDED.severity;

INSERT INTO raw.soc_physical_access (access_id, user_id, badge_time, location, result)
VALUES ('badge-jsmith-austin', 'jsmith', now() - interval '2 hours', 'Austin HQ', 'granted')
ON CONFLICT (access_id) DO UPDATE SET
  badge_time = EXCLUDED.badge_time,
  location = EXCLUDED.location,
  result = EXCLUDED.result;
