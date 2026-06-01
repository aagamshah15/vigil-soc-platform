-- Phase 8A: Threat Intelligence IOC table
-- Stores indicators from OTX, ThreatFox, and Feodo Tracker.
-- Enriched via dbt join against raw.security_events (src_ip / dest_ip).

CREATE TABLE IF NOT EXISTS raw.iocs (
    ioc_id          TEXT PRIMARY KEY,           -- "<source>:<type>:<value>"
    source          TEXT NOT NULL,              -- 'otx' | 'threatfox' | 'feodo'
    ioc_type        TEXT NOT NULL,              -- 'ip' | 'domain' | 'url' | 'md5' | 'sha256'
    ioc_value       TEXT NOT NULL,
    malware_family  TEXT,
    confidence      INTEGER,                    -- 0-100
    tags            TEXT[],
    mitre_techniques TEXT[],
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fast lookup when enriching security events by IP or domain
CREATE INDEX IF NOT EXISTS idx_raw_iocs_value
    ON raw.iocs (ioc_value);

CREATE INDEX IF NOT EXISTS idx_raw_iocs_type_value
    ON raw.iocs (ioc_type, ioc_value);

CREATE TABLE IF NOT EXISTS raw.producer_offsets (
    source       TEXT NOT NULL,
    stream_id    TEXT NOT NULL,
    last_seen_id TEXT NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source, stream_id)
);
