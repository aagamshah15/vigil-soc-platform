-- Phase 7A: PostgreSQL LISTEN/NOTIFY triggers
-- Two channels:
--   soc_new_event      – fires on every INSERT to raw.security_events
--   soc_incident_state – fires on every INSERT/UPDATE to soc.incident_state
--
-- Payload is intentionally small (IDs + key fields only) because pg_notify
-- has a hard 8 kB limit on the payload string.

-- ──────────────────────────────────────────────────────────────────────────────
-- 1. New security event
-- ──────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION raw.notify_new_soc_event()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  payload JSON;
BEGIN
  payload := json_build_object(
    'event_id',     NEW.event_id,
    'event_time',   NEW.event_time,
    'entity_id',    NEW.entity_id,
    'entity_type',  NEW.entity_type,
    'severity',     NEW.severity,
    'source_system',NEW.source_system,
    'event_type',   NEW.event_type,
    'action',       NEW.action,
    'mitre',        NEW.mitre_technique
  );
  PERFORM pg_notify('soc_new_event', payload::text);
  RETURN NEW;
END;
$$;

-- Drop and recreate so re-running migrations is idempotent
DROP TRIGGER IF EXISTS trg_notify_new_soc_event ON raw.security_events;
CREATE TRIGGER trg_notify_new_soc_event
AFTER INSERT ON raw.security_events
FOR EACH ROW EXECUTE FUNCTION raw.notify_new_soc_event();

-- ──────────────────────────────────────────────────────────────────────────────
-- 2. Incident state change
-- ──────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION soc.notify_incident_state_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  payload JSON;
BEGIN
  payload := json_build_object(
    'incident_id', NEW.incident_id,
    'status',      NEW.status,
    'severity',    NEW.severity,
    'assignee',    NEW.assignee,
    'acknowledged', NEW.acknowledged,
    'investigated_entities', NEW.investigated_entities,
    'completed_steps', NEW.completed_steps,
    'version',     NEW.version,
    'updated_by',  NEW.updated_by,
    'updated_at',  NEW.updated_at
  );
  PERFORM pg_notify('soc_incident_state', payload::text);
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_notify_incident_state_change ON soc.incident_state;
CREATE TRIGGER trg_notify_incident_state_change
AFTER INSERT OR UPDATE ON soc.incident_state
FOR EACH ROW EXECUTE FUNCTION soc.notify_incident_state_change();
