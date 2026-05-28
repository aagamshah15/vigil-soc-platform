"""
Phase 7A – Incident state management router
=============================================
Endpoints
─────────
GET    /v1/soc/incidents/{incident_id}/state
PATCH  /v1/soc/incidents/{incident_id}/state   (optimistic locking via If-Match header)
GET    /v1/soc/incidents/{incident_id}/actions
POST   /v1/soc/incidents/{incident_id}/actions

Optimistic locking
──────────────────
The current version number is returned in every GET response and in the
ETag response header.  Clients MUST send `If-Match: <version>` on every
PATCH.  If the version has changed since the client last fetched state a
409 Conflict is returned.  The client should re-fetch and re-apply the
desired change.

PATCH body fields (all optional):
  status    – open | investigating | contained | resolved | closed
  severity  – info | low | medium | high | critical
  assignee  – analyst display name
  notes     – free text

Audit trail
───────────
Every successful PATCH automatically appends to soc.incident_actions with
action_type derived from which fields changed.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .db import get_conn
from .metrics import INCIDENT_ACTION_TOTAL
from .security import require_soc_auth

router = APIRouter(prefix="/v1/soc", tags=["soc-state"])


# ──────────────────────────────────────────────────────────────────────────────
# Schemas
# ──────────────────────────────────────────────────────────────────────────────

class PatchIncidentBody(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None


class AddActionBody(BaseModel):
    action_type: str
    new_value: dict[str, Any] = {}
    old_value: Optional[dict[str, Any]] = None


# ──────────────────────────────────────────────────────────────────────────────
# DB helpers
# ──────────────────────────────────────────────────────────────────────────────

_VALID_STATUSES = {"open", "investigating", "contained", "resolved", "closed"}
_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_VALID_ACTION_TYPES = {
    "acknowledged",
    "entity_investigated",
    "step_completed",
    "step_reopened",
    "assignee_change",
    "status_change",
    "severity_change",
    "note_added",
}


def _get_state(conn: Any, incident_id: str) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT incident_id, status, severity, assignee, notes, version, "
            "       created_at, updated_at, updated_by, acknowledged, "
            "       investigated_entities, completed_steps "
            "FROM soc.incident_state WHERE incident_id = %s",
            (incident_id,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {
        "incident_id": row[0],
        "status": row[1],
        "severity": row[2],
        "assignee": row[3],
        "notes": row[4],
        "version": row[5],
        "created_at": row[6].isoformat() if row[6] else None,
        "updated_at": row[7].isoformat() if row[7] else None,
        "updated_by": row[8],
        "acknowledged": bool(row[9]),
        "investigated_entities": row[10] or [],
        "completed_steps": row[11] or [],
    }


def _ensure_state_exists(conn: Any, incident_id: str) -> None:
    """Create a default state row if the incident has none yet."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO soc.incident_state (incident_id, status, severity, assignee, version) "
            "VALUES (%s, 'open', 'medium', 'Unassigned', 1) ON CONFLICT (incident_id) DO NOTHING",
            (incident_id,),
        )
    conn.commit()


def _get_actions(conn: Any, incident_id: str, limit: int = 100) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT action_id, incident_id, actor, action_type, old_value, new_value, created_at "
            "FROM soc.incident_actions "
            "WHERE incident_id = %s ORDER BY created_at DESC LIMIT %s",
            (incident_id, limit),
        )
        rows = cur.fetchall()
    return [
        {
            "action_id": str(row[0]),
            "incident_id": row[1],
            "actor": row[2],
            "action_type": row[3],
            "old_value": row[4],
            "new_value": row[5],
            "created_at": row[6].isoformat() if row[6] else None,
        }
        for row in rows
    ]


def _build_audit_entries(
    old: dict[str, Any],
    patch: PatchIncidentBody,
    actor: str,
    incident_id: str,
) -> list[tuple]:
    """Returns a list of (incident_id, actor, action_type, old_value, new_value) tuples."""
    entries: list[tuple] = []

    if patch.status and patch.status != old.get("status"):
        entries.append((
            incident_id, actor, "status_change",
            json.dumps({"status": old.get("status")}),
            json.dumps({"status": patch.status}),
        ))
    if patch.assignee and patch.assignee != old.get("assignee"):
        entries.append((
            incident_id, actor, "assignee_change",
            json.dumps({"assignee": old.get("assignee")}),
            json.dumps({"assignee": patch.assignee}),
        ))
    if patch.severity and patch.severity != old.get("severity"):
        entries.append((
            incident_id, actor, "severity_change",
            json.dumps({"severity": old.get("severity")}),
            json.dumps({"severity": patch.severity}),
        ))
    if patch.notes is not None and patch.notes != old.get("notes"):
        entries.append((
            incident_id, actor, "note_added",
            json.dumps({"notes": old.get("notes")}),
            json.dumps({"notes": patch.notes}),
        ))
    return entries


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/incidents/{incident_id}/state")
def get_incident_state(
    incident_id: str,
    current_user: Optional[dict] = Depends(require_soc_auth),
) -> JSONResponse:
    _ = current_user
    with get_conn() as conn:
        _ensure_state_exists(conn, incident_id)
        state = _get_state(conn, incident_id)

    if not state:
        raise HTTPException(status_code=404, detail="Incident not found")

    response = JSONResponse(state)
    response.headers["ETag"] = str(state["version"])
    response.headers["Cache-Control"] = "no-store"
    return response


@router.patch("/incidents/{incident_id}/state")
def patch_incident_state(
    incident_id: str,
    body: PatchIncidentBody,
    if_match: Optional[str] = Header(default=None, alias="if-match"),
    current_user: Optional[dict] = Depends(require_soc_auth),
) -> JSONResponse:
    # Determine actor for audit trail
    actor = (current_user or {}).get("sub") or (current_user or {}).get("display_name") or "anonymous"

    with get_conn() as conn:
        _ensure_state_exists(conn, incident_id)
        current = _get_state(conn, incident_id)
        if not current:
            raise HTTPException(status_code=404, detail="Incident not found")

        # Optimistic locking check
        if if_match is None:
            raise HTTPException(status_code=428, detail="If-Match header required for incident state updates.")
        try:
            client_version = int(if_match.strip('"'))
        except ValueError:
            raise HTTPException(status_code=400, detail="If-Match must be an integer version number")
        if client_version != current["version"]:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Version conflict: server is at version {current['version']}, "
                    f"you sent If-Match: {client_version}.  Re-fetch and retry."
                ),
            )

        # Validate enum values
        if body.status and body.status not in _VALID_STATUSES:
            raise HTTPException(status_code=422, detail=f"Invalid status '{body.status}'. Valid: {_VALID_STATUSES}")
        if body.severity and body.severity not in _VALID_SEVERITIES:
            raise HTTPException(status_code=422, detail=f"Invalid severity '{body.severity}'. Valid: {_VALID_SEVERITIES}")

        # Build audit entries before mutating current
        audit_entries = _build_audit_entries(current, body, actor, incident_id)

        # Nothing changed → return current state as-is
        if not audit_entries and body.notes is None:
            response = JSONResponse(current)
            response.headers["ETag"] = str(current["version"])
            return response

        # Apply the update
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE soc.incident_state SET
                  status     = COALESCE(%s, status),
                  severity   = COALESCE(%s, severity),
                  assignee   = COALESCE(%s, assignee),
                  notes      = COALESCE(%s, notes),
                  version    = version + 1,
                  updated_at = now(),
                  updated_by = %s
                WHERE incident_id = %s AND version = %s
                RETURNING incident_id, status, severity, assignee, notes, version,
                          created_at, updated_at, updated_by, acknowledged,
                          investigated_entities, completed_steps
                """,
                (
                    body.status, body.severity, body.assignee, body.notes,
                    actor, incident_id, current["version"],
                ),
            )
            row = cur.fetchone()

        if not row:
            # Another write beat us — highly unlikely but handle it
            conn.rollback()
            raise HTTPException(
                status_code=409,
                detail="Concurrent modification detected. Re-fetch and retry.",
            )

        # Write audit entries
        if audit_entries:
            with conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO soc.incident_actions "
                    "(incident_id, actor, action_type, old_value, new_value) "
                    "VALUES (%s, %s, %s, %s::jsonb, %s::jsonb)",
                    audit_entries,
                )
                for entry in audit_entries:
                    INCIDENT_ACTION_TOTAL.labels(entry[2]).inc()
        conn.commit()

    updated = {
        "incident_id": row[0],
        "status": row[1],
        "severity": row[2],
        "assignee": row[3],
        "notes": row[4],
        "version": row[5],
        "created_at": row[6].isoformat() if row[6] else None,
        "updated_at": row[7].isoformat() if row[7] else None,
        "updated_by": row[8],
        "acknowledged": bool(row[9]),
        "investigated_entities": row[10] or [],
        "completed_steps": row[11] or [],
    }
    response = JSONResponse(updated)
    response.headers["ETag"] = str(updated["version"])
    return response


@router.get("/incidents/{incident_id}/actions")
def list_incident_actions(
    incident_id: str,
    current_user: Optional[dict] = Depends(require_soc_auth),
) -> dict[str, Any]:
    _ = current_user
    with get_conn() as conn:
        actions = _get_actions(conn, incident_id)
    return {"incident_id": incident_id, "actions": actions}


@router.post("/incidents/{incident_id}/actions")
def add_incident_action(
    incident_id: str,
    body: AddActionBody,
    current_user: Optional[dict] = Depends(require_soc_auth),
) -> dict[str, Any]:
    """Manually append an action (e.g. analyst notes, acknowledgements)."""
    if body.action_type not in _VALID_ACTION_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid action_type '{body.action_type}'. Valid: {sorted(_VALID_ACTION_TYPES)}",
        )

    actor = (current_user or {}).get("sub") or (current_user or {}).get("display_name") or "anonymous"
    with get_conn() as conn:
        # Ensure state row exists
        _ensure_state_exists(conn, incident_id)
        current = _get_state(conn, incident_id)
        if not current:
            raise HTTPException(status_code=404, detail="Incident not found")

        with conn.cursor() as cur:
            if body.action_type == "acknowledged":
                cur.execute(
                    """
                    UPDATE soc.incident_state
                    SET acknowledged = true, version = version + 1, updated_at = now(), updated_by = %s
                    WHERE incident_id = %s
                    """,
                    (actor, incident_id),
                )
            elif body.action_type == "entity_investigated":
                entity_id = body.new_value.get("entity_id")
                if not entity_id:
                    raise HTTPException(status_code=422, detail="entity_investigated requires new_value.entity_id")
                cur.execute(
                    """
                    UPDATE soc.incident_state
                    SET investigated_entities = CASE
                          WHEN %s = ANY(investigated_entities) THEN investigated_entities
                          ELSE array_append(investigated_entities, %s)
                        END,
                        version = version + 1,
                        updated_at = now(),
                        updated_by = %s
                    WHERE incident_id = %s
                    """,
                    (entity_id, entity_id, actor, incident_id),
                )
            elif body.action_type in {"step_completed", "step_reopened"}:
                step_id = body.new_value.get("step_id")
                if not step_id:
                    raise HTTPException(status_code=422, detail=f"{body.action_type} requires new_value.step_id")
                if body.action_type == "step_completed":
                    cur.execute(
                        """
                        UPDATE soc.incident_state
                        SET completed_steps = CASE
                              WHEN %s = ANY(completed_steps) THEN completed_steps
                              ELSE array_append(completed_steps, %s)
                            END,
                            version = version + 1,
                            updated_at = now(),
                            updated_by = %s
                        WHERE incident_id = %s
                        """,
                        (step_id, step_id, actor, incident_id),
                    )
                else:
                    cur.execute(
                        """
                        UPDATE soc.incident_state
                        SET completed_steps = array_remove(completed_steps, %s),
                            version = version + 1,
                            updated_at = now(),
                            updated_by = %s
                        WHERE incident_id = %s
                        """,
                        (step_id, actor, incident_id),
                    )
            elif body.action_type == "assignee_change":
                assignee = body.new_value.get("assignee")
                if not assignee:
                    raise HTTPException(status_code=422, detail="assignee_change requires new_value.assignee")
                cur.execute(
                    """
                    UPDATE soc.incident_state
                    SET assignee = %s, version = version + 1, updated_at = now(), updated_by = %s
                    WHERE incident_id = %s
                    """,
                    (assignee, actor, incident_id),
                )
            elif body.action_type == "status_change":
                status_value = body.new_value.get("status")
                if status_value not in _VALID_STATUSES:
                    raise HTTPException(status_code=422, detail=f"Invalid status '{status_value}'.")
                cur.execute(
                    """
                    UPDATE soc.incident_state
                    SET status = %s, version = version + 1, updated_at = now(), updated_by = %s
                    WHERE incident_id = %s
                    """,
                    (status_value, actor, incident_id),
                )
            elif body.action_type == "severity_change":
                severity_value = body.new_value.get("severity")
                if severity_value not in _VALID_SEVERITIES:
                    raise HTTPException(status_code=422, detail=f"Invalid severity '{severity_value}'.")
                cur.execute(
                    """
                    UPDATE soc.incident_state
                    SET severity = %s, version = version + 1, updated_at = now(), updated_by = %s
                    WHERE incident_id = %s
                    """,
                    (severity_value, actor, incident_id),
                )

            cur.execute(
                "INSERT INTO soc.incident_actions "
                "(incident_id, actor, action_type, old_value, new_value) "
                "VALUES (%s, %s, %s, %s::jsonb, %s::jsonb) RETURNING action_id, created_at",
                (
                    incident_id,
                    actor,
                    body.action_type,
                    json.dumps(body.old_value) if body.old_value else "null",
                    json.dumps(body.new_value),
                ),
            )
            row = cur.fetchone()
        conn.commit()
    INCIDENT_ACTION_TOTAL.labels(body.action_type).inc()

    return {
        "action_id": str(row[0]),
        "incident_id": incident_id,
        "actor": actor,
        "action_type": body.action_type,
        "new_value": body.new_value,
        "created_at": row[1].isoformat(),
    }
