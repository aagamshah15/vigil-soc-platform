"""
Phase 7A – WebSocket infrastructure
=====================================
ConnectionManager  : fan-out registry for active WebSocket clients
listen_postgres    : asyncpg LISTEN/NOTIFY background task
                     Subscribes to two channels:
                       soc_new_event       → broadcast to all clients
                       soc_incident_state  → broadcast to all clients

Single-node assumption
──────────────────────
This implementation is correct for a single-replica deployment.  When running
multiple API replicas in Kubernetes each replica has its own ConnectionManager
and its own asyncpg LISTEN connection.  A NOTIFY received by Postgres is
delivered to *all* LISTEN connections (one per replica), so each replica
broadcasts to its own set of clients — which is exactly correct provided the
load-balancer uses sticky sessions (ip_hash / cookie-based affinity).  If
sticky sessions are not available a cross-replica pub-sub bus (Redis Streams,
NATS) must be added; that is deferred to Phase 7D.

WebSocket message envelope
──────────────────────────
Every message sent to clients is a JSON object with a "type" discriminator:

  { "type": "soc_event",            "data": { ...pg_notify payload... } }
  { "type": "incident_state_change", "data": { ...pg_notify payload... } }
  { "type": "ping",                  "ts":   "<ISO-8601>" }
  { "type": "error",                 "detail": "..." }
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import asyncpg
from fastapi import WebSocket, WebSocketDisconnect

from .config import ASYNC_DB_DSN, validate_secrets
from .db import get_conn
from .metrics import WS_BROADCAST_FAILURES, WS_BROADCAST_TOTAL, WS_CONNECTED_CLIENTS, WS_RECONNECTS

log = logging.getLogger(__name__)

# Ping interval for keepalive (seconds)
_PING_INTERVAL = 30


class ConnectionManager:
    """Thread-safe registry of active WebSocket connections."""

    def __init__(self) -> None:
        self._clients: dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()
        self._listener_ok = False

    async def connect(self, client_id: str, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients[client_id] = ws
            WS_CONNECTED_CLIENTS.set(len(self._clients))
        WS_RECONNECTS.inc()
        log.info("[ws] client connected: %s  (total=%d)", client_id, len(self._clients))

    async def disconnect(self, client_id: str) -> None:
        async with self._lock:
            self._clients.pop(client_id, None)
            WS_CONNECTED_CLIENTS.set(len(self._clients))
        log.info("[ws] client disconnected: %s  (total=%d)", client_id, len(self._clients))

    async def broadcast(self, message: dict[str, Any]) -> None:
        if not self._clients:
            return
        payload = json.dumps(message, default=str)
        message_type = str(message.get("type") or "unknown")
        dead: list[str] = []
        for client_id, ws in list(self._clients.items()):
            try:
                await ws.send_text(payload)
                WS_BROADCAST_TOTAL.labels(message_type).inc()
            except Exception:
                WS_BROADCAST_FAILURES.labels(message_type).inc()
                dead.append(client_id)
        for client_id in dead:
            await self.disconnect(client_id)

    @property
    def count(self) -> int:
        return len(self._clients)

    @property
    def listener_ok(self) -> bool:
        return self._listener_ok

    def set_listener_ok(self, ok: bool) -> None:
        self._listener_ok = ok


# Module-level singleton — imported by main.py at startup
manager = ConnectionManager()


# ──────────────────────────────────────────────────────────────────────────────
# Background PGLISTEN task
# ──────────────────────────────────────────────────────────────────────────────

async def _on_soc_event(
    _conn: asyncpg.Connection,
    _pid: int,
    _channel: str,
    payload: str,
) -> None:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        data = {"raw": payload}
    await manager.broadcast({"type": "soc_event", "data": data})


async def _on_incident_state(
    _conn: asyncpg.Connection,
    _pid: int,
    _channel: str,
    payload: str,
) -> None:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        data = {"raw": payload}
    await manager.broadcast({"type": "incident_state_change", "data": data})


async def listen_postgres() -> None:
    """
    Long-running async task.  Connects to Postgres, subscribes to both
    NOTIFY channels, and sends keepalive pings to all WebSocket clients
    every _PING_INTERVAL seconds.

    Reconnects automatically after any connection failure (3-second back-off).
    """
    while True:
        conn: asyncpg.Connection | None = None
        try:
            conn = await asyncpg.connect(ASYNC_DB_DSN)
            await conn.add_listener("soc_new_event", _on_soc_event)
            await conn.add_listener("soc_incident_state", _on_incident_state)
            manager.set_listener_ok(True)
            log.info("[ws] PGLISTEN active on soc_new_event + soc_incident_state")

            while True:
                await asyncio.sleep(_PING_INTERVAL)
                # Heartbeat: keeps the asyncpg connection alive and lets
                # clients detect a broken WebSocket before the OS TCP timeout.
                await manager.broadcast({
                    "type": "ping",
                    "ts": datetime.now(timezone.utc).isoformat(),
                })

        except asyncio.CancelledError:
            log.info("[ws] PGLISTEN task cancelled – shutting down cleanly")
            break
        except Exception as exc:
            manager.set_listener_ok(False)
            log.warning("[ws] PGLISTEN error: %s – reconnecting in 3 s", exc)
            await asyncio.sleep(3)
        finally:
            if conn and not conn.is_closed():
                try:
                    await conn.close()
                except Exception as close_exc:
                    log.debug("[ws] failed to close PGLISTEN connection cleanly: %s", close_exc)
            manager.set_listener_ok(False)


# ──────────────────────────────────────────────────────────────────────────────
# Housekeeping: expired WS ticket cleanup
# ──────────────────────────────────────────────────────────────────────────────

_TICKET_CLEANUP_INTERVAL = 3600  # seconds (hourly)


async def _cleanup_ws_tickets() -> None:
    """
    Background task that periodically removes expired auth.ws_tickets rows.
    Runs once per hour; prevents unbounded table growth from unused tickets.
    """
    while True:
        try:
            await asyncio.sleep(_TICKET_CLEANUP_INTERVAL)
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM auth.ws_tickets WHERE expires_at < now() - interval '1 hour'"
                    )
                    deleted = cur.rowcount
                conn.commit()
            if deleted:
                log.info("[ws] ticket cleanup: removed %d expired row(s)", deleted)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.warning("[ws] ticket cleanup error: %s", exc)


# ──────────────────────────────────────────────────────────────────────────────
# FastAPI lifespan context manager (used in main.py)
# ──────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def ws_lifespan(_app: Any):
    # Fail fast if secrets are still at insecure defaults
    validate_secrets()

    pglisten_task = asyncio.create_task(listen_postgres(), name="pglisten")
    cleanup_task  = asyncio.create_task(_cleanup_ws_tickets(), name="ticket-cleanup")
    log.info("[ws] lifespan: PGLISTEN + ticket-cleanup tasks started")
    try:
        yield
    finally:
        for task in (pglisten_task, cleanup_task):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        log.info("[ws] lifespan: background tasks stopped")


# ──────────────────────────────────────────────────────────────────────────────
# WebSocket endpoint handler (called from main.py)
# ──────────────────────────────────────────────────────────────────────────────

async def soc_stream_handler(websocket: WebSocket, client_id: str) -> None:
    """
    Manages the full lifecycle of a single WebSocket client.
    The caller (main.py) is responsible for ticket validation before calling here.
    """
    await manager.connect(client_id, websocket)
    try:
        while True:
            # We primarily push data; we also accept "pong" messages to
            # confirm the client is alive (mirrors the ping heartbeat).
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=_PING_INTERVAL * 2)
                msg = json.loads(raw)
                if msg.get("type") == "pong":
                    pass  # client acknowledged our ping; all good
            except asyncio.TimeoutError:
                # No message from client in 2× ping interval → disconnect
                break
            except WebSocketDisconnect:
                break
            except Exception:
                break
    finally:
        await manager.disconnect(client_id)
