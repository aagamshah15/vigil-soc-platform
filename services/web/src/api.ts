import { fallbackSocData } from "./mockData";
import type {
  ComplianceResponse,
  Incident,
  QnaAnswer,
  QnaTemplate,
  RiskEntity,
  SocLoadResult,
  TriageReport,
} from "./types";

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";

// ──────────────────────────────────────────────────────────────────────────────
// WebSocket URL — derived from API_BASE_URL so it works in both environments:
//   Docker  → nginx proxies /api/* with WS upgrade headers to api:8000
//   Dev     → vite proxy forwards /api/* (including WS upgrades) to localhost:8000
// ──────────────────────────────────────────────────────────────────────────────
export function buildWsUrl(): string {
  const base = API_BASE_URL;
  if (base.startsWith("http://") || base.startsWith("https://")) {
    return base.replace(/^http/, "ws") + "/v1/soc/stream";
  }
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${base}/v1/soc/stream`;
}

// ──────────────────────────────────────────────────────────────────────────────
// Core fetch helper
// ──────────────────────────────────────────────────────────────────────────────
async function requestJson<T>(
  path: string,
  apiKey: string | null,
  accessToken?: string | null,
  options?: RequestInit,
): Promise<T> {
  const inherited = (options?.headers ?? {}) as Record<string, string>;
  const headers: Record<string, string> = { ...inherited };
  if (apiKey) headers["x-api-key"] = apiKey;
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });
  if (!response.ok) {
    const body = await response.text();
    const err = Object.assign(
      new Error(`${path} → ${response.status}${body ? `: ${body.slice(0, 180)}` : ""}`),
      { status: response.status },
    );
    throw err;
  }
  return (await response.json()) as T;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return "Unknown API error";
}

// ──────────────────────────────────────────────────────────────────────────────
// Fallback data helpers (used when the API is unreachable)
// ──────────────────────────────────────────────────────────────────────────────
function refreshedFallbackData() {
  const now = Date.now();
  const timeline = fallbackSocData.triage.timeline.map((event, index) => ({
    ...event,
    event_time: new Date(
      now - (fallbackSocData.triage.timeline.length - index) * 3 * 60_000,
    ).toISOString(),
  }));
  const lastSeenAt =
    timeline[timeline.length - 1]?.event_time ?? new Date(now).toISOString();
  return {
    ...fallbackSocData,
    entities: fallbackSocData.entities.map((entity, index) => ({
      ...entity,
      last_seen_at: new Date(now - index * 4 * 60_000).toISOString(),
    })),
    incidents: fallbackSocData.incidents.map((incident) => ({
      ...incident,
      started_at: timeline[0]?.event_time ?? incident.started_at,
      last_seen_at: lastSeenAt,
    })),
    triage: { ...fallbackSocData.triage, timeline },
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Primary SOC data load
// ──────────────────────────────────────────────────────────────────────────────
export async function loadSocData(apiKey: string | null, accessToken?: string | null): Promise<SocLoadResult> {
  try {
    const [risk, incidents, qnaTemplates, pci, soc2] = await Promise.all([
      requestJson<{ rows: RiskEntity[] }>("/v1/soc/risk/entities?limit=20", apiKey, accessToken),
      requestJson<{ rows: Incident[] }>("/v1/soc/incidents?limit=20", apiKey, accessToken),
      requestJson<{ templates: QnaTemplate[] }>("/v1/soc/qna/templates", apiKey, accessToken),
      requestJson<ComplianceResponse>("/v1/soc/compliance/PCI-DSS", apiKey, accessToken),
      requestJson<ComplianceResponse>("/v1/soc/compliance/SOC2", apiKey, accessToken),
    ]);
    const incidentId = incidents.rows[0]?.incident_id ?? "INC-PAYMENT-001";
    const triage = await requestJson<TriageReport>(
      `/v1/soc/incidents/${encodeURIComponent(incidentId)}/triage-report`,
      apiKey,
      accessToken,
    );
    const answers = await Promise.all(
      qnaTemplates.templates
        .slice(0, 4)
        .map((t) => requestJson<QnaAnswer>(`/v1/soc/qna/${t.question_id}`, apiKey, accessToken)),
    );

    return {
      source: "live",
      data: {
        entities: risk.rows,
        incidents: incidents.rows,
        triage,
        qnaTemplates: qnaTemplates.templates,
        qnaAnswers: answers,
        compliance: [pci, soc2],
      },
    };
  } catch (error) {
    console.warn("Using fallback SOC data", error);
    return {
      data: refreshedFallbackData(),
      source: "fallback",
      errorMessage: errorMessage(error),
    };
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Phase 7A: Incident mutable state
// ──────────────────────────────────────────────────────────────────────────────
export interface IncidentStateResult {
  incident_id: string;
  status: string;
  severity: string;
  assignee: string;
  notes: string | null;
  version: number;
  updated_at: string | null;
  updated_by: string | null;
  acknowledged?: boolean;
  investigated_entities?: string[];
  completed_steps?: string[];
}

export async function getIncidentState(
  incidentId: string,
  apiKey: string | null,
  accessToken?: string | null,
): Promise<IncidentStateResult | null> {
  try {
    return await requestJson<IncidentStateResult>(
      `/v1/soc/incidents/${encodeURIComponent(incidentId)}/state`,
      apiKey,
      accessToken,
    );
  } catch {
    return null;
  }
}

export async function postIncidentAction(
  incidentId: string,
  actionType: string,
  newValue: Record<string, unknown>,
  apiKey: string | null,
  accessToken?: string | null,
): Promise<void> {
  await requestJson(
    `/v1/soc/incidents/${encodeURIComponent(incidentId)}/actions`,
    apiKey,
    accessToken,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action_type: actionType, new_value: newValue }),
    },
  );
}

export async function patchIncidentState(
  incidentId: string,
  patch: { status?: string; assignee?: string; notes?: string },
  version: number,
  apiKey: string | null,
  accessToken?: string | null,
): Promise<IncidentStateResult> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "If-Match": String(version),
  };
  if (apiKey) headers["x-api-key"] = apiKey;
  if (accessToken) headers["Authorization"] = `Bearer ${accessToken}`;

  const response = await fetch(
    `${API_BASE_URL}/v1/soc/incidents/${encodeURIComponent(incidentId)}/state`,
    { method: "PATCH", headers, body: JSON.stringify(patch) },
  );

  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { version?: number; detail?: string };
    throw Object.assign(new Error(body.detail ?? `PATCH ${response.status}`), {
      status: response.status,
      serverVersion: body.version,
    });
  }
  return (await response.json()) as IncidentStateResult;
}

// ──────────────────────────────────────────────────────────────────────────────
// Phase 7A: JWT auth  (security-hardened: refresh token in httpOnly cookie)
// ──────────────────────────────────────────────────────────────────────────────

/**
 * The shape returned by /auth/login and /auth/refresh.
 * NOTE: refresh_token is NOT included — it lives exclusively in the httpOnly
 * "soc_rt" cookie set by the server and is never readable from JavaScript.
 */
export interface LoginResult {
  access_token: string;
  token_type: string;
  /** ISO-8601 — when the access token expires (15 min by default). */
  access_expires_at: string;
  refresh_expires_at: string;
  user: {
    user_id: string;
    email: string;
    role: string;
    display_name: string;
  };
}

/**
 * Fetch a short-lived single-use WebSocket upgrade ticket.
 * Returns the ticket string, or null if the request fails (e.g. no JWT session).
 */
export async function fetchWsTicket(accessToken: string): Promise<string | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/ws-ticket`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) return null;
    const data = (await response.json()) as { ticket: string };
    return data.ticket ?? null;
  } catch {
    return null;
  }
}

export async function loginUser(email: string, password: string): Promise<LoginResult> {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",   // send/receive cookies
    body: JSON.stringify({ email, password }),
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { detail?: string };
    throw new Error(body.detail ?? "Invalid credentials");
  }
  return (await response.json()) as LoginResult;
}

/**
 * Silently refresh the access token using the httpOnly "soc_rt" cookie.
 * Returns the new LoginResult on success, or null if the session has expired.
 * Called on page load to restore an active session without a re-login prompt.
 */
export async function refreshSession(): Promise<LoginResult | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: "POST",
      credentials: "same-origin",   // browser attaches the soc_rt cookie automatically
      headers: { "Content-Type": "application/json" },
    });
    if (!response.ok) return null;
    return (await response.json()) as LoginResult;
  } catch {
    return null;
  }
}

/** Best-effort logout — revokes the server-side refresh token and clears the cookie. */
export async function logoutUser(): Promise<void> {
  await fetch(`${API_BASE_URL}/auth/logout`, {
    method: "POST",
    credentials: "same-origin",   // browser sends the soc_rt cookie so server can revoke it
    headers: { "Content-Type": "application/json" },
  }).catch(() => {
    /* best-effort */
  });
}
