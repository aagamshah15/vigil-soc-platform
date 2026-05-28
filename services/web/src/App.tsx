import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bell,
  ChevronDown,
  CheckCircle2,
  ClipboardList,
  Database,
  Download,
  FileQuestion,
  Gauge,
  HelpCircle,
  KeyRound,
  ListChecks,
  Lock,
  LogIn,
  LogOut,
  Mail,
  PieChart as PieChartIcon,
  RefreshCw,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Target,
  Wifi,
  WifiOff,
  X,
} from "lucide-react";
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import {
  buildWsUrl,
  fetchWsTicket,
  getIncidentState,
  loadSocData,
  loginUser,
  logoutUser,
  patchIncidentState,
  postIncidentAction,
  refreshSession,
  type IncidentStateResult,
  type LoginResult,
} from "./api";
import { fallbackSocData } from "./mockData";
import type {
  ComplianceControl,
  ComplianceResponse,
  QnaAnswer,
  RiskBand,
  RiskEntity,
  SocData,
  TimelineEvent,
} from "./types";

const API_KEY_STORAGE = "soc_command_center_api_key";
// NOTE: AUTH_TOKENS_STORAGE is intentionally NOT written — the refresh token lives
// in an httpOnly cookie managed by the server.  Only the current role and non-secret
// preferences are persisted to localStorage.
const ACKNOWLEDGED_INCIDENTS_STORAGE = "soc_command_center_acknowledged_incidents";
const INVESTIGATED_ENTITIES_STORAGE = "soc_command_center_investigated_entities";
const ASSIGNEE_STORAGE = "soc_command_center_assignee";
const CURRENT_ROLE_STORAGE = "soc_current_role";
const INCIDENT_STATUS_STORAGE = "soc_command_center_incident_status";
const TRIAGE_STEPS_STORAGE = "soc_command_center_triage_steps";
const ALERT_EMAIL_STORAGE = "soc_command_center_alert_email";
const BROWSER_NOTIFICATIONS_STORAGE = "soc_command_center_browser_notifications";
const ANALYST_ROSTER = ["Unassigned", "Avery Chen", "Morgan Patel", "Riley Johnson"];

const navItems = [
  { id: "overview", label: "Overview", icon: Gauge },
  { id: "risk", label: "Entity Risk", icon: ShieldAlert },
  { id: "timeline", label: "Timeline", icon: Activity },
  { id: "triage", label: "Triage", icon: ClipboardList },
  { id: "qna", label: "Q&A", icon: FileQuestion },
  { id: "compliance", label: "Evidence", icon: ListChecks },
] as const;

type ViewId = (typeof navItems)[number]["id"];

const navGroups: { label: string; items: ViewId[] }[] = [
  { label: "Detection", items: ["overview", "risk"] },
  { label: "Investigation", items: ["timeline", "triage", "qna"] },
  { label: "Compliance", items: ["compliance"] },
];
type BandFilter = RiskBand | "all";
type RiskSort = "score-desc" | "score-asc" | "recent";
type RoleId = "l1" | "l2" | "manager" | "ciso" | "compliance";
type IncidentStatus = "Open" | "Investigating" | "Contained" | "Resolved";
type GlobalTimeRange = "1h" | "6h" | "24h" | "7d" | "all";
type RiskViewMode = "table" | "cards";
type NotificationKind = "critical" | "status" | "timeline";
type WsStatus = "connecting" | "connected" | "disconnected";

interface SocStreamMessage {
  type: "soc_event" | "incident_state_change" | "ping" | "error";
  data?: Record<string, unknown>;
  ts?: string;
  detail?: string;
}

interface SocNotification {
  id: string;
  kind: NotificationKind;
  title: string;
  detail: string;
  createdAt: string;
}

interface RoleProfile {
  id: RoleId;
  name: string;
  role: string;
  description: string;
  avatar: string;
  views: ViewId[];
  canAcknowledge: boolean;
  canInvestigate: boolean;
  canAssign: boolean;
  canChangeStatus: boolean;
  canExportCompliance: boolean;
}

const roleProfiles: RoleProfile[] = [
  {
    id: "l1",
    name: "Alex Rivera",
    role: "L1 Analyst",
    description: "First responder focused on monitoring, risk review, and timeline inspection.",
    avatar: "AR",
    views: ["overview", "timeline", "risk"],
    canAcknowledge: false,
    canInvestigate: false,
    canAssign: false,
    canChangeStatus: false,
    canExportCompliance: false,
  },
  {
    id: "l2",
    name: "Jordan Kim",
    role: "L2 Analyst",
    description: "Incident investigator with authority to acknowledge and mark entities reviewed.",
    avatar: "JK",
    views: ["overview", "risk", "timeline", "triage", "qna", "compliance"],
    canAcknowledge: true,
    canInvestigate: true,
    canAssign: false,
    canChangeStatus: true,
    canExportCompliance: false,
  },
  {
    id: "manager",
    name: "Sam Okafor",
    role: "SOC Manager",
    description: "Team lead with incident ownership, assignment, and lifecycle authority.",
    avatar: "SO",
    views: ["overview", "risk", "timeline", "triage", "qna", "compliance"],
    canAcknowledge: true,
    canInvestigate: true,
    canAssign: true,
    canChangeStatus: true,
    canExportCompliance: true,
  },
  {
    id: "ciso",
    name: "Dr. Priya Nair",
    role: "CISO",
    description: "Executive view of active risk, blast radius, and current response posture.",
    avatar: "PN",
    views: ["overview"],
    canAcknowledge: false,
    canInvestigate: false,
    canAssign: false,
    canChangeStatus: false,
    canExportCompliance: false,
  },
  {
    id: "compliance",
    name: "Marcus Chen",
    role: "Compliance Officer",
    description: "Audit and evidence review for PCI-DSS and SOC 2 reporting.",
    avatar: "MC",
    views: ["overview", "compliance"],
    canAcknowledge: false,
    canInvestigate: false,
    canAssign: false,
    canChangeStatus: false,
    canExportCompliance: true,
  },
];

const roleById = Object.fromEntries(roleProfiles.map((profile) => [profile.id, profile])) as Record<RoleId, RoleProfile>;

const bandColors: Record<RiskBand, string> = {
  low: "#22c55e",
  medium: "#facc15",
  high: "#f97316",
  critical: "#ef4444",
};

const bandBadgeClasses: Record<RiskBand, string> = {
  low: "border-emerald-400/30 bg-emerald-500/15 text-emerald-200",
  medium: "border-yellow-400/30 bg-yellow-500/15 text-yellow-100",
  high: "border-orange-400/30 bg-orange-500/15 text-orange-200",
  critical: "border-red-400/30 bg-red-500/15 text-red-200",
};

const severityDotClasses: Record<RiskBand, string> = {
  low: "border-emerald-400/40 bg-emerald-500/15",
  medium: "border-yellow-400/40 bg-yellow-500/15",
  high: "border-orange-400/40 bg-orange-500/15",
  critical: "border-red-400/50 bg-red-500/20",
};

const incidentStatusClasses: Record<IncidentStatus, string> = {
  Open: "border-red-400/30 bg-red-500/15 text-red-200",
  Investigating: "border-orange-400/30 bg-orange-500/15 text-orange-200",
  Contained: "border-yellow-400/30 bg-yellow-500/15 text-yellow-100",
  Resolved: "border-emerald-400/30 bg-emerald-500/15 text-emerald-200",
};

// ──────────────────────────────────────────────────────────────────────────────
// useSocStream — real-time WebSocket hook
// ──────────────────────────────────────────────────────────────────────────────
function useSocStream(
  onMessage: (msg: SocStreamMessage) => void,
  accessToken: string | null,
): WsStatus {
  const [wsStatus, setWsStatus] = useState<WsStatus>("disconnected");
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef<number | null>(null);
  const destroyedRef = useRef(false);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    destroyedRef.current = false;

    async function connect() {
      if (destroyedRef.current) return;
      setWsStatus("connecting");

      // If a JWT session is active, obtain a single-use WS upgrade ticket.
      // When JWT_AUTH_ENABLED=false the backend accepts connections without one.
      let url = buildWsUrl();
      if (accessToken) {
        const ticket = await fetchWsTicket(accessToken);
        if (!ticket) {
          setWsStatus("disconnected");
          scheduleRetry();
          return;
        }
        url += `?ticket=${encodeURIComponent(ticket)}`;
      }

      if (destroyedRef.current) return; // may have been torn down while awaiting

      let ws: WebSocket;
      try {
        ws = new WebSocket(url);
      } catch {
        scheduleRetry();
        return;
      }
      wsRef.current = ws;

      ws.onopen = () => {
        if (destroyedRef.current) { ws.close(); return; }
        setWsStatus("connected");
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data as string) as SocStreamMessage;
          if (msg.type === "ping") {
            ws.send(JSON.stringify({ type: "pong" }));
            return;
          }
          onMessageRef.current(msg);
        } catch {
          /* ignore malformed frames */
        }
      };

      ws.onclose = () => {
        wsRef.current = null;
        if (!destroyedRef.current) {
          setWsStatus("disconnected");
          scheduleRetry();
        }
      };

      ws.onerror = () => {
        ws.close();
      };
    }

    function scheduleRetry() {
      if (destroyedRef.current) return;
      // Each reconnect fetches a fresh ticket — old ones are single-use
      retryRef.current = window.setTimeout(() => { void connect(); }, 5_000);
    }

    void connect();

    return () => {
      destroyedRef.current = true;
      if (retryRef.current) window.clearTimeout(retryRef.current);
      wsRef.current?.close();
    };
  }, [accessToken]);

  return wsStatus;
}

function readStoredStringArray(key: string): string[] {
  try {
    const value = localStorage.getItem(key);
    const parsed = value ? JSON.parse(value) : [];
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function App() {
  const [currentRoleId, setCurrentRoleId] = useState<RoleId | null>(() => {
    const stored = localStorage.getItem(CURRENT_ROLE_STORAGE);
    return stored && stored in roleById ? (stored as RoleId) : null;
  });
  const [activeView, setActiveView] = useState<ViewId>("overview");
  const [apiKey, setApiKey] = useState(() => localStorage.getItem(API_KEY_STORAGE) ?? "");
  const [pendingApiKey, setPendingApiKey] = useState(apiKey);
  const [data, setData] = useState<SocData>(fallbackSocData);
  const [source, setSource] = useState<"live" | "fallback">("fallback");
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [acknowledgedIncidents, setAcknowledgedIncidents] = useState<string[]>(() =>
    readStoredStringArray(ACKNOWLEDGED_INCIDENTS_STORAGE),
  );
  const [investigatedEntities, setInvestigatedEntities] = useState<string[]>(() =>
    readStoredStringArray(INVESTIGATED_ENTITIES_STORAGE),
  );
  const [assignee, setAssignee] = useState(() => localStorage.getItem(ASSIGNEE_STORAGE) ?? "Unassigned");
  const [riskBandFilter, setRiskBandFilter] = useState<BandFilter>("all");
  const [riskSortMode, setRiskSortMode] = useState<RiskSort>("score-desc");
  const [riskQuery, setRiskQuery] = useState("");
  const [riskViewMode, setRiskViewMode] = useState<RiskViewMode>("table");
  const [globalSearch, setGlobalSearch] = useState("");
  const [searchMessage, setSearchMessage] = useState<string | null>(null);
  const [globalTimeRange, setGlobalTimeRange] = useState<GlobalTimeRange>("24h");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [lastSeenNotificationsAt, setLastSeenNotificationsAt] = useState("1970-01-01T00:00:00.000Z");
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [timelineEntityFilter, setTimelineEntityFilter] = useState<string | null>(null);
  const [incidentStatus, setIncidentStatus] = useState<IncidentStatus>(
    () => (localStorage.getItem(INCIDENT_STATUS_STORAGE) as IncidentStatus | null) ?? "Open",
  );
  const [incidentStatusChangedAt, setIncidentStatusChangedAt] = useState(() => new Date().toISOString());
  const [completedSteps, setCompletedSteps] = useState<string[]>(() => readStoredStringArray(TRIAGE_STEPS_STORAGE));
  const [alertEmail, setAlertEmail] = useState(() => localStorage.getItem(ALERT_EMAIL_STORAGE) ?? "");
  const [browserNotificationsEnabled, setBrowserNotificationsEnabled] = useState(
    () => localStorage.getItem(BROWSER_NOTIFICATIONS_STORAGE) === "true",
  );
  // Phase 7A: JWT auth tokens — access token in memory ONLY; refresh token is an
  // httpOnly cookie the browser attaches automatically (never readable from JS).
  const [authTokens, setAuthTokens] = useState<LoginResult | null>(null);
  // Phase 7A: server-side incident state version (for optimistic locking)
  const [incidentVersion, setIncidentVersion] = useState(1);
  const [patchError, setPatchError] = useState<string | null>(null);

  const currentRole = currentRoleId ? roleById[currentRoleId] : null;
  const availableNavItems = useMemo(
    () => (currentRole ? navItems.filter((item) => currentRole.views.includes(item.id)) : []),
    [currentRole],
  );

  const accessToken = authTokens?.access_token ?? null;

  const refresh = useCallback(async (key: string) => {
    setLoading(true);
    const result = await loadSocData(key || null, accessToken);
    setData(result.data);
    setSource(result.source);
    setApiError(result.errorMessage ?? null);
    setLastRefresh(new Date());
    setLoading(false);
  }, [accessToken]);

  useEffect(() => {
    void refresh(apiKey);
  }, [apiKey, refresh]);

  // 5-minute polling fallback (WebSocket is the primary update path)
  useEffect(() => {
    const interval = window.setInterval(() => {
      void refresh(apiKey);
    }, 5 * 60_000);
    return () => window.clearInterval(interval);
  }, [apiKey, refresh]);

  // Phase 7A: WebSocket real-time feed
  const wsStatus = useSocStream(
    useCallback(
      (msg: SocStreamMessage) => {
        if (msg.type === "soc_event") {
          // New security event arrived → refresh full data
          void refresh(apiKey);
        } else if (msg.type === "incident_state_change" && msg.data) {
          const d = msg.data as Partial<IncidentStateResult>;
          // Patch local state from push without a full reload
          if (d.status) {
            const serverStatus = capitalize(d.status) as IncidentStatus;
            if (["Open", "Investigating", "Contained", "Resolved"].includes(serverStatus)) {
              setIncidentStatus(serverStatus);
              setIncidentStatusChangedAt(d.updated_at ?? new Date().toISOString());
            }
	          }
	          if (d.assignee) setAssignee(d.assignee);
	          if (d.version) setIncidentVersion(d.version);
	          if (d.acknowledged && d.incident_id) {
	            setAcknowledgedIncidents((current) =>
	              current.includes(d.incident_id as string) ? current : [...current, d.incident_id as string],
	            );
	          }
	          if (d.investigated_entities) setInvestigatedEntities(d.investigated_entities);
	          if (d.completed_steps) setCompletedSteps(d.completed_steps);
	        }
      },
      [apiKey, refresh],
    ),
    accessToken,
  );

  // ── Token refresh loop ────────────────────────────────────────────────────
  // Access tokens expire in ACCESS_TOKEN_TTL_MINUTES (default 15 min).
  // Schedule a silent refresh 2 minutes before expiry so the session never
  // visibly breaks mid-demo.  Re-runs whenever authTokens changes (login /
  // silent restore / each successful refresh).
  useEffect(() => {
    if (!authTokens?.access_expires_at) return;

    const msUntilRefresh =
      new Date(authTokens.access_expires_at).getTime() - Date.now() - 2 * 60 * 1000;

    const doRefresh = () => {
      void refreshSession().then((result) => {
        if (result) setAuthTokens(result);
        else logout(); // refresh token also expired — back to login
      });
    };

    if (msUntilRefresh <= 0) {
      // Already within the 2-min window (e.g. tab was backgrounded) — refresh now
      doRefresh();
      return;
    }

    const timer = window.setTimeout(doRefresh, msUntilRefresh);
    return () => window.clearTimeout(timer);
  }, [authTokens?.access_expires_at]);

  // Phase 7A: on mount, silently restore an active JWT session via the httpOnly
  // refresh-token cookie.  If the cookie is valid we get a fresh access token
  // without asking the user to log in again.
  useEffect(() => {
    if (!currentRoleId) return;   // not logged in via role select, nothing to restore
    void refreshSession().then((result) => {
      if (!result) return;
      setAuthTokens(result);
      // Keep the role in sync with whatever the server says (handles role changes)
      const jwtRoleMap: Record<string, RoleId> = {
        l1: "l1",
        l2: "l2",
        soc_manager: "manager",
        ciso: "ciso",
        compliance: "compliance",
      };
      const roleId = jwtRoleMap[result.user.role];
      if (roleId && roleId !== currentRoleId) {
        setCurrentRoleId(roleId);
      }
    });
  }, [currentRoleId]);

  // Phase 7A: fetch server-side incident state on initial load (to get version)
  const incidentId = data.triage.incident_id;
  useEffect(() => {
    void getIncidentState(incidentId, apiKey, accessToken).then((state) => {
      if (!state) return;
      setIncidentVersion(state.version);
      // Reconcile server state → local state (server wins on first load)
      const serverStatus = capitalize(state.status) as IncidentStatus;
      if (["Open", "Investigating", "Contained", "Resolved"].includes(serverStatus)) {
        setIncidentStatus(serverStatus);
      }
      if (state.assignee && state.assignee !== "Unassigned") {
        setAssignee(state.assignee);
      }
      if (state.acknowledged) {
        setAcknowledgedIncidents((current) =>
          current.includes(incidentId) ? current : [...current, incidentId],
        );
      }
      if (state.investigated_entities) {
        setInvestigatedEntities(state.investigated_entities);
      }
      if (state.completed_steps) {
        setCompletedSteps(state.completed_steps);
      }
    });
  }, [incidentId, apiKey, accessToken]);

  useEffect(() => {
    localStorage.setItem(ACKNOWLEDGED_INCIDENTS_STORAGE, JSON.stringify(acknowledgedIncidents));
  }, [acknowledgedIncidents]);

  useEffect(() => {
    localStorage.setItem(INVESTIGATED_ENTITIES_STORAGE, JSON.stringify(investigatedEntities));
  }, [investigatedEntities]);

  useEffect(() => {
    localStorage.setItem(ASSIGNEE_STORAGE, assignee);
  }, [assignee]);

  useEffect(() => {
    localStorage.setItem(INCIDENT_STATUS_STORAGE, incidentStatus);
  }, [incidentStatus]);

  useEffect(() => {
    localStorage.setItem(TRIAGE_STEPS_STORAGE, JSON.stringify(completedSteps));
  }, [completedSteps]);

  useEffect(() => {
    localStorage.setItem(ALERT_EMAIL_STORAGE, alertEmail);
  }, [alertEmail]);

  useEffect(() => {
    localStorage.setItem(BROWSER_NOTIFICATIONS_STORAGE, String(browserNotificationsEnabled));
  }, [browserNotificationsEnabled]);

  useEffect(() => {
    if (currentRole && !currentRole.views.includes(activeView)) {
      setActiveView(currentRole.views[0]);
    }
  }, [activeView, currentRole]);

  const criticalEntities = data.entities.filter((entity) => entity.risk_band === "critical");
  const timeline = data.triage.timeline;
  const filteredTimelineForRange = filterTimelineByRange(timeline, globalTimeRange);
  const eventTimes = timeline
    .map((event) => event.event_time)
    .filter((eventTime): eventTime is string => Boolean(eventTime))
    .sort();
  const newestEvent = eventTimes[eventTimes.length - 1];
  const hasRecentTimelineEvent = filteredTimelineForRange.length > 0;

  const notifications = useMemo(
    () => buildNotifications(data, criticalEntities, incidentStatus, incidentStatusChangedAt),
    [criticalEntities, data, incidentStatus, incidentStatusChangedAt],
  );
  const unreadNotifications = notifications.filter(
    (notification) =>
      notification.kind === "critical" &&
      new Date(notification.createdAt).getTime() > new Date(lastSeenNotificationsAt).getTime(),
  ).length;

  const saveApiKey = () => {
    if (pendingApiKey === apiKey) {
      setSettingsOpen(false);
      return;
    }
    localStorage.setItem(API_KEY_STORAGE, pendingApiKey);
    setApiKey(pendingApiKey);
    setSettingsOpen(false);
  };

  const clearApiKey = () => {
    if (!apiKey && !pendingApiKey) {
      return;
    }
    localStorage.removeItem(API_KEY_STORAGE);
    setApiKey("");
    setPendingApiKey("");
  };

  useEffect(() => {
    if (!searchMessage) {
      return;
    }
    const timeout = window.setTimeout(() => setSearchMessage(null), 3_000);
    return () => window.clearTimeout(timeout);
  }, [searchMessage]);

  useEffect(() => {
    if (!patchError) {
      return;
    }
    const timeout = window.setTimeout(() => setPatchError(null), 5_000);
    return () => window.clearTimeout(timeout);
  }, [patchError]);

  const toggleBrowserNotifications = async (enabled: boolean) => {
    if (!enabled) {
      setBrowserNotificationsEnabled(false);
      return;
    }
    if (!("Notification" in window)) {
      setBrowserNotificationsEnabled(false);
      return;
    }
    const permission =
      Notification.permission === "default" ? await Notification.requestPermission() : Notification.permission;
    setBrowserNotificationsEnabled(permission === "granted");
  };

  useEffect(() => {
    if (!browserNotificationsEnabled || !("Notification" in window) || Notification.permission !== "granted") {
      return;
    }
    const latestCritical = notifications.find((notification) => notification.kind === "critical");
    if (!latestCritical) {
      return;
    }
    const marker = `notified:${latestCritical.id}`;
    if (sessionStorage.getItem(marker)) {
      return;
    }
    sessionStorage.setItem(marker, "true");
    new Notification(latestCritical.title, { body: latestCritical.detail });
  }, [browserNotificationsEnabled, notifications]);

  const acknowledgePrimaryIncident = () => {
    const incidentId = data.triage.incident_id;
    if (!acknowledgedIncidents.includes(incidentId)) {
      setAcknowledgedIncidents([...acknowledgedIncidents, incidentId]);
    }
    void postIncidentAction(incidentId, "acknowledged", {}, apiKey, accessToken)
      .catch(() => {
        /* offline fallback: localStorage persistence keeps the click */
      });
  };

  const markEntityInvestigated = (entityId: string) => {
    if (!investigatedEntities.includes(entityId)) {
      setInvestigatedEntities([...investigatedEntities, entityId]);
    }
    void postIncidentAction(
      data.triage.incident_id,
      "entity_investigated",
      { entity_id: entityId },
      apiKey,
      accessToken,
    ).catch(() => {
      /* offline fallback: localStorage persistence keeps the click */
    });
  };

  const login = (profile: RoleProfile, tokens?: LoginResult) => {
    localStorage.setItem(CURRENT_ROLE_STORAGE, profile.id);
    // Store access token in memory only — never in localStorage
    if (tokens) {
      setAuthTokens(tokens);
    }
    setCurrentRoleId(profile.id);
    setActiveView(profile.views[0]);
    // Ensure no overlay from a previous session is visible on the fresh dashboard
    setUserMenuOpen(false);
    setSettingsOpen(false);
    setNotificationsOpen(false);
    setHelpOpen(false);
  };

  const logout = () => {
    // Tell the server to revoke the httpOnly refresh-token cookie and clear it
    void logoutUser();
    localStorage.removeItem(CURRENT_ROLE_STORAGE);
    setAuthTokens(null);
    setCurrentRoleId(null);
    setActiveView("overview");
    // Close all overlay UI so none of them re-appear on the next login
    // (covers both manual "Switch profile" and silent token-expiry logout)
    setUserMenuOpen(false);
    setSettingsOpen(false);
    setNotificationsOpen(false);
    setHelpOpen(false);
  };

  const refreshNow = useCallback(() => {
    void refresh(apiKey);
  }, [apiKey, refresh]);

  const openEntityTimeline = (entity: RiskEntity) => {
    setTimelineEntityFilter(entity.entity_id);
    setActiveView("timeline");
  };

  const jumpToEntityRisk = (entity: RiskEntity) => {
    setRiskQuery(entity.display_name);
    setRiskBandFilter("all");
    setActiveView("risk");
  };

  const submitGlobalSearch = () => {
    const normalized = globalSearch.trim().toLowerCase();
    if (!normalized) {
      return;
    }
    setSearchMessage(null);
    const matchedEntity = data.entities.find((entity) =>
      `${entity.display_name} ${entity.entity_id} ${entity.entity_type}`.toLowerCase().includes(normalized),
    );
    if (matchedEntity) {
      setRiskQuery(matchedEntity.display_name);
      setRiskBandFilter("all");
      setActiveView("risk");
      setGlobalSearch("");
      return;
    }
    const matchedTimelineEntity = timeline.find((event) =>
      `${event.entity_id ?? ""} ${event.display_name ?? ""} ${event.src_ip ?? ""} ${event.dest_ip ?? ""} ${event.asset ?? ""} ${event.asset_name ?? ""}`
        .toLowerCase()
        .includes(normalized),
    );
    if (matchedTimelineEntity) {
      setTimelineEntityFilter(matchedTimelineEntity.entity_id ?? matchedTimelineEntity.display_name ?? null);
      setActiveView("timeline");
      setGlobalSearch("");
      return;
    }
    setSearchMessage(`No results for "${globalSearch.trim()}"`);
    setGlobalSearch("");
  };

  const closeNotifications = () => {
    setNotificationsOpen(false);
    setLastSeenNotificationsAt(new Date().toISOString());
  };

  const changeIncidentStatus = (status: IncidentStatus) => {
    // Optimistic local update
    setIncidentStatus(status);
    setIncidentStatusChangedAt(new Date().toISOString());
    setPatchError(null);

    // Persist to API (best-effort; errors shown as a toast)
    void patchIncidentState(
      data.triage.incident_id,
      { status: status.toLowerCase() },
      incidentVersion,
	      apiKey,
	      accessToken,
    )
      .then((updated) => {
        setIncidentVersion(updated.version);
      })
      .catch((err: Error & { status?: number }) => {
        if (err.status === 409) {
          setPatchError("Status updated by another analyst — refreshing…");
          void refresh(apiKey);
        }
        // For other errors (network down, etc.) the local state is already set
        // so the analyst's work isn't lost; the error is informational only.
      });
  };

  const changeAssignee = (newAssignee: string) => {
    setAssignee(newAssignee);
    setPatchError(null);
    void patchIncidentState(
      data.triage.incident_id,
      { assignee: newAssignee },
      incidentVersion,
	      apiKey,
	      accessToken,
    )
      .then((updated) => {
        setIncidentVersion(updated.version);
      })
      .catch(() => {
        /* silent — local state already updated */
      });
  };

  const toggleStep = (incidentId: string, index: number) => {
    const stepId = `${incidentId}:${index}`;
    const nextCompleted = !completedSteps.includes(stepId);
    setCompletedSteps((current) =>
      current.includes(stepId) ? current.filter((item) => item !== stepId) : [...current, stepId],
    );
    void postIncidentAction(
      incidentId,
      nextCompleted ? "step_completed" : "step_reopened",
      { step_id: stepId },
      apiKey,
      accessToken,
    ).catch(() => {
      /* offline fallback: localStorage persistence keeps the click */
    });
  };

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.target instanceof HTMLInputElement || event.target instanceof HTMLSelectElement) {
        return;
      }
      if (event.key === "Escape") {
        setSettingsOpen(false);
        setHelpOpen(false);
        closeNotifications();
        setUserMenuOpen(false);
      }
      if (event.key.toLowerCase() === "r") {
        refreshNow();
      }
      if (event.key === "/") {
        event.preventDefault();
        document.getElementById("global-soc-search")?.focus();
      }
      if (event.key === "?") {
        setHelpOpen(true);
      }
      const index = Number(event.key) - 1;
      if (Number.isInteger(index) && availableNavItems[index]) {
        setActiveView(availableNavItems[index].id);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [availableNavItems, refreshNow]);

  if (!currentRole) {
    return (
      <LoginScreen
        onLogin={login}
        onJwtLogin={async (email, password) => {
          const result = await loginUser(email, password);
          // Map JWT role → local RoleProfile
          const jwtRoleMap: Record<string, RoleId> = {
            l1: "l1",
            l2: "l2",
            soc_manager: "manager",
            ciso: "ciso",
            compliance: "compliance",
          };
          const roleId = jwtRoleMap[result.user.role] ?? "l1";
          const profile = roleById[roleId];
          login(profile, result);
        }}
      />
    );
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <div className="flex min-h-screen">
        <aside className="hidden w-64 shrink-0 border-r border-zinc-800 bg-zinc-950/95 px-4 py-5 lg:block">
          <Brand incidentStatus={incidentStatus} />
          <nav className="mt-8 space-y-6">
            {navGroups.map((group) => {
              const groupItems = availableNavItems.filter((item) => group.items.includes(item.id));
              if (groupItems.length === 0) {
                return null;
              }
              return (
                <div key={group.label}>
                  <p className="mb-2 px-3 text-[11px] font-semibold uppercase tracking-[0.18em] text-zinc-600">
                    {group.label}
                  </p>
                  <div className="space-y-1">
                    {groupItems.map((item) => (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => setActiveView(item.id)}
                        className={`nav-button ${activeView === item.id ? "nav-button-active" : ""}`}
                      >
                        <item.icon className="h-4 w-4" />
                        <span>{item.label}</span>
                        {item.id === "risk" && criticalEntities.some((entity) => !investigatedEntities.includes(entity.entity_id)) && (
                          <span className="ml-auto rounded-full bg-red-500 px-2 py-0.5 text-[10px] font-semibold uppercase text-white">
                            {criticalEntities.length} critical
                          </span>
                        )}
                        {item.id === "timeline" && hasRecentTimelineEvent && (
                          <span className="ml-auto h-2.5 w-2.5 rounded-full bg-red-400 shadow-[0_0_12px_rgba(248,113,113,0.85)]" />
                        )}
                        {item.id === "triage" && (
                          <span className={`ml-auto rounded border px-1.5 py-0.5 text-[10px] ${incidentStatusClasses[incidentStatus]}`}>
                            {incidentStatus}
                          </span>
                        )}
                      </button>
                    ))}
                  </div>
                </div>
              );
            })}
          </nav>
        </aside>

        <main className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-20 border-b border-zinc-800 bg-zinc-950/90 px-4 py-3 backdrop-blur md:px-6">
            <div className="grid gap-3 xl:grid-cols-[auto_minmax(320px,1fr)_auto] xl:items-center">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-md bg-cyan-500/15 text-cyan-300">
                  <ShieldAlert className="h-5 w-5" />
                </div>
                <div>
                  <h1 className="text-lg font-semibold text-zinc-50 md:text-xl">Meridian Financial — SOC</h1>
                </div>
              </div>

              <div className="grid gap-2 md:grid-cols-[minmax(240px,1fr)_auto]">
                <div className="relative">
                  <label className={`flex min-w-0 items-center gap-2 rounded-md border bg-zinc-900/80 px-3 py-2 ${searchMessage ? "border-amber-500/50" : "border-zinc-800"}`}>
                    <Search className="h-4 w-4 shrink-0 text-zinc-500" />
                    <input
                      id="global-soc-search"
                      value={globalSearch}
                      onChange={(event) => {
                        setGlobalSearch(event.target.value);
                        setSearchMessage(null);
                      }}
                      onKeyDown={(event) => {
                        if (event.key === "Enter") {
                          submitGlobalSearch();
                        }
                      }}
                      placeholder="Search entities, IPs, assets, indicators..."
                      className="min-w-0 flex-1 bg-transparent text-sm text-zinc-200 outline-none placeholder:text-zinc-600"
                    />
                  </label>
                  {searchMessage && (
                    <div className="absolute left-0 top-full z-30 mt-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">
                      {searchMessage}
                    </div>
                  )}
                </div>
                <TimeRangeControl value={globalTimeRange} onChange={setGlobalTimeRange} />
              </div>

              <div className="relative flex flex-wrap items-center justify-start gap-2 xl:justify-end">
                <WsStatusBadge status={wsStatus} />
                <StatusPill source={source} loading={loading} errorMessage={apiError} onRefresh={refreshNow} />
                <button
                  type="button"
                  onClick={() => {
                    setNotificationsOpen((open) => {
                      if (open) {
                        setLastSeenNotificationsAt(new Date().toISOString());
                      }
                      return !open;
                    });
                    setUserMenuOpen(false);
                  }}
                  className="icon-button relative"
                  aria-label="Open notifications"
                >
                  <Bell className="h-4 w-4" />
                  {unreadNotifications > 0 && (
                    <span className="absolute -right-1 -top-1 rounded-full bg-red-500 px-1.5 text-[10px] font-semibold text-white">
                      {unreadNotifications}
                    </span>
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setUserMenuOpen((open) => !open);
                    closeNotifications();
                  }}
                  className="inline-flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-900/80 px-2 py-1.5 text-sm text-zinc-200 hover:border-zinc-600"
                >
                  <span className="flex h-7 w-7 items-center justify-center rounded-md bg-zinc-100 text-xs font-semibold text-zinc-950">
                    {currentRole.avatar}
                  </span>
                  <span className="hidden md:inline">{currentRole.name}</span>
                  <span className="rounded border border-zinc-700 px-2 py-0.5 text-xs text-zinc-400">{currentRole.role}</span>
                  <ChevronDown className="h-3.5 w-3.5 text-zinc-500" />
                </button>
                <button type="button" onClick={() => setSettingsOpen(true)} className="icon-button" aria-label="Open settings">
                  <Settings className="h-4 w-4" />
                </button>
                <button type="button" onClick={() => setHelpOpen(true)} className="icon-button" aria-label="Keyboard shortcuts">
                  <HelpCircle className="h-4 w-4" />
                </button>
                {(notificationsOpen || userMenuOpen) && (
                  <button
                    type="button"
                    aria-label="Close open menu"
                    className="fixed inset-0 z-[25] cursor-default bg-transparent"
                    onClick={() => {
                      closeNotifications();
                      setUserMenuOpen(false);
                    }}
                  />
                )}
                <NotificationTray open={notificationsOpen} notifications={notifications} onClose={closeNotifications} />
                <UserMenu open={userMenuOpen} role={currentRole} onLogout={logout} />
              </div>
            </div>

            <div className="mt-3 flex gap-2 overflow-x-auto pb-1 lg:hidden">
              {availableNavItems.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveView(item.id)}
                  className={`mobile-tab ${activeView === item.id ? "mobile-tab-active" : ""}`}
                >
                  <item.icon className="h-4 w-4" />
                  {item.label}
                </button>
              ))}
            </div>
          </header>

          <section className="flex-1 px-4 py-5 md:px-6">
            {apiError && (
              <div className="mb-4 rounded-md border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
                {currentRole.id === "ciso" ? "Connection degraded. Briefing reflects the last known state." : `Connection lost. Showing last known state. ${apiError}`}
              </div>
            )}
            {patchError && (
              <div className="mb-4 rounded-md border border-orange-500/30 bg-orange-500/10 px-4 py-3 text-sm text-orange-100">
                {patchError}
              </div>
            )}
            {activeView === "overview" && (
              <OverviewView
                data={data}
                lastRefresh={lastRefresh}
                newestEvent={newestEvent}
                filteredTimeline={filteredTimelineForRange}
                globalTimeRange={globalTimeRange}
                onSelectEntity={jumpToEntityRisk}
                onViewTimeline={() => setActiveView("timeline")}
                onAcknowledge={acknowledgePrimaryIncident}
                acknowledged={acknowledgedIncidents.includes(data.triage.incident_id)}
                assignee={assignee}
                onAssigneeChange={changeAssignee}
                role={currentRole}
                incidentStatus={incidentStatus}
              />
            )}
            {activeView === "risk" && (
              <RiskView
                entities={data.entities}
                investigatedEntities={investigatedEntities}
                onMarkInvestigated={markEntityInvestigated}
                bandFilter={riskBandFilter}
                onBandFilterChange={setRiskBandFilter}
                sortMode={riskSortMode}
                onSortModeChange={setRiskSortMode}
                query={riskQuery}
                onQueryChange={setRiskQuery}
                viewMode={riskViewMode}
                onViewModeChange={setRiskViewMode}
                globalTimeRange={globalTimeRange}
                onOpenTimeline={openEntityTimeline}
                canInvestigate={currentRole.canInvestigate}
              />
            )}
            {activeView === "timeline" && (
              <TimelineView
                incidentId={data.triage.incident_id}
                timeline={timeline}
                entityFilter={timelineEntityFilter}
                onEntityFilterChange={setTimelineEntityFilter}
                range={globalTimeRange}
              />
            )}
            {activeView === "triage" && (
              <TriageView
                data={data}
                entities={data.entities}
                assignee={assignee}
                onAssigneeChange={changeAssignee}
                onViewTimeline={() => setActiveView("timeline")}
                role={currentRole}
                incidentStatus={incidentStatus}
                onIncidentStatusChange={changeIncidentStatus}
                completedSteps={completedSteps}
                onToggleStep={toggleStep}
              />
            )}
            {activeView === "qna" && <QnaView answers={data.qnaAnswers} />}
            {activeView === "compliance" && <ComplianceView frameworks={data.compliance} canExport={currentRole.canExportCompliance} />}
          </section>
        </main>
      </div>
      <SettingsDrawer
        open={settingsOpen}
        apiKey={pendingApiKey}
        onApiKeyChange={setPendingApiKey}
        onSave={saveApiKey}
        onClear={clearApiKey}
        onClose={() => setSettingsOpen(false)}
        alertEmail={alertEmail}
        onAlertEmailChange={setAlertEmail}
        browserNotificationsEnabled={browserNotificationsEnabled}
        onBrowserNotificationsChange={toggleBrowserNotifications}
      />
      <ShortcutOverlay open={helpOpen} onClose={() => setHelpOpen(false)} />
    </div>
  );
}

function LoginScreen({
  onLogin,
  onJwtLogin,
}: {
  onLogin: (profile: RoleProfile) => void;
  onJwtLogin: (email: string, password: string) => Promise<void>;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loginLoading, setLoginLoading] = useState(false);

  const handleJwtLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;
    setLoginError(null);
    setLoginLoading(true);
    try {
      await onJwtLogin(email, password);
    } catch (err) {
      setLoginError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoginLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 px-4 py-10 text-zinc-100">
      <div className="mx-auto max-w-5xl">
        <div className="mb-8 flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-md bg-zinc-100 text-zinc-950">
            <Target className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold">Threat Risk Platform</h1>
            <p className="text-sm text-zinc-500">Meridian Financial — SOC Command Center</p>
          </div>
        </div>

        {/* JWT login form */}
        <section className="panel mb-8 p-6">
          <p className="section-label">Analyst sign-in</p>
          <h2 className="mt-1 text-lg font-semibold text-zinc-50">Sign in with credentials</h2>
          <p className="mt-1 text-sm text-zinc-500">
            Demo accounts: <span className="font-mono text-zinc-400">manager@soc.internal</span> · password:{" "}
            <span className="font-mono text-zinc-400">changeme</span>
          </p>
          <form onSubmit={(e) => void handleJwtLogin(e)} className="mt-5 flex flex-col gap-3 md:flex-row md:items-end">
            <label className="flex-1">
              <span className="section-label">Email</span>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@soc.internal"
                autoComplete="username"
                className="mt-2 w-full rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-zinc-600"
              />
            </label>
            <label className="flex-1">
              <span className="section-label">Password</span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete="current-password"
                className="mt-2 w-full rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-zinc-600"
              />
            </label>
            <button
              type="submit"
              disabled={loginLoading || !email || !password}
              className={`flex shrink-0 items-center gap-2 rounded-md px-5 py-2.5 text-sm font-semibold ${loginLoading || !email || !password ? "cursor-not-allowed bg-zinc-800 text-zinc-500" : "bg-cyan-500 text-zinc-950 hover:bg-cyan-400"}`}
            >
              <LogIn className="h-4 w-4" />
              {loginLoading ? "Signing in…" : "Sign in"}
            </button>
          </form>
          {loginError && (
            <p className="mt-3 text-sm text-red-300">{loginError}</p>
          )}
        </section>

        {/* Role-card demo access */}
        <div className="mb-4">
          <p className="section-label">Demo access — select a profile</p>
          <p className="mt-1 text-xs text-zinc-600">No credentials required. Bypasses JWT for local development.</p>
        </div>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {roleProfiles.map((profile) => (
            <button
              key={profile.id}
              type="button"
              onClick={() => onLogin(profile)}
              className="panel p-5 text-left transition hover:border-zinc-600"
            >
              <div className="flex items-center gap-3">
                <span className="flex h-11 w-11 items-center justify-center rounded-md bg-zinc-100 text-sm font-semibold text-zinc-950">
                  {profile.avatar}
                </span>
                <div>
                  <p className="font-semibold text-zinc-100">{profile.name}</p>
                  <p className="text-sm text-zinc-500">{profile.role}</p>
                </div>
              </div>
              <p className="mt-4 text-sm leading-6 text-zinc-400">{profile.description}</p>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function SettingsDrawer({
  open,
  apiKey,
  onApiKeyChange,
  onSave,
  onClear,
  onClose,
  alertEmail,
  onAlertEmailChange,
  browserNotificationsEnabled,
  onBrowserNotificationsChange,
}: {
  open: boolean;
  apiKey: string;
  onApiKeyChange: (value: string) => void;
  onSave: () => void;
  onClear: () => void;
  onClose: () => void;
  alertEmail: string;
  onAlertEmailChange: (value: string) => void;
  browserNotificationsEnabled: boolean;
  onBrowserNotificationsChange: (value: boolean) => void | Promise<void>;
}) {
  if (!open) {
    return null;
  }
  return (
    <div className="fixed inset-0 z-40 bg-black/50" onClick={onClose}>
      <aside className="ml-auto h-full w-full max-w-md border-l border-zinc-800 bg-zinc-950 p-5 shadow-panel" onClick={(event) => event.stopPropagation()}>
        <div className="flex items-center justify-between">
          <div>
            <p className="section-label">Settings</p>
            <h2 className="mt-1 text-xl font-semibold">Connection</h2>
          </div>
          <button type="button" onClick={onClose} className="icon-button" aria-label="Close settings">
            <X className="h-4 w-4" />
          </button>
        </div>
        <label className="mt-6 block">
          <span className="section-label">API key</span>
          <div className="mt-2 flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2">
            <KeyRound className="h-4 w-4 text-zinc-500" />
            <input
              value={apiKey}
              onChange={(event) => onApiKeyChange(event.target.value)}
              type="password"
              placeholder="Optional API key"
              className="min-w-0 flex-1 bg-transparent text-sm text-zinc-200 outline-none placeholder:text-zinc-600"
            />
          </div>
        </label>
        <div className="mt-4 flex gap-2">
          <button type="button" onClick={onSave} className="command-button">Save</button>
          <button type="button" onClick={onClear} className="rounded-md border border-zinc-800 px-3 py-2 text-sm text-zinc-300">Clear</button>
        </div>
        <div className="mt-8 border-t border-zinc-800 pt-5">
          <p className="section-label">Alert delivery</p>
          <label className="mt-4 block">
            <span className="text-sm font-medium text-zinc-300">Alert email</span>
            <div className="mt-2 flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2">
              <Mail className="h-4 w-4 text-zinc-500" />
              <input
                value={alertEmail}
                onChange={(event) => onAlertEmailChange(event.target.value)}
                type="email"
                placeholder="soc-alerts@meridian.example"
                className="min-w-0 flex-1 bg-transparent text-sm text-zinc-200 outline-none placeholder:text-zinc-600"
              />
            </div>
          </label>
          <label className="mt-4 flex items-center justify-between gap-3 rounded-md border border-zinc-800 bg-zinc-900/70 px-3 py-3 text-sm text-zinc-300">
            <span>Browser critical alerts</span>
            <input
              type="checkbox"
              checked={browserNotificationsEnabled}
              onChange={(event) => void onBrowserNotificationsChange(event.target.checked)}
              className="h-4 w-4 accent-cyan-400"
            />
          </label>
          <button
            type="button"
            onClick={() => alertEmail && window.alert(`Test alert queued for ${alertEmail}`)}
            className="mt-3 rounded-md border border-zinc-800 px-3 py-2 text-sm text-zinc-300 hover:border-zinc-600"
          >
            Send test alert
          </button>
        </div>
      </aside>
    </div>
  );
}

function TimeRangeControl({
  value,
  onChange,
}: {
  value: GlobalTimeRange;
  onChange: (value: GlobalTimeRange) => void;
}) {
  const options: { value: GlobalTimeRange; label: string }[] = [
    { value: "1h", label: "Last 1h" },
    { value: "6h", label: "Last 6h" },
    { value: "24h", label: "Last 24h" },
    { value: "7d", label: "Last 7d" },
    { value: "all", label: "All" },
  ];
  return (
    <select
      value={value}
      onChange={(event) => onChange(event.target.value as GlobalTimeRange)}
      className="rounded-md border border-zinc-800 bg-zinc-900/80 px-3 py-2 text-sm text-zinc-200 outline-none"
      aria-label="Global time range"
    >
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  );
}

function NotificationTray({
  open,
  notifications,
  onClose,
}: {
  open: boolean;
  notifications: SocNotification[];
  onClose: () => void;
}) {
  if (!open) {
    return null;
  }
  return (
    <div className="absolute right-0 top-11 z-30 w-[min(420px,calc(100vw-2rem))] rounded-md border border-zinc-800 bg-zinc-950 p-3 shadow-panel">
      <div className="flex items-center justify-between">
        <div>
          <p className="section-label">Notifications</p>
          <h2 className="mt-1 text-sm font-semibold text-zinc-100">Alert history</h2>
        </div>
        <button type="button" onClick={onClose} className="icon-button" aria-label="Close notifications">
          <X className="h-4 w-4" />
        </button>
      </div>
      <div className="mt-3 max-h-96 space-y-2 overflow-y-auto">
        {notifications.map((notification) => (
          <div key={notification.id} className="rounded-md border border-zinc-800 bg-zinc-900/80 p-3">
            <div className="flex items-start gap-3">
              <span className={`mt-1 h-2.5 w-2.5 rounded-full ${notification.kind === "critical" ? "bg-red-400" : notification.kind === "status" ? "bg-orange-300" : "bg-cyan-300"}`} />
              <div className="min-w-0">
                <p className="text-sm font-semibold text-zinc-100">{notification.title}</p>
                <p className="mt-1 text-xs leading-5 text-zinc-400">{notification.detail}</p>
                <p className="mt-2 text-xs text-zinc-600">{formatRelativeAge(notification.createdAt)}</p>
              </div>
            </div>
          </div>
        ))}
        {notifications.length === 0 && <EmptyState message="No alerts in the current operating window." />}
      </div>
    </div>
  );
}

function UserMenu({
  open,
  role,
  onLogout,
}: {
  open: boolean;
  role: RoleProfile;
  onLogout: () => void;
}) {
  if (!open) {
    return null;
  }
  return (
    <div className="absolute right-0 top-11 z-30 w-72 rounded-md border border-zinc-800 bg-zinc-950 p-3 shadow-panel">
      <div className="rounded-md border border-zinc-800 bg-zinc-900/80 p-3">
        <p className="font-semibold text-zinc-100">{role.name}</p>
        <p className="mt-1 text-sm text-zinc-500">{role.role}</p>
      </div>
      <button type="button" onClick={onLogout} className="mt-3 flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm text-zinc-300 hover:bg-zinc-900 hover:text-zinc-100">
        <LogOut className="h-4 w-4" />
        Switch operating profile
      </button>
    </div>
  );
}

function ShortcutOverlay({ open, onClose }: { open: boolean; onClose: () => void }) {
  if (!open) {
    return null;
  }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="panel w-full max-w-lg p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-semibold">Keyboard shortcuts</h2>
          <button type="button" onClick={onClose} className="icon-button" aria-label="Close shortcuts">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="mt-5 grid gap-3 text-sm text-zinc-300">
          <ShortcutRow keys="1-6" label="Switch navigation views" />
          <ShortcutRow keys="R" label="Refresh now" />
          <ShortcutRow keys="/" label="Focus global search" />
          <ShortcutRow keys="?" label="Open shortcuts" />
          <ShortcutRow keys="Esc" label="Close overlays" />
        </div>
      </div>
    </div>
  );
}

function ShortcutRow({ keys, label }: { keys: string; label: string }) {
  return (
    <div className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-950/60 px-3 py-2">
      <span>{label}</span>
      <kbd className="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-400">{keys}</kbd>
    </div>
  );
}

function Brand({ incidentStatus }: { incidentStatus: IncidentStatus }) {
  return (
    <div className="flex items-center gap-3">
      <div className="flex h-9 w-9 items-center justify-center rounded-md bg-zinc-100 text-zinc-950">
        <Target className="h-5 w-5" />
      </div>
      <div>
        <p className="text-sm font-semibold text-zinc-100">Threat Risk Platform</p>
        <p className={`mt-1 inline-flex rounded border px-2 py-0.5 text-xs ${incidentStatusClasses[incidentStatus]}`}>
          {incidentStatus}
        </p>
      </div>
    </div>
  );
}

function WsStatusBadge({ status }: { status: WsStatus }) {
  if (status === "connected") {
    return (
      <div title="Real-time feed connected" className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1.5 text-xs text-emerald-300">
        <Wifi className="h-3.5 w-3.5" />
        <span className="hidden sm:inline">Live</span>
      </div>
    );
  }
  if (status === "connecting") {
    return (
      <div title="Connecting to real-time feed…" className="inline-flex items-center gap-1.5 rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-1.5 text-xs text-amber-300">
        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
        <span className="hidden sm:inline">Connecting</span>
      </div>
    );
  }
  return (
    <div title="Real-time feed disconnected — polling every 5 min" className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700/50 bg-zinc-900/60 px-2 py-1.5 text-xs text-zinc-500">
      <WifiOff className="h-3.5 w-3.5" />
      <span className="hidden sm:inline">Offline</span>
    </div>
  );
}

function StatusPill({
  source,
  loading,
  errorMessage,
  onRefresh,
}: {
  source: "live" | "fallback";
  loading: boolean;
  errorMessage: string | null;
  onRefresh: () => void;
}) {
  const isLive = source === "live";
  return (
    <div
      title={errorMessage ?? undefined}
      className={`inline-flex items-center gap-2 rounded-md border px-3 py-2 text-sm ${
        isLive ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200" : "border-amber-500/30 bg-amber-500/10 text-amber-100"
      }`}
    >
      {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : isLive ? <ShieldCheck className="h-4 w-4" /> : <Database className="h-4 w-4" />}
      {loading ? "Loading" : isLive ? "Live" : "Offline mode"}
      <button type="button" onClick={onRefresh} className="ml-1 rounded p-0.5 opacity-60 transition hover:bg-white/10 hover:opacity-100" aria-label="Refresh now">
        <RefreshCw className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

function OverviewView({
  data,
  lastRefresh,
  newestEvent,
  filteredTimeline,
  globalTimeRange,
  onSelectEntity,
  onViewTimeline,
  onAcknowledge,
  acknowledged,
  assignee,
  onAssigneeChange,
  role,
  incidentStatus,
}: {
  data: SocData;
  lastRefresh: Date | null;
  newestEvent: string | undefined;
  filteredTimeline: TimelineEvent[];
  globalTimeRange: GlobalTimeRange;
  onSelectEntity: (entity: RiskEntity) => void;
  onViewTimeline: () => void;
  onAcknowledge: () => void;
  acknowledged: boolean;
  assignee: string;
  onAssigneeChange: (value: string) => void;
  role: RoleProfile;
  incidentStatus: IncidentStatus;
}) {
  const criticalCount = data.entities.filter((entity) => entity.risk_band === "critical").length;
  const highCount = data.entities.filter((entity) => entity.risk_band === "high").length;
  const incident = data.incidents[0];
  const primaryEntity = data.entities[0];
  const cisoMode = role.id === "ciso";

  if (cisoMode) {
    return (
      <CisoOverview
        data={data}
        criticalCount={criticalCount}
        highCount={highCount}
        newestEvent={newestEvent}
        assignee={assignee}
        incidentStatus={incidentStatus}
        lastRefresh={lastRefresh}
      />
    );
  }

  return (
    <div className="space-y-5">
      <div className="grid gap-4 xl:grid-cols-[1.3fr_0.7fr]">
        <section className="panel p-5">
          <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
            <div>
              <p className="section-label">Current assessment</p>
              <h2 className="mt-2 text-2xl font-semibold text-zinc-50 md:text-3xl">
                Are we under attack right now?
              </h2>
              <p className="mt-3 max-w-3xl text-base leading-7 text-zinc-300">{incident?.summary ?? data.triage.summary}</p>
            </div>
            <BandBadge band={incident?.severity ?? data.triage.severity} />
          </div>
          <div className="mt-5 grid gap-3 md:grid-cols-3">
            <MetricCard label="Critical entities" value={criticalCount.toString()} icon={ShieldAlert} tone="red" />
            <MetricCard label="High entities" value={highCount.toString()} icon={AlertTriangle} tone="orange" />
            <MetricCard label="SOC freshness" value={formatRelativeAge(newestEvent)} icon={Activity} tone="cyan" />
          </div>
        </section>

        <section className="panel p-5">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="section-label">What to do next</p>
              <h3 className="mt-2 text-lg font-semibold text-zinc-50">{primaryEntity?.recommended_action}</h3>
            </div>
            <span className={`rounded-md border px-2 py-1 text-xs ${role.canAcknowledge && acknowledged ? "border-emerald-500/30 text-emerald-200" : "border-zinc-800 text-zinc-500"}`}>
              {role.canAcknowledge ? (acknowledged ? "Acknowledged" : "Unacknowledged") : "Review status"}
            </span>
          </div>
          <div className="mt-4 space-y-3">
            {data.triage.recommended_next_steps.slice(0, 4).map((step) => (
              <div key={step} className="flex gap-3 text-sm leading-6 text-zinc-300">
                <CheckCircle2 className="mt-1 h-4 w-4 shrink-0 text-emerald-300" />
                <span>{step}</span>
              </div>
            ))}
          </div>
          <div className="mt-4 grid gap-2 sm:grid-cols-[1fr_auto]">
            {role.canAssign && (
              <select
                value={assignee}
                onChange={(event) => onAssigneeChange(event.target.value)}
                className="rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 outline-none"
              >
                {ANALYST_ROSTER.map((analyst) => (
                  <option key={analyst}>{analyst}</option>
                ))}
              </select>
            )}
            {role.canAcknowledge && (
              <button
                type="button"
                onClick={onAcknowledge}
                disabled={acknowledged}
                className={acknowledged ? "command-button-disabled" : "command-button"}
              >
                <CheckCircle2 className="h-4 w-4" />
                {acknowledged ? "Acknowledged" : "Acknowledge"}
              </button>
            )}
          </div>
        </section>
      </div>

      <div className="grid gap-4 xl:grid-cols-[0.95fr_1.05fr]">
        <section className="panel p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="section-label">Risk posture</p>
              <h3 className="mt-1 text-lg font-semibold text-zinc-50">Entity risk distribution</h3>
            </div>
            <PieChartIcon className="h-5 w-5 text-zinc-500" />
          </div>
          <RiskPosturePanel entities={data.entities} onSelectEntity={onSelectEntity} />
        </section>

        <section className="panel p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="section-label">Attack chain</p>
              <h3 className="mt-1 text-lg font-semibold text-zinc-50">{data.triage.incident_id}</h3>
            </div>
            <span className="text-xs text-zinc-500">
              {filteredTimeline.length > 5
                ? `Showing 5 of ${filteredTimeline.length} events`
                : `${filteredTimeline.length} events in ${formatRangeLabel(globalTimeRange)}`}
            </span>
          </div>
          <MiniTimeline events={filteredTimeline} />
          <button type="button" onClick={onViewTimeline} className="mt-4 inline-flex items-center gap-2 text-sm font-medium text-cyan-200 hover:text-cyan-100">
            View full timeline
            <Activity className="h-4 w-4" />
          </button>
        </section>
      </div>

      <div className="rounded-md border border-zinc-800 bg-zinc-900/70 px-4 py-3 text-sm text-zinc-400">
        Last updated {lastRefresh ? formatRelativeAge(lastRefresh.toISOString()) : "pending"} · {incidentStatus}
      </div>
    </div>
  );
}

function CisoOverview({
  data,
  criticalCount,
  highCount,
  newestEvent,
  assignee,
  incidentStatus,
  lastRefresh,
}: {
  data: SocData;
  criticalCount: number;
  highCount: number;
  newestEvent: string | undefined;
  assignee: string;
  incidentStatus: IncidentStatus;
  lastRefresh: Date | null;
}) {
  const incident = data.incidents[0] ?? data.triage;
  const touchedSystems = data.triage.target_assets;
  const activeStages = inferKillChainStages(data.triage.timeline);
  const firstEvent = [...data.triage.timeline]
    .map((event) => event.event_time)
    .filter((value): value is string => Boolean(value))
    .sort()[0];
  const owner = assignee === "Unassigned" ? "SOC Manager queue" : assignee;
  const summary = `${data.triage.summary} ${data.triage.entities_involved.length} entities are involved, ${touchedSystems.length} systems are in scope, and response is currently ${incidentStatus.toLowerCase()}.`;

  return (
    <div className="space-y-5">
      <section className="panel border-red-500/30 bg-red-950/20 p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <p className="section-label text-red-200/70">Executive assessment</p>
            <h2 className="mt-2 text-2xl font-semibold text-zinc-50 md:text-3xl">
              Active incident against {summarizeTargets(touchedSystems)}
            </h2>
            <p className="mt-3 max-w-4xl text-base leading-7 text-zinc-200">{summary}</p>
          </div>
          <BandBadge band={incident.severity ?? data.triage.severity} />
        </div>
        <div className="mt-5 grid gap-3 md:grid-cols-5">
          <MetricCard label="Critical entities" value={criticalCount.toString()} icon={ShieldAlert} tone="red" />
          <MetricCard label="High entities" value={highCount.toString()} icon={AlertTriangle} tone="orange" />
          <MetricCard label="Impacted assets" value={touchedSystems.length.toString()} icon={Database} tone="cyan" />
          <MetricCard label="SOC freshness" value={formatRelativeAge(newestEvent)} icon={Activity} tone="cyan" />
          <MetricCard label="SLA clock" value={formatDurationSince(firstEvent)} icon={Gauge} tone="orange" />
        </div>
      </section>

      <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
        <section className="panel p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="section-label">Kill chain stage</p>
              <h3 className="mt-1 text-lg font-semibold text-zinc-50">Blast radius progression</h3>
            </div>
            <span className={`rounded-md border px-2 py-1 text-xs ${incidentStatusClasses[incidentStatus]}`}>{incidentStatus}</span>
          </div>
          <KillChainBar activeStages={activeStages} />
        </section>

        <section className="panel p-5">
          <p className="section-label">Response posture</p>
          <div className="mt-4 grid gap-3">
            <ExecutiveDetail label="Owner" value={owner} />
            <ExecutiveDetail label="Status" value={incidentStatus} />
            <ExecutiveDetail label="Open for" value={formatDurationSince(firstEvent)} />
            <ExecutiveDetail label="Last updated" value={lastRefresh ? formatRelativeAge(lastRefresh.toISOString()) : "pending"} />
          </div>
        </section>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_0.9fr]">
        <section className="panel p-5">
          <p className="section-label">Business impact</p>
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            {touchedSystems.map((asset) => (
              <div key={asset} className="rounded-md border border-zinc-800 bg-zinc-950/60 p-3">
                <p className="font-semibold text-zinc-100">{asset}</p>
                <p className="mt-1 text-xs uppercase text-red-200/80">
                  {/payment|database|active directory/i.test(asset) ? "Critical system" : "Sensitive access path"}
                </p>
              </div>
            ))}
          </div>
        </section>
        <section className="panel border-amber-500/30 bg-amber-500/10 p-5">
          <p className="section-label text-amber-100/70">Compliance implication</p>
          <h3 className="mt-2 text-lg font-semibold text-amber-50">PCI-DSS incident response review likely required</h3>
          <p className="mt-3 text-sm leading-6 text-amber-100/80">
            Payment infrastructure is in scope. Legal and compliance should be prepared for PCI-DSS 12.10 evidence review if containment confirms unauthorized access.
          </p>
        </section>
      </div>
    </div>
  );
}

function KillChainBar({ activeStages }: { activeStages: Set<string> }) {
  const stages = ["Initial Access", "Execution", "Lateral Movement", "Command & Control", "Exfiltration"];
  return (
    <div className="mt-5 grid gap-2 md:grid-cols-5">
      {stages.map((stage, index) => {
        const active = activeStages.has(stage);
        return (
          <div key={stage} className={`rounded-md border px-3 py-4 ${active ? "border-red-500/40 bg-red-500/15" : "border-zinc-800 bg-zinc-950/60"}`}>
            <p className={`text-xs font-semibold uppercase ${active ? "text-red-100" : "text-zinc-500"}`}>Stage {index + 1}</p>
            <p className={`mt-2 text-sm font-medium ${active ? "text-zinc-50" : "text-zinc-400"}`}>{stage}</p>
          </div>
        );
      })}
    </div>
  );
}

function ExecutiveDetail({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-zinc-800 bg-zinc-950/60 p-3">
      <p className="section-label">{label}</p>
      <p className="mt-1 font-semibold text-zinc-100">{value}</p>
    </div>
  );
}

function EntityActions({
  entity,
  investigated,
  canInvestigate,
  onMarkInvestigated,
  onOpenTimeline,
}: {
  entity: RiskEntity;
  investigated: boolean;
  canInvestigate: boolean;
  onMarkInvestigated: (entityId: string) => void;
  onOpenTimeline: (entity: RiskEntity) => void;
}) {
  return (
    <div className="mt-3 flex flex-wrap gap-2">
      <button
        type="button"
        onClick={() => onMarkInvestigated(entity.entity_id)}
        disabled={investigated || !canInvestigate}
        className={
          investigated || !canInvestigate
            ? "inline-flex cursor-not-allowed items-center gap-2 rounded-md border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs font-medium text-zinc-500"
            : "inline-flex items-center gap-2 rounded-md border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-200 hover:border-zinc-500"
        }
      >
        <CheckCircle2 className="h-3.5 w-3.5" />
        {investigated ? "Investigated" : "Mark investigated"}
      </button>
      <button
        type="button"
        onClick={() => onOpenTimeline(entity)}
        className="inline-flex items-center gap-2 rounded-md border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-200 hover:border-zinc-500"
      >
        <Activity className="h-3.5 w-3.5" />
        View timeline
      </button>
    </div>
  );
}

function RiskView({
  entities,
  investigatedEntities,
  onMarkInvestigated,
  bandFilter,
  onBandFilterChange,
  sortMode,
  onSortModeChange,
  query,
  onQueryChange,
  viewMode,
  onViewModeChange,
  globalTimeRange,
  onOpenTimeline,
  canInvestigate,
}: {
  entities: RiskEntity[];
  investigatedEntities: string[];
  onMarkInvestigated: (entityId: string) => void;
  bandFilter: BandFilter;
  onBandFilterChange: (value: BandFilter) => void;
  sortMode: RiskSort;
  onSortModeChange: (value: RiskSort) => void;
  query: string;
  onQueryChange: (value: string) => void;
  viewMode: RiskViewMode;
  onViewModeChange: (value: RiskViewMode) => void;
  globalTimeRange: GlobalTimeRange;
  onOpenTimeline: (entity: RiskEntity) => void;
  canInvestigate: boolean;
}) {
  const visibleEntities = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    const latestSeenMs = Math.max(
      ...entities
        .map((entity) => (entity.last_seen_at ? new Date(entity.last_seen_at).getTime() : Number.NaN))
        .filter((time) => Number.isFinite(time)),
    );
    const anchorMs = Number.isFinite(latestSeenMs) ? latestSeenMs : Date.now();
    const rangeHours = rangeToHours(globalTimeRange);
    return [...entities]
      .filter((entity) => bandFilter === "all" || entity.risk_band === bandFilter)
      .filter((entity) => {
        if (globalTimeRange === "all" || !entity.last_seen_at) {
          return true;
        }
        return anchorMs - new Date(entity.last_seen_at).getTime() <= rangeHours * 60 * 60 * 1000;
      })
      .filter((entity) => {
        if (!normalizedQuery) {
          return true;
        }
        return `${entity.display_name} ${entity.entity_id} ${entity.entity_type}`.toLowerCase().includes(normalizedQuery);
      })
      .sort((a, b) => {
        if (sortMode === "score-asc") {
          return a.risk_score - b.risk_score;
        }
        if (sortMode === "recent") {
          return new Date(b.last_seen_at ?? 0).getTime() - new Date(a.last_seen_at ?? 0).getTime();
        }
        return b.risk_score - a.risk_score;
      });
  }, [bandFilter, entities, globalTimeRange, query, sortMode]);

  return (
    <div className="space-y-4">
      <ViewHeader eyebrow="Entity risk" title="Prioritized analyst queue" description={`Ranked users, devices, vendors, and assets active in ${formatRangeLabel(globalTimeRange)}.`} />
      <div className="panel grid gap-3 p-3 xl:grid-cols-[1fr_auto_auto_auto]">
        <label className="flex min-w-0 items-center gap-2 rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2">
          <Search className="h-4 w-4 shrink-0 text-zinc-500" />
          <input
            value={query}
            onChange={(event) => onQueryChange(event.target.value)}
            placeholder="Search entity, type, or id"
            className="min-w-0 flex-1 bg-transparent text-sm text-zinc-200 outline-none placeholder:text-zinc-600"
          />
        </label>
        <select
          value={bandFilter}
          onChange={(event) => onBandFilterChange(event.target.value as BandFilter)}
          className="rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 outline-none"
        >
          <option value="all">All bands</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={sortMode}
          onChange={(event) => onSortModeChange(event.target.value as RiskSort)}
          className="rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 outline-none"
        >
          <option value="score-desc">Risk high to low</option>
          <option value="score-asc">Risk low to high</option>
          <option value="recent">Most recent</option>
        </select>
        <div className="inline-flex rounded-md border border-zinc-800 bg-zinc-950 p-1">
          {(["table", "cards"] as RiskViewMode[]).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => onViewModeChange(mode)}
              className={`rounded px-3 py-1.5 text-sm ${viewMode === mode ? "bg-cyan-500/20 text-cyan-100" : "text-zinc-500 hover:text-zinc-200"}`}
            >
              {capitalize(mode)}
            </button>
          ))}
        </div>
      </div>
      <div className="grid gap-3">
        {viewMode === "table" ? (
          <div className="panel overflow-hidden">
            {visibleEntities.map((entity) => (
              <RiskTableRow
                key={entity.entity_id}
                entity={entity}
                investigated={investigatedEntities.includes(entity.entity_id)}
                canInvestigate={canInvestigate}
                onMarkInvestigated={onMarkInvestigated}
                onOpenTimeline={onOpenTimeline}
              />
            ))}
          </div>
        ) : (
          visibleEntities.map((entity) => (
            <article key={entity.entity_id} className={`panel border-l-4 p-4 ${severityBorderClass(entity.risk_band)}`}>
              <div className="grid gap-4 lg:grid-cols-[220px_1fr_260px] lg:items-start">
                <div>
                  <div className="flex items-center gap-3">
                    <ScoreRing score={entity.risk_score} band={entity.risk_band} />
                    <div>
                      <h3 className="font-semibold text-zinc-50">{entity.display_name}</h3>
                      <p className="text-xs uppercase text-zinc-500">{entity.entity_type} - {entity.entity_id}</p>
                      <p className="mt-1 text-xs text-zinc-500">Last seen {formatRelativeAge(entity.last_seen_at)}</p>
                    </div>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  {entity.top_risk_reasons.map((reason) => (
                    <span key={reason} className="reason-chip">
                      {reason}
                    </span>
                  ))}
                </div>
                <div className="rounded-md border border-zinc-800 bg-zinc-950/60 p-3 text-sm leading-6 text-zinc-300">
                  <p className="section-label mb-1">Recommended action</p>
                  <p>{entity.recommended_action}</p>
                  <EntityActions
                    entity={entity}
                    investigated={investigatedEntities.includes(entity.entity_id)}
                    canInvestigate={canInvestigate}
                    onMarkInvestigated={onMarkInvestigated}
                    onOpenTimeline={onOpenTimeline}
                  />
                </div>
              </div>
            </article>
          ))
        )}
        {visibleEntities.length === 0 && (
          <div className="panel p-6 text-sm text-zinc-400">No entities match the current filters.</div>
        )}
      </div>
    </div>
  );
}

function RiskTableRow({
  entity,
  investigated,
  canInvestigate,
  onMarkInvestigated,
  onOpenTimeline,
}: {
  entity: RiskEntity;
  investigated: boolean;
  canInvestigate: boolean;
  onMarkInvestigated: (entityId: string) => void;
  onOpenTimeline: (entity: RiskEntity) => void;
}) {
  return (
    <div className={`grid gap-3 border-b border-zinc-800 px-4 py-3 last:border-b-0 xl:grid-cols-[88px_1.1fr_1.5fr_1fr_auto] xl:items-center ${severityBackgroundClass(entity.risk_band)}`}>
      <div className="flex items-center gap-3">
        <span className="h-9 w-1.5 rounded-full" style={{ backgroundColor: bandColors[entity.risk_band] }} />
        <span className="text-lg font-semibold text-zinc-50">{entity.risk_score}</span>
      </div>
      <div className="min-w-0">
        <p className="truncate font-semibold text-zinc-100">{entity.display_name}</p>
        <p className="mt-0.5 truncate text-xs uppercase text-zinc-500">{entity.entity_type} - {entity.entity_id}</p>
      </div>
      <div className="min-w-0 text-sm text-zinc-300">
        <p className="truncate">{entity.top_risk_reasons.slice(0, 2).join(" · ")}</p>
        {entity.top_risk_reasons.length > 2 && (
          <p className="mt-1 text-xs text-zinc-500">+{entity.top_risk_reasons.length - 2} more signals</p>
        )}
      </div>
      <div className="text-sm text-zinc-400">
        <BandBadge band={entity.risk_band} />
        <p className="mt-2 text-xs text-zinc-500">Last seen {formatRelativeAge(entity.last_seen_at)}</p>
      </div>
      <EntityActions
        entity={entity}
        investigated={investigated}
        canInvestigate={canInvestigate}
        onMarkInvestigated={onMarkInvestigated}
        onOpenTimeline={onOpenTimeline}
      />
    </div>
  );
}

function RiskPosturePanel({
  entities,
  onSelectEntity,
}: {
  entities: RiskEntity[];
  onSelectEntity: (entity: RiskEntity) => void;
}) {
  const allDistribution = (["critical", "high", "medium", "low"] as RiskBand[]).map((band) => ({
    band,
    count: entities.filter((entity) => entity.risk_band === band).length,
  }));
  const distribution = allDistribution.filter((entry) => entry.count > 0);

  return (
    <div className="mt-4 grid gap-4 lg:grid-cols-[170px_1fr]">
      <div className="h-40">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={distribution} dataKey="count" nameKey="band" innerRadius={42} outerRadius={68} paddingAngle={3}>
              {distribution.map((entry) => (
                <Cell key={entry.band} fill={bandColors[entry.band]} />
              ))}
            </Pie>
            <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #3f3f46", borderRadius: 6 }} />
          </PieChart>
        </ResponsiveContainer>
        <div className="mt-2 grid grid-cols-2 gap-1 text-xs text-zinc-400">
          {allDistribution.map((entry) => (
            <div key={entry.band} className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: bandColors[entry.band] }} />
              <span>{capitalize(entry.band)}</span>
              <span className="ml-auto">{entry.count}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="space-y-3">
        {entities.slice(0, 5).map((entity) => (
          <button
            type="button"
            key={entity.entity_id}
            onClick={() => onSelectEntity(entity)}
            className="w-full rounded-md border border-zinc-800 bg-zinc-950/60 p-3 text-left transition hover:border-zinc-600"
          >
            <div className="flex items-center justify-between gap-3 text-sm">
              <span className="min-w-0 truncate font-medium text-zinc-200">{entity.display_name}</span>
              <span className="font-semibold text-zinc-50">{entity.risk_score}</span>
            </div>
            <div className="mt-2 h-2 rounded-full bg-zinc-800">
              <div
                className="h-2 rounded-full"
                style={{ width: `${entity.risk_score}%`, backgroundColor: bandColors[entity.risk_band] }}
              />
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function TimelineView({
  incidentId,
  timeline,
  entityFilter,
  onEntityFilterChange,
  range,
}: {
  incidentId: string;
  timeline: TimelineEvent[];
  entityFilter: string | null;
  onEntityFilterChange: (value: string | null) => void;
  range: GlobalTimeRange;
}) {
  const [expandedEvents, setExpandedEvents] = useState<string[]>([]);
  const latestEventMs = Math.max(
    ...timeline
      .map((event) => (event.event_time ? new Date(event.event_time).getTime() : Number.NaN))
      .filter((time) => Number.isFinite(time)),
  );
  const timelineAnchorMs = Number.isFinite(latestEventMs) ? latestEventMs : Date.now();
  const filteredTimeline = timeline.filter((event) => {
    const matchesEntity =
      !entityFilter ||
      event.entity_id === entityFilter ||
      event.display_name === entityFilter ||
      event.asset_id === entityFilter ||
      event.asset === entityFilter;
    if (!matchesEntity) {
      return false;
    }
    if (range === "all" || !event.event_time) {
      return true;
    }
    const hours = rangeToHours(range);
    return timelineAnchorMs - new Date(event.event_time).getTime() <= hours * 60 * 60 * 1000;
  });

  const toggleEvent = (eventKey: string) => {
    setExpandedEvents((current) =>
      current.includes(eventKey) ? current.filter((item) => item !== eventKey) : [...current, eventKey],
    );
  };

  return (
    <div className="space-y-4">
      <ViewHeader eyebrow="Incident timeline" title={`${incidentId} attack chain`} description="Correlated sequence from initial access through target-system impact." />
      <div className="panel flex flex-col gap-3 p-3 md:flex-row md:items-center md:justify-between">
        <div className="text-sm text-zinc-400">
          Showing {filteredTimeline.length} events in {formatRangeLabel(range)}
        </div>
        {entityFilter && (
          <button type="button" onClick={() => onEntityFilterChange(null)} className="text-sm text-cyan-200 hover:text-cyan-100">
            Clear entity filter: {entityFilter}
          </button>
        )}
      </div>
      <div className="panel p-5">
        <div className="relative space-y-5">
          {filteredTimeline.map((event, index) => {
            const eventKey = event.event_id ?? `${event.event_time}-${index}`;
            const expanded = expandedEvents.includes(eventKey);
            return (
            <div key={eventKey} className="grid gap-3 md:grid-cols-[120px_28px_1fr] xl:grid-cols-[150px_28px_1fr]">
              <div className="text-sm text-zinc-400">{formatDateTime(event.event_time)}</div>
              <div className="relative flex justify-center">
                <div className={`h-7 w-7 rounded-full border ${severityDotClass(event.severity)}`} />
                {index < filteredTimeline.length - 1 && <div className="absolute top-7 h-[calc(100%+1.25rem)] w-px bg-zinc-800" />}
              </div>
              <button type="button" onClick={() => toggleEvent(eventKey)} className="rounded-md border border-zinc-800 bg-zinc-900/70 p-4 text-left">
                <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                  <div>
                    <h3 className="font-semibold text-zinc-50">{event.action}</h3>
                    <p className="mt-1 text-sm leading-6 text-zinc-400">{event.rule_explanation ?? `${event.source_system} ${event.event_type}`}</p>
                  </div>
                  <span className="rounded-md border border-zinc-700 px-2 py-1 text-xs text-zinc-300">{event.mitre_technique ?? "No MITRE"}</span>
                </div>
                {expanded && <div className="mt-3 grid gap-2 text-xs text-zinc-500 md:grid-cols-4">
                  <span>Source: {event.source_system}</span>
                  <span>Asset: {event.asset_name ?? event.asset_id ?? event.asset ?? "unknown"}</span>
                  <span>Src: {event.src_ip ?? "n/a"}</span>
                  <span>Dest: {event.dest_ip ?? "n/a"}</span>
                </div>}
              </button>
            </div>
          );})}
          {filteredTimeline.length === 0 && <EmptyState message="No timeline events match the current filters." />}
        </div>
      </div>
    </div>
  );
}

function TriageView({
  data,
  entities,
  assignee,
  onAssigneeChange,
  onViewTimeline,
  role,
  incidentStatus,
  onIncidentStatusChange,
  completedSteps,
  onToggleStep,
}: {
  data: SocData;
  entities: RiskEntity[];
  assignee: string;
  onAssigneeChange: (value: string) => void;
  onViewTimeline: () => void;
  role: RoleProfile;
  incidentStatus: IncidentStatus;
  onIncidentStatusChange: (value: IncidentStatus) => void;
  completedSteps: string[];
  onToggleStep: (incidentId: string, index: number) => void;
}) {
  const displayNamesById = new Map(entities.map((entity) => [entity.entity_id, entity.display_name]));
  const entityNames = data.triage.entities_involved.map((entityId) => displayNamesById.get(entityId) ?? entityId);

  return (
    <div className="space-y-4">
      <ViewHeader eyebrow="Automated triage" title={data.triage.incident_id} description={data.triage.summary} />
      <div className="grid gap-4 xl:grid-cols-[1fr_0.8fr]">
        <section className="panel p-5">
          <div className="flex items-center justify-between gap-3">
            <p className="section-label">Response steps</p>
            <button type="button" onClick={onViewTimeline} className="inline-flex items-center gap-2 text-sm font-medium text-cyan-200 hover:text-cyan-100">
              View timeline
              <Activity className="h-4 w-4" />
            </button>
          </div>
          <div className="mt-4 space-y-3">
            {data.triage.recommended_next_steps.map((step, index) => (
              <div key={step} className="flex gap-3 rounded-md border border-zinc-800 bg-zinc-950/60 p-3">
                <input
                  type="checkbox"
                  checked={completedSteps.includes(`${data.triage.incident_id}:${index}`)}
                  onChange={() => onToggleStep(data.triage.incident_id, index)}
                  disabled={!role.canChangeStatus}
                  className="mt-1 h-4 w-4 accent-emerald-400"
                />
                <p className={`text-sm leading-6 ${completedSteps.includes(`${data.triage.incident_id}:${index}`) ? "text-emerald-300 line-through" : "text-zinc-300"}`}>
                  {index + 1}. {step}
                </p>
              </div>
            ))}
          </div>
        </section>
        <section className="panel p-5">
          <p className="section-label">Incident evidence</p>
          <div className="mt-4">
            <span className="section-label">Incident status</span>
            <div className="mt-2 grid grid-cols-2 gap-2">
              {(["Open", "Investigating", "Contained", "Resolved"] as IncidentStatus[]).map((status) => (
                <button
                  key={status}
                  type="button"
                  disabled={!role.canChangeStatus}
                  onClick={() => onIncidentStatusChange(status)}
                  className={`rounded-md border px-3 py-2 text-sm ${incidentStatus === status ? incidentStatusClasses[status] : "border-zinc-800 bg-zinc-950 text-zinc-400"} ${role.canChangeStatus ? "" : "cursor-not-allowed opacity-70"}`}
                >
                  {status}
                </button>
              ))}
            </div>
          </div>
          <label className="mt-4 block">
            <span className="section-label">Assigned analyst</span>
            <select
              value={assignee}
              onChange={(event) => onAssigneeChange(event.target.value)}
              disabled={!role.canAssign}
              className="mt-2 w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 outline-none"
            >
                {ANALYST_ROSTER.map((analyst) => (
                  <option key={analyst}>{analyst}</option>
                ))}
            </select>
          </label>
          <dl className="mt-4 space-y-4">
            <Detail label="Severity" value={data.triage.severity} />
            <Detail label="Target assets" value={data.triage.target_assets.join(", ")} />
            <Detail label="Entities involved" value={entityNames.join(", ")} />
            <Detail label="MITRE techniques" value={data.triage.mitre_techniques.join(", ")} />
          </dl>
        </section>
      </div>
    </div>
  );
}

function QnaView({ answers }: { answers: QnaAnswer[] }) {
  return (
    <div className="space-y-4">
      <ViewHeader eyebrow="Analyst Q&A" title="Saved analyst questions" description="Pre-approved questions return repeatable SQL-backed answers for incident triage." />
      <div className="grid gap-4">
        {answers.map((answer) => (
          <section key={answer.question_id} className="panel p-5">
            <p className="section-label">Saved question</p>
            <h3 className="mt-2 text-lg font-semibold text-zinc-50">{answer.question}</h3>
            <QnaAnswerRows answer={answer} />
          </section>
        ))}
      </div>
    </div>
  );
}

function QnaAnswerRows({ answer }: { answer: QnaAnswer }) {
  if (answer.answer_rows.length === 0) {
    return <EmptyState message="No matching records for this question in the current data window." />;
  }

  if (answer.question_id === "critical_entities_now") {
    return (
      <div className="mt-4 grid gap-3">
        {answer.answer_rows.map((row, index) => (
          <div key={index} className="rounded-md border border-zinc-800 bg-zinc-950/60 p-4">
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="font-semibold text-zinc-100">{stringifyCellValue(row.display_name ?? row.entity_id)}</p>
                <p className="mt-1 font-mono text-xs text-zinc-500">{stringifyCellValue(row.entity_id)}</p>
              </div>
              <ScoreRing score={Number(row.risk_score ?? 0)} band={normalizeBand(row.risk_band)} />
            </div>
            {Array.isArray(row.top_risk_reasons) && (
              <div className="mt-3">
                <ArrayCell values={row.top_risk_reasons} />
              </div>
            )}
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="mt-4 grid gap-3">
      {answer.answer_rows.map((row, index) => (
        <div key={index} className="rounded-md border border-zinc-800 bg-zinc-950/60 p-4">
          <div className="grid gap-3 md:grid-cols-3">
            {Object.entries(row).map(([key, value]) => (
              <div key={key}>
                <p className="section-label">{key}</p>
                <div className="mt-1 text-sm text-zinc-300">{renderQnaValue(key, value)}</div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function ComplianceView({ frameworks, canExport }: { frameworks: ComplianceResponse[]; canExport: boolean }) {
  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <ViewHeader eyebrow="Compliance evidence" title="Audit-ready SOC and PCI views" description="Evidence generated from correlated SOC marts." />
        {canExport && (
          <button type="button" onClick={() => exportComplianceCsv(frameworks)} className="command-button">
            <Download className="h-4 w-4" />
            Export CSV
          </button>
        )}
      </div>
      <div className="grid gap-4">
        {frameworks.map((framework) => (
          <section key={framework.framework} className="panel p-5">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-zinc-50">{framework.framework}</h3>
              <Lock className="h-5 w-5 text-zinc-500" />
            </div>
            {framework.controls.length === 0 ? (
              <EmptyState message={`No ${framework.framework} controls found in the current evidence mart.`} />
            ) : (
              <div className="mt-4 overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Control</th>
                      <th>Name</th>
                      <th>Event count</th>
                      <th>Latest</th>
                      <th>Lineage</th>
                    </tr>
                  </thead>
                  <tbody>
                    {framework.controls.map((control) => (
                      <ComplianceRow key={`${control.framework}-${control.control_id}`} control={control} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        ))}
      </div>
    </div>
  );
}

function ComplianceRow({ control }: { control: ComplianceControl }) {
  return (
    <tr>
      <td>{control.control_id}</td>
      <td>{control.control_name}</td>
      <td>{control.evidence_count} {control.evidence_count === 1 ? "event" : "events"}</td>
      <td>{formatCompactDateTime(control.latest_evidence_at)}</td>
      <td>{control.lineage}</td>
    </tr>
  );
}

function MiniTimeline({ events }: { events: TimelineEvent[] }) {
  return (
    <div className="mt-4 space-y-3">
      {events.slice(0, 5).map((event, index) => (
        <div key={event.event_id ?? `${event.event_time}-${index}`} className="grid grid-cols-[84px_1fr_auto] items-center gap-3 rounded-md border border-zinc-800 bg-zinc-950/60 px-3 py-2">
          <span className="text-xs text-zinc-500">{formatTime(event.event_time)}</span>
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-zinc-200">{event.action}</p>
            <p className="truncate text-xs text-zinc-500">{event.source_system} - {event.asset_name ?? event.asset_id ?? event.asset ?? "unknown asset"}</p>
          </div>
          <span className="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-400">
            {event.mitre_technique ?? "No MITRE"}
          </span>
        </div>
      ))}
    </div>
  );
}

function MetricCard({
  label,
  value,
  icon: Icon,
  tone,
}: {
  label: string;
  value: string;
  icon: typeof ShieldAlert;
  tone: "red" | "orange" | "cyan";
}) {
  const toneClass = {
    red: "bg-red-500/15 text-red-300",
    orange: "bg-orange-500/15 text-orange-300",
    cyan: "bg-cyan-500/15 text-cyan-300",
  }[tone];
  return (
    <div className="rounded-md border border-zinc-800 bg-zinc-950/70 p-4">
      <div className={`flex h-9 w-9 items-center justify-center rounded-md ${toneClass}`}>
        <Icon className="h-5 w-5" />
      </div>
      <p className="mt-4 text-2xl font-semibold text-zinc-50">{value}</p>
      <p className="mt-1 text-sm text-zinc-500">{label}</p>
    </div>
  );
}

function ViewHeader({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) {
  return (
    <div className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
      <div>
        <p className="section-label">{eyebrow}</p>
        <h2 className="mt-1 text-2xl font-semibold text-zinc-50">{title}</h2>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-400">{description}</p>
      </div>
    </div>
  );
}

function BandBadge({ band }: { band: RiskBand }) {
  return (
    <span className={`inline-flex items-center rounded-md border px-3 py-2 text-sm font-semibold uppercase ${bandBadgeClasses[band]}`}>
      {band}
    </span>
  );
}

function ScoreRing({ score, band }: { score: number; band: RiskBand }) {
  return (
    <div
      className="flex h-16 w-16 shrink-0 flex-col items-center justify-center rounded-md border-2 text-lg font-bold text-zinc-950"
      style={{ backgroundColor: bandColors[band], borderColor: bandColors[band] }}
    >
      <span>{score}</span>
      <span className="text-[10px] font-semibold uppercase leading-none text-zinc-950/70">{band}</span>
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="section-label">{label}</dt>
      <dd className="mt-1 text-sm leading-6 text-zinc-300">{value}</dd>
    </div>
  );
}

function ArrayCell({ values }: { values: unknown[] }) {
  return (
    <div className="flex max-w-xl flex-wrap gap-1.5">
      {values.map((value, index) => (
        <span key={`${String(value)}-${index}`} className="rounded-md border border-zinc-700 bg-zinc-950/70 px-2 py-1 text-xs leading-5 text-zinc-300">
          {stringifyCellValue(value)}
        </span>
      ))}
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="mt-4 rounded-md border border-zinc-800 bg-zinc-950/60 px-4 py-5 text-sm text-zinc-400">
      {message}
    </div>
  );
}

function formatCellValue(value: unknown): ReactNode {
  if (value === null || value === undefined) {
    return "";
  }
  if (Array.isArray(value)) {
    return <ArrayCell values={value} />;
  }
  return stringifyCellValue(value);
}

function stringifyCellValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  if (Array.isArray(value)) {
    return value.map((item) => stringifyCellValue(item)).join(", ");
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function severityDotClass(severity: string | null | undefined) {
  const normalized = severity?.toLowerCase();
  if (normalized === "low" || normalized === "medium" || normalized === "high" || normalized === "critical") {
    return severityDotClasses[normalized];
  }
  return "border-zinc-600 bg-zinc-700/30";
}

function severityBorderClass(band: RiskBand) {
  return {
    critical: "border-l-red-500",
    high: "border-l-orange-500",
    medium: "border-l-yellow-400",
    low: "border-l-emerald-500",
  }[band];
}

function severityBackgroundClass(band: RiskBand) {
  return {
    critical: "bg-red-500/[0.06]",
    high: "bg-orange-500/[0.05]",
    medium: "bg-yellow-500/[0.04]",
    low: "bg-emerald-500/[0.035]",
  }[band];
}

function rangeToHours(range: GlobalTimeRange) {
  if (range === "1h") {
    return 1;
  }
  if (range === "6h") {
    return 6;
  }
  if (range === "7d") {
    return 24 * 7;
  }
  return 24;
}

function formatRangeLabel(range: GlobalTimeRange) {
  if (range === "all") {
    return "all available events";
  }
  return `the last ${range}`;
}

function filterTimelineByRange(timeline: TimelineEvent[], range: GlobalTimeRange) {
  if (range === "all") {
    return timeline;
  }
  const latestEventMs = Math.max(
    ...timeline
      .map((event) => (event.event_time ? new Date(event.event_time).getTime() : Number.NaN))
      .filter((time) => Number.isFinite(time)),
  );
  const anchorMs = Number.isFinite(latestEventMs) ? latestEventMs : Date.now();
  const hours = rangeToHours(range);
  return timeline.filter((event) => {
    if (!event.event_time) {
      return true;
    }
    return anchorMs - new Date(event.event_time).getTime() <= hours * 60 * 60 * 1000;
  });
}

function inferKillChainStages(timeline: TimelineEvent[]) {
  const stages = new Set<string>();
  timeline.forEach((event) => {
    const text = `${event.action} ${event.event_type} ${event.mitre_technique ?? ""}`.toLowerCase();
    if (/vendor|vpn|valid account|login|initial/.test(text)) {
      stages.add("Initial Access");
    }
    if (/powershell|process|execution|t1059/.test(text)) {
      stages.add("Execution");
    }
    if (/lateral|remote|active directory|t1021/.test(text)) {
      stages.add("Lateral Movement");
    }
    if (/t1105|t1071|t1102|command|control/.test(text)) {
      stages.add("Command & Control");
    }
    if (/t1041|t1048|exfil|payment_records/.test(text) || (/egress|outbound/.test(text) && !/t1105|t1071|t1102/.test(text))) {
      stages.add("Exfiltration");
    }
  });
  return stages;
}

function buildNotifications(
  data: SocData,
  criticalEntities: RiskEntity[],
  incidentStatus: IncidentStatus,
  incidentStatusChangedAt: string,
): SocNotification[] {
  const now = new Date().toISOString();
  const latestEvent = [...data.triage.timeline]
    .filter((event) => event.event_time)
    .sort((a, b) => new Date(b.event_time ?? 0).getTime() - new Date(a.event_time ?? 0).getTime())[0];
  return [
    ...criticalEntities.map((entity) => ({
      id: `critical:${entity.entity_id}:${entity.last_seen_at ?? now}`,
      kind: "critical" as const,
      title: `Critical entity detected: ${entity.display_name}`,
      detail: entity.top_risk_reasons.slice(0, 2).join(" · "),
      createdAt: entity.last_seen_at ?? now,
    })),
    {
      id: `status:${data.triage.incident_id}:${incidentStatus}`,
      kind: "status" as const,
      title: `Incident status: ${incidentStatus}`,
      detail: `${data.triage.incident_id} is assigned to the active response workflow.`,
      createdAt: incidentStatusChangedAt,
    },
    ...(latestEvent
      ? [
          {
            id: `timeline:${latestEvent.event_id ?? latestEvent.event_time}`,
            kind: "timeline" as const,
            title: `Latest timeline event: ${latestEvent.action}`,
            detail: `${latestEvent.source_system} observed ${latestEvent.asset_name ?? latestEvent.asset ?? "monitored asset"}.`,
            createdAt: latestEvent.event_time ?? now,
          },
        ]
      : []),
  ];
}

function normalizeBand(value: unknown): RiskBand {
  const normalized = String(value ?? "low").toLowerCase();
  if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low") {
    return normalized;
  }
  return "low";
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function renderQnaValue(key: string, value: unknown): ReactNode {
  if (/time|date|at$/i.test(key) && typeof value === "string") {
    return formatCompactDateTime(value);
  }
  if (/severity|risk_band|band/i.test(key)) {
    return <BandBadge band={normalizeBand(value)} />;
  }
  if (/id|user|entity|asset|vendor/i.test(key)) {
    return <span className="font-mono text-xs text-zinc-300">{stringifyCellValue(value)}</span>;
  }
  return formatCellValue(value);
}

function exportComplianceCsv(frameworks: ComplianceResponse[]) {
  const rows = frameworks.flatMap((framework) =>
    framework.controls.map((control) => [
      framework.framework,
      control.control_id,
      control.control_name,
      String(control.evidence_count),
      control.latest_evidence_at ?? "",
      control.lineage,
    ]),
  );
  const csv = [
    ["Framework", "Control", "Name", "Event count", "Latest", "Lineage"],
    ...rows,
  ]
    .map((row) => row.map((cell) => `"${cell.replace(/"/g, '""')}"`).join(","))
    .join("\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "soc-compliance-evidence.csv";
  link.click();
  URL.revokeObjectURL(url);
}

function summarizeTargets(targets: string[] | undefined) {
  if (!targets || targets.length === 0) {
    return "monitored assets";
  }
  const priorityTarget = targets.find((target) => /payment|database|paydb/i.test(target));
  return priorityTarget ?? targets.join(", ");
}

function formatDateTime(value: string | null | undefined) {
  if (!value) {
    return "n/a";
  }
  return new Date(value).toLocaleString();
}

function formatCompactDateTime(value: string | null | undefined) {
  if (!value) {
    return "n/a";
  }
  return new Date(value).toLocaleString([], {
    month: "numeric",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function formatTime(value: string | null | undefined) {
  if (!value) {
    return "n/a";
  }
  return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function formatRelativeAge(value: string | null | undefined) {
  if (!value) {
    return "n/a";
  }
  const ageMs = Date.now() - new Date(value).getTime();
  if (ageMs < 0) {
    return "just now";
  }
  const minutes = Math.floor(ageMs / 60_000);
  if (minutes < 1) {
    return "just now";
  }
  if (minutes < 60) {
    return `${minutes}m ago`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 48) {
    return `${hours}h ago`;
  }
  return `${Math.floor(hours / 24)}d ago`;
}

function formatDurationSince(value: string | null | undefined) {
  if (!value) {
    return "n/a";
  }
  const ageMs = Math.max(0, Date.now() - new Date(value).getTime());
  const minutes = Math.floor(ageMs / 60_000);
  if (minutes < 60) {
    return `${Math.max(1, minutes)}m`;
  }
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  if (hours < 48) {
    return remainingMinutes > 0 ? `${hours}h ${remainingMinutes}m` : `${hours}h`;
  }
  return `${Math.floor(hours / 24)}d`;
}

export default App;
