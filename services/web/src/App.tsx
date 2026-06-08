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
  Moon,
  Sun,
  Target,
  Wifi,
  WifiOff,
  X,
} from "lucide-react";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
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
const THEME_STORAGE = "soc_command_center_theme";
const ANALYST_ROSTER = ["Unassigned", "Avery Chen", "Morgan Patel", "Riley Johnson"];

const navItems = [
  { id: "overview", label: "Overview", icon: Gauge },
  { id: "risk", label: "Entity Risk Queue", icon: ShieldAlert },
  { id: "timeline", label: "Incident Timeline", icon: Activity },
  { id: "triage", label: "Triage Report", icon: ClipboardList },
  { id: "qna", label: "Q&A Assistant", icon: FileQuestion },
  { id: "compliance", label: "Vigil Comply", icon: ListChecks },
  { id: "pipeline", label: "Pipeline Health", icon: Database },
] as const;

type ViewId = (typeof navItems)[number]["id"];

const navGroups: { label: string; items: ViewId[] }[] = [
  { label: "Detection", items: ["overview", "risk"] },
  { label: "Investigation", items: ["timeline", "triage", "qna"] },
  { label: "Compliance", items: ["compliance"] },
  { label: "Platform", items: ["pipeline"] },
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
    views: ["overview", "timeline", "risk", "pipeline"],
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
    views: ["overview", "risk", "timeline", "triage", "qna", "compliance", "pipeline"],
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
    views: ["overview", "risk", "timeline", "triage", "qna", "compliance", "pipeline"],
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
  low:      "border-emerald-400/30 bg-emerald-500/15 text-emerald-700 dark:text-emerald-200",
  medium:   "border-yellow-400/30 bg-yellow-500/15 text-yellow-700 dark:text-yellow-100",
  high:     "border-orange-400/30 bg-orange-500/15 text-orange-700 dark:text-orange-200",
  critical: "border-red-400/30 bg-red-500/15 text-red-700 dark:text-red-200",
};

const severityDotClasses: Record<RiskBand, string> = {
  low: "border-emerald-400/40 bg-emerald-500/15",
  medium: "border-yellow-400/40 bg-yellow-500/15",
  high: "border-orange-400/40 bg-orange-500/15",
  critical: "border-red-400/50 bg-red-500/20",
};

const incidentStatusClasses: Record<IncidentStatus, string> = {
  Open:         "border-red-400/30 bg-red-500/15 text-red-600 dark:text-red-200",
  Investigating:"border-orange-400/30 bg-orange-500/15 text-orange-600 dark:text-orange-200",
  Contained:    "border-yellow-400/30 bg-yellow-500/15 text-yellow-700 dark:text-yellow-100",
  Resolved:     "border-emerald-400/30 bg-emerald-500/15 text-emerald-700 dark:text-emerald-200",
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
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    const stored = localStorage.getItem(THEME_STORAGE);
    return stored === "light" ? "light" : "dark";
  });

  useEffect(() => {
    const html = document.documentElement;
    if (theme === "dark") {
      html.classList.add("dark");
      html.classList.remove("light");
    } else {
      html.classList.remove("dark");
      html.classList.add("light");
    }
    localStorage.setItem(THEME_STORAGE, theme);
  }, [theme]);

  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"));

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
        theme={theme}
        onToggleTheme={toggleTheme}
      />
    );
  }

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-[var(--bg-app)] text-zinc-900 dark:text-zinc-100" style={{ fontFamily: "'Outfit', sans-serif" }}>
      <div className="flex flex-1 overflow-hidden">

        {/* ── Sidebar ── */}
        <aside className="hidden lg:flex w-[212px] shrink-0 flex-col border-r border-[var(--border-primary)] bg-[var(--bg-app)]">
          {/* Wordmark */}
          <div className="flex items-center gap-0 px-5 py-4 border-b border-[var(--border-primary)]">
            <span className="text-[#00e5c8] font-black text-xl tracking-tight">VIGIL</span>
            <span className="text-zinc-600 text-xl font-medium"> · ARIA</span>
          </div>

          {/* Nav */}
          <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
            {navGroups.map((group) => {
              const groupItems = availableNavItems.filter((item) => group.items.includes(item.id));
              if (groupItems.length === 0) return null;
              return (
                <div key={group.label}>
                  <p className="mb-1.5 px-2 text-[9px] font-semibold uppercase tracking-[0.3em] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                    {group.label}
                  </p>
                  <div className="space-y-0.5">
                    {groupItems.map((item) => (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => setActiveView(item.id)}
                        className={`flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm transition-all ${
                          activeView === item.id
                            ? "border border-[#00e5c8]/20 bg-[#00e5c8]/10 text-[#00e5c8]"
                            : "border border-transparent text-zinc-700 dark:text-zinc-500 hover:bg-[var(--bg-elevated)] hover:text-zinc-900 dark:hover:text-zinc-300"
                        }`}
                      >
                        <item.icon className="h-4 w-4 shrink-0" />
                        <span className="truncate">{item.label}</span>
                        {item.id === "risk" && criticalEntities.some((entity) => !investigatedEntities.includes(entity.entity_id)) && (
                          <span className="ml-auto rounded-full bg-red-500 px-1.5 py-0.5 text-[9px] font-semibold text-white">
                            {criticalEntities.length}
                          </span>
                        )}
                        {item.id === "timeline" && hasRecentTimelineEvent && (
                          <span className="ml-auto h-2 w-2 rounded-full bg-red-400 shadow-[0_0_8px_rgba(248,113,113,0.8)]" />
                        )}
                        {item.id === "triage" && (
                          <span className={`ml-auto rounded border px-1.5 py-0.5 text-[9px] font-medium ${incidentStatusClasses[incidentStatus]}`}>
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

          {/* Role badge */}
          <div className="border-t border-[var(--border-primary)] px-4 py-3">
            <div className="flex items-center gap-2.5">
              <span
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-[var(--bg-elevated)] text-[10px] font-bold text-[#00e5c8]"
                style={{ fontFamily: "'JetBrains Mono', monospace" }}
              >
                {currentRole.avatar}
              </span>
              <div className="min-w-0">
                <p className="truncate text-xs font-medium text-zinc-900 dark:text-zinc-100">{currentRole.name}</p>
                <p className="truncate text-[10px] text-zinc-700 dark:text-zinc-400">{currentRole.role}</p>
              </div>
              <button
                type="button"
                onClick={logout}
                className="ml-auto rounded p-1 text-zinc-700 transition-colors hover:text-zinc-400"
                title="Sign out"
              >
                <LogOut className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </aside>

        {/* ── Main ── */}
        <main className="flex flex-1 flex-col overflow-hidden">
          {/* Topbar */}
          <header className="flex shrink-0 items-center gap-3 border-b border-[var(--border-primary)] bg-[var(--bg-app)] px-5 py-2.5">
            <div className="relative flex min-w-0 flex-1 items-center gap-3">
              <label className={`flex min-w-0 w-64 items-center gap-2 rounded-lg border bg-[var(--bg-input)] px-3 py-2 ${searchMessage ? "border-amber-500/50" : "border-[var(--border-secondary)]"}`}>
                <Search className="h-3.5 w-3.5 shrink-0 text-zinc-600" />
                <input
                  id="global-soc-search"
                  value={globalSearch}
                  onChange={(event) => { setGlobalSearch(event.target.value); setSearchMessage(null); }}
                  onKeyDown={(event) => { if (event.key === "Enter") submitGlobalSearch(); }}
                  placeholder="Search entities, IPs, assets..."
                  className="min-w-0 flex-1 bg-transparent text-xs text-zinc-700 dark:text-zinc-300 outline-none placeholder:text-zinc-700"
                />
                {!globalSearch && (
                  <kbd className="shrink-0 rounded border border-[var(--border-secondary)] px-1.5 py-0.5 text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>/</kbd>
                )}
              </label>
              {searchMessage && (
                <div className="absolute left-0 top-full z-30 mt-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-100">
                  {searchMessage}
                </div>
              )}
              <TimeRangeControl value={globalTimeRange} onChange={setGlobalTimeRange} />
              <button
                type="button"
                onClick={() => setHelpOpen(true)}
                title="Keyboard shortcuts"
                className="flex h-7 items-center gap-1 rounded border border-[var(--border-secondary)] bg-[var(--bg-input)] px-2 text-[10px] text-zinc-600 hover:border-zinc-700 hover:text-zinc-400 transition-colors"
                style={{ fontFamily: "'JetBrains Mono', monospace" }}
              >
                ?
              </button>
            </div>

            <div className="flex items-center gap-2">
              <StatusPill source={source} loading={loading} errorMessage={apiError} onRefresh={refreshNow} wsStatus={wsStatus} />
              <button
                type="button"
                onClick={toggleTheme}
                className="flex h-8 w-8 items-center justify-center rounded-md text-zinc-500 transition-colors hover:bg-[var(--bg-elevated)] hover:text-zinc-700 dark:hover:text-zinc-300"
                aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
                title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              >
                {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              </button>
              <button
                type="button"
                onClick={() => {
                  setNotificationsOpen((open) => { if (open) setLastSeenNotificationsAt(new Date().toISOString()); return !open; });
                  setUserMenuOpen(false);
                }}
                className="relative flex h-8 w-8 items-center justify-center rounded-md text-zinc-500 transition-colors hover:bg-[var(--bg-elevated)] hover:text-zinc-700 dark:hover:text-zinc-300"
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
                onClick={() => { setUserMenuOpen((open) => !open); closeNotifications(); }}
                className="flex items-center gap-2 rounded-lg border border-[var(--border-secondary)] bg-[var(--bg-input)] px-2.5 py-1.5 text-sm text-zinc-700 dark:text-zinc-300 transition-colors hover:border-[var(--border-primary)]"
              >
                <span className="flex h-6 w-6 items-center justify-center rounded bg-[var(--bg-elevated)] text-[10px] font-bold text-[#00e5c8]" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                  {currentRole.avatar}
                </span>
                <span className="hidden text-xs md:inline">{currentRole.name}</span>
                <ChevronDown className="h-3.5 w-3.5 text-zinc-600" />
              </button>
            </div>

            {(notificationsOpen || userMenuOpen) && (
              <button type="button" aria-label="Close open menu" className="fixed inset-0 z-[25] cursor-default bg-transparent"
                onClick={() => { closeNotifications(); setUserMenuOpen(false); }} />
            )}
            <NotificationTray open={notificationsOpen} notifications={notifications} onClose={closeNotifications} />
            <UserMenu open={userMenuOpen} role={currentRole} onLogout={logout} onSettings={() => { setSettingsOpen(true); setUserMenuOpen(false); }} />
          </header>

          {/* Mobile tabs */}
          <div className="flex gap-2 overflow-x-auto border-b border-[var(--border-primary)] px-4 py-2 lg:hidden">
            {availableNavItems.map((item) => (
              <button key={item.id} type="button" onClick={() => setActiveView(item.id)}
                className={`mobile-tab ${activeView === item.id ? "mobile-tab-active" : ""}`}>
                <item.icon className="h-4 w-4" />
                {item.label}
              </button>
            ))}
          </div>

          {/* Content */}
          <section key={activeView} className="view-enter flex-1 overflow-y-auto px-5 py-5">
            {apiError && (
              <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-800 dark:text-amber-100">
                {currentRole.id === "ciso" ? "Connection degraded. Briefing reflects the last known state." : "Connection lost. Showing last known state."}
              </div>
            )}
            {patchError && (
              <div className="mb-4 rounded-lg border border-orange-500/30 bg-orange-500/10 px-4 py-3 text-sm text-orange-800 dark:text-orange-100">
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
                incidents={data.incidents}
                entities={data.entities}
                wsStatus={wsStatus}
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
            {activeView === "qna" && <QnaView answers={data.qnaAnswers} templates={data.qnaTemplates} />}
            {activeView === "compliance" && <ComplianceView frameworks={data.compliance} canExport={currentRole.canExportCompliance} />}
            {activeView === "pipeline" && <PipelineHealthView />}
          </section>
        </main>
      </div>

      {/* ── Footer status bar ── */}
      <footer className="shrink-0 border-t border-[var(--border-subtle)] bg-[var(--bg-app)] px-5 py-2">
        <div className="flex items-center gap-5">
          <span className="flex items-center gap-1.5 text-[10px] text-zinc-500" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
            <span className="h-1.5 w-1.5 rounded-full bg-[#00e5c8]" />
            ARIA: Active
          </span>
          <span className="text-[10px] text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
            {data.entities.length} entities scored
          </span>
          <span className="text-[10px] text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
            Last ETL: {lastRefresh ? formatRelativeAge(lastRefresh.toISOString()) : "pending"}
          </span>
        </div>
      </footer>

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

const VIGIL_THREAT_STATS = [
  { label: "Active Incidents", value: "12", level: "warn" },
  { label: "Critical Entities", value: "3", level: "crit" },
  { label: "Monitored Assets", value: "4,891", level: "ok" },
  { label: "Data Sources Online", value: "7 / 7", level: "ok" },
  { label: "Last Event Ingested", value: "< 2s ago", level: "ok" },
] as const;

function LoginScreen({
  onLogin,
  onJwtLogin,
  theme,
  onToggleTheme,
}: {
  onLogin: (profile: RoleProfile) => void;
  onJwtLogin: (email: string, password: string) => Promise<void>;
  theme: "dark" | "light";
  onToggleTheme: () => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loginLoading, setLoginLoading] = useState(false);
  const [showDemo, setShowDemo] = useState(false);
  const [hoveredProfile, setHoveredProfile] = useState<string | null>(null);

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
    <div className="min-h-screen flex text-slate-900 dark:text-zinc-100">

      {/* ── Left panel: always-dark branding ──
          Intentionally uses a fixed deep navy regardless of theme,
          so decorative effects (grid, scanline, glow) are always visible. */}
      <div
        className="hidden lg:flex lg:w-[46%] flex-col relative overflow-hidden"
        style={{ background: "#030d1a" }}
      >
        <div className="vigil-grid-bg absolute inset-0" />
        <div className="vigil-scanline absolute inset-0" />

        {/* Right-edge cyan accent line */}
        <div
          className="absolute top-0 right-0 w-px h-full pointer-events-none"
          style={{ background: "linear-gradient(to bottom, transparent 0%, rgba(0,229,200,0.25) 30%, rgba(0,229,200,0.12) 70%, transparent 100%)" }}
        />

        {/* Radial glow origin */}
        <div className="absolute top-0 left-0 w-[700px] h-[700px] rounded-full pointer-events-none"
          style={{ background: "radial-gradient(ellipse at 15% 10%, rgba(0,229,200,0.09) 0%, transparent 60%)" }} />

        {/* Large watermark VIGIL — depth element */}
        <div
          className="absolute -bottom-8 -right-12 select-none pointer-events-none"
          style={{
            fontSize: "280px",
            fontWeight: 900,
            lineHeight: 1,
            letterSpacing: "-0.04em",
            color: "rgba(0,229,200,0.025)",
            fontFamily: "'Outfit', sans-serif",
          }}
        >
          VIGIL
        </div>

        <div className="relative z-10 flex flex-col h-full px-12 py-14 justify-between">

          {/* Status chip */}
          <div className="flex items-center gap-2.5">
            <span className="vigil-status-dot h-2 w-2 rounded-full bg-[#00e5c8] inline-block" />
            <span className="text-[10px] tracking-[0.35em] text-[#00e5c8] uppercase" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
              All Systems Operational
            </span>
          </div>

          {/* Wordmark */}
          <div className="-mt-8">
            <h1
              className="text-[88px] font-black leading-none text-white tracking-tight select-none"
              style={{ letterSpacing: "-0.03em" }}
            >
              VIGIL
            </h1>
            <p
              className="text-[10px] tracking-[0.45em] text-zinc-500 uppercase mt-2.5"
              style={{ fontFamily: "'JetBrains Mono', monospace" }}
            >
              Security Operations Command Center
            </p>

            {/* Separator */}
            <div className="mt-10 h-px w-16 bg-[#00e5c8]/30" />

            {/* Live threat status table */}
            <div className="mt-8 space-y-0">
              <p
                className="text-[9px] tracking-[0.4em] text-zinc-600 uppercase mb-4"
                style={{ fontFamily: "'JetBrains Mono', monospace" }}
              >
                Live Threat Status
              </p>
              {VIGIL_THREAT_STATS.map(({ label, value, level }) => (
                <div
                  key={label}
                  className="flex items-center justify-between py-3 border-b border-white/5"
                >
                  <span
                    className="text-xs text-zinc-500"
                    style={{ fontFamily: "'JetBrains Mono', monospace" }}
                  >
                    {label}
                  </span>
                  <span
                    className={`text-xs font-semibold tabular-nums ${
                      level === "crit"
                        ? "text-red-400"
                        : level === "warn"
                          ? "text-amber-400"
                          : "text-[#00e5c8]"
                    }`}
                    style={{ fontFamily: "'JetBrains Mono', monospace" }}
                  >
                    {value}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Footer */}
          <div>
            <p
              className="text-[9px] tracking-[0.35em] text-zinc-600 uppercase"
              style={{ fontFamily: "'JetBrains Mono', monospace" }}
            >
              Meridian Financial Group
            </p>
            <p
              className="text-[9px] tracking-[0.35em] text-zinc-800 uppercase mt-1.5"
              style={{ fontFamily: "'JetBrains Mono', monospace" }}
            >
              Restricted — Authorized Personnel Only
            </p>
          </div>
        </div>
      </div>

      {/* ── Right panel: sign-in form ── */}
      <div
        className="flex flex-1 flex-col items-center justify-start overflow-y-auto relative px-8 py-12"
        style={{ background: "var(--login-right-bg)" }}
      >
        {/* Decorative grid — light mode only, fades in dark */}
        <div className="vigil-grid-bg-light absolute inset-0 opacity-100 dark:opacity-0 transition-opacity pointer-events-none" />

        {/* Subtle top-edge cyan accent */}
        <div
          className="absolute top-0 left-0 right-0 h-0.5 pointer-events-none dark:opacity-30"
          style={{ background: "linear-gradient(to right, transparent, rgba(0,229,200,0.5) 40%, rgba(0,229,200,0.5) 60%, transparent)" }}
        />

        {/* Mobile-only logo */}
        <div className="lg:hidden mb-10 text-center relative z-10">
          <h1 className="text-5xl font-black tracking-tight text-zinc-900 dark:text-white">VIGIL</h1>
          <p
            className="text-[10px] tracking-[0.35em] text-zinc-500 uppercase mt-2"
            style={{ fontFamily: "'JetBrains Mono', monospace" }}
          >
            Command Center
          </p>
        </div>

        {/* Form card — floats in light mode, flat in dark mode */}
        <div
          className="relative z-10 w-full max-w-[400px] vigil-fadein"
          style={{ background: "transparent" }}
        >

          {/* Heading */}
          <div className="mb-5">
            <h2
              className="text-2xl font-bold leading-tight"
              style={{ color: theme === "light" ? "#0f172a" : "#ffffff" }}
            >Sign in</h2>
            <p className="text-sm mt-1" style={{ color: theme === "light" ? "#64748b" : "#a1a1aa" }}>
              Enter your analyst credentials, or use{" "}
              <span style={{ color: "#00e5c8" }}>Demo Access</span> below.
            </p>
          </div>

          {/* Form */}
          <form onSubmit={(e) => void handleJwtLogin(e)} className="space-y-4">
            <div>
              <label
                className="block text-[10px] tracking-[0.2em] text-zinc-600 dark:text-zinc-500 uppercase mb-2"
                style={{ fontFamily: "'JetBrains Mono', monospace" }}
              >
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="l1@soc.internal"
                autoComplete="username"
                className="w-full rounded-lg border border-slate-400 dark:border-[var(--border-secondary)] bg-white dark:bg-[var(--bg-input)] px-4 py-3 text-sm text-zinc-900 dark:text-zinc-200 outline-none placeholder:text-zinc-400 dark:placeholder:text-zinc-600 shadow-sm dark:shadow-none focus:border-[#00e5c8]/60 focus:ring-2 focus:ring-[#00e5c8]/12 transition-all"
                style={theme === "light" ? { color: "#0f172a", WebkitTextFillColor: "#0f172a" } : undefined}
              />
            </div>

            <div>
              <label
                className="block text-[10px] tracking-[0.2em] text-zinc-600 dark:text-zinc-500 uppercase mb-2"
                style={{ fontFamily: "'JetBrains Mono', monospace" }}
              >
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete="current-password"
                className="w-full rounded-lg border border-slate-400 dark:border-[var(--border-secondary)] bg-white dark:bg-[var(--bg-input)] px-4 py-3 text-sm text-zinc-900 dark:text-zinc-200 outline-none placeholder:text-zinc-400 dark:placeholder:text-zinc-600 shadow-sm dark:shadow-none focus:border-[#00e5c8]/60 focus:ring-2 focus:ring-[#00e5c8]/12 transition-all"
                style={theme === "light" ? { color: "#0f172a", WebkitTextFillColor: "#0f172a" } : undefined}
              />
            </div>

            {loginError && (
              <div className="flex items-start gap-2.5 rounded-lg border border-red-200 dark:border-red-900/40 bg-red-50 dark:bg-red-950/20 px-4 py-3">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-500 dark:text-red-400" />
                <p className="text-sm text-red-700 dark:text-red-300 leading-snug">{loginError}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loginLoading || !email || !password}
              className={`mt-1 w-full rounded-lg px-4 py-3 text-sm font-semibold flex items-center justify-center gap-2 transition-all ${
                loginLoading || !email || !password
                  ? "cursor-not-allowed border border-slate-200 dark:border-[var(--border-secondary)] bg-slate-100 dark:bg-[var(--bg-input)] text-slate-400 dark:text-zinc-700"
                  : "bg-[#00e5c8] text-[#04080f] hover:bg-[#00f0d5] active:scale-[0.99] shadow-sm"
              }`}
            >
              {loginLoading ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin" />
                  Authenticating…
                </>
              ) : (
                <>
                  <LogIn className="h-4 w-4" />
                  Sign in
                </>
              )}
            </button>
          </form>

          {/* Demo access section */}
          <div className="mt-7">
            <button
              type="button"
              onClick={() => setShowDemo((v) => !v)}
              className="w-full flex items-center gap-3 text-xs text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors group"
            >
              <div className="flex-1 h-px bg-slate-200 dark:bg-[var(--border-primary)]" />
              <span
                className="flex items-center gap-1.5 shrink-0"
                style={{ fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.1em" }}
              >
                <ChevronDown
                  className={`h-3 w-3 transition-transform duration-200 ${showDemo ? "rotate-180" : ""}`}
                />
                Demo Access
              </span>
              <div className="flex-1 h-px bg-slate-200 dark:bg-[var(--border-primary)]" />
            </button>

            {showDemo && (
              <div className="mt-4 space-y-1.5 vigil-fadein">
                <p
                  className="text-[9px] tracking-[0.3em] text-zinc-500 dark:text-zinc-400 uppercase mb-3"
                  style={{ fontFamily: "'JetBrains Mono', monospace" }}
                >
                  Bypass JWT · Select Demo Profile
                </p>
                {roleProfiles.map((profile) => {
                  const isHovered = hoveredProfile === profile.id;
                  const cardBg = theme === "light"
                    ? (isHovered ? "#f0faf9" : "#ffffff")
                    : (isHovered ? "#0d1826" : "var(--bg-input)");
                  const cardBorder = isHovered ? "rgba(0,229,200,0.5)" : (theme === "light" ? "#cbd5e1" : "var(--border-subtle)");
                  const nameColor = theme === "light" ? "#0f172a" : (isHovered ? "#f4f4f5" : "#d4d4d8");
                  return (
                  <button
                    key={profile.id}
                    type="button"
                    onClick={() => onLogin(profile)}
                    onMouseEnter={() => setHoveredProfile(profile.id)}
                    onMouseLeave={() => setHoveredProfile(null)}
                    className="w-full flex items-center gap-3 rounded-xl border px-4 py-3 text-left shadow-sm dark:shadow-none transition-all"
                    style={{ backgroundColor: cardBg, borderColor: cardBorder }}
                  >
                    <span
                      className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[#030d1a] text-[10px] font-bold text-[#00e5c8]"
                      style={{ fontFamily: "'JetBrains Mono', monospace" }}
                    >
                      {profile.avatar}
                    </span>
                    <div className="min-w-0">
                      <p
                        className="text-sm font-medium truncate transition-colors"
                        style={{ color: nameColor, WebkitTextFillColor: nameColor }}
                      >
                        {profile.name}
                      </p>
                      <p className="text-xs text-zinc-500 dark:text-zinc-400 truncate">{profile.role}</p>
                    </div>
                    <ChevronDown
                      className="ml-auto h-3.5 w-3.5 -rotate-90 transition-colors shrink-0"
                      style={{ color: isHovered ? "#00e5c8" : (theme === "light" ? "#94a3b8" : "#3f3f46") }}
                    />
                  </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Theme toggle */}
          <div className="mt-6 flex justify-center">
            <button
              type="button"
              onClick={onToggleTheme}
              className="flex items-center gap-2 rounded-full border border-slate-200 dark:border-[var(--border-secondary)] px-4 py-1.5 text-xs text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300 hover:border-slate-300 dark:hover:border-[var(--border-primary)] transition-colors"
            >
              {theme === "dark" ? <Sun className="h-3 w-3" /> : <Moon className="h-3 w-3" />}
              {theme === "dark" ? "Light mode" : "Dark mode"}
            </button>
          </div>
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
  const [emailFeedback, setEmailFeedback] = useState<"sent" | "no-address" | null>(null);

  if (!open) return null;

  // Read browser permission state at render time — updates when parent re-renders after toggle
  const notifSupported = typeof Notification !== "undefined";
  const notifPermission = notifSupported ? Notification.permission : "denied";
  const notifBlocked = notifPermission === "denied";

  const sendTestNotification = () => {
    if (!notifSupported || notifPermission !== "granted") return;
    new Notification("Vigil · Test alert", {
      body: "Browser critical alerts are working correctly.",
    });
  };

  const handleSendTestEmail = () => {
    if (!alertEmail.trim()) {
      setEmailFeedback("no-address");
    } else {
      setEmailFeedback("sent");
    }
    setTimeout(() => setEmailFeedback(null), 5000);
  };

  return (
    <div className="fixed inset-0 z-40 bg-black/50" onClick={onClose}>
      <aside className="ml-auto h-full w-full max-w-md overflow-y-auto border-l border-[var(--border-primary)] bg-[var(--bg-panel)] p-5 shadow-panel" onClick={(event) => event.stopPropagation()}>
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
          <div className="mt-2 flex items-center gap-2 rounded-md border border-[var(--border-primary)] bg-[var(--bg-elevated)] px-3 py-2">
            <KeyRound className="h-4 w-4 text-zinc-500" />
            <input
              value={apiKey}
              onChange={(event) => onApiKeyChange(event.target.value)}
              type="password"
              placeholder="Optional API key"
              className="min-w-0 flex-1 bg-transparent text-sm text-zinc-700 dark:text-zinc-200 outline-none placeholder:text-zinc-500"
            />
          </div>
        </label>
        <div className="mt-4 flex gap-2">
          <button type="button" onClick={onSave} className="command-button">Save</button>
          <button type="button" onClick={onClear} className="rounded-md border border-[var(--border-primary)] px-3 py-2 text-sm text-zinc-600 dark:text-zinc-300">Clear</button>
        </div>

        <div className="mt-8 border-t border-[var(--border-primary)] pt-5">
          <p className="section-label">Alert delivery</p>

          {/* ── Email alert ── */}
          <label className="mt-4 block">
            <span className="text-sm font-medium text-zinc-700 dark:text-zinc-300">Alert email</span>
            <div className="mt-2 flex items-center gap-2 rounded-md border border-[var(--border-primary)] bg-[var(--bg-elevated)] px-3 py-2">
              <Mail className="h-4 w-4 text-zinc-500" />
              <input
                value={alertEmail}
                onChange={(event) => onAlertEmailChange(event.target.value)}
                type="email"
                placeholder="soc-alerts@meridian.example"
                className="min-w-0 flex-1 bg-transparent text-sm text-zinc-700 dark:text-zinc-200 outline-none placeholder:text-zinc-500"
              />
            </div>
          </label>
          <button
            type="button"
            onClick={handleSendTestEmail}
            className="mt-3 rounded-md border border-[var(--border-primary)] px-3 py-2 text-sm text-zinc-600 dark:text-zinc-300 hover:border-[var(--border-secondary)] transition-colors"
          >
            Send test alert
          </button>
          {emailFeedback === "sent" && (
            <div className="mt-2 flex items-start gap-2 rounded-md border border-[#00e5c8]/20 bg-[#00e5c8]/5 px-3 py-2">
              <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[#00e5c8]" />
              <p className="text-xs text-zinc-500 leading-snug">
                Test alert queued for <span className="text-zinc-700 dark:text-zinc-300 font-medium">{alertEmail}</span>.{" "}
                <span className="text-zinc-600">Email delivery requires the backend alert service to be configured.</span>
              </p>
            </div>
          )}
          {emailFeedback === "no-address" && (
            <div className="mt-2 flex items-start gap-2 rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2">
              <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400" />
              <p className="text-xs text-amber-600 dark:text-amber-400">Enter an alert email address first.</p>
            </div>
          )}

          {/* ── Browser notifications ── */}
          <div className="mt-6">
            <label className="flex items-center justify-between gap-3 rounded-md border border-[var(--border-primary)] bg-[var(--bg-elevated)] px-3 py-3">
              <div className="min-w-0">
                <span className="text-sm text-zinc-600 dark:text-zinc-300">Browser critical alerts</span>
                {notifBlocked && (
                  <p className="mt-0.5 text-xs text-amber-500 dark:text-amber-400">
                    Blocked — allow in browser site settings to enable
                  </p>
                )}
                {!notifBlocked && browserNotificationsEnabled && (
                  <p className="mt-0.5 text-xs text-emerald-500 dark:text-emerald-400">
                    Active — OS notifications enabled
                  </p>
                )}
                {!notifBlocked && !browserNotificationsEnabled && notifPermission === "default" && (
                  <p className="mt-0.5 text-xs text-zinc-500">
                    Enable to receive OS-level critical alerts
                  </p>
                )}
              </div>
              <input
                type="checkbox"
                checked={browserNotificationsEnabled}
                disabled={notifBlocked}
                onChange={(event) => void onBrowserNotificationsChange(event.target.checked)}
                className="h-4 w-4 shrink-0 accent-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed"
              />
            </label>
            {browserNotificationsEnabled && !notifBlocked && (
              <button
                type="button"
                onClick={sendTestNotification}
                className="mt-2 w-full rounded-md border border-[#00e5c8]/30 bg-[#00e5c8]/5 px-3 py-2 text-xs text-[#00e5c8] hover:bg-[#00e5c8]/10 transition-colors"
              >
                Send test notification
              </button>
            )}
          </div>
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
      className="rounded-md border border-zinc-800 bg-[var(--bg-elevated)] px-3 py-2 text-sm text-zinc-800 dark:text-zinc-200 outline-none"
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
  if (!open) return null;

  const kindDot: Record<string, string> = {
    critical: "bg-red-400 shadow-[0_0_6px_rgba(248,113,113,0.6)]",
    status:   "bg-orange-400",
    timeline: "bg-[#00e5c8]",
  };

  return (
    <div className="absolute right-0 top-11 z-30 w-[min(400px,calc(100vw-2rem))] overflow-hidden rounded-lg border border-[var(--border-secondary)] bg-[var(--bg-panel)] shadow-2xl vigil-fadein">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[var(--border-primary)] px-4 py-3">
        <div className="flex items-center gap-2">
          <Bell className="h-3.5 w-3.5 text-zinc-500" />
          <p className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">Notifications</p>
          {notifications.length > 0 && (
            <span className="rounded-full bg-red-500 px-1.5 py-0.5 text-[10px] font-bold text-white">
              {notifications.length}
            </span>
          )}
        </div>
        <button type="button" onClick={onClose}
          className="flex h-6 w-6 items-center justify-center rounded text-zinc-600 hover:bg-[var(--bg-elevated)] hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Body */}
      <div className="max-h-[420px] overflow-y-auto">
        {notifications.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-3 px-6 py-12 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-full border border-emerald-500/20 bg-emerald-500/10">
              <ShieldCheck className="h-6 w-6 text-emerald-400" />
            </div>
            <div>
              <p className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">All caught up</p>
              <p className="mt-1 text-xs text-zinc-600">No alerts in the current operating window.</p>
            </div>
            <p className="text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
              Last checked: just now
            </p>
          </div>
        ) : (
          <div className="space-y-0">
            {notifications.map((notification, i) => (
              <div
                key={notification.id}
                className={`flex items-start gap-3 px-4 py-3.5 transition-colors hover:bg-[var(--bg-hover)] ${
                  i < notifications.length - 1 ? "border-b border-[var(--border-subtle)]" : ""
                }`}
              >
                <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${kindDot[notification.kind] ?? "bg-zinc-500"}`} />
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-semibold text-zinc-800 dark:text-zinc-200 leading-snug">{notification.title}</p>
                  <p className="mt-1 text-xs leading-4 text-zinc-500">{notification.detail}</p>
                  <p className="mt-1.5 text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                    {formatRelativeAge(notification.createdAt)}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Footer */}
      {notifications.length > 0 && (
        <div className="border-t border-[var(--border-primary)] px-4 py-2.5">
          <p className="text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
            {notifications.length} alert{notifications.length !== 1 ? "s" : ""} · ARIA threat monitoring active
          </p>
        </div>
      )}
    </div>
  );
}

function UserMenu({
  open,
  role,
  onLogout,
  onSettings,
}: {
  open: boolean;
  role: RoleProfile;
  onLogout: () => void;
  onSettings: () => void;
}) {
  if (!open) return null;
  return (
    <div className="absolute right-0 top-11 z-30 w-64 rounded-lg border border-[var(--border-secondary)] bg-[var(--bg-panel)] p-2 shadow-2xl">
      <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-hover)] px-4 py-3 mb-1">
        <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">{role.name}</p>
        <p className="mt-0.5 text-xs text-zinc-600">{role.role}</p>
      </div>
      <button type="button" onClick={onSettings}
        className="flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-left text-xs text-zinc-500 transition-colors hover:bg-[var(--bg-elevated)] hover:text-zinc-800 dark:hover:text-zinc-200">
        <Settings className="h-3.5 w-3.5" />
        Settings
      </button>
      <div className="my-1 border-t border-[var(--border-primary)]" />
      <button type="button" onClick={onLogout}
        className="flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-left text-xs text-zinc-500 transition-colors hover:bg-[var(--bg-elevated)] hover:text-red-500 dark:hover:text-red-400">
        <LogOut className="h-3.5 w-3.5" />
        Sign out
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
        <div className="mt-5 grid gap-3 text-sm text-zinc-900 dark:text-zinc-100">
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
    <div className="flex items-center justify-between rounded-md border border-[var(--border-secondary)] bg-[var(--bg-elevated)] px-3 py-2">
      <span className="text-zinc-800 dark:text-zinc-200">{label}</span>
      <kbd className="rounded border border-[var(--border-secondary)] px-2 py-1 text-xs text-zinc-700 dark:text-zinc-400">{keys}</kbd>
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
        <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Threat Risk Platform</p>
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
      <div title="Real-time feed connected" className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1.5 text-xs text-emerald-700 dark:text-emerald-300">
        <Wifi className="h-3.5 w-3.5" />
        <span className="hidden sm:inline">Live</span>
      </div>
    );
  }
  if (status === "connecting") {
    return (
      <div title="Connecting to real-time feed…" className="inline-flex items-center gap-1.5 rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-1.5 text-xs text-amber-700 dark:text-amber-300">
        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
        <span className="hidden sm:inline">Connecting</span>
      </div>
    );
  }
  return (
    <div title="Real-time feed disconnected — polling every 5 min" className="inline-flex items-center gap-1.5 rounded-md border border-[var(--border-secondary)] bg-[var(--bg-elevated)] px-2 py-1.5 text-xs text-zinc-500">
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
  wsStatus,
}: {
  source: "live" | "fallback";
  loading: boolean;
  errorMessage: string | null;
  onRefresh: () => void;
  wsStatus: WsStatus;
}) {
  const isLive = source === "live";
  const wsConnected = wsStatus === "connected";
  const wsConnecting = wsStatus === "connecting";

  if (loading) {
    return (
      <div className="inline-flex items-center gap-2 rounded-lg border border-[var(--border-secondary)] bg-[var(--bg-elevated)] px-3 py-1.5 text-xs text-zinc-400">
        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
        Loading
      </div>
    );
  }

  if (!isLive) {
    return (
      <div title={errorMessage ?? "Showing last known state"} className="inline-flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-300">
        <Database className="h-3.5 w-3.5" />
        Offline mode
        <button type="button" onClick={onRefresh} className="ml-0.5 rounded p-0.5 opacity-60 transition hover:opacity-100" aria-label="Refresh">
          <RefreshCw className="h-3 w-3" />
        </button>
      </div>
    );
  }

  if (wsConnecting) {
    return (
      <div className="inline-flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-300">
        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
        Connecting
      </div>
    );
  }

  return (
    <div
      title={wsConnected ? "Real-time WebSocket feed active" : "Polling fallback — real-time feed disconnected"}
      className={`inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs ${
        wsConnected
          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
          : "border-[var(--border-secondary)] bg-[var(--bg-elevated)] text-zinc-500"
      }`}
    >
      {wsConnected ? (
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
        </span>
      ) : (
        <WifiOff className="h-3.5 w-3.5" />
      )}
      {wsConnected ? "Live" : "No feed"}
      {wsConnected && (
        <button type="button" onClick={onRefresh} className="ml-0.5 rounded p-0.5 opacity-40 transition hover:opacity-100" aria-label="Refresh">
          <RefreshCw className="h-3 w-3" />
        </button>
      )}
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
  const mediumCount = data.entities.filter((entity) => entity.risk_band === "medium").length;
  const lowCount = data.entities.filter((entity) => entity.risk_band === "low").length;

  if (role.id === "ciso") {
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

  const bandDistribution = [
    { label: "Critical", count: criticalCount, color: "#ef4444" },
    { label: "High", count: highCount, color: "#f97316" },
    { label: "Medium", count: mediumCount, color: "#facc15" },
    { label: "Low", count: lowCount, color: "#22c55e" },
  ];
  const totalEntityCount = Math.max(criticalCount + highCount + mediumCount + lowCount, 1);
  const maxBandCount = totalEntityCount;

  const incidentSeverityStatus = (sev: RiskBand): string =>
    sev === "critical" || sev === "high" ? "Investigating" : "Open";

  return (
    <div className="space-y-4">
      {/* 3 stat cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-lg border-t-2 border-red-500 bg-[var(--bg-stat-red)] px-5 py-4" style={{ borderLeftColor: "transparent", borderRightColor: "transparent", borderBottomColor: "transparent" }}>
          <p className="text-xs text-zinc-500">Active Incidents</p>
          <div className="mt-2 flex items-end justify-between gap-2">
            <p className="text-3xl font-bold text-red-400">{data.incidents.length}</p>
            <Sparkline values={[19, 21, 18, 23, 20, 22, data.incidents.length]} color="#ef4444" />
          </div>
          <p className="mt-1 text-xs text-zinc-600">↑ {Math.max(0, data.incidents.length - 19)} from yesterday</p>
        </div>
        <div className="rounded-lg border-t-2 border-red-800 bg-[var(--bg-stat-red)] px-5 py-4" style={{ borderLeftColor: "transparent", borderRightColor: "transparent", borderBottomColor: "transparent" }}>
          <p className="text-xs text-zinc-500">Critical Entities</p>
          <div className="mt-2 flex items-end justify-between gap-2">
            <p className="text-3xl font-bold text-red-600">{criticalCount}</p>
            <Sparkline values={[1, 3, 2, 4, 3, 2, criticalCount]} color="#b91c1c" />
          </div>
          <p className="mt-1 text-xs text-zinc-600">{criticalCount} entities active</p>
        </div>
        {(() => {
          const lagMs = newestEvent ? Date.now() - new Date(newestEvent).getTime() : null;
          const lagOk = lagMs !== null && lagMs < 10_000;
          const lagWarn = lagMs !== null && lagMs < 60_000;
          const borderCol = lagMs === null ? "border-t-zinc-700" : lagOk ? "border-t-emerald-700" : lagWarn ? "border-t-amber-600" : "border-t-red-700";
          const textCol = lagMs === null ? "text-zinc-500" : lagOk ? "text-emerald-400" : lagWarn ? "text-amber-400" : "text-red-400";
          const bgCol = lagMs === null ? "" : lagOk ? "bg-[var(--bg-stat-green)]" : lagWarn ? "bg-[var(--bg-stat-amber)]" : "bg-[var(--bg-stat-red)]";
          return (
            <div className={`rounded-lg border-t-2 ${borderCol} ${bgCol} px-5 py-4`} style={{ borderLeftColor: "transparent", borderRightColor: "transparent", borderBottomColor: "transparent" }}>
              <p className="text-xs text-zinc-500">Stream Freshness</p>
              <p className={`mt-2 text-3xl font-bold ${textCol}`}>{formatRelativeAge(newestEvent)}</p>
              <p className="mt-1 text-xs text-zinc-600">Lag · Target &lt; 5s</p>
            </div>
          );
        })()}
      </div>

      {/* Risk Band Distribution */}
      <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] px-5 py-5">
        <h3 className="text-sm font-semibold text-zinc-800 dark:text-zinc-200 mb-5">Risk Band Distribution</h3>
        <div className="space-y-3">
          {bandDistribution.map(({ label, count, color }) => (
            <div key={label} className="flex items-center gap-4">
              <span className="w-16 shrink-0 text-sm text-zinc-400">{label}</span>
              <div className="flex-1 h-5 rounded-sm bg-[var(--bg-subtle)] overflow-hidden">
                <div
                  className="h-full rounded-sm transition-all duration-700"
                  style={{ width: `${(count / maxBandCount) * 100}%`, backgroundColor: color }}
                />
              </div>
              <span className="w-7 shrink-0 text-right text-sm font-bold tabular-nums" style={{ color }}>
                {count}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Recent Incidents */}
      <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] px-5 py-5">
        <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 mb-4">Recent Incidents</h3>
        <div className="space-y-1">
          {data.incidents.slice(0, 4).map((incident) => {
            const status = incidentSeverityStatus(incident.severity);
            const borderColor = status === "Investigating" ? "#f97316" : "#ef4444";
            const statusClass = status === "Investigating"
              ? "border-orange-400/30 bg-orange-500/10 text-orange-700 dark:text-orange-300"
              : "border-red-400/30 bg-red-500/10 text-red-700 dark:text-red-300";
            return (
              <div
                key={incident.incident_id}
                className="flex items-center gap-4 rounded-r-md border-l-2 px-4 py-3 transition-colors hover:bg-[var(--bg-subtle)]"
                style={{ borderLeftColor: borderColor }}
              >
                <span className="w-20 shrink-0 text-xs font-semibold text-zinc-900 dark:text-zinc-100" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                  {incident.incident_id}
                </span>
                <span className="w-28 shrink-0 truncate text-xs text-zinc-700 dark:text-zinc-400">
                  {incident.entities_involved[0] ?? "—"}
                </span>
                <span className="min-w-0 flex-1 truncate text-xs text-zinc-400">{incident.summary}</span>
                <span className={`shrink-0 rounded border px-2 py-0.5 text-[10px] font-medium ${statusClass}`}>
                  {status}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* ARIA Engine status */}
      <div className="flex items-center gap-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-panel)] px-4 py-3">
        <span className="text-xs text-zinc-600">ARIA Engine</span>
        <span className="text-zinc-800">·</span>
        <span className="text-xs text-zinc-600">All systems:</span>
        <span className="flex items-center gap-1.5 text-xs text-emerald-400">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.6)]" />
          Healthy
        </span>
        <span className="ml-auto text-xs text-zinc-700">
          Last updated {lastRefresh ? formatRelativeAge(lastRefresh.toISOString()) : "pending"}
        </span>
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

  const overallRisk = criticalCount > 0 ? "HIGH" : highCount > 0 ? "MEDIUM" : "LOW";
  const riskColor = overallRisk === "HIGH" ? "text-red-600" : overallRisk === "MEDIUM" ? "text-orange-500" : "text-emerald-600";
  const riskBorder =
    overallRisk === "HIGH"
      ? "border-red-300 dark:border-red-500/30 bg-red-50 dark:bg-red-500/10"
      : overallRisk === "MEDIUM"
        ? "border-orange-200 dark:border-orange-500/30 bg-orange-50 dark:bg-orange-500/10"
        : "border-emerald-200 dark:border-emerald-500/30 bg-emerald-50 dark:bg-emerald-500/10";

  return (
    <div className="-mx-5 -mt-5 min-h-full bg-white dark:bg-[var(--bg-app)] px-8 py-8 text-zinc-900 dark:text-zinc-100">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-zinc-900 dark:text-zinc-100">Organisational Risk Posture</h2>
        <p className="mt-1 text-sm text-zinc-400">
          Executive view · Updated {lastRefresh ? formatRelativeAge(lastRefresh.toISOString()) : "2 min ago"}
        </p>
      </div>

      {/* Overall risk card */}
      <div className={`mt-6 inline-block rounded-lg border-2 px-6 py-5 ${riskBorder}`}>
        <p className="text-xs font-medium uppercase tracking-widest text-zinc-400">Overall Risk Level</p>
        <p className={`mt-2 text-5xl font-black ${riskColor}`}>{overallRisk}</p>
        <p className="mt-2 text-sm text-zinc-500">{criticalCount} critical entities active</p>
      </div>

      {/* 4 stat cards */}
      <div className="mt-6 grid grid-cols-2 gap-4 xl:grid-cols-4">
        {[
          { label: "Open Incidents", value: data.incidents.length.toString(), color: "text-zinc-900 dark:text-zinc-100" },
          { label: "Critical Entities", value: criticalCount.toString(), color: "text-red-600" },
          { label: "High Entities", value: highCount.toString(), color: "text-orange-500" },
          { label: "SLO Compliance", value: "99.94%", color: "text-emerald-600" },
        ].map(({ label, value, color }) => (
          <div key={label} className="rounded-lg border border-zinc-200 dark:border-[var(--border-primary)] bg-white dark:bg-[var(--bg-panel)] px-5 py-4">
            <p className="text-xs text-zinc-400">{label}</p>
            <p className={`mt-2 text-3xl font-bold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Top Risk Entities */}
      <div className="mt-6 rounded-lg border border-zinc-200 dark:border-[var(--border-primary)] bg-white dark:bg-[var(--bg-panel)]">
        <div className="border-b border-zinc-100 dark:border-[var(--border-subtle)] px-5 py-4">
          <h3 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">Top Risk Entities</h3>
        </div>
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-100 dark:border-[var(--border-subtle)] bg-zinc-50 dark:bg-[var(--bg-elevated)]">
              {["Entity", "Vigil Score", "Risk Band", "Top Trigger", "Status"].map((col) => (
                <th key={col} className="px-5 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.entities.slice(0, 4).map((entity) => {
              const scoreColor =
                entity.risk_band === "critical" ? "text-red-600" :
                entity.risk_band === "high" ? "text-orange-500" :
                entity.risk_band === "medium" ? "text-yellow-600" : "text-emerald-600";
              const bandColor =
                entity.risk_band === "critical" ? "text-red-600" :
                entity.risk_band === "high" ? "text-orange-500" :
                entity.risk_band === "medium" ? "text-yellow-600" : "text-emerald-600";
              return (
                <tr key={entity.entity_id} className="border-b border-zinc-100 dark:border-[var(--border-subtle)] last:border-0 hover:bg-zinc-50 dark:hover:bg-[var(--bg-hover)]">
                  <td className="px-5 py-4 font-medium text-zinc-800 dark:text-zinc-200">{entity.display_name}</td>
                  <td className={`px-5 py-4 font-bold ${scoreColor}`}>{entity.risk_score}</td>
                  <td className={`px-5 py-4 font-semibold uppercase ${bandColor}`}>{entity.risk_band}</td>
                  <td className="px-5 py-4 text-zinc-500">{entity.top_risk_reasons[0] ?? "—"}</td>
                  <td className="px-5 py-4">
                    <span className="rounded border border-orange-200 dark:border-orange-500/30 bg-orange-50 dark:bg-orange-500/10 px-2 py-0.5 text-xs font-medium text-orange-600 dark:text-orange-300">
                      Investigating
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Bottom status */}
      <div className="mt-4 flex items-center gap-2 text-xs text-zinc-400">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
        <span>All systems operational</span>
        <span className="text-zinc-300 dark:text-zinc-700">·</span>
        <span>PCI-DSS: 90.5%</span>
        <span className="text-zinc-300 dark:text-zinc-700">·</span>
        <span>SOC 2: 87.1%</span>
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
          <div key={stage} className={`rounded-md border px-3 py-4 ${active ? "border-red-500/40 bg-red-500/15" : "border-zinc-800 bg-[var(--bg-elevated)]"}`}>
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
    <div className="rounded-md border border-zinc-800 bg-[var(--bg-elevated)] p-3">
      <p className="section-label">{label}</p>
      <p className="mt-1 font-semibold text-zinc-900 dark:text-zinc-100">{value}</p>
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
            : "inline-flex items-center gap-2 rounded-md border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-800 dark:text-zinc-200 hover:border-zinc-500"
        }
      >
        <CheckCircle2 className="h-3.5 w-3.5" />
        {investigated ? "Investigated" : "Mark investigated"}
      </button>
      <button
        type="button"
        onClick={() => onOpenTimeline(entity)}
        className="inline-flex items-center gap-2 rounded-md border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-800 dark:text-zinc-200 hover:border-zinc-500"
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

  const [selectedEntity, setSelectedEntity] = useState<RiskEntity | null>(null);

  const BAND_FILTERS: { value: BandFilter; label: string; activeClass: string }[] = [
    { value: "all", label: "ALL", activeClass: "bg-zinc-700 text-white border-[var(--border-secondary)]" },
    { value: "critical", label: "CRITICAL", activeClass: "bg-red-500 text-white border-red-400" },
    { value: "high", label: "HIGH", activeClass: "bg-orange-500 text-white border-orange-400" },
    { value: "medium", label: "MEDIUM", activeClass: "bg-yellow-400 text-zinc-900 border-yellow-300" },
    { value: "low", label: "LOW", activeClass: "bg-emerald-500 text-white border-emerald-400" },
  ];

  return (
    <div className="flex flex-col gap-4">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-zinc-900 dark:text-zinc-100">Entity Risk Queue</h2>
        <p className="mt-0.5 text-xs text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
          Ranked by ARIA Vigil Score · Last scored {formatRelativeAge(visibleEntities[0]?.last_seen_at)}
        </p>
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-3">
        <label className="flex min-w-0 w-64 items-center gap-2 rounded-lg border border-[var(--border-secondary)] bg-[var(--bg-input)] px-3 py-2">
          <Search className="h-3.5 w-3.5 shrink-0 text-zinc-600" />
          <input
            value={query}
            onChange={(event) => onQueryChange(event.target.value)}
            placeholder="Search entities..."
            className="min-w-0 flex-1 bg-transparent text-xs text-zinc-700 dark:text-zinc-300 outline-none placeholder:text-zinc-700"
          />
        </label>
        <div className="flex items-center gap-1.5">
          {BAND_FILTERS.map(({ value, label, activeClass }) => (
            <button key={value} type="button" onClick={() => onBandFilterChange(value)}
              className={`rounded-full border px-3 py-1 text-xs font-semibold transition-all ${
                bandFilter === value ? activeClass : "border-[var(--border-secondary)] bg-[var(--bg-input)] text-zinc-600 hover:border-zinc-700 hover:text-zinc-400"
              }`}>
              {label}
            </button>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-2">
          <select value={sortMode} onChange={(e) => onSortModeChange(e.target.value as RiskSort)}
            className="rounded-lg border border-[var(--border-secondary)] bg-[var(--bg-input)] px-3 py-2 text-xs text-zinc-400 outline-none">
            <option value="score-desc">Score ↓</option>
            <option value="score-asc">Score ↑</option>
            <option value="recent">Most recent</option>
          </select>
          <button type="button" className="flex items-center gap-1.5 rounded-lg border border-[var(--border-secondary)] bg-[var(--bg-input)] px-3 py-2 text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors">
            <Download className="h-3.5 w-3.5" />Export
          </button>
        </div>
      </div>

      {/* Table + detail panel */}
      <div className="flex gap-4">
        {/* Table */}
        <div className={`flex flex-col overflow-hidden rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] transition-all duration-200 ${selectedEntity ? "flex-1 min-w-0" : "w-full"}`}>
          <div className="grid shrink-0 border-b border-[var(--border-primary)] px-4 py-3 text-[10px] font-semibold uppercase tracking-widest text-zinc-600"
            style={{ gridTemplateColumns: "1.4fr 90px 140px 110px 130px 1fr 120px", fontFamily: "'JetBrains Mono', monospace" }}>
            <span>Entity</span><span>Type</span><span>Vigil Score</span><span>Risk Band</span>
            <span>Last Activity</span><span>Top Trigger</span><span className="text-right">Actions</span>
          </div>
          <div className="flex-1 overflow-y-auto">
            {visibleEntities.length === 0 ? (
              <div className="flex flex-col items-center justify-center gap-3 px-4 py-16 text-center">
                <ShieldAlert className="h-8 w-8 text-zinc-800" />
                <div>
                  <p className="text-sm font-medium text-zinc-500">No entities match</p>
                  <p className="mt-1 text-xs text-zinc-700">Try clearing the band filter or broadening your search.</p>
                </div>
                {(bandFilter !== "all" || query) && (
                  <button type="button" onClick={() => { onBandFilterChange("all"); onQueryChange(""); }}
                    className="rounded-lg border border-[var(--border-secondary)] px-3 py-1.5 text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors">
                    Clear filters
                  </button>
                )}
              </div>
            ) : (
              visibleEntities.map((entity) => (
                <RiskTableRow
                  key={entity.entity_id}
                  entity={entity}
                  investigated={investigatedEntities.includes(entity.entity_id)}
                  canInvestigate={canInvestigate}
                  onMarkInvestigated={onMarkInvestigated}
                  onOpenTimeline={onOpenTimeline}
                  isSelected={selectedEntity?.entity_id === entity.entity_id}
                  onSelect={setSelectedEntity}
                />
              ))
            )}
          </div>
          <div className="shrink-0 flex items-center justify-between border-t border-[var(--border-primary)] px-4 py-2.5">
            <span className="text-xs text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
              Showing {visibleEntities.length} of {entities.length} entities
            </span>
            {selectedEntity && (
              <span className="text-xs text-[#00e5c8]">1 selected</span>
            )}
          </div>
        </div>

        {/* Detail panel */}
        {selectedEntity && (
          <div className="w-80 shrink-0 flex flex-col overflow-hidden rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] vigil-fadein">
            {/* Panel header */}
            <div className="flex shrink-0 items-center justify-between border-b border-[var(--border-primary)] px-4 py-3">
              <p className="text-xs font-semibold text-zinc-700 dark:text-zinc-300">Entity Detail</p>
              <button type="button" onClick={() => setSelectedEntity(null)}
                className="flex h-6 w-6 items-center justify-center rounded text-zinc-600 hover:bg-[var(--bg-elevated)] hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors">
                <X className="h-3.5 w-3.5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto px-4 py-4 space-y-5">
              {/* Entity identity */}
              <div>
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <p className="text-lg font-bold text-zinc-900 dark:text-zinc-100 leading-tight">{selectedEntity.display_name}</p>
                    <p className="mt-0.5 text-[10px] text-zinc-600 font-mono">{selectedEntity.entity_id}</p>
                  </div>
                  <span className={`shrink-0 rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase ${BAND_PILL[selectedEntity.risk_band]}`}>
                    {selectedEntity.risk_band}
                  </span>
                </div>
              </div>

              {/* Score */}
              <div className="flex items-center gap-4 rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] px-4 py-3">
                <div>
                  <p className="text-[9px] uppercase tracking-widest text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>Vigil Score</p>
                  <p className="mt-1 text-4xl font-black" style={{ color: bandColors[selectedEntity.risk_band] }}>
                    {selectedEntity.risk_score}
                  </p>
                </div>
                <div className="flex-1">
                  <div className="h-2 overflow-hidden rounded-full bg-[var(--bg-subtle)]">
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${selectedEntity.risk_score}%`, backgroundColor: bandColors[selectedEntity.risk_band] }} />
                  </div>
                  <p className="mt-1.5 text-[10px] text-zinc-600">Last seen {formatRelativeAge(selectedEntity.last_seen_at)}</p>
                </div>
              </div>

              {/* Risk reasons */}
              <div>
                <p className="mb-2 text-[9px] uppercase tracking-widest text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                  Risk Signals ({selectedEntity.top_risk_reasons.length})
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {selectedEntity.top_risk_reasons.map((reason) => (
                    <span key={reason} className="rounded-md border border-zinc-800 bg-[var(--bg-elevated)] px-2 py-1 text-[10px] text-zinc-400">
                      {reason}
                    </span>
                  ))}
                </div>
              </div>

              {/* Recommended action */}
              <div>
                <p className="mb-2 text-[9px] uppercase tracking-widest text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                  Recommended Action
                </p>
                <p className="text-xs leading-5 text-zinc-700 dark:text-zinc-300">{selectedEntity.recommended_action}</p>
              </div>
            </div>

            {/* Panel actions */}
            <div className="shrink-0 flex gap-2 border-t border-[var(--border-primary)] px-4 py-3">
              {canInvestigate && (
                <button type="button"
                  onClick={() => { onMarkInvestigated(selectedEntity.entity_id); setSelectedEntity(null); }}
                  disabled={investigatedEntities.includes(selectedEntity.entity_id)}
                  className={`flex-1 rounded-lg py-2 text-xs font-semibold transition-all ${
                    investigatedEntities.includes(selectedEntity.entity_id)
                      ? "border border-zinc-800 text-zinc-600 cursor-not-allowed"
                      : "bg-[#00e5c8] text-[#04080f] hover:bg-[#00f0d5]"
                  }`}>
                  {investigatedEntities.includes(selectedEntity.entity_id) ? "Investigated" : "Investigate"}
                </button>
              )}
              <button type="button" onClick={() => onOpenTimeline(selectedEntity)}
                className="flex-1 rounded-lg border border-[var(--border-secondary)] py-2 text-xs font-medium text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors">
                View Timeline
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const ENTITY_TYPE_STYLES: Record<string, { label: string; cls: string }> = {
  user:    { label: "USER",    cls: "bg-violet-500/20 text-violet-700 dark:text-violet-300 border-violet-500/30" },
  device:  { label: "HOST",    cls: "bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-500/30" },
  vendor:  { label: "SERVICE", cls: "bg-teal-500/20 text-teal-700 dark:text-teal-300 border-teal-500/30" },
  asset:   { label: "ASSET",   cls: "bg-zinc-200/60 text-zinc-600 dark:bg-zinc-700/40 dark:text-zinc-400 border-zinc-400/40 dark:border-zinc-600/40" },
};

const BAND_PILL: Record<RiskBand, string> = {
  critical: "bg-red-500/20 text-red-700 dark:text-red-300 border-red-500/40",
  high:     "bg-orange-500/20 text-orange-700 dark:text-orange-300 border-orange-500/40",
  medium:   "bg-yellow-500/20 text-yellow-700 dark:text-yellow-200 border-yellow-500/40",
  low:      "bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-500/40",
};

function RiskTableRow({
  entity,
  investigated,
  canInvestigate,
  onMarkInvestigated,
  onOpenTimeline,
  isSelected,
  onSelect,
}: {
  entity: RiskEntity;
  investigated: boolean;
  canInvestigate: boolean;
  onMarkInvestigated: (entityId: string) => void;
  onOpenTimeline: (entity: RiskEntity) => void;
  isSelected?: boolean;
  onSelect?: (entity: RiskEntity) => void;
}) {
  const typeStyle = ENTITY_TYPE_STYLES[entity.entity_type] ?? { label: entity.entity_type.toUpperCase(), cls: "bg-zinc-200/60 text-zinc-600 dark:bg-zinc-700/40 dark:text-zinc-400 border-zinc-400/40 dark:border-zinc-600/40" };

  return (
    <div
      onClick={() => onSelect?.(isSelected ? null as unknown as RiskEntity : entity)}
      className={`group grid cursor-pointer items-center border-b border-[var(--border-subtle)] px-4 py-3 last:border-b-0 transition-colors ${
        isSelected ? "bg-[var(--bg-elevated)] border-l-2 border-l-[#00e5c8]" : "hover:bg-[var(--bg-hover)]"
      }`}
      style={{ gridTemplateColumns: "1.4fr 90px 140px 110px 130px 1fr 120px" }}
    >
      {/* Entity */}
      <div className="flex min-w-0 items-center gap-2 pr-4">
        <p className="min-w-0 truncate text-sm font-semibold text-zinc-800 dark:text-zinc-200">{entity.display_name}</p>
        <ChevronDown
          className={`h-3.5 w-3.5 shrink-0 -rotate-90 transition-all duration-150 ${
            isSelected ? "text-[#00e5c8]" : "text-zinc-700 opacity-0 group-hover:opacity-100"
          }`}
        />
      </div>

      {/* Type badge */}
      <div>
        <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[10px] font-bold tracking-wide ${typeStyle.cls}`}>
          {typeStyle.label}
        </span>
      </div>

      {/* Vigil Score — bar + number */}
      <div className="flex items-center gap-2 pr-4">
        <div className="flex-1 h-1.5 rounded-full bg-[var(--bg-subtle)] overflow-hidden">
          <div
            className="h-full rounded-full"
            style={{ width: `${entity.risk_score}%`, backgroundColor: bandColors[entity.risk_band] }}
          />
        </div>
        <span className="w-7 shrink-0 text-right text-sm font-bold tabular-nums" style={{ color: bandColors[entity.risk_band] }}>
          {entity.risk_score}
        </span>
      </div>

      {/* Risk Band pill */}
      <div>
        <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wide ${BAND_PILL[entity.risk_band]}`}>
          {entity.risk_band}
        </span>
      </div>

      {/* Last Activity */}
      <span className="text-xs text-zinc-500">{formatRelativeAge(entity.last_seen_at)}</span>

      {/* Top Trigger */}
      <span className="truncate pr-4 text-xs text-zinc-400">{entity.top_risk_reasons[0] ?? "—"}</span>

      {/* Actions */}
      <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
        {canInvestigate ? (
          <button type="button" onClick={() => onMarkInvestigated(entity.entity_id)} disabled={investigated}
            className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-all ${
              investigated ? "border-zinc-800 bg-transparent text-zinc-600 cursor-not-allowed"
                : "border-[#00e5c8]/30 bg-[#00e5c8]/10 text-[#00e5c8] hover:bg-[#00e5c8]/20"
            }`}>
            {investigated ? "Done" : "Investigate"}
          </button>
        ) : (
          <button type="button" onClick={() => onOpenTimeline(entity)}
            className="rounded-lg border border-[var(--border-secondary)] bg-[var(--bg-input)] px-3 py-1.5 text-xs font-medium text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors">
            View
          </button>
        )}
        <button type="button" onClick={() => onOpenTimeline(entity)}
          className="flex h-7 w-7 items-center justify-center rounded-lg border border-[var(--border-secondary)] bg-[var(--bg-input)] text-zinc-600 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors">
          <Activity className="h-3.5 w-3.5" />
        </button>
      </div>
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
            className="w-full rounded-md border border-zinc-800 bg-[var(--bg-elevated)] p-3 text-left transition hover:border-zinc-600"
          >
            <div className="flex items-center justify-between gap-3 text-sm">
              <span className="min-w-0 truncate font-medium text-zinc-800 dark:text-zinc-200">{entity.display_name}</span>
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
  incidents,
  entities,
  wsStatus,
}: {
  incidentId: string;
  timeline: TimelineEvent[];
  entityFilter: string | null;
  onEntityFilterChange: (value: string | null) => void;
  range: GlobalTimeRange;
  incidents: import("./types").Incident[];
  entities: RiskEntity[];
  wsStatus: WsStatus;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(incidentId);
  const [actionedIds, setActionedIds] = useState<Record<string, "acknowledged" | "escalated">>({});
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);
  type TabKey = "all" | "open" | "investigating" | "resolved";
  const [tab, setTab] = useState<TabKey>("all");

  const handleAction = (id: string, action: "acknowledged" | "escalated") => {
    setActionedIds((prev) => ({ ...prev, [id]: action }));
    setActionFeedback(action === "acknowledged" ? "Incident acknowledged" : "Incident escalated to L3");
    setTimeout(() => setActionFeedback(null), 3000);
  };

  const incidentStatus = (sev: RiskBand): "Open" | "Investigating" | "Resolved" =>
    sev === "critical" || sev === "high" ? "Investigating" : sev === "medium" ? "Open" : "Resolved";

  const counts = {
    all: incidents.length,
    open: incidents.filter((i) => incidentStatus(i.severity) === "Open").length,
    investigating: incidents.filter((i) => incidentStatus(i.severity) === "Investigating").length,
    resolved: incidents.filter((i) => incidentStatus(i.severity) === "Resolved").length,
  };

  const tabs: { key: TabKey; label: string }[] = [
    { key: "all", label: `All (${counts.all})` },
    { key: "open", label: `Open (${counts.open})` },
    { key: "investigating", label: `Investigating (${counts.investigating})` },
    { key: "resolved", label: `Resolved (${counts.resolved})` },
  ];

  const visibleIncidents = incidents.filter((i) =>
    tab === "all" ? true : incidentStatus(i.severity).toLowerCase() === tab,
  );

  const selected = selectedId
    ? (incidents.find((i) => i.incident_id === selectedId) ?? incidents[0])
    : null;
  const selectedEntity = selected
    ? (entities.find((e) => selected.entities_involved.includes(e.entity_id)) ?? entities[0])
    : null;

  const eventThread = selectedEntity
    ? timeline.filter(
        (e) =>
          e.entity_id === selectedEntity.entity_id ||
          e.display_name === selectedEntity.display_name ||
          e.display_name === selectedEntity.entity_id,
      )
    : timeline;

  const scoreBreakdown = selectedEntity
    ? (() => {
        const reasons = selectedEntity.top_risk_reasons;
        if (reasons.length === 0) return [];
        const weights = reasons.map((r) => {
          const l = r.toLowerCase();
          if (/lateral movement|privilege escalation|ransomware|malware/.test(l)) return 4;
          if (/critical asset|admin|c2|command|exfil/.test(l)) return 3;
          if (/outside hours|failed login|burst|anomal/.test(l)) return 2;
          return 1;
        });
        const totalW = weights.reduce((a, b) => a + b, 0);
        const pts = reasons.map((_, i) => Math.round((weights[i] / totalW) * selectedEntity.risk_score));
        const diff = selectedEntity.risk_score - pts.reduce((a, b) => a + b, 0);
        if (pts.length > 0) pts[0] += diff;
        return reasons.map((r, i) => ({ reason: r, pts: pts[i] }));
      })()
    : [];

  const statusBorderColor = (s: "Open" | "Investigating" | "Resolved") =>
    s === "Investigating" ? "#f97316" : s === "Resolved" ? "#22c55e" : "#ef4444";

  const eventDot = (sev: string) => {
    if (sev === "critical") return "bg-red-500";
    if (sev === "high") return "bg-orange-500";
    if (sev === "medium") return "bg-yellow-400";
    return "bg-zinc-600";
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-zinc-900 dark:text-zinc-100">Incident Timeline</h2>
        <p className="mt-0.5 text-xs" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
          <span className="text-[#00e5c8]">Real-time feed</span>
          <span className="text-zinc-700"> · </span>
          <span className={wsStatus === "connected" ? "text-[#00e5c8]" : "text-zinc-600"}>
            WebSocket {wsStatus === "connected" ? "connected" : wsStatus}
          </span>
          {entityFilter && (
            <>
              <span className="text-zinc-700"> · </span>
              <button type="button" onClick={() => onEntityFilterChange(null)} className="text-amber-400 hover:text-amber-300">
                Filtered: {entityFilter} ×
              </button>
            </>
          )}
        </p>
      </div>

      {/* Two-panel layout */}
      <div className="flex gap-4" style={{ minHeight: "560px" }}>

        {/* Left — incident list */}
        <div className="flex w-[44%] shrink-0 flex-col overflow-hidden rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)]">
          {/* Tabs */}
          <div className="flex shrink-0 border-b border-[var(--border-primary)] overflow-x-auto">
            {tabs.map(({ key, label }) => (
              <button
                key={key}
                type="button"
                onClick={() => setTab(key)}
                className={`shrink-0 border-b-2 px-4 py-3 text-xs font-medium whitespace-nowrap transition-colors -mb-px ${
                  tab === key
                    ? "border-[#00e5c8] text-[#00e5c8]"
                    : "border-transparent text-zinc-600 hover:text-zinc-700 dark:hover:text-zinc-300"
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {/* Cards */}
          <div className="flex-1 overflow-y-auto">
            {visibleIncidents.map((inc) => {
              const status = incidentStatus(inc.severity);
              const borderColor = statusBorderColor(status);
              const isSelected = inc.incident_id === selectedId;
              return (
                <button
                  key={inc.incident_id}
                  type="button"
                  onClick={() => setSelectedId(inc.incident_id)}
                  className={`w-full border-b border-[var(--border-subtle)] border-l-2 px-4 py-4 text-left transition-colors hover:bg-[var(--bg-hover)] ${
                    isSelected ? "bg-[var(--bg-elevated)]" : ""
                  }`}
                  style={{ borderLeftColor: borderColor }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-bold text-zinc-900 dark:text-zinc-100" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                      {inc.incident_id}
                    </span>
                    <span className="text-[10px] text-zinc-600">{formatTime(inc.last_seen_at)}</span>
                  </div>
                  <p className="mt-0.5 text-xs text-zinc-500">{inc.entities_involved[0] ?? "—"}</p>
                  <p className="mt-1 line-clamp-1 text-xs text-zinc-400">{inc.summary}</p>
                  <div className="mt-2.5 flex justify-end">
                    {status === "Resolved" ? (
                      <span className="text-[10px] font-semibold text-emerald-400">{status}</span>
                    ) : (
                      <span
                        className="rounded px-2 py-0.5 text-[10px] font-semibold text-white"
                        style={{ backgroundColor: borderColor }}
                      >
                        {status}
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right — detail panel */}
        {selected && selectedEntity && (
          <div className="flex flex-1 flex-col overflow-hidden rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)]">
            {/* Detail header */}
            <div className="shrink-0 border-b border-[var(--border-primary)] px-5 py-4">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-zinc-900 dark:text-zinc-100" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                  {selected.incident_id}
                </span>
                <span className="text-zinc-700">—</span>
                <span className={`text-xs font-bold uppercase ${
                  selected.severity === "critical" ? "text-red-400" :
                  selected.severity === "high" ? "text-orange-400" :
                  selected.severity === "medium" ? "text-yellow-400" : "text-emerald-400"
                }`}>
                  {selected.severity}
                </span>
              </div>
              <p className="mt-0.5 text-xs text-zinc-500">
                {selectedEntity.display_name} · {selectedEntity.top_risk_reasons.slice(0, 2).join(" + ")}
              </p>
            </div>

            <div className="flex-1 overflow-y-auto px-5 py-5 space-y-6">
              {/* Score + breakdown */}
              <div className="grid grid-cols-[auto_1fr] gap-6">
                <div>
                  <p className="mb-2 text-[9px] uppercase tracking-widest text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                    Vigil Score
                  </p>
                  <div className="flex items-baseline gap-1">
                    <span className="text-5xl font-black" style={{ color: bandColors[selectedEntity.risk_band] }}>
                      {selectedEntity.risk_score}
                    </span>
                    <span className="text-sm text-zinc-700">/100</span>
                  </div>
                </div>
                <div>
                  <p className="mb-2 text-[9px] uppercase tracking-widest text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                    Score Breakdown
                  </p>
                  <div className="space-y-1.5">
                    {scoreBreakdown.map(({ reason, pts }) => (
                      <div key={reason} className="flex items-center gap-3 text-xs">
                        <span className="w-8 shrink-0 font-mono font-semibold text-emerald-400">+{pts}</span>
                        <span className="text-zinc-400">{reason}</span>
                      </div>
                    ))}
                    <div className="flex items-center gap-3 border-t border-[var(--border-primary)] pt-1.5 text-xs">
                      <span className="w-8 shrink-0 font-mono font-semibold text-orange-400">= {selectedEntity.risk_score}</span>
                      <span className="text-zinc-700">(capped at 100)</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Event thread */}
              <div>
                <p className="mb-3 text-[9px] uppercase tracking-widest text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                  Event Thread
                </p>
                <div className="space-y-2.5">
                  {(eventThread.length > 0 ? eventThread : timeline).slice(0, 8).map((ev, i) => (
                    <div key={ev.event_id ?? i} className="flex items-start gap-3">
                      <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${eventDot(ev.severity)}`} />
                      <span className="w-14 shrink-0 text-[10px] font-mono text-zinc-600">
                        {formatTime(ev.event_time)}
                      </span>
                      <span className="text-xs text-zinc-700 dark:text-zinc-300">{ev.action}</span>
                    </div>
                  ))}
                  {timeline.length === 0 && (
                    <p className="text-xs text-zinc-700">No events in range.</p>
                  )}
                </div>
              </div>
            </div>

            {/* Action row */}
            {actionFeedback && (
              <div className="shrink-0 mx-5 mb-0 mt-2 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-700 px-3 py-2 text-xs font-medium text-emerald-700 dark:text-emerald-400 vigil-fadein">
                ✓ {actionFeedback}
              </div>
            )}
            <div className="shrink-0 flex items-center gap-2 border-t border-[var(--border-primary)] px-5 py-3">
              {actionedIds[selected.incident_id] === "acknowledged" ? (
                <div className="flex-1 rounded-lg bg-emerald-100 dark:bg-emerald-900/30 px-4 py-2 text-xs font-semibold text-emerald-700 dark:text-emerald-400 text-center">
                  ✓ Acknowledged
                </div>
              ) : actionedIds[selected.incident_id] === "escalated" ? null : (
                <button
                  type="button"
                  onClick={() => handleAction(selected.incident_id, "acknowledged")}
                  className="flex-1 rounded-lg bg-[#00e5c8] px-4 py-2 text-xs font-semibold text-[#04080f] transition-colors hover:bg-[#00f0d5]"
                >
                  Acknowledge
                </button>
              )}
              {actionedIds[selected.incident_id] === "escalated" ? (
                <div className="flex-1 rounded-lg bg-red-100 dark:bg-red-900/30 px-4 py-2 text-xs font-semibold text-red-700 dark:text-red-400 text-center">
                  ↑ Escalated
                </div>
              ) : actionedIds[selected.incident_id] === "acknowledged" ? null : (
                <button
                  type="button"
                  onClick={() => handleAction(selected.incident_id, "escalated")}
                  className="flex-1 rounded-lg bg-red-500 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-red-400"
                >
                  Escalate
                </button>
              )}
              <button
                type="button"
                onClick={() => setSelectedId(null)}
                className="rounded-lg border border-[var(--border-secondary)] px-4 py-2 text-xs font-medium text-zinc-600 transition-colors hover:text-zinc-700 dark:hover:text-zinc-300"
              >
                Dismiss
              </button>
            </div>
          </div>
        )}
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
  const [assignFeedback, setAssignFeedback] = useState<boolean>(false);
  const primaryEntity = entities.find((e) => data.triage.entities_involved.includes(e.entity_id)) ?? entities[0];

  const scoreBreakdown = primaryEntity
    ? (() => {
        const reasons = primaryEntity.top_risk_reasons;
        if (reasons.length === 0) return [];
        const weights = reasons.map((r) => {
          const l = r.toLowerCase();
          if (/lateral movement|privilege escalation|ransomware|malware/.test(l)) return 4;
          if (/critical asset|admin|c2|command|exfil/.test(l)) return 3;
          if (/outside hours|failed login|burst|anomal/.test(l)) return 2;
          return 1;
        });
        const totalW = weights.reduce((a, b) => a + b, 0);
        const pts = reasons.map((_, i) => Math.round((weights[i] / totalW) * primaryEntity.risk_score));
        const diff = primaryEntity.risk_score - pts.reduce((a, b) => a + b, 0);
        if (pts.length > 0) pts[0] += diff;
        return reasons.map((r, i) => ({ reason: r, pts: pts[i] }));
      })()
    : [];

  const maxPts = Math.max(...scoreBreakdown.map((s) => s.pts), 1);

  const ptColor = (pts: number) => {
    const ratio = pts / maxPts;
    if (ratio > 0.8) return { bar: "#ef4444", text: "text-red-400" };
    if (ratio > 0.5) return { bar: "#f97316", text: "text-orange-400" };
    return { bar: "#facc15", text: "text-yellow-400" };
  };

  const mockRules = data.triage.mitre_techniques.slice(0, 4).map((tech, i) => ({
    id: `RULE-0${i + 1}`,
    name: tech.toLowerCase().replace(/\s+/g, "_").replace(/[^a-z0-9_]/g, ""),
    pts: scoreBreakdown[i]?.pts ?? 10,
  }));

  const evidenceArtifacts = [
    { source: "URLhaus", detail: "Outbound IP matched active C2 record", color: "bg-emerald-400" },
    { source: "CISA KEV", detail: `CVE-2024-3400 on ${data.triage.target_assets[0] ?? "unknown"}`, color: "bg-red-400" },
    { source: "Security Events", detail: "Raw auth + access from soc_events", color: "bg-blue-400" },
    { source: "CrowdStrike", detail: "EDR malware alert #88441", color: "bg-violet-400" },
  ];

  const generatedAt = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-zinc-900 dark:text-zinc-100">Triage Report</h2>
        <p className="mt-0.5 text-xs text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
          {data.triage.incident_id} · Generated by ARIA · {generatedAt}
        </p>
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onViewTimeline}
          className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors"
        >
          <Activity className="h-3.5 w-3.5" />
          ← Back to Timeline
        </button>
        <div className="ml-auto flex items-center gap-2">
          {role.canAssign && (
            <select
              value={assignee}
              onChange={(e) => onAssigneeChange(e.target.value)}
              className="rounded-lg border border-[var(--border-secondary)] bg-[var(--bg-input)] px-3 py-2 text-xs text-zinc-400 outline-none"
            >
              {ANALYST_ROSTER.map((a) => <option key={a}>{a}</option>)}
            </select>
          )}
          <button
            type="button"
            className="flex items-center gap-1.5 rounded-lg border border-[var(--border-secondary)] bg-[var(--bg-input)] px-3 py-2 text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors"
          >
            <Download className="h-3.5 w-3.5" />
            Export PDF
          </button>
          {role.canChangeStatus && (
            <select
              value={incidentStatus}
              onChange={(e) => onIncidentStatusChange(e.target.value as IncidentStatus)}
              className={`rounded-lg border px-3 py-2 text-xs font-semibold outline-none ${incidentStatusClasses[incidentStatus]}`}
            >
              {(["Open", "Investigating", "Contained", "Resolved"] as IncidentStatus[]).map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          )}
          {role.canAssign && (
            assignFeedback ? (
              <div className="rounded-lg bg-emerald-100 dark:bg-emerald-900/30 px-4 py-2 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
                ✓ Assigned to L2 queue
              </div>
            ) : (
              <button
                type="button"
                onClick={() => {
                  setAssignFeedback(true);
                  setTimeout(() => setAssignFeedback(false), 3000);
                }}
                className="rounded-lg bg-[#00e5c8] px-4 py-2 text-xs font-semibold text-[#04080f] hover:bg-[#00f0d5] transition-colors"
              >
                Assign to L2 →
              </button>
            )
          )}
        </div>
      </div>

      {/* Two-column body */}
      <div className="grid gap-4 xl:grid-cols-[1fr_0.7fr]">

        {/* ── Left column ── */}
        <div className="space-y-4">

          {/* Entity Summary */}
          <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] p-5">
            <p className="mb-3 text-[9px] uppercase tracking-widest text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
              Entity Summary
            </p>
            {primaryEntity && (
              <>
                <h3 className="text-2xl font-black text-zinc-900 dark:text-zinc-100">{primaryEntity.display_name}</h3>
                <p className="mt-0.5 text-xs text-zinc-500">
                  {primaryEntity.entity_type.charAt(0).toUpperCase() + primaryEntity.entity_type.slice(1)} · {primaryEntity.entity_id}
                </p>
                <div className="mt-4 grid grid-cols-4 gap-3">
                  <div>
                    <p className="text-[10px] text-zinc-600">Vigil Score</p>
                    <p className={`mt-1 text-sm font-bold ${
                      primaryEntity.risk_band === "critical" ? "text-red-400" :
                      primaryEntity.risk_band === "high" ? "text-orange-400" :
                      primaryEntity.risk_band === "medium" ? "text-yellow-400" : "text-emerald-400"
                    }`}>
                      {primaryEntity.risk_score} / {primaryEntity.risk_band.toUpperCase()}
                    </p>
                  </div>
                  <div>
                    <p className="text-[10px] text-zinc-600">Last seen</p>
                    <p className="mt-1 text-sm font-semibold text-zinc-800 dark:text-zinc-200">{formatRelativeAge(primaryEntity.last_seen_at)}</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-zinc-600">Affected assets</p>
                    <p className="mt-1 text-sm font-semibold text-zinc-800 dark:text-zinc-200">{data.triage.target_assets.length}</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-zinc-600">Incidents</p>
                    <p className="mt-1 text-sm font-bold text-red-400">1 Open</p>
                  </div>
                </div>
              </>
            )}
          </div>

          {/* ARIA Score Breakdown */}
          <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] p-5">
            <p className="mb-4 text-[9px] uppercase tracking-widest text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
              ARIA Score Breakdown
            </p>
            <div className="space-y-3">
              {scoreBreakdown.map(({ reason, pts }) => {
                const { bar, text } = ptColor(pts);
                return (
                  <div key={reason} className="flex items-center gap-3">
                    <span className="w-40 shrink-0 text-xs text-zinc-400 truncate">{reason}</span>
                    <div className="flex-1 h-2 rounded-full bg-[var(--bg-subtle)] overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${(pts / maxPts) * 100}%`, backgroundColor: bar }} />
                    </div>
                    <span className={`w-10 shrink-0 text-right text-xs font-bold tabular-nums ${text}`}>+{pts}</span>
                  </div>
                );
              })}
              <div className="flex items-center justify-between border-t border-[var(--border-primary)] pt-2 text-xs">
                <span className="text-zinc-600">Total = {primaryEntity?.risk_score ?? 0} pts (capped at 100)</span>
              </div>
            </div>
          </div>

          {/* Triggered Detection Rules */}
          {mockRules.length > 0 && (
            <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] p-5">
              <p className="mb-4 text-[9px] uppercase tracking-widest text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                Triggered Detection Rules
              </p>
              <div className="space-y-0">
                {mockRules.map(({ id, name, pts }) => (
                  <div key={id} className="flex items-center gap-4 border-b border-[var(--border-subtle)] py-2.5 last:border-0">
                    <span className="w-16 shrink-0 text-[10px] text-zinc-700 font-mono">{id}</span>
                    <span className="flex-1 text-xs text-zinc-700 dark:text-zinc-300">{name}</span>
                    <span className="text-xs font-bold text-orange-400">{pts} pts</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── Right column ── */}
        <div className="space-y-4">

          {/* ARIA Narrative */}
          <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] p-5">
            <div className="mb-3 flex items-center justify-between">
              <p className="text-[9px] uppercase tracking-widest text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                ARIA Narrative
              </p>
              <span className="rounded border border-[#00e5c8]/30 bg-[#00e5c8]/10 px-2 py-0.5 text-[9px] font-semibold text-[#00e5c8]">
                AI Generated
              </span>
            </div>
            <p className="text-xs leading-5 text-zinc-700 dark:text-zinc-300">{data.triage.summary}</p>
            <p className="mt-2 text-xs leading-5 text-zinc-500">
              {data.triage.entities_involved.length} entities are involved. {data.triage.target_assets.length} systems are in scope.
            </p>
            <p className="mt-3 text-xs text-[#00e5c8]">
              ARIA confidence: HIGH · Recommend: Isolate + Escalate
            </p>
          </div>

          {/* Recommended Actions */}
          <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] p-5">
            <p className="mb-4 text-[9px] uppercase tracking-widest text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
              Recommended Actions
            </p>
            <div className="space-y-2.5">
              {data.triage.recommended_next_steps.slice(0, 5).map((step, i) => {
                const key = `${data.triage.incident_id}:${i}`;
                const done = completedSteps.includes(key);
                return (
                  <button
                    key={step}
                    type="button"
                    disabled={!role.canChangeStatus}
                    onClick={() => onToggleStep(data.triage.incident_id, i)}
                    className={`flex w-full items-start gap-3 text-left transition-opacity ${!role.canChangeStatus ? "cursor-default" : ""}`}
                  >
                    <span className={`flex h-5 w-5 shrink-0 items-center justify-center rounded text-[10px] font-bold ${
                      done ? "bg-emerald-500/20 text-emerald-400" : "bg-orange-500/20 text-orange-400"
                    }`}>
                      {i + 1}
                    </span>
                    <span className={`text-xs leading-5 ${done ? "text-zinc-600 line-through" : "text-zinc-700 dark:text-zinc-300"}`}>
                      {step}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Evidence Artifacts */}
          <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] p-5">
            <p className="mb-4 text-[9px] uppercase tracking-widest text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
              Evidence Artifacts
            </p>
            <div className="space-y-3">
              {evidenceArtifacts.map(({ source, detail, color }) => (
                <div key={source} className="flex items-start gap-3">
                  <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${color}`} />
                  <div className="min-w-0">
                    <span className="text-xs font-semibold text-zinc-700 dark:text-zinc-300">{source}</span>
                    <span className="ml-2 text-xs text-zinc-500">{detail}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="flex items-center gap-3 text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
        <span className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-[#00e5c8]" />
          ARIA Engine: Active
        </span>
        <span>· Report generated in 0.3s</span>
        <span>· ETag: {data.triage.incident_id.slice(-8).toLowerCase()}</span>
      </div>
    </div>
  );
}

const SUGGESTED_QUERY_ICONS: Record<string, string> = {
  critical_entities_now: "🔴",
  high_incidents_24h: "🟠",
  score_jump: "👤",
  c2_connections: "🌐",
  privilege_escalations: "🔑",
  exec_briefing: "📋",
  active_cves: "🛡️",
  pipeline_health: "📊",
};

function formatAriaAnswer(answer: QnaAnswer): string {
  if (answer.answer_rows.length === 0) return "No matching records in the current data window.";
  const rows = answer.answer_rows;
  return rows
    .map((row) =>
      Object.entries(row)
        .map(([k, v]) => `${k}: ${stringifyCellValue(v)}`)
        .join("  ·  "),
    )
    .join("\n");
}

function QnaView({ answers, templates }: { answers: QnaAnswer[]; templates: import("./types").QnaTemplate[] }) {
  const [activeId, setActiveId] = useState<string | null>(answers[0]?.question_id ?? null);
  const [inputValue, setInputValue] = useState("");
  const chatEndRef = useRef<HTMLDivElement>(null);

  const suggestedQueries = templates.length > 0 ? templates : answers.map((a) => ({ question_id: a.question_id, question: a.question }));

  const activeAnswers = activeId ? answers.filter((a) => a.question_id === activeId) : answers;

  const handleSelect = (id: string) => {
    setActiveId(id);
    setTimeout(() => chatEndRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
  };

  const timestamp = (offsetSec: number) => {
    const d = new Date(Date.now() - offsetSec * 1000);
    return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-zinc-900 dark:text-zinc-100">ARIA Q&A Assistant</h2>
        <p className="mt-0.5 text-xs text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
          Ask anything about your threat landscape · Context-aware · Powered by ARIA
        </p>
      </div>

      {/* Two-panel layout */}
      <div className="flex gap-4" style={{ height: "600px" }}>

        {/* Left — suggested queries */}
        <div className="flex w-72 shrink-0 flex-col rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] overflow-hidden">
          <div className="shrink-0 border-b border-[var(--border-primary)] px-4 py-3">
            <p className="text-xs font-semibold text-zinc-700 dark:text-zinc-300">Suggested Queries</p>
          </div>
          <div className="flex-1 overflow-y-auto p-2 space-y-1">
            {suggestedQueries.map((t) => (
              <button
                key={t.question_id}
                type="button"
                onClick={() => handleSelect(t.question_id)}
                className={`flex w-full items-start gap-2.5 rounded-lg px-3 py-3 text-left text-xs transition-colors ${
                  activeId === t.question_id
                    ? "bg-[var(--bg-elevated)] text-zinc-800 dark:text-zinc-200"
                    : "text-zinc-500 hover:bg-[var(--bg-hover)] hover:text-zinc-700 dark:hover:text-zinc-300"
                }`}
              >
                <span className="shrink-0 text-sm leading-4">
                  {SUGGESTED_QUERY_ICONS[t.question_id] ?? "💬"}
                </span>
                <span className="leading-4">{t.question}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Right — chat */}
        <div className="flex flex-1 flex-col overflow-hidden rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)]">
          {/* Chat header */}
          <div className="shrink-0 flex items-center justify-between border-b border-[var(--border-primary)] px-5 py-3">
            <p className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">ARIA Intelligence Chat</p>
            <div className="flex items-center gap-2">
              <span className="rounded border border-[var(--border-primary)] px-2 py-0.5 text-[10px] text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                ARIA v2
              </span>
              <span className="rounded border border-[#00e5c8]/30 bg-[#00e5c8]/10 px-2 py-0.5 text-[10px] font-semibold text-[#00e5c8]" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                RAG
              </span>
            </div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-5 py-5 space-y-6">
            {activeAnswers.map((answer, i) => (
              <div key={answer.question_id} className="space-y-4">
                {/* User bubble */}
                <div className="flex justify-end">
                  <div className="max-w-[70%]">
                    <div className="rounded-2xl rounded-tr-sm bg-[var(--bg-elevated)] px-4 py-3 text-sm text-zinc-800 dark:text-zinc-200">
                      {answer.question}
                    </div>
                    <p className="mt-1 text-right text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                      {timestamp(120 - i * 30)}
                    </p>
                  </div>
                </div>

                {/* ARIA response */}
                <div className="flex items-start gap-3">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-[#00e5c8]/20 text-xs font-bold text-[#00e5c8]">
                    A
                  </div>
                  <div className="min-w-0 flex-1">
                    {answer.answer_rows.length === 0 ? (
                      <p className="text-sm text-zinc-500">No matching records in the current data window.</p>
                    ) : (
                      <div className="rounded-2xl rounded-tl-sm border border-[var(--border-primary)] bg-[var(--bg-app)] px-4 py-3">
                        {/* Formatted rows */}
                        <div className="space-y-1 font-mono text-xs text-zinc-400" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                          {answer.answer_rows.slice(0, 6).map((row, ri) => (
                            <div key={ri} className="flex flex-wrap gap-x-4 gap-y-0.5">
                              {Object.entries(row).map(([k, v]) => (
                                <span key={k}>
                                  <span className="text-zinc-600">{k}:</span>{" "}
                                  <span className={
                                    k === "risk_band" && typeof v === "string"
                                      ? v === "critical" ? "text-red-400" : v === "high" ? "text-orange-400" : v === "medium" ? "text-yellow-400" : "text-emerald-400"
                                      : k === "risk_score" ? "text-orange-600 dark:text-orange-300" : "text-[#00b5a0] dark:text-[#00e5c8]"
                                  }>
                                    {stringifyCellValue(v)}
                                  </span>
                                </span>
                              ))}
                            </div>
                          ))}
                          {answer.answer_rows.length > 6 && (
                            <p className="text-zinc-700">+{answer.answer_rows.length - 6} more rows</p>
                          )}
                        </div>
                      </div>
                    )}
                    <div className="mt-1.5 flex items-center gap-3 text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                      <span>{timestamp(118 - i * 30)}</span>
                      <span>· Confidence: HIGH</span>
                      <span>· Sources: {Math.max(2, answer.answer_rows.length)}</span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
            <div ref={chatEndRef} />
          </div>

          {/* Input bar */}
          <div className="shrink-0 flex items-center gap-3 border-t border-[var(--border-primary)] px-4 py-3">
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && inputValue.trim()) setInputValue(""); }}
              placeholder="Ask ARIA about any entity, incident, or threat..."
              className="flex-1 bg-transparent text-sm text-zinc-700 dark:text-zinc-300 outline-none placeholder:text-zinc-700"
            />
            <button
              type="button"
              onClick={() => setInputValue("")}
              className="flex items-center gap-1.5 rounded-lg bg-[#00e5c8] px-4 py-2 text-xs font-semibold text-[#04080f] hover:bg-[#00f0d5] transition-colors"
            >
              Send ↑
            </button>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="flex items-center gap-4 text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
        <span className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-[#00e5c8]" />
          ARIA Q&A: Online
        </span>
        <span>· RAG index: 14,832 docs</span>
        <span>· Context: 42% used</span>
      </div>
    </div>
  );
}

function controlStatus(control: ComplianceControl): "PASS" | "FAIL" | "REVIEW" {
  if (control.evidence_count === 0) return "FAIL";
  if (control.evidence_count < 3) return "REVIEW";
  return "PASS";
}

function ComplianceView({ frameworks, canExport }: { frameworks: ComplianceResponse[]; canExport: boolean }) {
  const [activeFramework, setActiveFramework] = useState(frameworks[0]?.framework ?? "");

  const current = frameworks.find((f) => f.framework === activeFramework) ?? frameworks[0];
  const allControls = frameworks.flatMap((f) => f.controls);

  const passCount = (fw: ComplianceResponse) => fw.controls.filter((c) => controlStatus(c) === "PASS").length;
  const failCount = allControls.filter((c) => controlStatus(c) === "FAIL").length;
  const reviewCount = allControls.filter((c) => controlStatus(c) === "REVIEW").length;
  const totalEvidence = allControls.reduce((sum, c) => sum + c.evidence_count, 0);

  const pciFramework = frameworks.find((f) => f.framework.toUpperCase().includes("PCI"));
  const soc2Framework = frameworks.find((f) => f.framework.toUpperCase().includes("SOC"));

  // Generate live evidence feed from controls
  const EVENT_TYPES = ["AUTH_SUCCESS", "DATA_ACCESS", "PRIV_CHANGE", "NET_BLOCK", "AUTH_FAIL", "LOG_WRITE", "ALERT_GEN"];
  const SOURCES = ["j.morrison", "vendor-portal", "firewall-01", "svc-account", "siem-logger", "ARIA", "r.chen"];
  const liveFeed = allControls.slice(0, 8).map((c, i) => ({
    time: `09:${String(14 - i).padStart(2, "0")}`,
    event: EVENT_TYPES[i % EVENT_TYPES.length],
    req: c.control_id,
    source: SOURCES[i % SOURCES.length],
    dot: controlStatus(c) === "PASS" ? "bg-emerald-400" : controlStatus(c) === "FAIL" ? "bg-red-400" : "bg-yellow-400",
  }));

  return (
    <div className="flex flex-col gap-4">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-zinc-900 dark:text-zinc-100">Vigil Comply</h2>
        <p className="mt-0.5 text-xs text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
          {frameworks.map((f) => f.framework).join(" & ")} · Evidence auto-generated from live events
        </p>
      </div>

      {/* Tabs + Export */}
      <div className="flex items-center gap-0 border-b border-[var(--border-primary)]">
        {frameworks.map((f) => (
          <button
            key={f.framework}
            type="button"
            onClick={() => setActiveFramework(f.framework)}
            className={`border-b-2 px-5 py-2.5 text-xs font-medium transition-colors -mb-px ${
              activeFramework === f.framework
                ? "border-[#00e5c8] text-[#00e5c8]"
                : "border-transparent text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300"
            }`}
          >
            {f.framework}
          </button>
        ))}
        <div className="ml-auto pb-1">
          {canExport && (
            <button
              type="button"
              onClick={() => exportComplianceCsv(frameworks)}
              className="flex items-center gap-1.5 rounded-lg border border-[var(--border-secondary)] bg-[var(--bg-input)] px-3 py-2 text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors"
            >
              <Download className="h-3.5 w-3.5" />
              Export Evidence Pack
            </button>
          )}
        </div>
      </div>

      {/* 4 stat cards */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        {[
          {
            label: "PCI-DSS Controls",
            value: pciFramework ? `${passCount(pciFramework)} / ${pciFramework.controls.length}` : "—",
            sub: pciFramework ? `${Math.round((passCount(pciFramework) / Math.max(pciFramework.controls.length, 1)) * 100)}% compliant` : "",
            valueColor: "text-emerald-400",
            border: "border-t-emerald-700",
          },
          {
            label: "SOC 2 Controls",
            value: soc2Framework ? `${passCount(soc2Framework)} / ${soc2Framework.controls.length}` : "—",
            sub: soc2Framework ? `${Math.round((passCount(soc2Framework) / Math.max(soc2Framework.controls.length, 1)) * 100)}% compliant` : "",
            valueColor: "text-emerald-400",
            border: "border-t-emerald-700",
          },
          {
            label: "Open Findings",
            value: String(failCount + reviewCount),
            sub: `${failCount} Failed · ${reviewCount} Review`,
            valueColor: "text-orange-400",
            border: "border-t-orange-700",
          },
          {
            label: "Evidence Items",
            value: totalEvidence.toLocaleString(),
            sub: "Auto-generated",
            valueColor: "text-blue-400",
            border: "border-t-blue-700",
          },
        ].map(({ label, value, sub, valueColor, border }) => (
          <div key={label} className={`rounded-lg border-t-2 bg-[var(--bg-panel)] px-5 py-4 ${border}`} style={{ borderLeftColor: "transparent", borderRightColor: "transparent", borderBottomColor: "transparent" }}>
            <p className="text-xs text-zinc-500">{label}</p>
            <p className={`mt-2 text-2xl font-black ${valueColor}`}>{value}</p>
            <p className="mt-1 text-[10px] text-zinc-600">{sub}</p>
          </div>
        ))}
      </div>

      {/* Two-panel body */}
      <div className="flex gap-4" style={{ minHeight: "420px" }}>

        {/* Left — controls table */}
        <div className="flex flex-1 flex-col overflow-hidden rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)]">
          {current?.controls.length === 0 ? (
            <div className="flex flex-1 items-center justify-center text-sm text-zinc-600">
              No controls found for {activeFramework}.
            </div>
          ) : (
            <>
              {/* Table header */}
              <div
                className="grid shrink-0 border-b border-[var(--border-primary)] px-4 py-3 text-[10px] font-semibold uppercase tracking-widest text-zinc-600"
                style={{ gridTemplateColumns: "80px 1fr 90px 100px 60px", fontFamily: "'JetBrains Mono', monospace" }}
              >
                <span>REQ</span>
                <span>Control</span>
                <span>Status</span>
                <span>Last Check</span>
                <span className="text-right">EVD</span>
              </div>

              {/* Rows */}
              <div className="flex-1 overflow-y-auto">
                {current?.controls.map((control) => {
                  const status = controlStatus(control);
                  const statusStyle =
                    status === "PASS"
                      ? "bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-500/30"
                      : status === "FAIL"
                        ? "bg-red-500/20 text-red-700 dark:text-red-300 border-red-500/30"
                        : "bg-yellow-500/20 text-yellow-700 dark:text-yellow-200 border-yellow-500/30";
                  return (
                    <div
                      key={control.control_id}
                      className="grid items-center border-b border-[var(--border-subtle)] px-4 py-3 last:border-0 hover:bg-[var(--bg-hover)] transition-colors"
                      style={{ gridTemplateColumns: "80px 1fr 90px 100px 60px" }}
                    >
                      <span className="text-xs font-semibold text-[#00e5c8]" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                        {control.control_id}
                      </span>
                      <span className="pr-4 text-xs text-zinc-700 dark:text-zinc-300">{control.control_name}</span>
                      <span className={`inline-flex w-fit items-center rounded border px-2 py-0.5 text-[10px] font-bold ${statusStyle}`}>
                        {status}
                      </span>
                      <span className="text-xs text-zinc-500">{formatRelativeAge(control.latest_evidence_at)}</span>
                      <span className="text-right text-xs font-semibold text-[#00e5c8]">{control.evidence_count}</span>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>

        {/* Right — live evidence feed */}
        <div className="flex w-72 shrink-0 flex-col overflow-hidden rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)]">
          <div className="shrink-0 border-b border-[var(--border-primary)] px-4 py-3">
            <p className="text-xs font-semibold text-zinc-700 dark:text-zinc-300">Live Evidence Feed</p>
          </div>
          <div className="flex-1 overflow-y-auto">
            {liveFeed.map((item, i) => (
              <div key={i} className="flex items-start gap-3 border-b border-[var(--border-subtle)] px-4 py-3 last:border-0">
                <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${item.dot}`} />
                <div className="min-w-0">
                  <div className="flex items-baseline gap-2">
                    <span className="text-[10px] text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                      {item.time}
                    </span>
                    <span className="text-xs font-semibold text-zinc-700 dark:text-zinc-300" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                      {item.event}
                    </span>
                  </div>
                  <p className="mt-0.5 text-[10px] text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                    REQ {item.req} · {item.source}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="flex items-center gap-4 text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
        {pciFramework && (
          <span>PCI-DSS {Math.round((passCount(pciFramework) / Math.max(pciFramework.controls.length, 1)) * 100)}%</span>
        )}
        {soc2Framework && (
          <span>· SOC 2 {Math.round((passCount(soc2Framework) / Math.max(soc2Framework.controls.length, 1)) * 100)}%</span>
        )}
        <span>· Next audit: 2026-07-01</span>
      </div>
    </div>
  );
}

function PipelineHealthView() {
  const services = [
    { name: "Redpanda",      role: "Kafka broker",    status: "healthy", metric: "8,412 msg/s" },
    { name: "MinIO",         role: "Object lake",     status: "healthy", metric: "2.4 TB" },
    { name: "PostgreSQL",    role: "Warehouse",       status: "healthy", metric: "142 entities" },
    { name: "dbt Core",      role: "Transforms",      status: "healthy", metric: "Last: 2m ago" },
    { name: "Prefect",       role: "Orchestration",   status: "warning", metric: "1 flow paused" },
    { name: "FastAPI",       role: "REST + WS",       status: "healthy", metric: "23 routes up" },
    { name: "Prometheus",    role: "Scraper",         status: "healthy", metric: "142 targets" },
    { name: "Alertmanager",  role: "Routing",         status: "healthy", metric: "0 active" },
  ] as const;

  const slos = [
    { label: "API Availability",   target: "≤99.9%",    actual: "99.94%",  pass: true },
    { label: "Pipeline Freshness", target: "≤5min lag", actual: "0.8s avg", pass: true },
    { label: "Scoring Latency",    target: "<2s p95",   actual: "1.4s p95", pass: true },
    { label: "Stream Uptime",      target: "99.5%",     actual: "99.5%",    pass: true },
    { label: "ETL Run Success",    target: ">98%",      actual: "97.1%",    pass: false },
  ];

  const throughput = [
    { t: "08:00", v: 4200 }, { t: "08:06", v: 5800 }, { t: "08:12", v: 7100 },
    { t: "08:18", v: 8900 }, { t: "08:24", v: 11204 },{ t: "08:30", v: 9600 },
    { t: "08:36", v: 8800 }, { t: "08:42", v: 9200 }, { t: "08:48", v: 8700 },
    { t: "08:54", v: 9100 }, { t: "09:00", v: 8412 },
  ];

  const pipelineRuns = [
    { name: "kev_batch_ingest",      time: "09:10", dur: "42s",  status: "Success" },
    { name: "urlhaus_stream_tick",   time: "09:15", dur: "1.2s", status: "Success" },
    { name: "soc_events_score",      time: "09:14", dur: "3.8s", status: "Success" },
    { name: "dbt_transform_mart",    time: "09:13", dur: "18s",  status: "Success" },
    { name: "prefect_health_check",  time: "09:12", dur: "—",    status: "Paused"  },
  ];

  const portMap = [
    ["PostgreSQL", ":5432",  "MinIO",      ":9000"],
    ["Redpanda",   ":19092", "Prefect",    ":4200"],
    ["Console",    ":8080",  "Prometheus", ":9090"],
    ["FastAPI",    ":8000",  "Grafana",    ":3001"],
  ];

  const topics = [
    { name: "soc-events-raw",   lag: 0, throughput: "4,120/s" },
    { name: "urlhaus-stream",   lag: 0, throughput: "812/s" },
    { name: "kev-updates",      lag: 0, throughput: "batch" },
    { name: "vigil-alerts",     lag: 2, throughput: "41/s" },
  ];

  const alertLog = [
    { time: "09:08", msg: "Malware alert: 10.14.2.88 (severity: page)", dot: "bg-red-500" },
    { time: "09:05", msg: "Vigil Score > 80: j.morrison",               dot: "bg-orange-400" },
    { time: "08:58", msg: "Login burst: j.morrison",                    dot: "bg-yellow-400" },
    { time: "08:44", msg: "Prefect flow health_check paused",           dot: "bg-yellow-400" },
  ];

  const passingSlos = slos.filter((s) => s.pass).length;

  return (
    <div className="flex flex-col gap-4">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-zinc-900 dark:text-zinc-100">Pipeline Health</h2>
        <p className="mt-0.5 text-xs text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
          Prometheus + Grafana · SLO tracking · Real-time observability
        </p>
      </div>

      {/* Service status bar */}
      <div className="grid grid-cols-4 gap-3 xl:grid-cols-8">
        {services.map((svc) => (
          <div
            key={svc.name}
            className={`rounded-lg border-t-2 bg-[var(--bg-panel)] px-3 py-3 ${
              svc.status === "warning" ? "border-t-amber-500" : "border-t-emerald-600"
            }`}
            style={{ borderLeftColor: "transparent", borderRightColor: "transparent", borderBottomColor: "transparent" }}
          >
            <p className="text-xs font-semibold text-zinc-800 dark:text-zinc-200">{svc.name}</p>
            <p className="mt-0.5 text-[10px] text-zinc-600">{svc.role}</p>
            <p className={`mt-2 flex items-center gap-1 text-[10px] font-semibold ${svc.status === "warning" ? "text-amber-400" : "text-emerald-400"}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${svc.status === "warning" ? "bg-amber-400" : "bg-emerald-400"}`} />
              {svc.status === "warning" ? "Warning" : "Healthy"}
            </p>
            <p className="mt-1 text-[10px] text-zinc-600">{svc.metric}</p>
          </div>
        ))}
      </div>

      {/* 3-column body */}
      <div className="grid gap-4 xl:grid-cols-[1fr_1.2fr_1fr]">

        {/* Left col */}
        <div className="space-y-4">
          {/* SLO Status */}
          <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] px-5 py-4">
            <p className="mb-4 text-sm font-semibold text-zinc-800 dark:text-zinc-200">
              SLO Status <span className="ml-2 text-xs font-normal text-zinc-600">· 30 days</span>
            </p>
            <div className="space-y-0">
              {slos.map(({ label, target, actual, pass }) => (
                <div key={label} className="grid grid-cols-[1fr_auto_auto] items-center gap-4 border-b border-[var(--border-subtle)] py-2.5 last:border-0">
                  <span className="text-xs text-zinc-400">{label}</span>
                  <span className="text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>{target}</span>
                  <span className={`text-xs font-bold tabular-nums ${pass ? "text-emerald-400" : "text-amber-400"}`}>
                    {actual}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Service Port Map */}
          <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] px-5 py-4">
            <p className="mb-4 text-sm font-semibold text-zinc-800 dark:text-zinc-200">Service Port Map</p>
            <div className="space-y-2">
              {portMap.map(([svcA, portA, svcB, portB], i) => (
                <div key={i} className="grid grid-cols-2 gap-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-400">{svcA}</span>
                    <span className="font-mono text-[#00e5c8]">{portA}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-400">{svcB}</span>
                    <span className="font-mono text-[#00e5c8]">{portB}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Center col */}
        <div className="space-y-4">
          {/* Throughput chart */}
          <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] px-5 py-4">
            <p className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">
              Event Throughput
              <span className="ml-2 text-xs font-normal text-zinc-600">last 60 min</span>
            </p>
            <p className="mt-0.5 text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>msg/s</p>
            <div className="mt-3 h-40">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={throughput} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                  <XAxis dataKey="t" tick={{ fontSize: 9, fill: "#52525b", fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: "#080e16", border: "1px solid #111c2a", borderRadius: 6, fontSize: 11 }}
                    labelStyle={{ color: "#71717a" }}
                    itemStyle={{ color: "#00e5c8" }}
                  />
                  <Bar dataKey="v" fill="#00e5c8" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <p className="mt-2 text-[10px]" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
              <span className="text-[#00e5c8]">Current: 8,412 msg/s</span>
              <span className="text-zinc-700"> · </span>
              <span className="text-zinc-500">Peak: 11,204</span>
            </p>
          </div>

          {/* Redpanda Topics */}
          <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] px-5 py-4">
            <p className="mb-4 text-sm font-semibold text-zinc-800 dark:text-zinc-200">Redpanda Topics</p>
            <div className="space-y-0">
              <div className="grid grid-cols-[1fr_60px_100px] border-b border-[var(--border-primary)] pb-2 text-[10px] font-semibold uppercase tracking-widest text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                <span>Topic</span>
                <span className="text-right">Lag</span>
                <span className="text-right">Throughput</span>
              </div>
              {topics.map(({ name, lag, throughput: tp }) => (
                <div key={name} className="grid grid-cols-[1fr_60px_100px] items-center border-b border-[var(--border-subtle)] py-2.5 last:border-0">
                  <span className="text-xs text-zinc-700 dark:text-zinc-300" style={{ fontFamily: "'JetBrains Mono', monospace" }}>{name}</span>
                  <span className={`text-right text-xs font-bold ${lag > 0 ? "text-orange-400" : "text-emerald-400"}`}>{lag}</span>
                  <span className="text-right text-xs text-zinc-500">{tp}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right col */}
        <div className="space-y-4">
          {/* Recent Pipeline Runs */}
          <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] px-5 py-4">
            <p className="mb-4 text-sm font-semibold text-zinc-800 dark:text-zinc-200">Recent Pipeline Runs</p>
            <div className="space-y-0">
              {pipelineRuns.map(({ name, time, dur, status }) => (
                <div key={name} className="flex items-center gap-3 border-b border-[var(--border-subtle)] py-2.5 last:border-0">
                  <span className={`h-2 w-2 shrink-0 rounded-full ${status === "Success" ? "bg-emerald-400" : "bg-amber-400"}`} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-xs text-zinc-700 dark:text-zinc-300" style={{ fontFamily: "'JetBrains Mono', monospace" }}>{name}</p>
                    <p className="text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>{time} · {dur}</p>
                  </div>
                  <span className={`shrink-0 text-[10px] font-semibold ${status === "Success" ? "text-emerald-400" : "text-amber-400"}`}>
                    {status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Alert Log */}
          <div className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-panel)] px-5 py-4">
            <div className="mb-4 flex items-baseline justify-between">
              <p className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">Alert Log</p>
              <span className="text-[10px] text-zinc-600" style={{ fontFamily: "'JetBrains Mono', monospace" }}>Alertmanager · last 1 hour</span>
            </div>
            <div className="space-y-3">
              {alertLog.map(({ time, msg, dot }, i) => (
                <div key={i} className="flex items-start gap-2.5">
                  <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${dot}`} />
                  <div className="min-w-0">
                    <p className="text-xs text-zinc-700 dark:text-zinc-300">{msg}</p>
                    <p className="text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>{time}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="flex items-center gap-4 text-[10px] text-zinc-700" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
        <span className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
          All systems operational
        </span>
        <span>· SLOs: {passingSlos}/{slos.length} green</span>
        <span>· Prometheus: 142/142 targets up</span>
      </div>
    </div>
  );
}

function MiniTimeline({ events }: { events: TimelineEvent[] }) {
  return (
    <div className="mt-4 space-y-3">
      {events.slice(0, 5).map((event, index) => (
        <div key={event.event_id ?? `${event.event_time}-${index}`} className="grid grid-cols-[84px_1fr_auto] items-center gap-3 rounded-md border border-zinc-800 bg-[var(--bg-elevated)] px-3 py-2">
          <span className="text-xs text-zinc-500">{formatTime(event.event_time)}</span>
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-zinc-800 dark:text-zinc-200">{event.action}</p>
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
    red: "bg-red-500/15 text-red-700 dark:text-red-300",
    orange: "bg-orange-500/15 text-orange-700 dark:text-orange-300",
    cyan: "bg-cyan-500/15 text-cyan-700 dark:text-cyan-300",
  }[tone];
  return (
    <div className="rounded-md border border-zinc-800 bg-[var(--bg-elevated)] p-4">
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
      <dd className="mt-1 text-sm leading-6 text-zinc-700 dark:text-zinc-300">{value}</dd>
    </div>
  );
}

function ArrayCell({ values }: { values: unknown[] }) {
  return (
    <div className="flex max-w-xl flex-wrap gap-1.5">
      {values.map((value, index) => (
        <span key={`${String(value)}-${index}`} className="rounded-md border border-zinc-700 bg-[var(--bg-elevated)] px-2 py-1 text-xs leading-5 text-zinc-700 dark:text-zinc-300">
          {stringifyCellValue(value)}
        </span>
      ))}
    </div>
  );
}

function Sparkline({ values, color }: { values: number[]; color: string }) {
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = Math.max(max - min, 1);
  const w = 64, h = 28;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - ((v - min) / range) * h;
    return `${x},${y}`;
  }).join(" ");
  const fill = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - ((v - min) / range) * h;
    return `${x},${y}`;
  });
  const areaPath = `M0,${h} L${fill.join(" L")} L${w},${h} Z`;
  return (
    <svg width={w} height={h} className="shrink-0 overflow-visible" style={{ opacity: 0.7 }}>
      <defs>
        <linearGradient id={`sg-${color.replace("#","")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={0.3} />
          <stop offset="100%" stopColor={color} stopOpacity={0} />
        </linearGradient>
      </defs>
      <path d={areaPath} fill={`url(#sg-${color.replace("#","")})`} />
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={fill[fill.length - 1].split(",")[0]} cy={fill[fill.length - 1].split(",")[1]} r={2.5} fill={color} />
    </svg>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="mt-4 rounded-md border border-zinc-800 bg-[var(--bg-elevated)] px-4 py-5 text-sm text-zinc-400">
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
    return <span className="font-mono text-xs text-zinc-700 dark:text-zinc-300">{stringifyCellValue(value)}</span>;
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
