export type RiskBand = "low" | "medium" | "high" | "critical";

export interface RiskEntity {
  entity_id: string;
  entity_type: string;
  display_name: string;
  risk_score: number;
  risk_band: RiskBand;
  last_seen_at: string | null;
  top_risk_reasons: string[];
  recommended_action: string;
}

export interface Incident {
  incident_id: string;
  severity: RiskBand;
  summary: string;
  started_at: string | null;
  last_seen_at: string | null;
  entities_involved: string[];
  target_assets: string[];
  mitre_techniques: string[];
}

export interface TimelineEvent {
  event_id: string;
  event_time: string | null;
  source_system: string;
  event_type: string;
  entity_id?: string | null;
  display_name?: string | null;
  action: string;
  severity: string;
  asset?: string | null;
  asset_id: string | null;
  asset_name?: string | null;
  src_ip: string | null;
  dest_ip: string | null;
  mitre_technique: string | null;
  rule_explanation?: string | null;
}

export interface TriageReport {
  incident_id: string;
  severity: RiskBand;
  summary: string;
  target_assets: string[];
  entities_involved: string[];
  timeline: TimelineEvent[];
  mitre_techniques: string[];
  evidence: {
    event_count: number;
    lineage: string;
  };
  recommended_next_steps: string[];
}

export interface QnaTemplate {
  question_id: string;
  question: string;
}

export interface QnaAnswer {
  question_id: string;
  question: string;
  answer_rows: Record<string, unknown>[];
}

export interface ComplianceControl {
  framework: string;
  control_id: string;
  control_name: string;
  evidence_count: number;
  latest_evidence_at: string | null;
  lineage: string;
}

export interface ComplianceResponse {
  framework: string;
  controls: ComplianceControl[];
}

export interface SocData {
  entities: RiskEntity[];
  incidents: Incident[];
  triage: TriageReport;
  qnaTemplates: QnaTemplate[];
  qnaAnswers: QnaAnswer[];
  compliance: ComplianceResponse[];
}

export interface SocLoadResult {
  data: SocData;
  source: "live" | "fallback";
  errorMessage?: string;
}
