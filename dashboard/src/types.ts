export interface RuleMitre {
  id?: string[];
  tactic?: string[];
  technique?: string[];
}

export interface AlertSource {
  timestamp: string;
  rule: {
    id: string;
    level: number;
    description: string;
    groups?: string[];
    mitre?: RuleMitre;
  };
  agent?: { name?: string; ip?: string };
  location?: string;
  full_log?: string;
  data?: Record<string, unknown>;
  decoder?: { name?: string };
}

export type Role = "viewer" | "analyst" | "admin";
export type TriageStatus = "new" | "acknowledged" | "investigating" | "closed";

export type AiVerdict = "agree" | "disagree";

export interface TriageState {
  status: TriageStatus;
  assignee: string | null;
  note: string;
  /** The human's judgement of the AI finding (null = not yet judged). */
  aiVerdict: AiVerdict | null;
  updatedBy: string;
  updatedAt: string;
}

/** Advisory AI output. Never carries workflow state — see server/analysis.js. */
export interface AiFinding {
  flagged: boolean;
  score: number;
  /** 1 = investigate first. */
  priority: number;
  /** Deterministic, auditable factors behind the score. */
  reasons: string[];
  /** Optional LLM prose. Unverified — shown labelled as such. */
  summary: string | null;
  summaryModel: string | null;
  at: string;
  by: string;
}

export interface AnalysisConfig {
  minLevel: number;
  threshold: number;
  llmEnabled: boolean;
  llmModel: string | null;
}

export interface AnalysisRun {
  considered: number;
  flagged: number;
  minLevel: number;
  threshold: number;
  llm: boolean;
  at: string;
}

export interface Session {
  user: string;
  role: Role;
}

export interface AuditEvent {
  ts: string;
  action: string;
  user?: string;
  role?: string;
  alertId?: string;
  status?: string;
  assignee?: string | null;
  ip?: string;
}

export interface Alert {
  id: string;
  source: AlertSource;
  triage?: TriageState | null;
  ai?: AiFinding | null;
}

export interface TechniqueStat {
  id: string;
  count: number;
  maxLevel: number;
  tactic: string | null;
}

export interface AgentStat {
  name: string;
  count: number;
  maxLevel: number;
  /** Timestamp of this host's most recent ALERT — not a connectivity signal. */
  lastSeen: string | null;
}

export interface Stats {
  total: number;
  byLevel: { level: number; count: number }[];
  byTechnique: TechniqueStat[];
  overTime: { t: number; count: number }[];
  byAgent: AgentStat[];
  triageCounts: Record<TriageStatus, number>;
}

export interface Filters {
  range: string;
  technique?: string;
  minLevel?: number;
  host?: string;
  search?: string;
}
