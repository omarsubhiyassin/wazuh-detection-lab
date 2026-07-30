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

/**
 * How an investigation ended. "false-positive" blames the RULE (it fired on
 * something it does not describe); "benign" means the rule was right and the
 * activity was authorized. Required to close.
 */
export type Disposition = "true-positive" | "false-positive" | "benign";

/** Durable alert facts denormalized onto the triage record for metrics. */
export interface AlertContext {
  ruleId: string | null;
  ruleLevel: number | null;
  description: string | null;
  host: string | null;
  alertTs: string | null;
}

export interface TriageState {
  status: TriageStatus;
  assignee: string | null;
  note: string;
  /** The human's judgement of the AI finding (null = not yet judged). */
  aiVerdict: AiVerdict | null;
  disposition: Disposition | null;
  context: AlertContext | null;
  updatedBy: string;
  updatedAt: string;
  firstTouchedAt: string;
}

/** Advisory AI output. Never carries workflow state — see server/analysis.js. */
export interface AiFinding {
  flagged: boolean;
  score: number;
  /** 1 = investigate first. */
  priority: number;
  /** How many alerts this one queue item stands for (same rule + host). */
  occurrences: number;
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
  /** Alerts over the threshold before same-rule/same-host grouping. */
  matched: number;
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

// --- Detection efficacy metrics ---------------------------------------------

export interface RuleEfficacy {
  ruleId: string;
  ruleLevel: number | null;
  description: string | null;
  triaged: number;
  closed: number;
  truePositive: number;
  falsePositive: number;
  benign: number;
  agreed: number;
  disagreed: number;
  /** null until something has been closed — never a misleading 0%. */
  falsePositiveRate: number | null;
  benignRate: number | null;
  precision: number | null;
  medianTimeToCloseMs: number | null;
}

export interface Metrics {
  totals: {
    triaged: number;
    closed: number;
    open: number;
    /** Records with no rule attribution (written before context was stamped). */
    unattributed: number;
    dispositions: Record<Disposition, number>;
  };
  scorer: {
    judged: number;
    agreed: number;
    disagreed: number;
    agreementRate: number | null;
  };
  timing: {
    medianTimeToFirstTouchMs: number | null;
    medianTimeToCloseMs: number | null;
    sampled: number;
  };
  rules: RuleEfficacy[];
  analysts: { user: string; closed: number }[];
  generatedAt: string;
}

export interface Filters {
  range: string;
  technique?: string;
  minLevel?: number;
  host?: string;
  search?: string;
}
