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

export interface TriageState {
  status: TriageStatus;
  assignee: string | null;
  note: string;
  updatedBy: string;
  updatedAt: string;
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
}

export interface TechniqueStat {
  id: string;
  count: number;
  maxLevel: number;
  tactic: string | null;
}

export interface Stats {
  total: number;
  byLevel: { level: number; count: number }[];
  byTechnique: TechniqueStat[];
  overTime: { t: number; count: number }[];
}

export interface Filters {
  range: string;
  technique?: string;
  minLevel?: number;
  host?: string;
  search?: string;
}
