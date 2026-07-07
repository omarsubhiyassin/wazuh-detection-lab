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

export interface Alert {
  id: string;
  source: AlertSource;
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
