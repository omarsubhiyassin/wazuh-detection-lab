// Static MITRE ATT&CK reference for the techniques this lab covers. The matrix
// places each technique in its tactic column per the framework (not per data),
// which is how ATT&CK Navigator represents coverage. Extend as scenarios grow.

export const TACTIC_ORDER = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
] as const;

export type Tactic = (typeof TACTIC_ORDER)[number];

export interface TechDef {
  name: string;
  tactics: Tactic[];
}

export const TECHNIQUES: Record<string, TechDef> = {
  T1110: { name: "Brute Force", tactics: ["Credential Access"] },
  T1078: { name: "Valid Accounts", tactics: ["Initial Access"] },
  "T1059.001": { name: "PowerShell", tactics: ["Execution"] },
  "T1053.005": { name: "Scheduled Task", tactics: ["Persistence"] },
  "T1071.004": { name: "DNS", tactics: ["Command and Control"] },
  T1105: { name: "Ingress Tool Transfer", tactics: ["Command and Control"] },
};

/** Tactics that contain at least one known technique, in canonical order. */
export function coveredTactics(): Tactic[] {
  const present = new Set<Tactic>();
  for (const def of Object.values(TECHNIQUES)) def.tactics.forEach((t) => present.add(t));
  return TACTIC_ORDER.filter((t) => present.has(t));
}

/** Technique IDs mapped into a given tactic column, in a stable order. */
export function techniquesForTactic(tactic: Tactic): string[] {
  return Object.entries(TECHNIQUES)
    .filter(([, def]) => def.tactics.includes(tactic))
    .map(([id]) => id)
    .sort();
}
