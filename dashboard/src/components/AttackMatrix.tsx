import type { Coverage, CoverageState, CoveringRule, TechniqueStat } from "../types";
import { coveredTactics, TECHNIQUES, techniquesForTactic } from "../attack";

interface Props {
  byTechnique: TechniqueStat[];
  selected?: string;
  onSelect: (technique: string | undefined) => void;
  /** Which techniques our own ruleset covers. Absent = coverage unknown. */
  coverage?: Coverage;
}

/** Heat class from alert count relative to the busiest technique. */
function heat(count: number, max: number): string {
  if (count <= 0) return "heat-0";
  const r = count / (max || 1);
  if (r > 0.66) return "heat-3";
  if (r > 0.33) return "heat-2";
  return "heat-1";
}

/**
 * Coverage and activity are independent axes. Reading alert volume as coverage
 * is how a SOC convinces itself it is covered when it is not — a technique with
 * no rule and one with a rule that simply never fired both show zero.
 */
function coverageOf(rules: CoveringRule[] | undefined, count: number, known: boolean): CoverageState {
  if (!known) return "unknown";
  if (rules && rules.length > 0) return count > 0 ? "active" : "quiet";
  return count > 0 ? "vendor" : "gap";
}

const LABEL: Record<CoverageState, string> = {
  active: "covered by our rules, and firing",
  quiet: "covered by our rules — no alerts in this window, which is not a gap",
  vendor: "no rule of ours — these alerts came from the built-in ruleset",
  gap: "no detection and no alerts — a blind spot",
  unknown: "coverage unknown (the ruleset could not be read)",
};

const LEGEND: { state: CoverageState; text: string }[] = [
  { state: "active", text: "covered · firing" },
  { state: "quiet", text: "covered · quiet" },
  { state: "vendor", text: "vendor rules only" },
  { state: "gap", text: "blind spot" },
];

export function AttackMatrix({ byTechnique, selected, onSelect, coverage }: Props) {
  const stat = new Map(byTechnique.map((t) => [t.id, t]));
  const max = byTechnique.reduce((m, t) => Math.max(m, t.count), 0);
  const tactics = coveredTactics();
  // A failed read must not masquerade as "nothing is covered".
  const known = Boolean(coverage && !coverage.error);

  const tally = { active: 0, quiet: 0, vendor: 0, gap: 0, unknown: 0 };
  for (const id of Object.keys(TECHNIQUES)) {
    tally[coverageOf(coverage?.byTechnique?.[id], stat.get(id)?.count ?? 0, known)] += 1;
  }

  // Rules mapped to techniques the matrix does not draw — real coverage that
  // would otherwise be invisible here.
  const offMatrix = Object.keys(coverage?.byTechnique ?? {})
    .filter((t) => !TECHNIQUES[t]);

  return (
    <>
      <div className="matrix">
        {tactics.map((tactic) => (
          <div className="matrix-col" key={tactic}>
            <div className="matrix-head">{tactic}</div>
            {techniquesForTactic(tactic).map((id) => {
              const s = stat.get(id);
              const count = s?.count ?? 0;
              const rules = coverage?.byTechnique?.[id];
              const cov = coverageOf(rules, count, known);
              const isSel = selected === id;
              return (
                <button
                  key={id}
                  className={`cell ${heat(count, max)} cov-${cov}${isSel ? " selected" : ""}`}
                  title={`${id} ${TECHNIQUES[id]?.name ?? ""} — ${count} alerts` +
                    (s ? `, max level ${s.maxLevel}` : "") +
                    `\n${LABEL[cov]}` +
                    (rules?.length
                      ? `\nour rules: ${rules.map((r) => `${r.id} (level ${r.level})`).join(", ")}`
                      : "")}
                  onClick={() => onSelect(isSel ? undefined : id)}
                >
                  <span className="cell-id">{id}</span>
                  <span className="cell-name">{TECHNIQUES[id]?.name ?? ""}</span>
                  <span className="cell-count">{count}</span>
                  {rules?.length ? (
                    <span className="cell-cov" aria-label={`${rules.length} custom rules`}>
                      {rules.length}★
                    </span>
                  ) : null}
                </button>
              );
            })}
          </div>
        ))}
      </div>

      <div className="matrix-legend">
        {LEGEND.map((l) => (
          <span key={l.state} className="legend-item">
            <span className={`legend-swatch cov-${l.state}`} /> {l.text}
            <span className="muted"> ({tally[l.state]})</span>
          </span>
        ))}
        <span className="legend-note">
          {!known
            ? `Coverage unknown — ${coverage?.error ?? "ruleset not loaded"}. Cells show alert volume only.`
            : `★ = detections of our own mapped to that technique. ` +
              `${coverage?.detectionCount ?? 0} custom detections, ${coverage?.mappedRuleCount ?? 0} ATT&CK-mapped.` +
              (offMatrix.length
                ? ` ${offMatrix.length} mapped technique(s) not drawn here: ${offMatrix.join(", ")}.`
                : "")}
        </span>
      </div>
    </>
  );
}
