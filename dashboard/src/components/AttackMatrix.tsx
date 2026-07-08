import type { TechniqueStat } from "../types";
import { coveredTactics, TECHNIQUES, techniquesForTactic } from "../attack";

interface Props {
  byTechnique: TechniqueStat[];
  selected?: string;
  onSelect: (technique: string | undefined) => void;
}

/** Heat class from alert count relative to the busiest technique. */
function heat(count: number, max: number): string {
  if (count <= 0) return "cell heat-0";
  const r = count / (max || 1);
  if (r > 0.66) return "cell heat-3";
  if (r > 0.33) return "cell heat-2";
  return "cell heat-1";
}

export function AttackMatrix({ byTechnique, selected, onSelect }: Props) {
  const stat = new Map(byTechnique.map((t) => [t.id, t]));
  const max = byTechnique.reduce((m, t) => Math.max(m, t.count), 0);
  const tactics = coveredTactics();

  return (
    <div className="matrix">
      {tactics.map((tactic) => (
        <div className="matrix-col" key={tactic}>
          <div className="matrix-head">{tactic}</div>
          {techniquesForTactic(tactic).map((id) => {
            const s = stat.get(id);
            const count = s?.count ?? 0;
            const isSel = selected === id;
            return (
              <button
                key={id}
                className={`${heat(count, max)}${isSel ? " selected" : ""}`}
                title={`${id} ${TECHNIQUES[id]?.name ?? ""} — ${count} alerts` +
                  (s ? `, max level ${s.maxLevel}` : "")}
                onClick={() => onSelect(isSel ? undefined : id)}
              >
                <span className="cell-id">{id}</span>
                <span className="cell-name">{TECHNIQUES[id]?.name ?? ""}</span>
                <span className="cell-count">{count}</span>
              </button>
            );
          })}
        </div>
      ))}
    </div>
  );
}
