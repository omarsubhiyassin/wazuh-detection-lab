import type { Alert } from "../types";
import { reviewOf } from "../review";

interface Props {
  alerts: Alert[];
  total: number;
  loading: boolean;
  onSelect: (a: Alert) => void;
  /** Optional badge describing an extra client-side filter (e.g. triage state). */
  note?: string;
}

function levelClass(level: number): string {
  if (level >= 12) return "sev sev-critical";
  if (level >= 8) return "sev sev-high";
  if (level >= 4) return "sev sev-medium";
  return "sev sev-low";
}

function fmtTime(ts: string): string {
  const d = new Date(ts);
  return isNaN(d.getTime()) ? ts : d.toLocaleString();
}

export function AlertTable({ alerts, total, loading, onSelect, note }: Props) {
  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Alerts {note && <span className="chip chip-sm">{note}</span>}</h2>
        <span className="muted">
          {loading ? "loading…" : `showing ${alerts.length} of ${total}`}
        </span>
      </div>
      <div className="table-wrap">
        <table className="alerts">
          <thead>
            <tr>
              <th>Time</th>
              <th>Lvl</th>
              <th title="Suggested investigation order from the scoring pass. Advisory only.">AI</th>
              <th>Technique</th>
              <th>Rule</th>
              <th>Description</th>
              <th>Host</th>
              <th>Review</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => {
              const r = a.source.rule;
              const mitre = r.mitre?.id ?? [];
              const rev = reviewOf(a);
              return (
                <tr key={a.id} onClick={() => onSelect(a)}
                  className={rev.key === "ai-awaiting" ? "row-flagged" : undefined}>
                  <td className="nowrap">{fmtTime(a.source.timestamp)}</td>
                  <td><span className={levelClass(r.level)}>{r.level}</span></td>
                  <td className="nowrap">
                    {a.ai?.flagged
                      ? <span className="ai-pri" title={`score ${a.ai.score} — ${a.ai.reasons[0] ?? ""}`}>
                          P{a.ai.priority}
                        </span>
                      : <span className="muted">—</span>}
                  </td>
                  <td className="nowrap">
                    {mitre.length
                      ? mitre.map((t) => <span className="tag" key={t}>{t}</span>)
                      : <span className="muted">—</span>}
                  </td>
                  <td className="mono">{r.id}</td>
                  <td className="desc">{r.description}</td>
                  <td className="nowrap">{a.source.agent?.name ?? "—"}</td>
                  <td className="nowrap">
                    <span className={`r-badge r-${rev.key}`} title={rev.detail}>{rev.label}</span>
                  </td>
                </tr>
              );
            })}
            {!loading && alerts.length === 0 && (
              <tr><td colSpan={8} className="muted center">No alerts match the current filters.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
