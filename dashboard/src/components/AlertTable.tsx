import type { Alert } from "../types";

interface Props {
  alerts: Alert[];
  total: number;
  loading: boolean;
  onSelect: (a: Alert) => void;
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

export function AlertTable({ alerts, total, loading, onSelect }: Props) {
  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Alerts</h2>
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
              <th>Technique</th>
              <th>Rule</th>
              <th>Description</th>
              <th>Host</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => {
              const r = a.source.rule;
              const mitre = r.mitre?.id ?? [];
              return (
                <tr key={a.id} onClick={() => onSelect(a)}>
                  <td className="nowrap">{fmtTime(a.source.timestamp)}</td>
                  <td><span className={levelClass(r.level)}>{r.level}</span></td>
                  <td className="nowrap">
                    {mitre.length
                      ? mitre.map((t) => <span className="tag" key={t}>{t}</span>)
                      : <span className="muted">—</span>}
                  </td>
                  <td className="mono">{r.id}</td>
                  <td className="desc">{r.description}</td>
                  <td className="nowrap">{a.source.agent?.name ?? "—"}</td>
                </tr>
              );
            })}
            {!loading && alerts.length === 0 && (
              <tr><td colSpan={6} className="muted center">No alerts match the current filters.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
