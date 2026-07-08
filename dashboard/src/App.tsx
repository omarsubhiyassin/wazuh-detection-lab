import { useEffect, useMemo, useState } from "react";
import type { Alert, Filters, Stats } from "./types";
import { getAlerts, getStats } from "./api";
import { AttackMatrix } from "./components/AttackMatrix";
import { AlertTable } from "./components/AlertTable";
import { AlertDrawer } from "./components/AlertDrawer";
import { TECHNIQUES } from "./attack";

const RANGES = ["1h", "24h", "7d", "30d", "all"];

function sumLevels(stats: Stats | null, lo: number, hi: number): number {
  if (!stats) return 0;
  return stats.byLevel.filter((b) => b.level >= lo && b.level <= hi)
    .reduce((n, b) => n + b.count, 0);
}

function TimeSpark({ data }: { data: Stats["overTime"] }) {
  const max = data.reduce((m, d) => Math.max(m, d.count), 0) || 1;
  return (
    <div className="spark" title="alerts over time">
      {data.map((d) => (
        <div key={d.t} className="spark-bar"
          style={{ height: `${Math.max(2, (d.count / max) * 100)}%` }}
          title={`${new Date(d.t).toLocaleString()}: ${d.count}`} />
      ))}
    </div>
  );
}

export function App() {
  const [filters, setFilters] = useState<Filters>({ range: "7d" });
  const [stats, setStats] = useState<Stats | null>(null);
  const [data, setData] = useState<{ total: number; alerts: Alert[] }>({ total: 0, alerts: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Alert | null>(null);

  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(null);
    Promise.all([getStats(filters), getAlerts(filters)])
      .then(([s, a]) => { if (live) { setStats(s); setData(a); } })
      .catch((e) => { if (live) setError(String(e)); })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [filters]);

  const coveredCount = useMemo(() => {
    const known = Object.keys(TECHNIQUES);
    const hit = new Set((stats?.byTechnique ?? []).filter((t) => t.count > 0).map((t) => t.id));
    return { hit: known.filter((k) => hit.has(k)).length, total: known.length };
  }, [stats]);

  const set = (patch: Partial<Filters>) => setFilters((f) => ({ ...f, ...patch }));

  return (
    <div className="app">
      <header className="top">
        <div className="brand">
          <span className="dot" /> Detection Lab <span className="muted">— ATT&CK Dashboard</span>
        </div>
        <div className="controls">
          <label>Range
            <select value={filters.range} onChange={(e) => set({ range: e.target.value })}>
              {RANGES.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </label>
          <label>Min level
            <select value={filters.minLevel ?? 0} onChange={(e) => set({ minLevel: Number(e.target.value) || undefined })}>
              <option value={0}>any</option>
              <option value={4}>4+</option>
              <option value={8}>8+</option>
              <option value={12}>12+</option>
            </select>
          </label>
          <input placeholder="host…" value={filters.host ?? ""}
            onChange={(e) => set({ host: e.target.value || undefined })} />
          <input placeholder="search…" value={filters.search ?? ""}
            onChange={(e) => set({ search: e.target.value || undefined })} />
        </div>
      </header>

      {error && <div className="error">Cannot reach the API: {error}. Is the BFF running and the indexer up?</div>}

      <section className="tiles">
        <div className="tile"><div className="tile-n">{stats?.total ?? "—"}</div><div className="tile-l">alerts</div></div>
        <div className="tile crit"><div className="tile-n">{sumLevels(stats, 12, 15)}</div><div className="tile-l">critical (12+)</div></div>
        <div className="tile high"><div className="tile-n">{sumLevels(stats, 8, 11)}</div><div className="tile-l">high (8–11)</div></div>
        <div className="tile"><div className="tile-n">{coveredCount.hit}/{coveredCount.total}</div><div className="tile-l">techniques seen</div></div>
        <div className="tile wide"><div className="tile-l">activity</div><TimeSpark data={stats?.overTime ?? []} /></div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>ATT&CK coverage</h2>
          {filters.technique && (
            <button className="chip" onClick={() => set({ technique: undefined })}>
              filtered: {filters.technique} ×
            </button>
          )}
        </div>
        <AttackMatrix
          byTechnique={stats?.byTechnique ?? []}
          selected={filters.technique}
          onSelect={(t) => set({ technique: t })}
        />
      </section>

      <AlertTable alerts={data.alerts} total={data.total} loading={loading} onSelect={setSelected} />

      <AlertDrawer alert={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
