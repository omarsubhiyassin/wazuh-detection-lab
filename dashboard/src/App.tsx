import { useEffect, useMemo, useState } from "react";
import type { Alert, AnalysisConfig, Coverage, Filters, Session, Stats, TriageState, TriageStatus } from "./types";
import { getAlerts, getAnalysis, getCoverage, getSession, getStats, logout, runAnalysis, HttpError } from "./api";
import { awaitingReview } from "./review";
import { AttackMatrix } from "./components/AttackMatrix";
import { AlertTable } from "./components/AlertTable";
import { AlertDrawer } from "./components/AlertDrawer";
import { AuditPanel } from "./components/AuditPanel";
import { MetricsPanel } from "./components/MetricsPanel";
import { FleetRail } from "./components/FleetRail";
import { Sidebar } from "./components/Sidebar";
import { Login } from "./components/Login";
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
  // undefined = session check in flight, null = signed out, Session = signed in.
  const [session, setSession] = useState<Session | null | undefined>(undefined);
  const [filters, setFilters] = useState<Filters>({ range: "7d" });
  const [stats, setStats] = useState<Stats | null>(null);
  const [data, setData] = useState<{ total: number; alerts: Alert[] }>({ total: 0, alerts: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [showAudit, setShowAudit] = useState(false);
  const [showMetrics, setShowMetrics] = useState(false);
  // Client-side filter over the loaded alert page (triage state lives in the
  // BFF store, not the indexer, so it can't be part of the indexer query).
  const [triageFilter, setTriageFilter] = useState<TriageStatus | null>(null);
  // AI advisory layer: config for the sidebar copy, a queue filter, and a
  // manual run trigger. Analysis is explicitly operator-triggered rather than
  // automatic — a pass has a cost (and, with the LLM on, a per-alert API call).
  const [aiConfig, setAiConfig] = useState<AnalysisConfig | undefined>(undefined);
  const [coverage, setCoverage] = useState<Coverage | undefined>(undefined);
  const [aiFilter, setAiFilter] = useState(false);
  const [running, setRunning] = useState(false);
  const [runNote, setRunNote] = useState<string | null>(null);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    getSession().then(setSession).catch(() => setSession(null));
  }, []);

  useEffect(() => {
    if (!session) return;
    getAnalysis().then((a) => setAiConfig(a.config)).catch(() => { /* non-fatal */ });
    // Coverage is static per deploy, so fetch once. On failure it stays
    // undefined and the matrix reports coverage as unknown rather than absent.
    getCoverage().then(setCoverage).catch(() => { /* non-fatal */ });
  }, [session]);

  useEffect(() => {
    if (!session) return;
    let live = true;
    setLoading(true);
    setError(null);
    Promise.all([getStats(filters), getAlerts(filters)])
      .then(([s, a]) => { if (live) { setStats(s); setData(a); } })
      .catch((e) => {
        if (!live) return;
        // Session expired mid-use: drop back to the login screen.
        if (e instanceof HttpError && e.status === 401) setSession(null);
        else setError(String(e));
      })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [filters, session, reload]);

  // Run a scoring pass over the current filter window, then reload so the new
  // advisory findings show up on the alerts.
  const analyze = () => {
    setRunning(true); setRunNote(null);
    runAnalysis(filters)
      .then((r) => {
        setRunNote(r.matched > r.flagged
          ? `${r.matched} of ${r.considered} alerts over threshold, grouped into ${r.flagged} review items.`
          : `Flagged ${r.flagged} of ${r.considered} alerts at level ${r.minLevel}+.`);
        setReload((n) => n + 1);
      })
      .catch((e) => {
        if (e instanceof HttpError && e.status === 401) setSession(null);
        else setRunNote(e instanceof Error ? e.message : String(e));
      })
      .finally(() => setRunning(false));
  };

  // Patch an alert's triage state in place after a successful update.
  const applyTriage = (id: string, t: TriageState) => {
    setData((d) => ({ ...d, alerts: d.alerts.map((a) => a.id === id ? { ...a, triage: t } : a) }));
    setSelected((s) => s && s.id === id ? { ...s, triage: t } : s);
  };

  const coveredCount = useMemo(() => {
    const known = Object.keys(TECHNIQUES);
    const hit = new Set((stats?.byTechnique ?? []).filter((t) => t.count > 0).map((t) => t.id));
    return { hit: known.filter((k) => hit.has(k)).length, total: known.length };
  }, [stats]);

  const set = (patch: Partial<Filters>) => setFilters((f) => ({ ...f, ...patch }));

  const awaitingCount = useMemo(
    () => data.alerts.filter(awaitingReview).length,
    [data.alerts],
  );

  const visibleAlerts = useMemo(() => {
    // The AI queue is a review queue, so it sorts by suggested priority rather
    // than by time; every other view stays newest-first.
    if (aiFilter) {
      return data.alerts.filter(awaitingReview)
        .sort((a, b) => (a.ai?.priority ?? 0) - (b.ai?.priority ?? 0));
    }
    return triageFilter
      ? data.alerts.filter((a) => a.triage?.status === triageFilter)
      : data.alerts;
  }, [data.alerts, triageFilter, aiFilter]);

  if (session === undefined) return null; // session check in flight
  if (session === null) return <Login onLogin={setSession} />;

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
          <span className="session muted">{session.user}</span>
          <span className={`role-badge role-${session.role}`}>{session.role}</span>
          <button className="linkish" onClick={() => setShowMetrics(true)}>efficacy</button>
          {session.role === "admin" && (
            <button className="linkish" onClick={() => setShowAudit(true)}>audit log</button>
          )}
          <button className="linkish" onClick={() => { logout().finally(() => setSession(null)); }}>
            sign out
          </button>
        </div>
      </header>

      {error && <div className="error">Cannot reach the API: {error}. Is the BFF running and the indexer up?</div>}

      <div className="shell">
      <Sidebar
        filters={filters}
        onView={(patch) => { setTriageFilter(null); setAiFilter(false); set(patch); }}
        triageCounts={stats?.triageCounts}
        triageFilter={triageFilter}
        onTriageFilter={(s) => { setAiFilter(false); setTriageFilter(s); }}
        aiFilter={aiFilter}
        onAiFilter={(on) => { setTriageFilter(null); setAiFilter(on); }}
        awaitingCount={awaitingCount}
        canRun={session.role !== "viewer"}
        running={running}
        onRun={analyze}
        analysis={aiConfig}
        runNote={runNote}
      />

      <div className="shell-main">
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
          coverage={coverage}
        />
      </section>

      <AlertTable
        alerts={visibleAlerts}
        total={triageFilter || aiFilter ? visibleAlerts.length : data.total}
        loading={loading}
        onSelect={setSelected}
        note={aiFilter ? "AI-flagged · awaiting human review"
          : triageFilter ? `triage: ${triageFilter}` : undefined}
      />
      </div>

      <FleetRail
        stats={stats}
        filters={{ host: filters.host, technique: filters.technique }}
        onHost={(host) => set({ host })}
        onTechnique={(technique) => set({ technique })}
      />
      </div>

      <AlertDrawer alert={selected} role={session.role} onClose={() => setSelected(null)}
        onTriaged={applyTriage} onExpired={() => setSession(null)} />

      {showMetrics && <MetricsPanel onClose={() => setShowMetrics(false)} />}
      {showAudit && <AuditPanel onClose={() => setShowAudit(false)} />}
    </div>
  );
}
