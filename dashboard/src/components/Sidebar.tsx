import type { Filters, TriageStatus } from "../types";

// Saved views: one-click filter presets over the existing filter model. Each
// knows how to apply itself and how to tell whether it is currently active.
interface View {
  id: string;
  label: string;
  hint: string;
  patch: Partial<Filters>;
  match: (f: Filters) => boolean;
}

const BASE: Filters = { range: "7d" };

export const VIEWS: View[] = [
  {
    id: "all", label: "All alerts", hint: "last 7 days",
    patch: { ...BASE, technique: undefined, minLevel: undefined, host: undefined, search: undefined },
    match: (f) => f.range === "7d" && !f.minLevel && !f.technique && !f.host && !f.search,
  },
  {
    id: "critical", label: "Critical", hint: "level 12+",
    patch: { minLevel: 12, technique: undefined, host: undefined, search: undefined },
    match: (f) => f.minLevel === 12,
  },
  {
    id: "high", label: "High and above", hint: "level 8+",
    patch: { minLevel: 8, technique: undefined, host: undefined, search: undefined },
    match: (f) => f.minLevel === 8,
  },
  {
    id: "today", label: "Last 24 hours", hint: "all levels",
    patch: { range: "24h", minLevel: undefined, technique: undefined, host: undefined, search: undefined },
    match: (f) => f.range === "24h" && !f.minLevel,
  },
  {
    id: "recent", label: "Last hour", hint: "what's happening now",
    patch: { range: "1h", minLevel: undefined, technique: undefined, host: undefined, search: undefined },
    match: (f) => f.range === "1h" && !f.minLevel,
  },
];

const QUEUE: { status: TriageStatus; label: string }[] = [
  { status: "new", label: "New" },
  { status: "acknowledged", label: "Acknowledged" },
  { status: "investigating", label: "Investigating" },
  { status: "closed", label: "Closed" },
];

interface Props {
  filters: Filters;
  onView: (patch: Partial<Filters>) => void;
  triageCounts?: Record<TriageStatus, number>;
  triageFilter: TriageStatus | null;
  onTriageFilter: (s: TriageStatus | null) => void;
}

export function Sidebar({ filters, onView, triageCounts, triageFilter, onTriageFilter }: Props) {
  return (
    <aside className="sidebar">
      <div className="rail-block">
        <h3 className="rail-title">Views</h3>
        <nav className="view-list">
          {VIEWS.map((v) => (
            <button key={v.id} type="button"
              className={`view-item${v.match(filters) ? " active" : ""}`}
              onClick={() => onView(v.patch)}>
              <span className="view-label">{v.label}</span>
              <span className="view-hint">{v.hint}</span>
            </button>
          ))}
        </nav>
      </div>

      <div className="rail-block">
        <h3 className="rail-title">Triage queue</h3>
        <nav className="view-list">
          {QUEUE.map((q) => {
            const n = triageCounts?.[q.status] ?? 0;
            const active = triageFilter === q.status;
            return (
              <button key={q.status} type="button"
                className={`queue-item${active ? " active" : ""}`}
                onClick={() => onTriageFilter(active ? null : q.status)}>
                <span className={`t-badge t-${q.status}`}>{q.label}</span>
                <span className="queue-count">{n}</span>
              </button>
            );
          })}
        </nav>
        {triageFilter && (
          <button className="rail-clear" type="button" onClick={() => onTriageFilter(null)}>
            clear triage filter
          </button>
        )}
        <p className="rail-note">
          Counts are all triaged alerts. Filtering applies to the alerts loaded below.
        </p>
      </div>
    </aside>
  );
}
