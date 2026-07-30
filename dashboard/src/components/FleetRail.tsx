import type { AgentStat, Stats } from "../types";
import { TECHNIQUES } from "../attack";

function sevClass(level: number): string {
  if (level >= 12) return "dot-crit";
  if (level >= 8) return "dot-high";
  if (level >= 4) return "dot-med";
  return "dot-low";
}

function ago(iso: string | null): string {
  if (!iso) return "—";
  const ms = Date.now() - new Date(iso).getTime();
  if (!isFinite(ms) || ms < 0) return "—";
  const m = Math.floor(ms / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

interface Props {
  stats: Stats | null;
  filters: { host?: string; technique?: string };
  onHost: (host: string | undefined) => void;
  onTechnique: (id: string | undefined) => void;
}

export function FleetRail({ stats, filters, onHost, onTechnique }: Props) {
  const agents: AgentStat[] = stats?.byAgent ?? [];
  const techniques = [...(stats?.byTechnique ?? [])]
    .filter((t) => t.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  return (
    <aside className="fleet-rail">
      <div className="rail-block">
        <h3 className="rail-title">Fleet activity</h3>
        {agents.length === 0 ? (
          <p className="rail-empty muted">No hosts in this range.</p>
        ) : (
          <ul className="agent-list">
            {agents.map((a) => (
              <li key={a.name}>
                <button type="button"
                  className={`agent-item${filters.host === a.name ? " active" : ""}`}
                  onClick={() => onHost(filters.host === a.name ? undefined : a.name)}>
                  <span className={`agent-dot ${sevClass(a.maxLevel)}`} />
                  <span className="agent-name" title={a.name}>{a.name}</span>
                  <span className="agent-meta">{a.count}</span>
                  <span className="agent-seen">{ago(a.lastSeen)}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
        <p className="rail-note">
          Ranked by alert volume. Times are the last <em>alert</em> from that host,
          not a connectivity check.
        </p>
      </div>

      <div className="rail-block">
        <h3 className="rail-title">Top techniques</h3>
        {techniques.length === 0 ? (
          <p className="rail-empty muted">Nothing seen in this range.</p>
        ) : (
          <ul className="tech-list">
            {techniques.map((t) => (
              <li key={t.id}>
                <button type="button"
                  className={`tech-item${filters.technique === t.id ? " active" : ""}`}
                  onClick={() => onTechnique(filters.technique === t.id ? undefined : t.id)}>
                  <span className="tag">{t.id}</span>
                  <span className="tech-name" title={TECHNIQUES[t.id]?.name ?? ""}>
                    {TECHNIQUES[t.id]?.name ?? "—"}
                  </span>
                  <span className="tech-count">{t.count}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </aside>
  );
}
