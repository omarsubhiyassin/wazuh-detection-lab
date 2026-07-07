import type { Alert } from "../types";

interface Props {
  alert: Alert | null;
  onClose: () => void;
}

export function AlertDrawer({ alert, onClose }: Props) {
  if (!alert) return null;
  const s = alert.source;
  const r = s.rule;
  const mitre = r.mitre;

  return (
    <div className="drawer-scrim" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-head">
          <h3>Rule {r.id} — level {r.level}</h3>
          <button className="close" onClick={onClose} aria-label="close">×</button>
        </div>

        <p className="drawer-desc">{r.description}</p>

        <dl className="kv">
          <dt>Time</dt><dd>{new Date(s.timestamp).toLocaleString()}</dd>
          <dt>Host</dt><dd>{s.agent?.name ?? "—"} {s.agent?.ip ? `(${s.agent.ip})` : ""}</dd>
          <dt>Location</dt><dd className="mono">{s.location ?? "—"}</dd>
          <dt>Decoder</dt><dd className="mono">{s.decoder?.name ?? "—"}</dd>
          <dt>Groups</dt><dd>{(r.groups ?? []).join(", ") || "—"}</dd>
        </dl>

        {mitre?.id?.length ? (
          <div className="mitre-box">
            {mitre.id.map((id, i) => (
              <div className="mitre-row" key={id}>
                <span className="tag tag-lg">{id}</span>
                <span>{mitre.technique?.[i] ?? ""}</span>
                <span className="muted">{mitre.tactic?.[i] ?? ""}</span>
              </div>
            ))}
          </div>
        ) : null}

        <h4>Raw log</h4>
        <pre className="raw">{s.full_log ?? "(no full_log)"}</pre>

        <h4>Event (_source)</h4>
        <pre className="raw">{JSON.stringify(s, null, 2)}</pre>
      </aside>
    </div>
  );
}
