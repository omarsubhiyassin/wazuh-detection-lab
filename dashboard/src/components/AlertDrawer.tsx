import { useEffect, useState } from "react";
import type { Alert, Role, TriageState, TriageStatus } from "../types";
import { setTriage, HttpError } from "../api";

const STATUSES: TriageStatus[] = ["new", "acknowledged", "investigating", "closed"];

interface Props {
  alert: Alert | null;
  role: Role;
  onClose: () => void;
  onTriaged: (id: string, t: TriageState) => void;
  onExpired: () => void;
}

function Triage({ alert, role, onTriaged, onExpired }:
  { alert: Alert; role: Role; onTriaged: Props["onTriaged"]; onExpired: () => void }) {
  const t = alert.triage;
  const [status, setStatus] = useState<TriageStatus>(t?.status ?? "new");
  const [assignee, setAssignee] = useState(t?.assignee ?? "");
  const [note, setNote] = useState(t?.note ?? "");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Reset the form when a different alert is opened.
  useEffect(() => {
    setStatus(alert.triage?.status ?? "new");
    setAssignee(alert.triage?.assignee ?? "");
    setNote(alert.triage?.note ?? "");
    setErr(null);
  }, [alert.id]);

  const readOnly = role === "viewer";

  const save = () => {
    setSaving(true); setErr(null);
    setTriage(alert.id, { status, assignee: assignee || null, note })
      .then((r) => onTriaged(alert.id, r.triage))
      .catch((e) => {
        if (e instanceof HttpError && e.status === 401) onExpired();
        else setErr(e instanceof Error ? e.message : String(e));
      })
      .finally(() => setSaving(false));
  };

  return (
    <div className="triage">
      <h4>Triage {t && <span className={`t-badge t-${t.status}`}>{t.status}</span>}</h4>
      {readOnly ? (
        <p className="muted">You have view-only access. Ask an analyst to triage.</p>
      ) : (
        <>
          <div className="triage-row">
            <label>Status
              <select value={status} onChange={(e) => setStatus(e.target.value as TriageStatus)}>
                {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>
            <label>Assignee
              <input value={assignee} placeholder="unassigned"
                onChange={(e) => setAssignee(e.target.value)} />
            </label>
          </div>
          <label className="triage-note">Note
            <textarea value={note} rows={2} onChange={(e) => setNote(e.target.value)} />
          </label>
          {err && <div className="error">{err}</div>}
          <button className="triage-save" disabled={saving} onClick={save}>
            {saving ? "Saving…" : "Save triage"}
          </button>
        </>
      )}
      {t && <p className="muted t-meta">last updated by {t.updatedBy} · {new Date(t.updatedAt).toLocaleString()}</p>}
    </div>
  );
}

export function AlertDrawer({ alert, role, onClose, onTriaged, onExpired }: Props) {
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

        <Triage alert={alert} role={role} onTriaged={onTriaged} onExpired={onExpired} />

        <h4>Raw log</h4>
        <pre className="raw">{s.full_log ?? "(no full_log)"}</pre>

        <h4>Event (_source)</h4>
        <pre className="raw">{JSON.stringify(s, null, 2)}</pre>
      </aside>
    </div>
  );
}
