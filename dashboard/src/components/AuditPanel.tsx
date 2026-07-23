import { useEffect, useState } from "react";
import type { AuditEvent } from "../types";
import { getAudit } from "../api";

export function AuditPanel({ onClose }: { onClose: () => void }) {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getAudit(300)
      .then((r) => setEvents(r.events))
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  return (
    <div className="drawer-scrim" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-head">
          <h3>Audit log</h3>
          <button className="close" onClick={onClose} aria-label="close">×</button>
        </div>
        <p className="muted">Who signed in and who changed alert triage state. Newest first.</p>
        {error && <div className="error">{error}</div>}
        {!events ? <p className="muted">Loading…</p> : (
          <table className="alerts audit">
            <thead>
              <tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th></tr>
            </thead>
            <tbody>
              {events.map((e, i) => (
                <tr key={i}>
                  <td className="nowrap mono">{new Date(e.ts).toLocaleString()}</td>
                  <td>{e.user ?? "—"}{e.role ? ` (${e.role})` : ""}</td>
                  <td><span className={`t-badge audit-${e.action}`}>{e.action}</span></td>
                  <td className="mono">
                    {e.action === "triage"
                      ? `${e.alertId} → ${e.status}${e.assignee ? ` @${e.assignee}` : ""}`
                      : e.ip ?? ""}
                  </td>
                </tr>
              ))}
              {!events.length && <tr><td colSpan={4} className="muted">No events yet.</td></tr>}
            </tbody>
          </table>
        )}
      </aside>
    </div>
  );
}
