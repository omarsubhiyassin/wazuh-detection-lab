import { useEffect, useState } from "react";
import type { Alert, AiVerdict, Disposition, Role, TriageState, TriageStatus } from "../types";
import { setTriage, HttpError } from "../api";
import { reviewOf } from "../review";

const STATUSES: TriageStatus[] = ["new", "acknowledged", "investigating", "closed"];

// The wording matters: an analyst has to be able to tell "the rule was wrong"
// apart from "the rule was right, the activity was allowed". Conflating them
// blames the ruleset for normal admin work and hides the detections that
// actually need tuning.
const DISPOSITIONS: { value: Disposition; label: string; hint: string }[] = [
  { value: "true-positive", label: "True positive", hint: "real malicious or unauthorized activity" },
  { value: "false-positive", label: "False positive", hint: "the rule fired on something it does not describe — a detection defect" },
  { value: "benign", label: "Benign", hint: "the rule was right, but the activity was authorized" },
];

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
  const [verdict, setVerdict] = useState<AiVerdict | null>(t?.aiVerdict ?? null);
  const [disposition, setDisposition] = useState<Disposition | null>(t?.disposition ?? null);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Reset the form when a different alert is opened.
  useEffect(() => {
    setStatus(alert.triage?.status ?? "new");
    setAssignee(alert.triage?.assignee ?? "");
    setNote(alert.triage?.note ?? "");
    setVerdict(alert.triage?.aiVerdict ?? null);
    setDisposition(alert.triage?.disposition ?? null);
    setErr(null);
  }, [alert.id]);

  const readOnly = role === "viewer";
  // Closing is the point of no return in the workflow, so require the analyst
  // to actually write something and to state the outcome. The server enforces
  // both; this just says so before the round trip.
  const needsNote = status === "closed" && !note.trim();
  const needsDisposition = status === "closed" && !disposition;

  const save = () => {
    setSaving(true); setErr(null);
    setTriage(alert.id, { status, assignee: assignee || null, note, aiVerdict: verdict, disposition })
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
          {alert.ai?.flagged && (
            <div className="verdict">
              <span className="verdict-q">Was the AI right to flag this?</span>
              <div className="verdict-btns">
                {(["agree", "disagree"] as AiVerdict[]).map((v) => (
                  <button key={v} type="button"
                    className={`verdict-btn${verdict === v ? " active" : ""}`}
                    onClick={() => setVerdict(verdict === v ? null : v)}>
                    {v === "agree" ? "Agree — worth investigating" : "Disagree — false positive"}
                  </button>
                ))}
              </div>
            </div>
          )}
          <div className="disp">
            <span className="verdict-q">
              Outcome {status === "closed" && <span className="req">required to close</span>}
            </span>
            <div className="disp-btns">
              {DISPOSITIONS.map((d) => (
                <button key={d.value} type="button" title={d.hint}
                  className={`disp-btn disp-${d.value}${disposition === d.value ? " active" : ""}`}
                  onClick={() => setDisposition(disposition === d.value ? null : d.value)}>
                  <span className="disp-label">{d.label}</span>
                  <span className="disp-hint">{d.hint}</span>
                </button>
              ))}
            </div>
          </div>
          <label className="triage-note">
            Note {status === "closed" && <span className="req">required to close</span>}
            <textarea value={note} rows={2} onChange={(e) => setNote(e.target.value)}
              placeholder={status === "closed"
                ? "What did you find? This is your conclusion, not the AI's."
                : "Optional context for the next analyst"} />
          </label>
          {err && <div className="error">{err}</div>}
          <button className="triage-save" disabled={saving || needsNote || needsDisposition} onClick={save}>
            {saving ? "Saving…" : status === "closed" ? "Confirm and close" : "Save triage"}
          </button>
          {(needsNote || needsDisposition) && (
            <p className="muted t-meta">
              {needsDisposition ? "Pick an outcome" : "Add a note"}
              {needsNote && needsDisposition ? " and write a note" : ""} before closing —
              it is what makes the detection metrics mean anything.
            </p>
          )}
        </>
      )}
      {t && <p className="muted t-meta">last updated by {t.updatedBy} · {new Date(t.updatedAt).toLocaleString()}</p>}
    </div>
  );
}

/**
 * The AI's advisory output. Deliberately framed as a suggestion: the
 * deterministic factors are listed first and in full, because they are what an
 * analyst can actually audit. Model prose, when enabled, is shown last and
 * labelled unverified — it is generated from attacker-controllable log text.
 */
function AiPanel({ alert }: { alert: Alert }) {
  const ai = alert.ai;
  if (!ai?.flagged) return null;
  return (
    <div className="ai-box">
      <div className="ai-head">
        <span className="ai-pri">P{ai.priority}</span>
        <h4>Flagged for review{ai.occurrences > 1 && ` — ${ai.occurrences} occurrences`}</h4>
        <span className="muted">score {ai.score}</span>
      </div>
      <ul className="ai-reasons">
        {ai.reasons.map((r) => <li key={r}>{r}</li>)}
      </ul>
      {ai.summary && (
        <div className="ai-summary">
          <div className="ai-summary-label">
            Model summary · unverified · {ai.summaryModel}
          </div>
          <p>{ai.summary}</p>
        </div>
      )}
      <p className="ai-disclaimer">
        Ranking is a deterministic score over the factors above — not a model
        judgement. Nothing here reviews, resolves, or closes the alert; only an
        analyst can do that below.
      </p>
    </div>
  );
}

export function AlertDrawer({ alert, role, onClose, onTriaged, onExpired }: Props) {
  if (!alert) return null;
  const s = alert.source;
  const r = s.rule;
  const mitre = r.mitre;
  const rev = reviewOf(alert);

  return (
    <div className="drawer-scrim" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-head">
          <h3>Rule {r.id} — level {r.level}</h3>
          <button className="close" onClick={onClose} aria-label="close">×</button>
        </div>

        <div className={`r-banner r-${rev.key}`}>{rev.detail}</div>

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

        <AiPanel alert={alert} />

        <Triage alert={alert} role={role} onTriaged={onTriaged} onExpired={onExpired} />

        <h4>Raw log</h4>
        <pre className="raw">{s.full_log ?? "(no full_log)"}</pre>

        <h4>Event (_source)</h4>
        <pre className="raw">{JSON.stringify(s, null, 2)}</pre>
      </aside>
    </div>
  );
}
