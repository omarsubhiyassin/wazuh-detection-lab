// Alert triage state for the dashboard — the deliberate, least-privilege write
// path. Kept OUT of the indexer (alerts stay read-only): a small JSON store on
// the BFF host, keyed by alert id, holding status + assignee + note + who/when.
// Persisted to disk so it survives a BFF restart; single-file so multiple
// analysts on one BFF share state.
//
// IDENTITY AND LIFETIME
//   Records are keyed by the OpenSearch `_id` of the alert, which is only
//   meaningful while that alert's index exists. ISM deletes indices on the
//   retention schedule, so an OPEN record eventually points at an alert nobody
//   can open — and until pruned it keeps inflating the queue counts, which makes
//   the sidebar lie about how much work is outstanding.
//
//   The fix is not to delete on a timer indiscriminately. CLOSED records are the
//   detection-efficacy measurement (see metrics.js) and are worth far more than
//   the alert they point at, so they are kept by default; the denormalized
//   `context` block means they stay attributable after the alert is gone. Only
//   open records whose alert has certainly aged out are dropped.
//
//   Growth is therefore bounded by how fast humans close things, not by alert
//   volume — which is the property that actually matters here.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FILE = process.env.DASH_TRIAGE_FILE ||
  path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "triage-state.json");

// Keep in sync with ALERTS_RETENTION_DAYS in infra/.env — how long an alert
// survives in the indexer. Past this, an open record is unactionable.
const ALERT_RETENTION_DAYS = Number(process.env.DASH_ALERT_RETENTION_DAYS || 30);
// 0 = keep closed records forever (the default). They are the metrics history.
const CLOSED_RETENTION_DAYS = Number(process.env.DASH_CLOSED_RETENTION_DAYS || 0);

export const STATUSES = ["new", "acknowledged", "investigating", "closed"];

/** Record shape version, so an old store can be read without special-casing. */
export const SCHEMA = 2;

let state = load();

/**
 * Bring a record written by an older build up to the current shape. Records
 * predating the metrics work have no context/disposition/firstTouchedAt;
 * inventing values would corrupt the efficacy numbers, so missing facts stay
 * null and `updatedAt` is the only defensible stand-in for a first touch.
 */
function migrate(rec) {
  if (!rec || typeof rec !== "object") return null;
  if (rec.v === SCHEMA) return rec;
  return {
    status: STATUSES.includes(rec.status) ? rec.status : "new",
    assignee: rec.assignee ?? null,
    note: rec.note ?? "",
    aiVerdict: rec.aiVerdict ?? null,
    disposition: rec.disposition ?? null,
    context: rec.context ?? null,
    updatedBy: rec.updatedBy ?? "unknown",
    updatedAt: rec.updatedAt ?? new Date(0).toISOString(),
    firstTouchedAt: rec.firstTouchedAt ?? rec.updatedAt ?? new Date(0).toISOString(),
    v: SCHEMA,
  };
}

function load() {
  let raw;
  try { raw = JSON.parse(fs.readFileSync(FILE, "utf8")) || {}; }
  catch { return {}; }
  const out = {};
  let migrated = 0;
  for (const [id, rec] of Object.entries(raw)) {
    const m = migrate(rec);
    if (!m) continue;
    if (rec?.v !== SCHEMA) migrated += 1;
    out[id] = m;
  }
  if (migrated) console.log(`[dashboard] triage: migrated ${migrated} record(s) to schema v${SCHEMA}`);
  return out;
}

function persist() {
  try {
    fs.writeFileSync(FILE + ".tmp", JSON.stringify(state), { mode: 0o600 });
    fs.renameSync(FILE + ".tmp", FILE); // atomic replace
  } catch (e) {
    console.error("[dashboard] triage write failed:", String(e));
  }
}

/** Triage record for one alert id, or null. */
export function get(id) {
  return state[id] || null;
}

/** Counts per status across the whole store (drives the sidebar queue). */
export function counts() {
  const out = Object.fromEntries(STATUSES.map((s) => [s, 0]));
  for (const rec of Object.values(state)) {
    if (rec && out[rec.status] !== undefined) out[rec.status] += 1;
  }
  return out;
}

/** Triage records for a set of ids, as { id: record }. */
export function getMany(ids) {
  const out = {};
  for (const id of ids) if (state[id]) out[id] = state[id];
  return out;
}

/**
 * Alert ids currently in a given status. Lets the alerts endpoint push a triage
 * filter into the indexer query as an `ids` clause instead of filtering the one
 * page the browser happened to load — the difference between "the 3 closed
 * alerts on this page" and "every closed alert".
 */
export function idsByStatus(status) {
  return Object.entries(state)
    .filter(([, rec]) => rec?.status === status)
    .map(([id]) => id);
}

/** Ids with any triage record at all. */
export function allIds() {
  return Object.keys(state);
}

/**
 * Drop records that can no longer be acted on. Returns a summary rather than
 * logging silently, so a scheduled prune is auditable.
 *
 * `orphaned` = open records whose alert has aged out of the indexer. They are
 * unopenable and, left in place, they inflate the queue counts.
 * `expired`  = closed records past an explicitly configured retention. OFF by
 * default: closed records are the efficacy measurement, and they stay
 * attributable without the alert thanks to the denormalized context.
 *
 * A record with no `context.alertTs` cannot be aged, so it is always kept —
 * guessing would delete real work.
 */
export function prune({
  alertRetentionDays = ALERT_RETENTION_DAYS,
  closedRetentionDays = CLOSED_RETENTION_DAYS,
  now = Date.now(),
} = {}) {
  const summary = { scanned: 0, orphaned: 0, expired: 0, kept: 0, unaged: 0 };
  const openCutoff = now - alertRetentionDays * 86400_000;
  const closedCutoff = now - closedRetentionDays * 86400_000;

  for (const [id, rec] of Object.entries(state)) {
    summary.scanned += 1;
    const ts = Date.parse(rec?.context?.alertTs ?? "");
    if (!Number.isFinite(ts)) { summary.unaged += 1; summary.kept += 1; continue; }

    if (rec.status !== "closed" && ts < openCutoff) {
      delete state[id]; summary.orphaned += 1; continue;
    }
    if (rec.status === "closed" && closedRetentionDays > 0 && ts < closedCutoff) {
      delete state[id]; summary.expired += 1; continue;
    }
    summary.kept += 1;
  }

  if (summary.orphaned || summary.expired) persist();
  return summary;
}

/** The retention settings in force, for the UI to report honestly. */
export const retention = () => ({
  alertRetentionDays: ALERT_RETENTION_DAYS,
  closedRetentionDays: CLOSED_RETENTION_DAYS,
});

/** Human verdicts on an AI finding. `null` = not yet judged. */
export const AI_VERDICTS = ["agree", "disagree"];

/**
 * How an investigation actually ended. Required to close, because a closure
 * with no stated outcome is the thing that makes efficacy metrics useless.
 *
 * The false-positive / benign split is the one that matters: "false-positive"
 * means the RULE was wrong (it fired on something it does not describe) and is
 * a defect to tune; "benign" means the rule was right but the activity was
 * authorized. Collapsing the two would blame the ruleset for normal admin work
 * and hide the detections that genuinely need fixing.
 */
export const DISPOSITIONS = ["true-positive", "false-positive", "benign"];

/** Every record, as { id: record }. Read-only view for the metrics layer. */
export function all() {
  return { ...state };
}

/**
 * Set/patch triage state for an alert. Returns { ok, record } or { ok:false,
 * error }. `by` is the acting username. `assignee`/`note`/`aiVerdict` optional.
 *
 * THIS IS THE ONLY WRITER OF WORKFLOW STATE, AND IT REQUIRES A HUMAN ACTOR.
 * `by` comes from an authenticated analyst+ session (see requireRole in
 * auth.js) and is rejected if absent — so an automated caller cannot advance
 * or close an investigation even if it reaches this function. The AI layer
 * (server/analysis.js) writes only to its own advisory store and never calls
 * this. "A person must confirm and close" is therefore a server-side
 * constraint, not a UI convention.
 */
export function set(id, { status, assignee, note, aiVerdict, disposition, context }, by) {
  if (!id) return { ok: false, error: "missing alert id" };
  if (typeof by !== "string" || !by.trim()) {
    return { ok: false, error: "triage requires an authenticated human actor" };
  }
  if (status !== undefined && !STATUSES.includes(status)) {
    return { ok: false, error: `status must be one of ${STATUSES.join(", ")}` };
  }
  if (aiVerdict !== undefined && aiVerdict !== null && !AI_VERDICTS.includes(aiVerdict)) {
    return { ok: false, error: `aiVerdict must be one of ${AI_VERDICTS.join(", ")}` };
  }
  if (disposition !== undefined && disposition !== null && !DISPOSITIONS.includes(disposition)) {
    return { ok: false, error: `disposition must be one of ${DISPOSITIONS.join(", ")}` };
  }

  const prev = state[id] || {};
  const nextStatus = status ?? prev.status ?? "new";
  const nextDisposition = disposition !== undefined ? disposition : (prev.disposition ?? null);
  // Closing without stating the outcome is rejected server-side. Otherwise the
  // efficacy numbers below silently become "of the closures that happened to be
  // labelled", which is not a measurement.
  if (nextStatus === "closed" && !nextDisposition) {
    return { ok: false, error: `closing requires a disposition: ${DISPOSITIONS.join(", ")}` };
  }

  const now = new Date().toISOString();
  const record = {
    status: nextStatus,
    assignee: assignee !== undefined ? assignee : (prev.assignee ?? null),
    note: note !== undefined ? note : (prev.note ?? ""),
    // Did the human agree with the AI's flag? Recorded so the scorer's
    // precision can be measured against analyst judgement.
    aiVerdict: aiVerdict !== undefined ? aiVerdict : (prev.aiVerdict ?? null),
    disposition: nextDisposition,
    // Denormalized alert facts, looked up server-side at first write. Kept here
    // so metrics survive the alert itself: ISM deletes old indices on the
    // retention schedule, and a record that only holds an index _id becomes
    // unattributable the moment its index is gone.
    context: context ?? prev.context ?? null,
    updatedBy: by,
    updatedAt: now,
    // When a human first picked this up. Never moves, so "time to first touch"
    // stays measurable no matter how many times the record is edited after.
    firstTouchedAt: prev.firstTouchedAt ?? now,
    v: SCHEMA,
  };
  state[id] = record;
  persist();
  return { ok: true, record };
}
