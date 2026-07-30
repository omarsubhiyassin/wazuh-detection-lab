// Alert triage state for the dashboard — the deliberate, least-privilege write
// path. Kept OUT of the indexer (alerts stay read-only): a small JSON store on
// the BFF host, keyed by alert id, holding status + assignee + note + who/when.
// Persisted to disk so it survives a BFF restart; single-file so multiple
// analysts on one BFF share state. Migrate to a dedicated indexer index later
// if multi-BFF is ever needed.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FILE = process.env.DASH_TRIAGE_FILE ||
  path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "triage-state.json");

export const STATUSES = ["new", "acknowledged", "investigating", "closed"];

let state = load();

function load() {
  try { return JSON.parse(fs.readFileSync(FILE, "utf8")) || {}; }
  catch { return {}; }
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

/** Human verdicts on an AI finding. `null` = not yet judged. */
export const AI_VERDICTS = ["agree", "disagree"];

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
export function set(id, { status, assignee, note, aiVerdict }, by) {
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
  const prev = state[id] || {};
  const record = {
    status: status ?? prev.status ?? "new",
    assignee: assignee !== undefined ? assignee : (prev.assignee ?? null),
    note: note !== undefined ? note : (prev.note ?? ""),
    // Did the human agree with the AI's flag? Recorded for the audit trail and
    // so false-positive rates per rule can be measured later.
    aiVerdict: aiVerdict !== undefined ? aiVerdict : (prev.aiVerdict ?? null),
    updatedBy: by,
    updatedAt: new Date().toISOString(),
  };
  state[id] = record;
  persist();
  return { ok: true, record };
}
