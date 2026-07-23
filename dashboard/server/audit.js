// Append-only audit log for the dashboard: who logged in, and who changed an
// alert's triage state. One JSON object per line (JSONL) so it is greppable and
// append-only. Admins read it via /api/audit. Zero dependencies.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FILE = process.env.DASH_AUDIT_FILE ||
  path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "audit.log");

/** Append an event with a server timestamp. Never throws into the request path. */
export function record(event) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...event }) + "\n";
  try {
    fs.appendFileSync(FILE, line, { mode: 0o600 });
  } catch (e) {
    console.error("[dashboard] audit write failed:", String(e));
  }
}

/** The most recent `limit` events, newest first. */
export function readRecent(limit = 200) {
  let text;
  try { text = fs.readFileSync(FILE, "utf8"); } catch { return []; }
  const lines = text.split("\n").filter(Boolean);
  const out = [];
  for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
    try { out.push(JSON.parse(lines[i])); } catch { /* skip corrupt line */ }
  }
  return out;
}
