// Regression tests for the AI triage layer.
//
// Two things are being protected here. First, that the ranking is genuinely
// deterministic and explainable — the claim the whole feature is sold on.
// Second, and more important, the AUTHORITY BOUNDARY: an analysis pass must
// never produce, alter, or erase workflow state. That is a security property,
// not a UI preference, so it gets tests rather than a comment.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Both stores read their path from env at import time, so point them at a
// throwaway directory before importing anything.
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "dl-analysis-"));
process.env.DASH_FINDINGS_FILE = path.join(tmp, "findings.json");
process.env.DASH_TRIAGE_FILE = path.join(tmp, "triage.json");

const analysis = await import("../server/analysis.js");
const triage = await import("../server/triage.js");

/** Build a minimal alert in the shape the BFF hands to the scorer. */
function alert({ id, rule = "100999", level = 8, tactic = "Execution", host = "AMIGO", ts = "2026-07-30T12:00:00Z" }) {
  return {
    id,
    source: {
      timestamp: ts,
      rule: { id: rule, level, description: `rule ${rule}`, mitre: { id: ["T1059"], tactic: [tactic] } },
      agent: { name: host },
    },
  };
}

// --- Scoring ----------------------------------------------------------------

test("alerts below the minimum level are never considered", () => {
  const r = analysis.analyze([
    alert({ id: "low", level: 3 }),
    alert({ id: "ok", level: 12, tactic: "Credential Access" }),
  ]);
  assert.equal(r.considered, 1);
  assert.ok(!r.flagged.some((f) => f.alert.id === "low"));
});

test("the score is the documented sum of its factors", () => {
  // level 12 (40) + correlation rule (30) + Credential Access (15)
  // + real endpoint (10) = 95.
  const { score, reasons } = analysis.scoreAlert(
    alert({ id: "a", rule: "100400", level: 12, tactic: "Credential Access", host: "AMIGO" }));
  assert.equal(score, 95);
  assert.equal(reasons.length, 4, "every contribution must be explained");
  assert.ok(reasons.some((x) => x.includes("level 12")));
  assert.ok(reasons.some((x) => x.includes("correlation")));
  assert.ok(reasons.some((x) => x.includes("Credential Access")));
  assert.ok(reasons.some((x) => x.includes("AMIGO")));
});

test("lab infrastructure does not get the real-endpoint bonus", () => {
  const real = analysis.scoreAlert(alert({ id: "a", host: "AMIGO" }));
  const lab = analysis.scoreAlert(alert({ id: "b", host: "agent-linux-01" }));
  assert.equal(real.score - lab.score, 10);
});

test("alerts under the flag threshold are scored but not flagged", () => {
  // level 8 (20) + Execution (5) on lab infrastructure = 25, below the 45 threshold.
  const r = analysis.analyze([alert({ id: "quiet", level: 8, host: "agent-linux-01" })]);
  assert.equal(r.considered, 1);
  assert.equal(r.flagged.length, 0);
});

test("the same input always produces the same ranking", () => {
  const input = [
    alert({ id: "a", rule: "100400", level: 12, tactic: "Credential Access" }),
    alert({ id: "b", rule: "100601", level: 13, tactic: "Defense Evasion" }),
    alert({ id: "c", rule: "100101", level: 8, host: "agent-linux-01" }),
  ];
  const shape = (r) => r.flagged.map((f) => [f.alert.id, f.score, f.reasons.join("|")]);
  assert.deepEqual(shape(analysis.analyze(input)), shape(analysis.analyze(input)));
});

test("higher scores rank first", () => {
  const r = analysis.analyze([
    alert({ id: "lower", rule: "100601", level: 13, tactic: "Defense Evasion" }),   // 65
    alert({ id: "higher", rule: "100400", level: 12, tactic: "Credential Access" }), // 95
  ]);
  assert.deepEqual(r.flagged.map((f) => f.alert.id), ["higher", "lower"]);
});

// --- Grouping ---------------------------------------------------------------

test("repeats of one rule on one host collapse into a single review item", () => {
  const many = Array.from({ length: 6 }, (_, i) =>
    alert({ id: `dup${i}`, rule: "100701", level: 13, tactic: "Command and Control",
      ts: `2026-07-30T1${i}:00:00Z` }));
  const r = analysis.analyze(many);
  assert.equal(r.matched, 6, "all six are over the threshold");
  assert.equal(r.flagged.length, 1, "but they are one decision, so one queue item");
  assert.equal(r.flagged[0].occurrences, 6);
  assert.ok(r.flagged[0].reasons.some((x) => x.includes("fired 6x")));
  // The per-instance repetition reason is replaced, not duplicated.
  assert.equal(r.flagged[0].reasons.filter((x) => x.startsWith("repeated ")).length, 0);
});

test("the same rule on different hosts stays separate", () => {
  const r = analysis.analyze([
    alert({ id: "x", rule: "100701", level: 13, tactic: "Command and Control", host: "AMIGO" }),
    alert({ id: "y", rule: "100701", level: 13, tactic: "Command and Control", host: "amigo-wsl" }),
  ]);
  assert.equal(r.flagged.length, 2, "two hosts is two investigations");
});

// --- Authority boundary (the security-critical part) ------------------------

test("a run produces advisory findings only — no workflow state", async () => {
  const summary = await analysis.run([
    alert({ id: "adv", rule: "100400", level: 12, tactic: "Credential Access" }),
  ], "runner");
  assert.equal(summary.flagged, 1);

  const finding = analysis.getMany(["adv"]).adv;
  assert.ok(finding.flagged);
  for (const forbidden of ["status", "assignee", "updatedBy", "resolved", "closed", "reviewed"]) {
    assert.ok(!(forbidden in finding), `findings must not carry "${forbidden}"`);
  }
  // `by` records who triggered the pass. It is not a review.
  assert.equal(finding.by, "runner");
});

test("a run never writes to the triage store", async () => {
  await analysis.run([alert({ id: "untouched", rule: "100400", level: 12, tactic: "Credential Access" })], "runner");
  assert.equal(triage.get("untouched"), null,
    "an analysis pass must not create triage state for an alert");
});

test("a re-run cannot reopen or overwrite a human's decision", async () => {
  const a = alert({ id: "decided", rule: "100400", level: 12, tactic: "Credential Access" });
  await analysis.run([a], "runner");

  const closed = triage.set("decided", { status: "closed", note: "benign", aiVerdict: "disagree" }, "analyst-jo");
  assert.ok(closed.ok);

  await analysis.run([a], "runner");           // the AI looks at it again...
  const after = triage.get("decided");
  assert.equal(after.status, "closed");        // ...and changes nothing.
  assert.equal(after.updatedBy, "analyst-jo");
  assert.equal(after.note, "benign");
  assert.equal(after.updatedAt, closed.record.updatedAt);
});

test("each pass replaces the advisory layer so stale flags cannot linger", async () => {
  await analysis.run([alert({ id: "old", rule: "100400", level: 12, tactic: "Credential Access" })], "runner");
  assert.ok(analysis.getMany(["old"]).old);
  await analysis.run([alert({ id: "new", rule: "100400", level: 12, tactic: "Credential Access" })], "runner");
  assert.equal(analysis.getMany(["old"]).old, undefined);
  assert.ok(analysis.getMany(["new"]).new);
});

// --- The LLM is genuinely optional ------------------------------------------

test("the model layer is off unless explicitly enabled", async () => {
  const cfg = analysis.config();
  assert.equal(cfg.llmEnabled, false);
  assert.equal(cfg.llmModel, null, "no model is named when the layer is off");
  // No network call, no API key, no failure: it simply returns nothing.
  assert.deepEqual(await analysis.summarize([{ alert: alert({ id: "a" }) }]), {});
});

test("scoring works with no model configured at all", async () => {
  const summary = await analysis.run([
    alert({ id: "nokey", rule: "100400", level: 12, tactic: "Credential Access" }),
  ], "runner");
  assert.equal(summary.llm, false);
  assert.equal(analysis.getMany(["nokey"]).nokey.summary, null);
});

test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
