// Regression tests for the triage store — the only writer of workflow state.
//
// The load-bearing assertion is that `set()` refuses to act without a named
// human actor. Every "a person, not the AI, closes the investigation" claim in
// this project reduces to that one guard, so it is tested from several angles.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "dl-triage-"));
const store = path.join(tmp, "triage.json");
process.env.DASH_TRIAGE_FILE = store;

const triage = await import("../server/triage.js");

// --- The human gate ---------------------------------------------------------

test("an unnamed actor cannot write workflow state", () => {
  for (const actor of [undefined, null, "", "   ", 0, {}, ["someone"]]) {
    const r = triage.set("alert-1", { status: "closed" }, actor);
    assert.equal(r.ok, false, `actor ${JSON.stringify(actor)} must be rejected`);
    assert.match(r.error, /authenticated human actor/);
  }
  assert.equal(triage.get("alert-1"), null, "nothing was written");
});

test("a named human can advance and close an alert", () => {
  const r = triage.set("alert-2", { status: "investigating", assignee: "jo", note: "looking" }, "jo");
  assert.ok(r.ok);
  assert.equal(r.record.status, "investigating");
  assert.equal(r.record.updatedBy, "jo");
  assert.ok(Date.parse(r.record.updatedAt) > 0);
});

test("the acting user is recorded on every transition", () => {
  triage.set("alert-3", { status: "acknowledged" }, "first");
  const second = triage.set("alert-3",
    { status: "closed", note: "done", disposition: "true-positive" }, "second");
  assert.equal(second.record.updatedBy, "second", "the last actor owns the record");
});

test("an alert cannot be closed without stating the outcome", () => {
  // Without this, the efficacy numbers degrade to "of the closures somebody
  // happened to label", which is not a measurement.
  const r = triage.set("alert-3b", { status: "closed", note: "done" }, "jo");
  assert.equal(r.ok, false);
  assert.match(r.error, /closing requires a disposition/);
  assert.equal(triage.get("alert-3b"), null);
});

test("a disposition set earlier still satisfies a later close", () => {
  triage.set("alert-3c", { status: "investigating", disposition: "benign" }, "jo");
  assert.ok(triage.set("alert-3c", { status: "closed" }, "jo").ok);
});

test("clearing the disposition of a closed alert is rejected", () => {
  triage.set("alert-3d", { status: "closed", disposition: "true-positive" }, "jo");
  const r = triage.set("alert-3d", { disposition: null }, "jo");
  assert.equal(r.ok, false, "a closed alert cannot be left with no stated outcome");
  assert.equal(triage.get("alert-3d").disposition, "true-positive");
});

test("unknown dispositions are rejected", () => {
  const r = triage.set("alert-3e", { status: "closed", disposition: "probably-fine" }, "jo");
  assert.equal(r.ok, false);
  assert.match(r.error, /disposition must be one of/);
});

// --- Validation -------------------------------------------------------------

test("unknown statuses are rejected", () => {
  const r = triage.set("alert-4", { status: "resolved-by-ai" }, "jo");
  assert.equal(r.ok, false);
  assert.match(r.error, /status must be one of/);
  assert.equal(triage.get("alert-4"), null);
});

test("unknown AI verdicts are rejected", () => {
  const r = triage.set("alert-5", { aiVerdict: "probably" }, "jo");
  assert.equal(r.ok, false);
  assert.match(r.error, /aiVerdict must be one of/);
});

test("a missing alert id is rejected", () => {
  assert.equal(triage.set("", { status: "closed" }, "jo").ok, false);
});

test("agree and disagree are both recorded verbatim", () => {
  for (const v of triage.AI_VERDICTS) {
    const r = triage.set(`verdict-${v}`,
      { status: "closed", aiVerdict: v, disposition: "benign" }, "jo");
    assert.ok(r.ok);
    assert.equal(r.record.aiVerdict, v);
  }
});

test("the AI verdict and the disposition are independent judgements", () => {
  // "the AI was right to flag this" and "the rule was right to fire" are
  // different questions, and an analyst can answer them differently.
  const r = triage.set("alert-independent",
    { status: "closed", aiVerdict: "agree", disposition: "false-positive" }, "jo");
  assert.ok(r.ok);
  assert.equal(r.record.aiVerdict, "agree");
  assert.equal(r.record.disposition, "false-positive");
});

test("a verdict can be cleared back to 'not yet judged'", () => {
  triage.set("alert-6", { aiVerdict: "agree" }, "jo");
  const r = triage.set("alert-6", { aiVerdict: null }, "jo");
  assert.equal(r.record.aiVerdict, null);
});

// --- Patch semantics --------------------------------------------------------

test("omitted fields keep their previous values", () => {
  triage.set("alert-7", {
    status: "investigating", assignee: "jo", note: "context",
    aiVerdict: "agree", disposition: "true-positive",
  }, "jo");
  const r = triage.set("alert-7", { status: "closed" }, "sam");
  assert.equal(r.record.assignee, "jo");
  assert.equal(r.record.note, "context");
  assert.equal(r.record.aiVerdict, "agree");
  assert.equal(r.record.disposition, "true-positive");
  assert.equal(r.record.status, "closed");
});

test("alert context is stamped once and never overwritten by a later patch", () => {
  const ctx = { ruleId: "100101", ruleLevel: 12, host: "AMIGO", alertTs: "2026-07-30T00:00:00Z" };
  triage.set("alert-ctx", { status: "acknowledged", context: ctx }, "jo");
  const r = triage.set("alert-ctx", { status: "investigating" }, "jo");
  assert.deepEqual(r.record.context, ctx, "metrics attribution must survive later edits");
});

test("the first touch time is preserved across later transitions", () => {
  const first = triage.set("alert-touch", { status: "acknowledged" }, "jo").record.firstTouchedAt;
  const later = triage.set("alert-touch", { status: "investigating" }, "jo").record;
  assert.equal(later.firstTouchedAt, first);
  assert.ok(Date.parse(later.updatedAt) >= Date.parse(first), "updatedAt tracks the latest edit");
});

test("a first write defaults to the 'new' status", () => {
  const r = triage.set("alert-8", { note: "just a note" }, "jo");
  assert.equal(r.record.status, "new");
  assert.equal(r.record.assignee, null);
});

// --- Queue counts + durability ----------------------------------------------

test("counts report every status, including the empty ones", () => {
  const c = triage.counts();
  for (const s of triage.STATUSES) assert.equal(typeof c[s], "number");
  const total = Object.values(c).reduce((n, x) => n + x, 0);
  assert.equal(total, Object.keys(JSON.parse(fs.readFileSync(store, "utf8"))).length);
});

test("state survives a restart", async () => {
  triage.set("durable", { status: "closed", note: "persisted", disposition: "benign" }, "jo");
  // A fresh module instance reading the same file == a restarted BFF.
  const reloaded = await import(`../server/triage.js?restart=${Date.now()}`);
  const rec = reloaded.get("durable");
  assert.equal(rec.status, "closed");
  assert.equal(rec.note, "persisted");
  assert.equal(rec.updatedBy, "jo");
});

test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
