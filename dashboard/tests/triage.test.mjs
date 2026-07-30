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
  const second = triage.set("alert-3", { status: "closed", note: "done" }, "second");
  assert.equal(second.record.updatedBy, "second", "the last actor owns the record");
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
    const r = triage.set(`verdict-${v}`, { status: "closed", aiVerdict: v }, "jo");
    assert.ok(r.ok);
    assert.equal(r.record.aiVerdict, v);
  }
});

test("a verdict can be cleared back to 'not yet judged'", () => {
  triage.set("alert-6", { aiVerdict: "agree" }, "jo");
  const r = triage.set("alert-6", { aiVerdict: null }, "jo");
  assert.equal(r.record.aiVerdict, null);
});

// --- Patch semantics --------------------------------------------------------

test("omitted fields keep their previous values", () => {
  triage.set("alert-7", { status: "investigating", assignee: "jo", note: "context", aiVerdict: "agree" }, "jo");
  const r = triage.set("alert-7", { status: "closed" }, "sam");
  assert.equal(r.record.assignee, "jo");
  assert.equal(r.record.note, "context");
  assert.equal(r.record.aiVerdict, "agree");
  assert.equal(r.record.status, "closed");
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
  triage.set("durable", { status: "closed", note: "persisted" }, "jo");
  // A fresh module instance reading the same file == a restarted BFF.
  const reloaded = await import(`../server/triage.js?restart=${Date.now()}`);
  const rec = reloaded.get("durable");
  assert.equal(rec.status, "closed");
  assert.equal(rec.note, "persisted");
  assert.equal(rec.updatedBy, "jo");
});

test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
