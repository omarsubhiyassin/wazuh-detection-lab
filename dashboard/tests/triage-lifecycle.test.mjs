// Tests for the triage record's identity and lifetime.
//
// Records are keyed by an OpenSearch _id, which stops meaning anything once ISM
// deletes that alert's index. Two failure modes follow, and they pull in
// opposite directions:
//
//   * keep everything  -> the queue counts report work that no longer exists
//   * delete on age    -> the efficacy history is destroyed, since closed
//                         records ARE the measurement
//
// So the rules under test are: open records that have aged out go, closed
// records stay by default, and anything that cannot be aged is never guessed at.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "dl-life-"));

const DAY = 86400_000;
const NOW = Date.parse("2026-07-31T00:00:00.000Z");
const ago = (days) => new Date(NOW - days * DAY).toISOString();

/** A fresh store module backed by its own file, seeded with raw records. */
async function freshStore(seed) {
  const file = path.join(tmp, `store-${Math.random().toString(16).slice(2)}.json`);
  if (seed) fs.writeFileSync(file, JSON.stringify(seed));
  process.env.DASH_TRIAGE_FILE = file;
  const mod = await import(`../server/triage.js?f=${path.basename(file)}`);
  return { mod, file };
}

const rec = ({ status = "new", alertTs = ago(1), disposition = null, by = "jo" } = {}) => ({
  status, assignee: null, note: "", aiVerdict: null, disposition,
  context: { ruleId: "100101", ruleLevel: 12, description: "d", host: "AMIGO", alertTs },
  updatedBy: by, updatedAt: ago(0), firstTouchedAt: ago(0), v: 2,
});

// --- Migration --------------------------------------------------------------

test("a record written before the metrics work is readable, not discarded", async () => {
  const { mod } = await freshStore({
    legacy: { status: "investigating", assignee: "sam", note: "old", updatedBy: "sam",
      updatedAt: "2026-07-01T10:00:00.000Z" },
  });
  const r = mod.get("legacy");
  assert.equal(r.status, "investigating");
  assert.equal(r.note, "old");
  assert.equal(r.v, mod.SCHEMA);
});

test("migration never invents facts it does not have", async () => {
  const { mod } = await freshStore({
    legacy: { status: "closed", updatedBy: "sam", updatedAt: "2026-07-01T10:00:00.000Z" },
  });
  const r = mod.get("legacy");
  // Fabricating a disposition or a rule id here would silently corrupt the
  // efficacy numbers with data nobody actually recorded.
  assert.equal(r.disposition, null);
  assert.equal(r.context, null);
  // updatedAt is the only defensible stand-in for a first touch.
  assert.equal(r.firstTouchedAt, "2026-07-01T10:00:00.000Z");
});

test("a corrupt entry is dropped rather than crashing the store", async () => {
  const { mod } = await freshStore({ bad: null, alsoBad: "not an object", good: rec() });
  assert.equal(mod.get("bad"), null);
  assert.equal(mod.get("alsoBad"), null);
  assert.ok(mod.get("good"));
});

// --- Pruning ----------------------------------------------------------------

test("open records whose alert has aged out are dropped", async () => {
  const { mod } = await freshStore({
    stale: rec({ status: "new", alertTs: ago(45) }),
    alsoStale: rec({ status: "investigating", alertTs: ago(31) }),
    fresh: rec({ status: "new", alertTs: ago(5) }),
  });
  const s = mod.prune({ alertRetentionDays: 30, now: NOW });
  assert.equal(s.orphaned, 2);
  assert.equal(mod.get("stale"), null);
  assert.equal(mod.get("alsoStale"), null);
  assert.ok(mod.get("fresh"), "an alert still in the indexer is still actionable");
});

test("closed records survive by default — they are the efficacy history", async () => {
  const { mod } = await freshStore({
    ancient: rec({ status: "closed", disposition: "false-positive", alertTs: ago(400) }),
  });
  const s = mod.prune({ alertRetentionDays: 30, now: NOW });
  assert.equal(s.expired, 0);
  const kept = mod.get("ancient");
  assert.ok(kept, "closing an alert is the measurement; the alert itself is disposable");
  assert.equal(kept.context.ruleId, "100101",
    "and it stays attributable to its rule without the alert");
});

test("closed records expire only when a retention is explicitly configured", async () => {
  const { mod } = await freshStore({
    old: rec({ status: "closed", disposition: "benign", alertTs: ago(200) }),
    recent: rec({ status: "closed", disposition: "benign", alertTs: ago(10) }),
  });
  const s = mod.prune({ alertRetentionDays: 30, closedRetentionDays: 90, now: NOW });
  assert.equal(s.expired, 1);
  assert.equal(mod.get("old"), null);
  assert.ok(mod.get("recent"));
});

test("a record with no alert timestamp is never aged out on a guess", async () => {
  const { mod } = await freshStore({
    unaged: { status: "new", updatedBy: "jo", updatedAt: ago(500), context: null },
  });
  const s = mod.prune({ alertRetentionDays: 30, closedRetentionDays: 1, now: NOW });
  assert.equal(s.unaged, 1);
  assert.equal(s.orphaned, 0);
  assert.ok(mod.get("unaged"), "deleting real work on an assumption is worse than keeping it");
});

test("pruning reports what it did and survives a restart", async () => {
  const { mod, file } = await freshStore({
    gone: rec({ status: "new", alertTs: ago(90) }),
    stays: rec({ status: "closed", disposition: "true-positive", alertTs: ago(90) }),
  });
  const s = mod.prune({ alertRetentionDays: 30, now: NOW });
  assert.deepEqual(
    { scanned: s.scanned, orphaned: s.orphaned, expired: s.expired, kept: s.kept },
    { scanned: 2, orphaned: 1, expired: 0, kept: 1 });
  const onDisk = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.deepEqual(Object.keys(onDisk), ["stays"], "the prune was persisted");
});

test("pruning corrects the queue counts rather than leaving them inflated", async () => {
  const { mod } = await freshStore({
    ghost1: rec({ status: "new", alertTs: ago(60) }),
    ghost2: rec({ status: "new", alertTs: ago(60) }),
    real: rec({ status: "new", alertTs: ago(2) }),
  });
  assert.equal(mod.counts().new, 3, "before: the sidebar would claim 3 outstanding");
  mod.prune({ alertRetentionDays: 30, now: NOW });
  assert.equal(mod.counts().new, 1, "after: only work that can actually be opened");
});

// --- Server-side filter resolution ------------------------------------------

test("ids can be resolved by status for a whole-store filter", async () => {
  const { mod } = await freshStore({
    a: rec({ status: "closed", disposition: "benign" }),
    b: rec({ status: "closed", disposition: "benign" }),
    c: rec({ status: "investigating" }),
  });
  assert.deepEqual(mod.idsByStatus("closed").sort(), ["a", "b"]);
  assert.deepEqual(mod.idsByStatus("investigating"), ["c"]);
  assert.deepEqual(mod.idsByStatus("new"), [],
    "an empty result must be empty, not everything");
  assert.equal(mod.allIds().length, 3);
});

test("new writes carry the schema version", async () => {
  const { mod } = await freshStore();
  const r = mod.set("fresh-write", { status: "acknowledged" }, "jo");
  assert.equal(r.record.v, mod.SCHEMA);
});

test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
