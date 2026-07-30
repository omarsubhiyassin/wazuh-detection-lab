// Tests for the detection efficacy metrics.
//
// The risk with a metrics layer is not that it crashes — it is that it reports
// a confident number derived from nothing. So most of these assert the honesty
// properties: no rate is invented before there is something to divide by,
// unattributable records are surfaced rather than absorbed, and the
// false-positive / benign distinction survives aggregation.
import test from "node:test";
import assert from "node:assert/strict";

const { compute } = await import("../server/metrics.js");

const HOUR = 3600_000;

/** A triage record as the store would hold it. */
function rec({
  rule = "100101", level = 12, host = "AMIGO", disposition = null, status = "closed",
  by = "jo", aiVerdict = null, alertTs = "2026-07-30T00:00:00.000Z",
  firstTouch = "2026-07-30T01:00:00.000Z", updated = "2026-07-30T02:00:00.000Z",
  context = undefined,
} = {}) {
  return {
    status, assignee: null, note: "", aiVerdict, disposition,
    context: context !== undefined ? context
      : { ruleId: rule, ruleLevel: level, description: `rule ${rule}`, host, alertTs },
    updatedBy: by, updatedAt: updated, firstTouchedAt: firstTouch,
  };
}

// --- Totals -----------------------------------------------------------------

test("an empty store reports zeros and no invented rates", () => {
  const m = compute({});
  assert.equal(m.totals.triaged, 0);
  assert.equal(m.totals.closed, 0);
  assert.deepEqual(m.rules, []);
  assert.equal(m.scorer.agreementRate, null, "no agreement rate without judgements");
  assert.equal(m.timing.medianTimeToCloseMs, null);
});

test("open and closed alerts are counted separately", () => {
  const m = compute({
    a: rec({ status: "investigating" }),
    b: rec({ disposition: "true-positive" }),
    c: rec({ disposition: "benign" }),
  });
  assert.equal(m.totals.triaged, 3);
  assert.equal(m.totals.closed, 2);
  assert.equal(m.totals.open, 1);
});

// --- Per-rule efficacy ------------------------------------------------------

test("false-positive rate is the share of CLOSED alerts an analyst called a rule defect", () => {
  const m = compute({
    a: rec({ rule: "100700", disposition: "false-positive" }),
    b: rec({ rule: "100700", disposition: "false-positive" }),
    c: rec({ rule: "100700", disposition: "false-positive" }),
    d: rec({ rule: "100700", disposition: "true-positive" }),
    e: rec({ rule: "100700", status: "investigating" }),   // open: not in the denominator
  });
  const r = m.rules.find((x) => x.ruleId === "100700");
  assert.equal(r.triaged, 5);
  assert.equal(r.closed, 4);
  assert.equal(r.falsePositiveRate, 75);
  assert.equal(r.precision, 25);
});

test("benign activity is not counted as a rule defect", () => {
  // The rule fired correctly; the behaviour was authorized. Blaming the rule
  // here would hide the detections that actually need tuning.
  const m = compute({
    a: rec({ rule: "100121", disposition: "benign" }),
    b: rec({ rule: "100121", disposition: "benign" }),
    c: rec({ rule: "100121", disposition: "true-positive" }),
  });
  const r = m.rules.find((x) => x.ruleId === "100121");
  assert.equal(r.falsePositiveRate, 0, "benign closures are not false positives");
  assert.equal(r.benignRate, 66.7);
  assert.equal(r.precision, 33.3);
});

test("a rule with nothing closed yet reports null rates, not 0%", () => {
  const m = compute({ a: rec({ rule: "100999", status: "acknowledged" }) });
  const r = m.rules.find((x) => x.ruleId === "100999");
  assert.equal(r.triaged, 1);
  assert.equal(r.closed, 0);
  assert.equal(r.falsePositiveRate, null, "0% would claim the rule is clean; it is unmeasured");
  assert.equal(r.precision, null);
});

test("the noisiest rule ranks first", () => {
  const m = compute({
    a: rec({ rule: "quiet", disposition: "true-positive" }),
    b: rec({ rule: "noisy", disposition: "false-positive" }),
    c: rec({ rule: "noisy", disposition: "false-positive" }),
  });
  assert.equal(m.rules[0].ruleId, "noisy");
});

test("rules are kept apart and levels carried through", () => {
  const m = compute({
    a: rec({ rule: "100101", level: 12 }, ),
    b: rec({ rule: "100601", level: 13 }),
  });
  assert.equal(m.rules.length, 2);
  assert.equal(m.rules.find((r) => r.ruleId === "100601").ruleLevel, 13);
});

// --- Attribution ------------------------------------------------------------

test("records with no rule context are reported, not silently dropped", () => {
  const m = compute({
    legacy: rec({ context: null, disposition: "true-positive" }),
    modern: rec({ rule: "100101", disposition: "true-positive" }),
  });
  assert.equal(m.totals.triaged, 2, "still counted in the totals");
  assert.equal(m.totals.unattributed, 1, "and flagged as unattributable");
  assert.equal(m.rules.length, 1, "but never invented into a fake rule bucket");
});

// --- Scorer accuracy --------------------------------------------------------

test("scorer agreement is measured only over flags a human actually judged", () => {
  const m = compute({
    a: rec({ aiVerdict: "agree", disposition: "true-positive" }),
    b: rec({ aiVerdict: "agree", disposition: "true-positive" }),
    c: rec({ aiVerdict: "disagree", disposition: "false-positive" }),
    d: rec({ aiVerdict: null, disposition: "benign" }),   // unjudged: excluded
  });
  assert.equal(m.scorer.judged, 3);
  assert.equal(m.scorer.agreed, 2);
  assert.equal(m.scorer.disagreed, 1);
  assert.equal(m.scorer.agreementRate, 66.7);
});

// --- Timing -----------------------------------------------------------------

test("time to close is measured from the alert, not from first touch", () => {
  const m = compute({
    a: rec({
      alertTs: "2026-07-30T00:00:00.000Z",
      firstTouch: "2026-07-30T01:00:00.000Z",
      updated: "2026-07-30T03:00:00.000Z",
      disposition: "true-positive",
    }),
  });
  assert.equal(m.timing.medianTimeToFirstTouchMs, HOUR);
  assert.equal(m.timing.medianTimeToCloseMs, 3 * HOUR);
});

test("the median resists a single outlier", () => {
  const at = (h) => `2026-07-30T${String(h).padStart(2, "0")}:00:00.000Z`;
  const m = compute({
    a: rec({ alertTs: at(0), updated: at(1), disposition: "true-positive" }),
    b: rec({ alertTs: at(0), updated: at(2), disposition: "true-positive" }),
    c: rec({ alertTs: at(0), updated: at(23), disposition: "true-positive" }),
  });
  assert.equal(m.timing.medianTimeToCloseMs, 2 * HOUR, "a mean would report 8.7h");
  assert.equal(m.timing.sampled, 3, "the sample size is always disclosed");
});

test("unusable or reversed timestamps are skipped rather than reported as negative", () => {
  const m = compute({
    a: rec({ alertTs: "not-a-date", updated: "2026-07-30T02:00:00.000Z", disposition: "benign" }),
    b: rec({ alertTs: "2026-07-30T05:00:00.000Z", updated: "2026-07-30T02:00:00.000Z", disposition: "benign" }),
  });
  assert.equal(m.timing.medianTimeToCloseMs, null);
  assert.equal(m.timing.sampled, 0);
});

// --- Analysts ---------------------------------------------------------------

test("closures are attributed to the analyst who made them", () => {
  const m = compute({
    a: rec({ by: "jo", disposition: "true-positive" }),
    b: rec({ by: "jo", disposition: "benign" }),
    c: rec({ by: "sam", disposition: "false-positive" }),
    d: rec({ by: "sam", status: "investigating" }),   // not a closure
  });
  assert.deepEqual(m.analysts, [{ user: "jo", closed: 2 }, { user: "sam", closed: 1 }]);
});
