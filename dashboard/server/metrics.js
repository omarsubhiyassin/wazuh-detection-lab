// Detection efficacy metrics.
//
// The point of this module is to close the loop: rules produce alerts, analysts
// triage them, and the triage record says whether the rule was actually right.
// Aggregating that tells you which of your own detections are noisy — which is
// the question a detection engineer is really being paid to answer.
//
// WHAT THESE NUMBERS ARE, HONESTLY:
//   They are ANALYST-REPORTED outcomes, not ground truth. A rule's "false
//   positive rate" here means "the share of closures where an analyst said this
//   rule fired on something it does not describe". That is the best signal
//   available short of a labelled corpus, and it is only as good as the triage
//   discipline behind it. Small sample sizes are reported rather than hidden,
//   so a 100% FP rate over 2 closures is visibly not the same claim as 40% over
//   200.
//
//   Everything here is derived from the triage store. Alerts nobody triaged are
//   invisible to it by construction — this measures reviewed alerts, not all
//   alerts, and the UI says so.
import * as triage from "./triage.js";

/** Milliseconds between two ISO timestamps, or null if either is unusable. */
function elapsed(fromISO, toISO) {
  const a = Date.parse(fromISO ?? "");
  const b = Date.parse(toISO ?? "");
  if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) return null;
  return b - a;
}

/** Median of a numeric array (more honest than a mean at small n). */
function median(xs) {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid] : Math.round((s[mid - 1] + s[mid]) / 2);
}

const pct = (n, d) => (d > 0 ? Math.round((n / d) * 1000) / 10 : null);

/**
 * Aggregate the triage store into per-rule and fleet-wide efficacy numbers.
 * Pure over its input, so it is trivially testable.
 */
export function compute(records = triage.all()) {
  const entries = Object.entries(records);

  const byRule = new Map();
  const byAnalyst = new Map();
  const timesToClose = [];
  const timesToFirstTouch = [];
  let closed = 0, unattributed = 0;
  const dispositions = { "true-positive": 0, "false-positive": 0, benign: 0 };
  const verdicts = { agree: 0, disagree: 0 };

  for (const [, rec] of entries) {
    if (!rec) continue;
    const ctx = rec.context || null;

    // Records written before rule context was stamped can still be counted in
    // the totals, but they cannot be attributed to a rule. Reported separately
    // rather than quietly dropped or lumped into a bogus "unknown" rule.
    if (!ctx?.ruleId) unattributed += 1;

    if (rec.aiVerdict && verdicts[rec.aiVerdict] !== undefined) verdicts[rec.aiVerdict] += 1;

    const ttft = elapsed(ctx?.alertTs, rec.firstTouchedAt);
    if (ttft !== null) timesToFirstTouch.push(ttft);

    let key = null;
    if (ctx?.ruleId) {
      key = String(ctx.ruleId);
      if (!byRule.has(key)) {
        byRule.set(key, {
          ruleId: key,
          ruleLevel: ctx.ruleLevel ?? null,
          description: ctx.description ?? null,
          triaged: 0, closed: 0,
          truePositive: 0, falsePositive: 0, benign: 0,
          agreed: 0, disagreed: 0,
          _times: [],
        });
      }
      const r = byRule.get(key);
      r.triaged += 1;
      if (rec.aiVerdict === "agree") r.agreed += 1;
      if (rec.aiVerdict === "disagree") r.disagreed += 1;
    }

    if (rec.status !== "closed") continue;
    closed += 1;

    if (rec.disposition && dispositions[rec.disposition] !== undefined) {
      dispositions[rec.disposition] += 1;
    }
    if (rec.updatedBy) {
      const a = byAnalyst.get(rec.updatedBy) ?? { user: rec.updatedBy, closed: 0 };
      a.closed += 1;
      byAnalyst.set(rec.updatedBy, a);
    }

    const ttc = elapsed(ctx?.alertTs, rec.updatedAt);
    if (ttc !== null) timesToClose.push(ttc);

    if (key) {
      const r = byRule.get(key);
      r.closed += 1;
      if (rec.disposition === "true-positive") r.truePositive += 1;
      if (rec.disposition === "false-positive") r.falsePositive += 1;
      if (rec.disposition === "benign") r.benign += 1;
      if (ttc !== null) r._times.push(ttc);
    }
  }

  // Rank by false-positive rate, then by how much noise the rule produced —
  // "which detection should I tune first" is the question this answers.
  const rules = [...byRule.values()]
    .map(({ _times, ...r }) => ({
      ...r,
      // Share of CLOSED alerts an analyst judged a rule defect. Null until
      // something has actually been closed, rather than a misleading 0%.
      falsePositiveRate: pct(r.falsePositive, r.closed),
      // "Benign true positive": the rule was right, the activity was authorized.
      benignRate: pct(r.benign, r.closed),
      precision: pct(r.truePositive, r.closed),
      medianTimeToCloseMs: median(_times),
    }))
    .sort((a, b) =>
      (b.falsePositiveRate ?? -1) - (a.falsePositiveRate ?? -1) || b.triaged - a.triaged);

  const judged = verdicts.agree + verdicts.disagree;

  return {
    totals: {
      triaged: entries.length,
      closed,
      open: entries.length - closed,
      unattributed,
      dispositions,
    },
    // How good the deterministic scorer is at picking what deserves attention,
    // measured only against flags a human actually judged.
    scorer: {
      judged,
      agreed: verdicts.agree,
      disagreed: verdicts.disagree,
      agreementRate: pct(verdicts.agree, judged),
    },
    timing: {
      medianTimeToFirstTouchMs: median(timesToFirstTouch),
      medianTimeToCloseMs: median(timesToClose),
      sampled: timesToClose.length,
    },
    rules,
    analysts: [...byAnalyst.values()].sort((a, b) => b.closed - a.closed),
    generatedAt: new Date().toISOString(),
  };
}
