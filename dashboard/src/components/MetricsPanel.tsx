import { useEffect, useState } from "react";
import type { Metrics } from "../types";
import { getMetrics } from "../api";

/** Human-readable duration from milliseconds. */
function dur(ms: number | null): string {
  if (ms === null) return "—";
  const m = Math.round(ms / 60000);
  if (m < 60) return `${m}m`;
  const h = m / 60;
  return h < 48 ? `${h.toFixed(1)}h` : `${(h / 24).toFixed(1)}d`;
}

const rate = (v: number | null) => (v === null ? "—" : `${v}%`);

/**
 * Sample-size caveat. A 100% false-positive rate over two closures is not the
 * same claim as 40% over two hundred, and the UI should not let them look alike.
 */
function Confidence({ n }: { n: number }) {
  if (n === 0) return <span className="conf conf-none">unmeasured</span>;
  if (n < 5) return <span className="conf conf-low" title={`only ${n} closed`}>n={n}</span>;
  return <span className="conf" title={`${n} closed`}>n={n}</span>;
}

export function MetricsPanel({ onClose }: { onClose: () => void }) {
  const [m, setM] = useState<Metrics | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getMetrics().then(setM).catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  return (
    <div className="drawer-scrim" onClick={onClose}>
      <aside className="drawer drawer-wide" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-head">
          <h3>Detection efficacy</h3>
          <button className="close" onClick={onClose} aria-label="close">×</button>
        </div>

        <p className="muted">
          Which of our own rules are noisy, how fast alerts get handled, and how often
          analysts agreed with the scorer.
        </p>

        {error && <div className="error">{error}</div>}
        {!m ? <p className="muted">Loading…</p> : (
          <>
            <section className="tiles metric-tiles">
              <div className="tile"><div className="tile-n">{m.totals.triaged}</div><div className="tile-l">triaged</div></div>
              <div className="tile"><div className="tile-n">{m.totals.closed}</div><div className="tile-l">closed</div></div>
              <div className="tile"><div className="tile-n">{dur(m.timing.medianTimeToFirstTouchMs)}</div><div className="tile-l">median to first touch</div></div>
              <div className="tile"><div className="tile-n">{dur(m.timing.medianTimeToCloseMs)}</div><div className="tile-l">median to close</div></div>
            </section>

            <h4>Outcomes</h4>
            <div className="disp-summary">
              <span className="disp-chip disp-true-positive">{m.totals.dispositions["true-positive"]} true positive</span>
              <span className="disp-chip disp-false-positive">{m.totals.dispositions["false-positive"]} false positive</span>
              <span className="disp-chip disp-benign">{m.totals.dispositions.benign} benign</span>
            </div>

            <h4>Rules, noisiest first</h4>
            <div className="table-wrap">
              <table className="alerts">
                <thead>
                  <tr>
                    <th>Rule</th><th>Lvl</th><th>Triaged</th>
                    <th title="Share of closed alerts an analyst judged a detection defect">FP rate</th>
                    <th title="Rule fired correctly, activity was authorized">Benign</th>
                    <th title="Share of closed alerts that were real">Precision</th>
                    <th>Median close</th><th>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {m.rules.map((r) => (
                    <tr key={r.ruleId}>
                      <td className="mono">{r.ruleId}
                        {r.description && <div className="muted rule-desc">{r.description}</div>}</td>
                      <td>{r.ruleLevel ?? "—"}</td>
                      <td>{r.triaged}</td>
                      <td className={r.falsePositiveRate !== null && r.falsePositiveRate >= 50 ? "fp-bad" : undefined}>
                        {rate(r.falsePositiveRate)}
                      </td>
                      <td>{rate(r.benignRate)}</td>
                      <td>{rate(r.precision)}</td>
                      <td className="nowrap">{dur(r.medianTimeToCloseMs)}</td>
                      <td><Confidence n={r.closed} /></td>
                    </tr>
                  ))}
                  {!m.rules.length && (
                    <tr><td colSpan={8} className="muted center">
                      Nothing triaged yet — close a few alerts and these fill in.
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>

            <h4>Scorer accuracy</h4>
            <p className="muted">
              {m.scorer.judged === 0
                ? "No AI flags have been judged yet."
                : `Analysts agreed with ${m.scorer.agreed} of ${m.scorer.judged} judged flags (${rate(m.scorer.agreementRate)}).`}
            </p>

            {m.analysts.length > 0 && (
              <>
                <h4>Closures by analyst</h4>
                <ul className="analyst-list">
                  {m.analysts.map((a) => (
                    <li key={a.user}><span>{a.user}</span><span className="mono">{a.closed}</span></li>
                  ))}
                </ul>
              </>
            )}

            <p className="rail-note metric-caveat">
              These are <strong>analyst-reported outcomes, not ground truth</strong>. A rule's
              false-positive rate means "the share of closures where an analyst said this rule
              fired on something it does not describe" — it is only as good as the triage
              discipline behind it. Alerts nobody triaged are invisible here by construction:
              this measures reviewed alerts, not all alerts.
              {m.totals.unattributed > 0 && ` ${m.totals.unattributed} record(s) predate rule
              attribution and are counted in the totals but not against any rule.`}
            </p>
          </>
        )}
      </aside>
    </div>
  );
}
