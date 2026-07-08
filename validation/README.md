# Validation harness

Closes the measurement loop: joins the generator's **ground truth** (what was injected)
against the **alerts in the indexer** (what was detected) and scores per-technique
detection rate, false negatives, and false positives — the metric that makes this a
detection-*engineering* project rather than "a SIEM with some rules."

## How it works

`validate.py` reads `generator/ground_truth/ground_truth.jsonl`, queries `wazuh-alerts-*`
(with the read-only account) for the run's time window, and matches each injected event
to alerts:

- **Detected (TP):** within ±`--window` seconds of the injected event, an alert fired whose
  `rule.mitre.id` contains the technique **or** whose `rule.id` is in the label's
  `expected_rules`.
- **False negative (FN):** an injected event with no matching alert.
- **False positive (FP):** a custom-rule alert (`id >= 100000`, level > 0) in the window
  that matches no injected event — measured against the benign baseline the generator mixes in.

## Run

The ground truth and the indexed alerts must come from the **same run**. Because the agent's
logcollector forwards newly *appended* lines, generate in **stream** mode so injected events
flow live and their timestamps line up with the alerts:

```bash
# 1) stream a fresh dataset through the live pipeline (~2 min at 180x)
cd generator
python3 generate.py --mode stream --hours 6 --compression 180 \
  --out   ~/detection-lab/generator/output \
  --ground-truth ~/detection-lab/generator/ground_truth/ground_truth.jsonl

# 2) let Filebeat flush, then score (RO creds from env or dashboard/.env)
export INDEXER_URL=https://localhost:9200 INDEXER_RO_USER=detectionlab_ro
export INDEXER_RO_PASSWORD=...          # the read-only account password
python3 validation/validate.py --ground-truth ~/detection-lab/generator/ground_truth/ground_truth.jsonl
```

## Output (`validation/reports/`, gitignored)

| File | Contents |
|------|----------|
| `coverage.md` | human-readable per-technique table + totals |
| `coverage.json` | machine-readable result (per-technique + per-event detail) |
| `attack-navigator-layer.json` | drop into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to render coverage on the matrix |

## Tuning

- `--window` (default 120s) — match tolerance between an injected event and its alert.
- `--pad` (default 300s) — how far outside the ground-truth span to pull alerts.
- Correlation techniques (T1078, DNS beacon) fire slightly after their trigger, which the
  default window comfortably covers.
