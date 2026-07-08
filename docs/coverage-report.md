# Detection coverage report — snapshot

**Run date:** 2026-07-07 · **Method:** live stream run through the full pipeline
(generator → Wazuh agent → manager → indexer), scored by
[validation/validate.py](../validation/validate.py) against the generator's
`ground_truth.jsonl`. This is a committed snapshot; the live artifacts in
`validation/reports/` (`coverage.md`, `coverage.json`, `attack-navigator-layer.json`)
regenerate on every run.

## Headline

| Metric | Value |
|--------|------:|
| Injected events | **11** |
| Detected | **11** |
| **Recall** | **100%** |
| False negatives | **0** |
| False positives | **0** |
| Match window | ±120 s |

Nine ATT&CK techniques across seven tactics; every injected event detected, no false
positives. FP is measured against benign baseline noise deliberately shaped to resemble the
attacks (e.g. legit LSASS access at the same access mask a dumper uses, a domain-hosted
`.ps1` download, normal SSH/DNS/HTTP/Sysmon activity).

## Per technique

| Technique | Tactic | Inj. | Det. | Rate | Detecting rules |
|-----------|--------|:--:|:--:|:--:|-----------------|
| T1078 — Valid Accounts | Initial Access | 1 | 1 | 100% | 5715, 100400 |
| T1059.001 — PowerShell | Execution | 2 | 2 | 100% | 100101, 100420, 100430 |
| T1070.001 — Clear Event Logs | Defense Evasion | 1 | 1 | 100% | 100600, 100601 |
| T1053.005 — Scheduled Task | Persistence | 2 | 2 | 100% | 100110, 100121, 100420 |
| T1110 — Brute Force | Credential Access | 1 | 1 | 100% | 5710, 5712, 100400 |
| T1003.001 — LSASS Memory | Credential Access | 1 | 1 | 100% | 100700, 100701 |
| T1021.002 — SMB/Admin Shares | Lateral Movement | 1 | 1 | 100% | 100500 |
| T1071.004 — DNS C2 | Command & Control | 1 | 1 | 100% | 100300, 100410 |
| T1105 — Ingress Tool Transfer | Command & Control | 1 | 1 | 100% | 100310, 100430 |

`5xxx` are built-in Wazuh rules; `100xxx` are custom (see [detections.md](detections.md)).
Correlation rules: 100400 (brute-force→success), 100410 (DNS beacon), 100420
(execution→persistence), 100430 (download↔execution).

## Reproduce

```bash
cd generator && python3 generate.py --mode stream --hours 6 --compression 180 \
  --out ~/detection-lab/generator/output \
  --ground-truth ~/detection-lab/generator/ground_truth/ground_truth.jsonl
export INDEXER_URL=https://localhost:9200 INDEXER_RO_USER=detectionlab_ro
export INDEXER_RO_PASSWORD=...   # the read-only account password
python3 validation/validate.py --ground-truth ~/detection-lab/generator/ground_truth/ground_truth.jsonl
```

Scope note: 100% reflects coverage of the **injected** technique set (v1 + additions), not
all of ATT&CK. Growth is breadth (more scenarios) and depth (evasion-resistant variants),
tracked in [roadmap.md](roadmap.md).
