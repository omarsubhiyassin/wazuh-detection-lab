# Architecture

## Data flow

```
┌─────────────────────┐   writes real-format log files   ┌──────────────────┐
│ Synthetic Log Gen   │ ───────────────────────────────► │  Wazuh Agent     │
│ (Python)            │   auth.log / windows_events.json  │  (localfile tail)│
│  • benign baseline  │   / eve.json / zeek.json          └────────┬─────────┘
│  • MITRE scenarios  │   + ground_truth.jsonl (labels)            │ 1514/tcp (TLS)
└─────────────────────┘                                            ▼
                                                    ┌──────────────────────────┐
                                                    │      Wazuh Manager        │
                                                    │  decoders → rule engine   │
                                                    │  MITRE tags + correlation │
                                                    └────────┬──────────────────┘
                                                             │ Filebeat
                                                             ▼
                                                    ┌──────────────────────────┐
                                                    │  Wazuh Indexer (OpenSearch)│
                                                    │  index: wazuh-alerts-*     │
                                                    └───┬───────────────────┬────┘
                                                        │                   │
                                            ┌───────────▼──────┐   ┌────────▼──────────┐
                                            │ Wazuh Dashboard  │   │  Custom Dashboard │
                                            │ (ops/debugging)  │   │  React, ATT&CK    │
                                            └──────────────────┘   │  heatmap; queries │
                                                                   │  indexer directly │
                                                                   └───────────────────┘
```

## Components

### Wazuh single-node stack (`infra/`)
- **Manager** — decoders parse raw logs; the rule engine evaluates built-in + our
  custom rules; matches carry native MITRE ATT&CK tags (`rule.mitre.id`,
  `rule.mitre.tactic`). Filebeat ships alerts to the indexer.
- **Indexer** — OpenSearch fork; stores alerts in `wazuh-alerts-*`.
- **Dashboard** — OpenSearch-Dashboards fork; used for operations and debugging.
- **Linux agent** — tails the generator's output files and forwards over TLS.

### Synthetic log generator (`generator/`)
Emits **byte-accurate real formats** so Wazuh's built-in decoders parse them for free,
keeping our custom work at the *detection-logic* layer:

| Domain | Format | Decoded by |
|--------|--------|-----------|
| Linux auth | sshd/sudo `auth.log` (syslog) | built-in |
| Windows auth | Security 4624/4625/4672/4688/4720/1102 as Event JSON | built-in |
| Endpoint | Sysmon 1/3/7/8/10/11/13 as Event JSON | built-in Sysmon ruleset |
| Network | Zeek conn/dns/http + Suricata `eve.json` | built-in |

Three layers of output:
1. **Baseline noise** — realistic benign activity with diurnal rhythm and multiple
   users/hosts, so detections aren't trivially true.
2. **Attack scenarios** — YAML playbooks (`generator/scenarios/`) describing ordered
   kill-chain steps with correlated events (same host/user/src-IP) and controllable
   timing (burst vs. low-and-slow).
3. **Ground truth** — every attack event also writes to `ground_truth.jsonl`
   (`event_id, timestamp, technique_id, tactic, scenario, host, expected_rule`),
   which the validation harness scores against.

Modes: deterministic seed; `--backfill` (past timestamps to populate instantly) vs.
`--stream` (real-time for demos); global time-compression factor.

### Detections (`detections/`)
Custom rules (XML, IDs 100000+), one file per ATT&CK tactic. Signature rules in
Phase 3; frequency/`if_matched_sid` correlation (brute-force→success, beaconing,
persistence-after-access) in Phase 4. Every rule ships a `wazuh-logtest` case.

### Custom dashboard (`dashboard/`)
React (Vite + TS) SPA querying the **Indexer's OpenSearch API** read-only (chosen so
alert docs' MITRE fields are directly available). Views: ATT&CK matrix heatmap, live
alert feed with raw-log detail drawer, filters (tactic/technique/host/severity/time),
and detection-engineering metrics fed by the validation harness.

### Validation (`validation/`)
Joins `ground_truth.jsonl` against indexed alerts to compute per-technique detection
rate, false negatives, and false positives (vs. the benign baseline), emitting a
Markdown/JSON coverage report and an ATT&CK-Navigator layer JSON.

## Key design decisions

| Decision | Choice | Why |
|----------|--------|-----|
| Deployment | Docker single-node on WSL2 | Lab-appropriate; multi-node adds only HA |
| Log formats | Emit real formats | Built-in decoders parse them; realistic; less plumbing |
| Windows telemetry | Synthetic JSON only | Proves detections without a Windows VM; reproducible |
| Dashboard source | Indexer/OpenSearch API | MITRE tags present in alert docs; flexible for custom heatmap |
| Vendored stack | Pinned tag, gitignored | Clean version bumps; pristine vendor files |
