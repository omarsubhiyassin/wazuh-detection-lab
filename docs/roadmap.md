# Roadmap

Phased build. Each phase is independently demoable and feeds the measurement loop
(generator ground truth → detections → validation coverage).

## Phase 0 — Lab infra + repo scaffolding ✅
Repo structure, pinned Wazuh single-node stack as code, bootstrap script, compose
overlay for custom content, runbook. **Done.**

## Phase 1 — Wazuh up + ingestion smoke test ✅
Stack healthy (indexer green, dashboard reachable at `admin`/`SecretPassword`); Linux
agent `agent-linux-01` enrolled into the `detection-lab` group and Active. Verified
end-to-end: a burst of canonical `sshd` failed-login lines fired the built-in ruleset —
5710 (non-existent user) and 5712 (brute force) — and the alerts landed in
`wazuh-alerts-*`. Proves ingestion → decode → correlate → index → query. **Done.**

Two fixes were needed to get here (both in this repo now): the Phase 0 placeholder
`local_rules.xml` was an empty `<group>` (fatal to `analysisd`, crashed the manager), and
the `detection-lab` agent group had to exist on the manager before authd would enroll the
agent (bootstrap now creates it).

## Phase 2 — Synthetic log generator ✅
Baseline noise (multi-host/user, diurnal) plus the 4 v1 scenarios, emitting real formats
(sshd `auth.log`, Windows Event JSON, Suricata `eve.json`) with a `ground_truth.jsonl` of
labels. Seed-reproducible; `backfill`/`stream` modes with time compression. See
[generator/README.md](../generator/README.md). **Done.**

## Phase 3 — Decoders + signature detections ✅
No custom decoders needed — every generated event decodes via the built-in `json`
decoder (confirmed with `wazuh-logtest`). Signature rules with `<mitre>` tags in
[detections/rules/local_rules.xml](../detections/rules/local_rules.xml):
100101 encoded PowerShell (T1059.001), 100110 schtasks `/Create` + 100121 Security 4698
suspicious task (T1053.005), 100300 DNS TXT tunneling (T1071.004). Each has a frozen
sample + expected result under [detections/tests/](../detections/tests/); the
`run_logtest.sh` harness passes 6/6 (4 detections fire, 2 benign stay level 0). Verified
end-to-end: appended events produced 100101/100300 alerts in `wazuh-alerts-*` with
`rule.mitre.id` populated. **Done.**

## Phase 4 — Correlation / composite detections ✅
Composite rules in [local_rules.xml](../detections/rules/local_rules.xml):
100400 SSH brute-force→success (`if_sid` 5715 + `if_matched_sid` 5712 + `same_source_ip`
→ **T1078**) and 100410 DNS-beacon regularity (`if_matched_sid` 100300 + `frequency` 8 /
`timeframe` 600 + `same_field` src_ip → **T1071.004**, one alert per session instead of
per-query). Harness now 8/8 (multi-line samples; logtest keeps rule state across lines).
Verified end-to-end: 100400 (`mitre.id` T1078/T1110) and 100410 (T1071.004) alerts in
`wazuh-alerts-*`. **Done.**

Update: the persistence-after-execution chain is now implemented (rule 100420 +
`exec_to_persistence` scenario) — see the v1+ note under Phase 6.

## Phase 5 — Custom dashboard ✅
React (Vite + TS) SPA over a thin Express BFF ([../dashboard/](../dashboard/)). The BFF
holds a least-privilege indexer account (`detectionlab_ro`, read-only on `wazuh-alerts-*`,
verified 403 on writes/other indices) so the browser only ever calls same-origin `/api`.
Views: ATT&CK matrix heatmap (static tactic map, live `rule.mitre.id` counts), stat tiles
+ activity sparkline, filterable alert feed, and a detail drawer (raw log + `_source` +
MITRE). Verified end-to-end against live data (697 alerts): `npm run build` clean,
BFF aggregations correct, and the rendered UI — matrix, click-to-filter (T1071.004 → 33
alerts), and drawer — confirmed via browser. **Done.**

## Phase 6 — Validation harness + docs ✅
[validation/validate.py](../validation/validate.py) joins `ground_truth.jsonl` against the
indexed alerts (via the read-only account) and emits `coverage.md`, `coverage.json`, and an
ATT&CK-Navigator layer. Measured on a live stream run: **injected 6, detected 5, recall
83%, FN 1 (T1105), FP 0** — T1105 (the download) is the honest gap, correctly red in the
Navigator layer. Per-detection catalog in [detections.md](detections.md). Two correctness
fixes came out of the first run: the `powershell_cradle` builder was crediting T1105 to the
T1059.001 rule (fixed — T1105 now has no expected detector), and the FP metric is defined
run-order-independently (custom alert tagged with a non-injected technique) so a shared
indexer's prior-run alerts don't inflate it. **Done.**

Project complete for v1. **v1+ added:**
1. Execution→persistence kill-chain correlation (rule 100420 + `exec_to_persistence`
   scenario on its own host to avoid false correlation).
2. T1105 closed with network telemetry — the cradle now emits its HTTP download
   (Suricata), detected by rule 100310 (script/exe fetched from a bare IP), with benign
   HTTP added to the baseline (incl. a legit domain-hosted `.ps1`) as a false-positive guard.
3. Download↔execution composite (rule 100430): the encoded-PowerShell process also opens an
   outbound connection (Sysmon Event ID 3), correlated to the execution by
   `win.eventdata.processGuid`. Process-GUID correlation sidesteps the network↔endpoint
   identity gap (Suricata `src_ip` vs Sysmon `computer` share no field). Verified to fire only
   for the cradle process, not benign network noise.

Measured recall is now **100% (8/8 injected events), 0 FP**. Remaining iterations are depth,
not breadth: the four deferred scenarios (LSASS, new account, lateral movement, log
clearing) and domain-hosted/HTTPS download detection.

## v1 attack scenarios

| Scenario | ATT&CK | Primary source |
|----------|--------|----------------|
| Brute-force → successful login | T1110 → T1078 | sshd auth.log / Windows 4625→4624 |
| Encoded PowerShell download-cradle | T1059.001, T1105 | Sysmon 1 (Windows Event JSON) |
| Scheduled-task persistence | T1053.005 | Sysmon 1 + Windows 4698 |
| DNS-tunnel C2 beacon | T1071.004 | Zeek dns / Suricata eve.json |

Deferred to a later iteration (from the fuller library): LSASS credential access
(T1003.001), new local admin account (T1136.001), lateral movement (T1021), log
clearing (T1070.001).
