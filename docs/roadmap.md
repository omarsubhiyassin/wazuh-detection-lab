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

Deferred: a persistence-after-execution chain (encoded PS → scheduled task on one host)
needs a tight-window kill-chain scenario in the generator; the current scenarios are
placed too far apart in the window to correlate. Future generator enhancement.

## Phase 5 — Custom dashboard
React SPA on the Indexer API: ATT&CK heatmap, alert feed + raw-log drawer, filters,
detection metrics. Read-only service account; secrets in `infra/.env`.

## Phase 6 — Validation harness + docs
Score alerts vs. ground truth → per-technique detection rate, FN, FP; coverage report +
ATT&CK-Navigator layer. Per-detection READMEs (hypothesis, source, logic, mapping, test,
limitations); top-level coverage map; runbook.

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
