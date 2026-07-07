# ATT&CK coverage map

Tracks which MITRE ATT&CK techniques the lab **injects** (generator) and **detects**
(rules), updated as phases land. The validation harness (Phase 6) produces the
authoritative machine-scored version + an ATT&CK-Navigator layer; this file is the
human-readable index.

Legend: ☐ planned · ◐ injected only · ● injected + detected

## v1 scope

| Technique | Name | Tactic | Data source | Injected | Detected |
|-----------|------|--------|-------------|:--:|:--:|
| T1110 | Brute Force | Credential Access | sshd auth.log | ◐ | ● |
| T1078 | Valid Accounts | Initial Access / Persistence | sshd auth.log | ◐ | ☐ |
| T1059.001 | PowerShell | Execution | Sysmon 1 | ◐ | ● |
| T1105 | Ingress Tool Transfer | Command & Control | Sysmon 1 | ◐ | ☐ |
| T1053.005 | Scheduled Task | Persistence / Execution | Sysmon 1 / Security 4698 | ◐ | ● |
| T1071.004 | DNS (App-Layer C2) | Command & Control | Suricata DNS | ◐ | ● |

Detected-by (rule ID → technique):
- **T1110** → built-in 5710/5712 (SSH brute force), verified end-to-end in Phase 1.
- **T1059.001** → custom **100101** (encoded PowerShell command line).
- **T1053.005** → custom **100110** (schtasks `/Create`) and **100121** (Security 4698 launching a suspicious interpreter).
- **T1071.004** → custom **100300** (DNS TXT query with long hex subdomain). Phase 4 adds a beacon-regularity correlation.

Gaps: **T1078** (success-after-brute-force) and **T1105** (the download itself) need Phase 4 correlation / network-side telemetry respectively; not yet detected.

## Detection catalog

Per-detection docs (hypothesis, data source, logic, ATT&CK mapping, test case,
limitations/evasions) live in `docs/detections/` and are added in Phase 3+.

## Notes on measurement

- **Injected** is set from the generator's `ground_truth.jsonl`.
- **Detected** is set only when a corresponding alert (matching host/time/technique)
  appears in `wazuh-alerts-*` during validation — not merely because a rule exists.
- False positives are measured against the benign baseline, not just the attack window.
