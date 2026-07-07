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
| T1078 | Valid Accounts | Initial Access / Persistence | sshd auth.log | ◐ | ● |
| T1059.001 | PowerShell | Execution | Sysmon 1 | ◐ | ● |
| T1105 | Ingress Tool Transfer | Command & Control | Suricata HTTP | ◐ | ● |
| T1053.005 | Scheduled Task | Persistence / Execution | Sysmon 1 / Security 4698 | ◐ | ● |
| T1070.001 | Clear Windows Event Logs | Defense Evasion | Security 1102 / Sysmon 1 | ◐ | ● |
| T1021.002 | SMB / Windows Admin Shares | Lateral Movement | Sysmon 1 (PSEXESVC) | ◐ | ● |
| T1071.004 | DNS (App-Layer C2) | Command & Control | Suricata DNS | ◐ | ● |

Detected-by (rule ID → technique):
- **T1110** → built-in 5710/5712 (SSH brute force), verified end-to-end in Phase 1.
- **T1078** → custom **100400** (successful SSH login from an IP that just brute-forced;
  `if_matched_sid` 5712 + `same_source_ip`). Phase 4 composite.
- **T1059.001** → custom **100101** (encoded PowerShell command line).
- **T1053.005** → custom **100110** (schtasks `/Create`) and **100121** (Security 4698 launching a suspicious interpreter).
- **T1059.001 + T1053.005 chain** → custom **100420** (composite): encoded PowerShell followed by scheduled-task persistence on the same host (`same_field win.system.computer`).
- **T1070.001** → custom **100600** (Security 1102, audit log cleared) and **100601** (`wevtutil cl` via Sysmon).
- **T1021.002** → custom **100500** (a process whose parent is `PSEXESVC.exe` = PsExec remote execution).
- **T1071.004** → custom **100300** (per-query long-hex TXT signature) and **100410**
  (Phase 4 beacon-regularity correlation: 8+ such queries from one host in 600s).
- **T1105** → custom **100310** (script/exe fetched over HTTP from a bare IP; Suricata HTTP)
  and **100430** (composite: an encoded-PowerShell process opens an outbound connection,
  correlated by `win.eventdata.processGuid`).

Gaps: none in the v1 technique set — **measured recall 100% (8/8 injected events), 0 FP**.
Depth (not breadth) remains: domain-hosted / HTTPS downloads, more scenarios, richer
correlation.

## Detection catalog

Per-detection docs (hypothesis, data source, logic, ATT&CK mapping, test case,
limitations/evasions) live in `docs/detections/` and are added in Phase 3+.

## Notes on measurement

- **Injected** is set from the generator's `ground_truth.jsonl`.
- **Detected** is set only when a corresponding alert (matching host/time/technique)
  appears in `wazuh-alerts-*` during validation — not merely because a rule exists.
- False positives are measured against the benign baseline, not just the attack window.
