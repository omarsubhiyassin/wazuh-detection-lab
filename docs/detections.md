# Detection catalog

One entry per custom rule in [../detections/rules/local_rules.xml](../detections/rules/local_rules.xml).
Each documents the hypothesis, data source, logic, ATT&CK mapping, test case, and known
limitations/evasions — the detection-as-code record behind the coverage numbers in
[attack-coverage.md](attack-coverage.md).

Levels: Wazuh 0–15 (0 = log-only, 12+ = high). Tests live in
[../detections/tests/](../detections/tests/) and run via `run_logtest.sh`.

---

## 100101 — Encoded PowerShell command line
- **ATT&CK:** T1059.001 (Execution) · **Level:** 12
- **Hypothesis:** Adversaries hide payloads by passing base64 to `powershell.exe -EncodedCommand`; a PowerShell process whose command line carries a long base64 blob after an `-e…` switch is suspicious.
- **Data source:** Sysmon Event ID 1 (process creation) → `win.eventdata.image`, `win.eventdata.commandLine`.
- **Logic:** child of 100100 (Sysmon proc-create); `image` ends in `powershell.exe`/`pwsh.exe` and `commandLine` matches `-e[a-z]* <30+ base64 chars>`.
- **Test:** `encoded_powershell.log` → 100101.
- **Limitations / evasions:** misses non-encoded cradles (see note below), fragmented/whitespace-obfuscated flags, and alternate interpreters. Does not decode the blob, so it can't attribute the downloaded payload (that gap is **T1105**, unaddressed at signature level). Pairs with EDR/AMSI in the real world.

## 100110 — Scheduled task created via schtasks.exe
- **ATT&CK:** T1053.005 (Persistence) · **Level:** 10
- **Hypothesis:** Interactive `schtasks.exe /Create` is a common persistence primitive.
- **Data source:** Sysmon Event ID 1 → `win.eventdata.image`, `win.eventdata.commandLine`.
- **Logic:** child of 100100; `image` ends in `schtasks.exe` and `commandLine` contains `/create`.
- **Test:** `schtasks_create.log` → 100110.
- **Limitations / evasions:** misses task creation via the Task Scheduler COM API / PowerShell `Register-ScheduledTask` (no `schtasks.exe`) — that path is caught instead by 100121 (the 4698 event), which is why both exist.

## 100121 — Scheduled task registered with a suspicious action (Security 4698)
- **ATT&CK:** T1053.005 (Persistence) · **Level:** 12 (child of 100120, level 8)
- **Hypothesis:** However a task is created, the OS logs Security 4698 with the task XML; a task whose action launches an interpreter/download is likely persistence.
- **Data source:** Windows Security 4698 → `win.eventdata.taskName`, `win.eventdata.taskContent`.
- **Logic:** 100120 matches any 4698; 100121 escalates when `taskContent` references `powershell`/`-enc`/`cmd.exe`/`.ps1`/`downloadstring`/`net.webclient`/`invoke-expression`.
- **Test:** `scheduled_task_4698.log` → 100121.
- **Limitations / evasions:** requires the "Other Object Access Events" audit policy enabled; a task launching a signed LOLBin not in the keyword list would only raise the level-8 base rule.

## 100300 — Suspicious DNS TXT query with long hex subdomain
- **ATT&CK:** T1071.004 (Command and Control) · **Level:** 10
- **Hypothesis:** DNS tunneling encodes data into high-entropy subdomain labels, often over TXT.
- **Data source:** Suricata `eve.json` DNS → `dns.rrtype`, `dns.rrname`.
- **Logic:** child of group `suricata`; `rrtype` = TXT and `rrname` begins with a 16+ char hex label.
- **Test:** `dns_txt_tunnel.log` → 100300.
- **Limitations / evasions:** per-query and noisy by design (fires on every beacon) — 100410 aggregates it. Misses base32/alphanumeric encodings and non-TXT tunneling; a short-label or low-entropy scheme evades the regex.

## 100310 — Script/executable downloaded over HTTP from a bare IP
- **ATT&CK:** T1105 (Command and Control / Ingress Tool Transfer) · **Level:** 12
- **Hypothesis:** Fetching a script or executable over plain HTTP directly from a raw IP (no domain) is a strong second-stage / tool-transfer IOC — exactly what a download cradle does.
- **Data source:** Suricata `eve.json` HTTP → `http.http_method`, `http.url`, `http.hostname`.
- **Logic:** child of group `suricata`; `GET`, `url` ends in a script/exe extension (`.ps1/.psm1/.exe/.dll/.bat/.hta/.vbs/.scr`), and `hostname` is a bare IPv4. The bare-IP requirement keeps legitimate CDN/domain fetches (e.g. `raw.githubusercontent.com/...install.ps1`) from matching.
- **Test:** `malicious_download.log` → 100310; `benign_http.log` (same `.ps1`, but from a domain) → no alert.
- **Limitations / evasions:** misses payloads hosted on a **domain** (needs threat-intel/newly-registered-domain enrichment or a JA3/UA signal), HTTPS downloads (no cleartext URL — would need TLS SNI + JA3), and non-script extensions. A same-host composite with 100101 (execution) would raise confidence further — a natural next step.

## 100400 — SSH brute-force followed by success (same source IP)
- **ATT&CK:** T1078 (Valid Accounts) + T1110 (Brute Force) · **Level:** 12 · **composite**
- **Hypothesis:** A successful login from an IP that was *just* brute-forcing indicates a compromised credential, not a benign login.
- **Data source:** built-in sshd rules — 5712 (brute force) and 5715 (auth success), correlated by source IP.
- **Logic:** `if_sid 5715` + `if_matched_sid 5712` + `same_source_ip`, `timeframe 300`.
- **Test:** `bruteforce_then_success.log` (multi-line burst + success) → 100400.
- **Limitations / evasions:** low-and-slow guessing that never trips 5712, or success from a *different* IP than the brute force (proxy rotation), evades it. Password-spray across many accounts from few attempts each may not reach the 5712 threshold.

## 100410 — DNS beaconing (repeated tunneling queries)
- **ATT&CK:** T1071.004 (Command and Control) · **Level:** 12 · **frequency**
- **Hypothesis:** One suspicious TXT query is weak signal; many from one host in a short window is a beaconing session.
- **Data source:** rule 100300 events, correlated by `src_ip`.
- **Logic:** `if_matched_sid 100300` + `frequency 8` / `timeframe 600` + `same_field src_ip` → one alert per session instead of per query.
- **Test:** `dns_beacon_session.log` (31 queries) → 100410.
- **Limitations / evasions:** inherits 100300's blind spots; a beacon slower than 8 queries / 600s, or spread across source IPs, stays under threshold. Tunable via frequency/timeframe.

## 100420 — Execution → persistence kill chain (same host)
- **ATT&CK:** T1059.001 (Execution) + T1053.005 (Persistence) · **Level:** 13 · **composite**
- **Hypothesis:** Encoded PowerShell *followed by* scheduled-task persistence on the same host in a short window is a classic intrusion chain — far higher confidence than either event alone.
- **Data source:** rules 100101 (encoded PS) and 100121 (suspicious 4698), correlated by `win.system.computer`.
- **Logic:** `if_sid 100121` + `if_matched_sid 100101` + `same_field win.system.computer`, `timeframe 600`. Correlates on the host name (not the agent — all Windows events arrive through one lab agent). The tight window keeps independent same-host activity from looking like a chain.
- **Test:** `exec_to_persistence.log` (PowerShell → schtasks → 4698, all one host) → 100420.
- **Limitations / evasions:** persistence via a mechanism other than a scheduled task (run key, service, WMI) isn't chained here; a dwell time longer than the timeframe between execution and persistence evades it. Validated to fire only for the dedicated kill-chain host, not for independent same-host scenarios.

## 100700 / 100701 — LSASS credential dumping
- **ATT&CK:** T1003.001 (Credential Access / LSASS Memory) · **Level:** 13 each
- **Hypothesis:** Reading `lsass.exe` memory harvests credentials; detect both the memory access and the tooling.
- **Data source:** Sysmon 10 (ProcessAccess) → `win.eventdata.sourceImage` / `targetImage` / `grantedAccess`; Sysmon 1 → `commandLine`.
- **Logic:**
  - **100700** — Sysmon 10 where `targetImage` is `lsass.exe`, `grantedAccess` is a memory-read mask (`0x1010/0x1410/0x1438/0x143a/0x1fffff`), and `sourceImage` is **not** an allow-listed system/AV process (`negate`). The allowlist is the discriminator — legit processes read LSASS with the *same* masks, so target+mask alone would be a flood of false positives. Verified: benign `MsMpEng.exe` reading LSASS at `0x1410` does **not** fire (1 alert on the attack vs. 0 on ~27 benign accesses in a run).
  - **100701** — Sysmon 1 whose command line matches known dump tooling (`-ma lsass`, `procdump…lsass`, `comsvcs.dll…MiniDump`, `rundll32…MiniDump`, `sekurlsa`, `nanodump`, …).
- **Test:** `credential_dumping.log` (procdump + Sysmon 10) → 100700 and 100701; `benign_lsass.log` → no alert.
- **Limitations / evasions:** an attacker abusing an **allow-listed** LOLBin (e.g. a signed process) to touch LSASS evades 100700; direct syscalls / handle duplication that don't surface as a Sysmon-10 open evade the access path (100701's command-line net still helps). Mask list is finite — an unusual read mask slips through.

## 100600 / 100601 — Windows event log cleared (indicator removal)
- **ATT&CK:** T1070.001 (Defense Evasion / Clear Windows Event Logs) · **Level:** 12 each
- **Hypothesis:** Clearing the Security event log is anti-forensics; detect both the *effect* the OS records and the *command* that did it.
- **Data source:** Security 1102 → `win.system.eventID`; Sysmon 1 → `win.eventdata.image` / `commandLine`.
- **Logic:**
  - **100600** — Security `eventID` = 1102 ("the audit log was cleared"). The authoritative signal.
  - **100601** — Sysmon 1 where `image` ends in `wevtutil.exe` and `commandLine` contains `cl`/`clear-log`. Catches the clear even if 1102 auditing is disabled (a common evasion is to disable auditing first).
- **Test:** `log_clearing.log` (wevtutil + 1102) → 100600 and 100601.
- **Limitations / evasions:** clearing via API/`Clear-EventLog`/direct `.evtx` deletion won't hit `wevtutil` (100601), but still trips 1102 (100600) unless the log service itself is stopped/tampered — a deeper evasion worth a follow-up rule (7035/7036 service state, or 1100 log-service-shutdown).

## 100500 — Remote command execution via PsExec (lateral movement)
- **ATT&CK:** T1021.002 (Lateral Movement / SMB & Windows Admin Shares) · **Level:** 12
- **Hypothesis:** A process whose parent is `PSEXESVC.exe` is a command run on this host *by* PsExec from elsewhere — a hallmark of lateral movement.
- **Data source:** Sysmon Event ID 1 → `win.eventdata.parentImage`.
- **Logic:** child of 100100; `parentImage` ends in `PSEXESVC.exe`. Fires on the remotely executed child (`cmd.exe`/`powershell.exe`), the actual foothold-expansion action, not just the service install.
- **Test:** `lateral_movement_psexec.log` (SMB connect → PSEXESVC → cmd) → 100500.
- **Limitations / evasions:** matches default PsExec only — a **renamed** service binary (`-r` flag) evades the name check; SMB/admin-share lateral movement without PsExec (wmiexec, `sc.exe` remote service, WinRM `wsmprovhost.exe`) needs its own rules. The source→target SMB flow is emitted for context but not correlated (network `src_ip` and endpoint `computer` share no field — the cross-host identity gap).

## 100430 — Download cradle: encoded PowerShell process opens a network connection
- **ATT&CK:** T1059.001 (Execution) + T1105 (Ingress Tool Transfer) · **Level:** 13 · **composite**
- **Hypothesis:** An encoded-PowerShell process that then makes an outbound connection is a download cradle fetching its second stage — far stronger than either signal alone.
- **Data source:** rule 100101 (encoded PS, Sysmon 1) and 100200 (Sysmon 3 network connection), correlated by **`win.eventdata.processGuid`** — the exact process, not just the host.
- **Logic:** `if_sid 100200` + `if_matched_sid 100101` + `same_field win.eventdata.processGuid`, `timeframe 300`. Process-GUID correlation is what lets endpoint execution and endpoint network telemetry be joined precisely; it also sidesteps the network↔endpoint identity problem (Suricata `src_ip` vs Sysmon `computer` have no shared field — hence the endpoint Sysmon-3 view here).
- **Test:** `exec_to_download.log` (Sysmon 1 + Sysmon 3, same processGuid) → 100430.
- **Limitations / evasions:** needs Sysmon Event ID 3 enabled; process-hollowing/injection that connects from a different process breaks the GUID link; a benign process making connections is correctly ignored (no prior 100101 for its GUID — verified against baseline network noise).
