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
