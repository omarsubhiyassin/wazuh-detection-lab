# Detection runbooks (SOC triage)

Operator-facing companion to [detections.md](detections.md). Where detections.md
records *how and why* each rule works, this says *what to do when it fires* —
triage steps, how to tell a true positive from noise, and when to escalate.

**Severity by Wazuh level:** 0–7 informational · 8–11 investigate · 12–13 high
(pages `#all-soc-alert`) · 14–15 critical. The Slack threshold is
`NOTIFY_MIN_LEVEL` (default 12) in `infra/.env`.

**General triage flow for any alert:**
1. Identify the **host** (`agent.name`) and **time** (`timestamp`).
2. Pull the full event (`data.win.eventdata` / `full_log`) from the alert drawer.
3. Establish **attribution** — which user/parent process, is it a known
   admin/automation, does it correlate with a change ticket or a person at
   keyboard?
4. Decide: benign (document + tune), suspicious (investigate host), or
   confirmed (escalate + contain).

---

## Execution

### 100101 — Encoded PowerShell (T1059.001) · level 12 · pages
**Fires when:** a `powershell.exe`/`pwsh.exe` process runs with a long base64
blob after `-e…`.
**Triage:** base64-decode the `commandLine` blob (`[Convert]::FromBase64String`
→ UTF-16) and read the intent. Check `parentImage` — Office apps, `wscript`,
`mshta`, or a browser as parent is a strong signal; a known deployment tool is
usually benign. Look for a following network connection from the same
`processGuid` (rule 100430).
**Likely FP:** legitimate installers, EDR, and some management agents use
encoded commands. Allow-list by parent + signer, not by the blob.
**Escalate if:** the decoded command downloads/executes remote content, the
parent is a document/mail app, or 100430 also fired → treat as active intrusion,
isolate the host.

## Persistence

### 100110 — Scheduled task via schtasks.exe (T1053.005) · level 10 · investigate
### 100121 — Scheduled task with suspicious action, Security 4698 (T1053.005) · level 12 · pages
**Fires when:** a task is created (`schtasks /create`, or any 4698 whose action
launches an interpreter/download).
**Triage:** read the task's action/command (`taskContent`) and trigger. A task
that runs PowerShell/`cmd`/a `.ps1` at logon or on a short interval is
persistence until proven otherwise. Confirm the creating user and whether a
software install was happening at that time.
**Likely FP:** software installers and IT automation create tasks constantly.
Correlate with change windows; allow-list known task names/paths.
**Escalate if:** the task launches an encoded command, writes to
`Users\Public`/`AppData\…\Temp`, or the creator is a service/compromised
account. Delete the task only after capturing its full definition.
**Depends on:** the "Other Object Access Events" audit subcategory (enabled by
`fleet/windows/install-agent.ps1`) — without it 4698 never logs.

## Credential Access

### 100700 — Suspicious LSASS memory access (T1003.001) · level 13 · pages
### 100701 — LSASS-dump tooling on the command line (T1003.001) · level 13 · pages
**Fires when:** a non-allow-listed process opens `lsass.exe` with read rights
(100700), or a command line matches known dump tooling — procdump `-ma lsass`,
`comsvcs.dll MiniDump`, `sekurlsa`, nanodump… (100701).
**Triage:** this is high-fidelity — LSASS is rarely touched legitimately.
Identify `sourceImage`/the tool and the user. Assume credential theft: any
account that was logged on to that host is now potentially compromised.
**Likely FP:** AV/EDR and a few system processes (already allow-listed in
100700 via `sourceImage` negate). A new legitimate security tool may need adding
to the allow-list.
**Escalate immediately if** confirmed: isolate the host, force-reset credentials
for all accounts with sessions on it (especially privileged), hunt for lateral
movement from it.

## Defense Evasion

### 100600 — Security audit log cleared, 1102 (T1070.001) · level 12 · pages
### 100601 — Event log cleared via wevtutil (T1070.001) · level 12 · pages
**Fires when:** the Security log is cleared (1102), or `wevtutil cl` runs
(100601 — catches it even if 1102 auditing is off).
**Triage:** log clearing is almost never legitimate outside a documented
maintenance action. Note **what was cleared and by whom**, and treat the cleared
window as a visibility gap — pivot to Sysmon/EDR and network telemetry for that
host, which an attacker clearing the *Security* log often forgets.
**Likely FP:** rare — some backup/imaging tools rotate logs. Verify against
change records.
**Escalate if:** unattended, or paired with any Execution/Cred-Access alert on
the same host → strong indicator of an attacker covering tracks mid-intrusion.

## Lateral Movement

### 100500 — Remote execution via PsExec service (T1021.002) · level 12 · pages
**Fires when:** a process is spawned by `PSEXESVC.exe` (the PsExec service).
**Triage:** identify the child command and the **source** host/user that invoked
PsExec (check the destination host's logon events for a network logon from that
account just before). PsExec is a legitimate admin tool *and* a top lateral-
movement technique — attribution is everything.
**Likely FP:** IT admins and deployment tooling use PsExec. Maintain an
allow-list of admin source hosts/accounts.
**Escalate if:** the source account isn't a known admin, the child command is an
encoded/download payload, or it fans out to multiple hosts → contain and hunt
the source.

## Command and Control

### 100300 — DNS TXT tunneling, per query (T1071.004) · level 10 · investigate
### 100410 — DNS beaconing, aggregated (T1071.004) · level 12 · pages · composite
**Fires when:** a TXT query carries a long hex subdomain (100300, per query);
100410 aggregates 8+ such queries from one source in 10 min into a single alert.
**Triage:** prefer the **100410** aggregate (100300 is intentionally noisy).
Identify the internal host and the queried domain — look up the parent domain's
registration/age and whether the host has any business talking to it. High query
volume with high-entropy labels to one domain = tunneling/beacon.
**Likely FP:** some CDNs, AV, and telemetry use TXT/long labels. Allow-list
known-good parent domains.
**Escalate if:** the domain is newly registered/unknown and the pattern is
regular → likely C2; block the domain, investigate the host.

### 100310 — Script/exe downloaded over HTTP from a bare IP (T1105) · level 12 · pages
**Fires when:** an HTTP GET for a script/exe extension goes to a raw IPv4 (no
domain).
**Triage:** a tool fetched from a bare IP over cleartext is a strong second-stage
IOC. Identify the requesting host/process and the file; retrieve it from the URL
in a sandbox if still up. Check whether the same host then executed it.
**Likely FP:** low — internal artifact servers addressed by IP. Allow-list them.
**Escalate if:** the file is a payload or the host executed it → active tool
transfer, isolate and analyze.

## High-confidence correlations (already investigated by design)

These fire only when multiple stages line up, so a hit is close to a confirmed
incident — escalate first, document second.

### 100400 — SSH brute-force → success, same IP (T1078+T1110) · level 12 · pages
A login succeeded from an IP that was *just* brute-forcing → treat the account as
**compromised**. Reset its credential, review what the session did, check for
persistence/lateral movement from the target host. FP only if a legitimate user
fat-fingered a password 8+ times then succeeded from the same IP.

### 100420 — Execution → persistence, same host (T1059.001+T1053.005) · level 13 · pages
Encoded PowerShell followed by scheduled-task persistence on one host inside 10
min = a kill chain. Isolate and do full IR on the host.

### 100430 — Download cradle confirmed (T1059.001+T1105) · level 13 · pages
The *same* encoded-PowerShell process opened an outbound connection (correlated
by `processGuid`) — execution tied to tool transfer with process-level precision.
Isolate; the payload it pulled is the priority artifact.

---

## Tuning workflow

False positives are fixed as **data, not by weakening rules**:
1. Confirm the FP and capture the distinguishing field (parent, signer, path,
   source IP…).
2. Add an allow-list clause (a `negate` field like 100700's `sourceImage`, or a
   base-domain/host allow-list), **not** a level reduction.
3. Add a benign sample to `detections/tests/` proving it now stays quiet, so CI
   guards the exemption forever.
4. Commit — the [CI pipeline](../.github/workflows/detections-ci.yml) re-runs the
   whole suite on the change.
