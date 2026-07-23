# Fleet enrollment — real endpoints

Phase 3 of the [production roadmap](../docs/production-roadmap.md): move from the
synthetic generator to **real telemetry** from real hosts. The generator stays
on as the regression suite (it reproduces every technique on demand); these
scripts put actual agents on actual machines.

## How it fits together

- **Collection config is central.** Enrolled agents join the `detection-lab`
  group and receive [`infra/config/agent-group.conf`](../infra/config/agent-group.conf)
  from the manager — Sysmon + Security channels on Windows, `auth.log`/`syslog`/
  `audit.log` on Linux. You never edit collection config per host; add a host to
  the group and it ships the right sources.
- **Enrollment is authenticated.** Every agent presents `AGENT_ENROLLMENT_PASSWORD`
  (from `infra/.env`) to authd. Grab it with:
  `grep ^AGENT_ENROLLMENT_PASSWORD= infra/.env`.
- **The manager is reached at the host's address.** With the lab stack running
  locally, Docker publishes `1514/1515`, so an agent on the same machine uses
  `127.0.0.1`. A remote endpoint uses the lab host's LAN/VPN address (those two
  ports are the only network-facing ones — see infra/README.md).

## Windows ([windows/](windows/))

Installs Sysmon (SwiftOnSecurity baseline config) + the pinned Wazuh agent. Run
in an **elevated PowerShell**:

```powershell
cd fleet\windows
.\install-agent.ps1 -RegistrationPassword '<AGENT_ENROLLMENT_PASSWORD>'
# remote lab host: add -Manager <host-ip>
```

Undo: `.\uninstall-agent.ps1` (add `-KeepSysmon` to leave Sysmon in place).

The existing rules already target the live Sysmon eventchannel schema
(`win.system.providerName`, `win.eventdata.*`), so real events hit them with no
rule changes — e.g. running an encoded PowerShell command fires rule 100101
(T1059.001) and pages Slack.

The installer also enables the audit **subcategories** our Security-channel
rules need but Windows leaves off by default — currently *Other Object Access
Events*, so scheduled-task creation logs event **4698** (rules 100120/100121).
Sysmon covers process/network/handle activity; this fills the Security-channel
gaps. To apply it to an already-enrolled host without re-running the installer:

```powershell
auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
```

## Linux ([linux/](linux/))

Installs auditd + the curated [audit.rules](linux/audit.rules) and the pinned
Wazuh agent:

```bash
cd fleet/linux
sudo ./install-agent.sh -p '<AGENT_ENROLLMENT_PASSWORD>'
# remote lab host: add -m <host-ip>
```

Undo: `sudo ./uninstall-agent.sh`.

### auditd under WSL2 — known caveat

This lab's host kernel reports `CONFIG_AUDIT=y` / `CONFIG_AUDITSYSCALL=y`, but
several WSL2 kernels accept audit rules yet never deliver events to userspace
(no working audit netlink). The installer detects this: if `auditctl -l` doesn't
show the loaded rules it warns and continues — **`auth.log`/`syslog` collection
still works**, only syscall/file auditing is unavailable. On a bare-metal or VM
Linux endpoint auditd works normally. Enrolling the WSL host itself is optional
(it already runs the containerized lab); the primary Linux target is a real
server.
