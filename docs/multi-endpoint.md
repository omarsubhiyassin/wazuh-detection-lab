# Monitoring multiple endpoints, organized into teams

How to go from the single-host lab to a handful of real PCs enrolled as agents,
grouped by team (Security, Network, Dev) so the dashboard can scope the view.

Two parts: **exposing the manager** so other machines can enroll, and **agent
groups** that drive both per-team telemetry config and the dashboard's team
switcher.

---

## Part 1 — Exposing the manager beyond localhost

### What already faces the network (and what must not)

`infra/docker-compose.override.yml` already publishes only the two agent ports
to all interfaces and keeps everything else on `127.0.0.1`:

| Port | Purpose | Exposure |
|------|---------|----------|
| 1514/tcp | agent event ingestion | LAN (agents connect here) |
| 1515/tcp | enrollment (authd) | LAN (agents register here) |
| 9200 | indexer | **localhost only** |
| 55000 | manager API | **localhost only** |
| 443 / 8787 | dashboards | **localhost only** |

That split is deliberate and correct: **only 1514/1515 should ever face the
network.** Do not "helpfully" expose 9200, 55000, or the dashboards — the BFF and
the team switcher reach the manager/indexer over the internal Docker network by
service name, so nothing else needs a routable port.

So docker-compose needs no change. The real blocker is WSL networking.

### The actual blocker: WSL2 NAT

The stack runs in WSL2, whose network is NAT'd behind Windows. Another PC hitting
`your-windows-ip:1514` reaches *Windows*, not the WSL VM, so enrollment fails.
Fix with **mirrored networking** (WSL ≥ 2.0.0 — check `wsl --version`):

1. In `%UserProfile%\.wslconfig` (create it if absent):
   ```ini
   [wsl2]
   networkingMode=mirrored
   ```
2. From an elevated PowerShell: `wsl --shutdown`, then reopen WSL. **This stops
   the stack** — bring it back with your normal `docker compose ... up -d`.
3. Verify from another LAN device (replace with the Windows host's LAN IP):
   ```
   Test-NetConnection <windows-lan-ip> -Port 1515    # PowerShell
   nc -vz <windows-lan-ip> 1515                       # Linux/mac
   ```

Mirrored mode shares the Windows host's interfaces with WSL, so LAN traffic to
`host-ip:1514/1515` reaches the manager.

### Windows Firewall — scope it to your subnet, not `Any`

Allow inbound 1514/1515 **only** from the subnet that has agents. From an
elevated PowerShell (adjust the subnet):

```powershell
New-NetFirewallRule -DisplayName "Wazuh agents (1514/1515)" `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1514,1515 `
  -RemoteAddress 192.168.1.0/24
```

`-RemoteAddress` is the point — a rule open to `Any` invites the whole world to
your enrollment port.

### Enrollment must require a password (it already does)

Open enrollment lets any machine that reaches 1515 register as an agent, and an
enrolled agent can inject events into your detections. This project enforces
authenticated enrollment: `bootstrap.sh` writes `AGENT_ENROLLMENT_PASSWORD` to
the manager's `authd.pass` and turns `<use_password>` on.

- `AGENT_ENROLLMENT_PASSWORD` lives in `infra/.env`, which is **gitignored and
  untracked** — only the placeholder `infra/.env.example` is committed. Keep it
  that way: treat the value as a secret, distribute it out-of-band, never commit
  it.
- Agents present it at install time via `-RegistrationPassword` /
  `WAZUH_REGISTRATION_PASSWORD` (the fleet scripts handle this).

### Security implications of exposing this at all

- **A compromised/rogue enrolled agent can inject alerts** — poisoning or
  flooding your detections. Enrollment control is the main defense; once your
  fleet is stable, consider disabling auto re-registration.
- **Keep the blast radius to 1514/1515.** The indexer, API, and dashboards stay
  localhost. If you ever need remote dashboard access, put it behind a VPN or an
  authenticating reverse proxy — do not publish 8787/443 to the LAN.
- **Scope the firewall to the agent subnet.** You are now running a network
  service that ingests data from other machines.

### WSL is a lab host, not a production monitor — stated plainly

This deployment runs on WSL2 on a workstation. That is fine for a lab and for a
handful of endpoints, but it is **not** a production security monitor, and the
reason is not hand-wavy: **when the workstation sleeps or reboots, the WSL VM
and every container stop, and the manager stops ingesting.** A monitor that
sleeps misses attacks during the gap, and agents buffer only so much before
dropping events. During development we repeatedly observed the whole stack exit
on host sleep.

This is an accepted, documented tradeoff for the lab — not an oversight. For
anything you actually depend on, run the manager on an always-on Linux host
(a small VM or cloud instance): no WSL NAT to work around, no sleep, and the
`deploy/` cloud-init + Terraform paths already target exactly that.

---

## Part 2 — Agent groups and the team switcher

Wazuh **agent groups** do two jobs here: they scope what telemetry each host
collects (each group gets its own `agent.conf`), and they drive the dashboard's
**Team** switcher.

### Create the groups and enroll into them

On the manager:

```bash
docker exec <manager> /var/ossec/bin/agent_groups -a -g sec-team -q
docker exec <manager> /var/ossec/bin/agent_groups -a -g network-team -q
docker exec <manager> /var/ossec/bin/agent_groups -a -g dev-team -q
```

Then enroll each PC into its team at install time — the fleet scripts already
take the group:

```powershell
# Windows (elevated)
.\fleet\windows\install-agent.ps1 -Manager <lan-ip> -AgentGroup sec-team `
  -RegistrationPassword <enrollment-password>
```
```bash
# Linux
sudo ./fleet/linux/install-agent.sh -m <lan-ip> -g dev-team -p <enrollment-password>
```

An agent can belong to more than one group; to move or add one after enrollment:
`agent_groups -a -i <agent-id> -g <group> -q`.

Optionally give a group its own collection profile by dropping an `agent.conf`
at `/var/ossec/etc/shared/<group>/` on the manager (e.g. dev machines collect
less, network boxes collect different sources). `infra/config/agent-group.conf`
is the model.

### How the dashboard uses groups

The alert documents only carry `{agent.id, name, ip}` — **not** the group. So
the dashboard's **Team** dropdown ([server/groups.js](../dashboard/server/groups.js))
asks the **manager API** which agents are in a group, then filters the alert
query by those agent names (server-side, so it covers every matching alert, not
just the loaded page). Add a host to a group on the manager and the switcher
reflects it within its cache TTL — no dashboard change.

Credentials: the dashboard container reads the manager API over the internal
Docker network (`WAZUH_API_URL=https://wazuh.manager:55000`, read-only use), using
the same `API_USERNAME`/`API_PASSWORD` from `infra/.env` — the host's
`127.0.0.1:55000` binding is untouched. If those are unset or the API is
unreachable, the switcher simply hides and the view stays **All**.

### This is filtering, not access control

The Team switcher is a **convenience filter**: any authenticated user can flip to
any team and see its alerts. It does **not** restrict what a role can see — a
Network analyst is not prevented from viewing Sec Team alerts. True per-team
isolation would be RBAC scoping (binding each user to allowed groups and
enforcing it server-side), which is a separate, larger feature and is
deliberately **not** built here. Don't mistake the dropdown for a security
boundary.
