# Monitoring multiple endpoints, organized into teams

How to go from the single-host lab to a handful of real PCs enrolled as agents,
grouped by team (Security, Network, Dev) so the dashboard can scope the view.

Two parts: **making the manager reachable** so other machines can enroll (LAN,
or off-LAN via a mesh VPN), and **agent groups** that drive both per-team
telemetry config and the dashboard's team switcher. A closing section covers
**migrating the manager** off this workstation when the lab outgrows it.

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

So docker-compose needs no change.

### Check reachability FIRST — with Docker Desktop it's usually already open

A common assumption (including an earlier version of this doc) is that WSL2's NAT
blocks LAN access and you must enable **mirrored networking** (`networkingMode=mirrored`
in `.wslconfig` + `wsl --shutdown`). That is true for a *raw* WSL2 stack — but this
project runs under **Docker Desktop**, which publishes container ports directly onto
the Windows host on all interfaces. So 1514/1515 are typically **already reachable on
the LAN IP** with no WSL changes at all.

Verify before changing anything. On the host:

```powershell
# what the manager ports are bound to — look for 0.0.0.0:1514 / 0.0.0.0:1515
netstat -an | Select-String ":1514|:1515" | Select-String "LISTENING"
# is the LAN IP itself answering?
Test-NetConnection <windows-lan-ip> -Port 1515 -InformationLevel Quiet
```

If you see `0.0.0.0:1514`/`0.0.0.0:1515` LISTENING and the test is `True`, the ports
already face the LAN — **do not** enable mirrored mode. Under Docker Desktop it is
unnecessary and can *interfere* with Docker's own port publishing; the only thing left
is the firewall rule below.

Mirrored mode is the fallback **only** if you are on raw WSL2 (no Docker Desktop) and
the ports are not reachable: add `[wsl2]\nnetworkingMode=mirrored` to
`%UserProfile%\.wslconfig`, `wsl --shutdown` (this stops the stack — restart it after),
then re-test.

> Note: a Docker Desktop container cannot loop back to the host's own published/LAN
> ports (hairpin isolation), so you **cannot** fully test enrollment from a throwaway
> container on the same host — it will fail to connect regardless of config. That is a
> same-host artifact, not a real-agent problem. The real test is a separate machine
> (below).

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

### Reaching PCs that aren't on your LAN

The unifying fact: **Wazuh agents always dial *out* to the manager on 1514/1515.**
The manager never reaches into an agent. So every option below is just a different
way to give a remote PC a stable address that reaches your manager — pick by how the
PC is networked, ranked for this setup:

1. **Mesh VPN — Tailscale / ZeroTier (recommended for remote PCs).** Install on the
   host and each PC; they get stable private IPs on an encrypted mesh. No router
   config, no public exposure, end-to-end encrypted (the provider never sees the
   traffic), free tier fine for a small fleet. See the concrete steps below.
2. **Move the manager to an always-on host** (cloud VM via `deploy/`, or a mini-PC /
   Pi on the LAN). The structural fix — solves reachability *and* the sleep-gap in one
   move. See "Migrating the manager later" at the end.
3. **TCP tunnel (ngrok / Cloudflare Tunnel).** Exposes 1515 through a public endpoint
   with no router access. Quick, but it is a public endpoint (attack-surface concern
   like a port-forward) and the relay provider sits in the transport path — more trust
   than a VPN. Fine for a demo, not standing infra.
4. **Router port-forward.** Works, discouraged — puts your enrollment service on the
   open internet. If you must: restrict source IPs at the router and treat the
   enrollment password as a high-value secret.

All five only get the agent *to* the manager; the manager still has to be **up** when
the agent calls — which is why #2 is the real answer once this grows.

#### Tailscale — the concrete path

1. Install Tailscale on the **host** and on **each remote PC**; sign them into the same
   tailnet. Each gets a `100.x` IP and a MagicDNS name.
2. **Enroll agents against the host's tailnet _name_, not its `100.x` IP.** This is the
   one bit of foresight that makes a future manager move nearly zero-touch (see the
   migration checklist): the name can follow the manager to a new host, so agents never
   need re-pointing.
   ```powershell
   # Windows (elevated) — installs Sysmon + the agent
   .\fleet\windows\install-agent.ps1 -Manager <host-tailnet-name> -AgentGroup sec-team `
     -RegistrationPassword <enrollment-password>
   ```
   ```bash
   # Linux
   sudo ./fleet/linux/install-agent.sh -m <host-tailnet-name> -g dev-team -p <enrollment-password>
   ```
3. Firewall: scope the inbound 1514/1515 rule to the **Tailscale interface/subnet**
   (`100.64.0.0/10`) instead of, or in addition to, your LAN subnet.
4. Verify on the manager: `agent_control -l` shows the host Active within ~30s, and the
   team's count in the dashboard **Team** switcher goes up by one.

(You already have a **Radmin VPN** too — same idea: enroll at its IP, scope the firewall
to its subnet. Tailscale is just the easier, more standard tool.)

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

---

## Migrating the manager later (workstation → always-on host)

Moving off this workstation onto a mini-PC or cloud VM is **not a rebuild** — the whole
stack is containerized and config-as-code, so most of it travels untouched. This is what
actually moves and what needs care.

**Travels unchanged** (it's all in the repo): the entire `detections/` tree, the
dashboard image and every feature, `docker-compose` + the override, the fleet scripts and
group model. On the new host: install Docker, clone the repo, run `bootstrap` +
`compose up` — the same commands you run now. Docker Desktop's quirks (hairpin, sleep-gap)
simply disappear on a real Linux host.

**Two things need attention:**

1. **The address agents point at.** If you enrolled against a stable **Tailscale tailnet
   name** (as advised above), give the new host that same name and agents reconnect with
   **zero changes**. If you enrolled against a raw IP, you'll re-point each agent (push a
   new `<server><address>` via the shared `agent.conf`, or re-enroll).
2. **State + data, if you want to keep it.** Copy these from the old host to the new one
   *before* first `compose up`, or start fresh and lose history:
   - `dashboard/state/` — dashboard users, triage state, audit log, AI findings.
   - the manager's **`client.keys`** — the enrolled-agent registry. **Copying this means
     agents do NOT re-enroll** — they just reconnect. Skip it and every agent must
     re-register.
   - the indexer data volume — the alert history. Skip it and you start with an empty
     alerts index (detections still work; you just lose the past).

**Checklist:**

1. Stand up Docker + the repo on the new host; **don't** start the stack yet.
2. Copy `dashboard/state/`, the manager `client.keys`, and (optionally) the indexer volume.
3. Give the new host the manager's tailnet name (or plan the agent re-point).
4. `bootstrap` + `compose up`; confirm the indexer goes green and the dashboard serves.
5. `agent_control -l` — agents reconnect (Active) without re-enrolling.
6. Retire the workstation stack.

Roughly an afternoon, not a project — which is the payoff of having built it as
containers + config from the start.
