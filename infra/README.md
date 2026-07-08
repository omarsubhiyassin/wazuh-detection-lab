# Infra runbook — Wazuh single-node lab

Infrastructure-as-code for the detection lab: a pinned Wazuh single-node stack
(manager + indexer + dashboard) plus one Linux agent, brought up with a bootstrap
script and a compose overlay that mounts our custom detection content.

## Requirements

- **Docker Desktop** with the **WSL2 backend** enabled.
- **~8 GB RAM allocated to WSL2**, 4 CPUs, ~50 GB free disk. The Wazuh indexer is a
  JVM (OpenSearch fork) and is the memory hog — heap is capped via `INDEXER_JAVA_OPTS`.
- `vm.max_map_count >= 262144` inside WSL (the bootstrap sets it; persist it in
  `/etc/sysctl.conf`). This is the #1 cause of the indexer failing to start.

### Allocate RAM to WSL2

Create/edit `C:\Users\<you>\.wslconfig`:

```ini
[wsl2]
memory=8GB
processors=4
```

Then `wsl --shutdown` from PowerShell and reopen your WSL distro.

## Run the lab from the WSL filesystem — not /mnt/c

This repo is scaffolded under `C:\Users\user\file-integrity-monitor` so you can edit it
from Windows. But **run** the stack against a copy on the Linux filesystem
(e.g. `~/detection-lab`), because the synthetic generator writes log files that the
agent tails, and **inotify change events are unreliable across the `/mnt/c` 9p mount** —
the agent would miss new log lines. Clone or copy the repo into WSL and point
`DETECTION_LAB_ROOT` at that path.

```bash
# inside WSL
cp -r /mnt/c/Users/user/file-integrity-monitor ~/detection-lab   # or git clone
cd ~/detection-lab/infra
```

## Bring it up (one command)

```bash
cp .env.example .env      # then edit: set DETECTION_LAB_ROOT + every password
./bootstrap.sh
```

That is the whole deploy. `bootstrap.sh` is idempotent (safe to re-run) and:
1. loads `.env` and **refuses default/placeholder secrets** (override with
   `ALLOW_DEFAULT_CREDS=true` for a throwaway lab),
2. checks/sets `vm.max_map_count`,
3. clones `wazuh/wazuh-docker` at the pinned `WAZUH_DOCKER_TAG` into `wazuh-docker/`
   (gitignored — vendored files stay pristine),
4. copies our `docker-compose.override.yml` next to the vendored compose,
5. generates indexer TLS certs (one-time),
6. `docker compose up -d` with both compose files,
7. **rotates the vendored default passwords** (`admin`, `kibanaserver`) to the `.env`
   values — bcrypt hash via the indexer's `hash.sh`, patches the vendored-clone
   `internal_users.yml`, pushes it with `securityadmin.sh` (that file only — a full
   push would wipe REST-created accounts), then recreates manager + dashboard so
   filebeat and the built-in dashboard use the new credentials,
8. **enforces authenticated agent enrollment** — writes `AGENT_ENROLLMENT_PASSWORD`
   to the manager's `authd.pass` and flips `<use_password>` on; the compose agent
   presents it automatically, real endpoints use it when enrolling,
9. creates the agent group and the **read-only dashboard account** (role + user via
   the security REST API, idempotent),
10. applies **retention (ISM) policies** — alerts deleted `ALERTS_RETENTION_DAYS`
    after index creation (daily indices), internal `wazuh-monitoring-*` /
    `wazuh-statistics-*` after `INTERNAL_RETENTION_DAYS`; `0` disables. Changing
    the window in `.env` and re-running updates the policy and re-points
    already-managed indices,
11. configures **Slack notifications** — alerts at/above `NOTIFY_MIN_LEVEL`
    (default 12) are posted to `SLACK_WEBHOOK_URL` via the Wazuh integrator
    (managed as a marked block in the manager's `ossec.conf`; unsetting the URL
    and re-running removes it),
11b. installs **self-monitoring** — `healthcheck.sh` on a 5-minute cron: containers
    up, indexer green, filebeat shipping, an agent Active, disk below
    `DISK_ALERT_PCT`. Posts to Slack on failure and recovery (reminders every
    `REMIND_HOURS` while broken), so a dead pipeline can't stay silent,
12. configures **active response** (opt-in, `ACTIVE_RESPONSE_ENABLED=true`) — an
    SSH brute-force alert (rules `5712`/`5763` by default) auto-blocks the source
    IP via `firewall-drop`, scoped to a safety allowlist (loopback + this
    project's Docker network + your own `ACTIVE_RESPONSE_ALLOWLIST`), auto-reverted
    after `ACTIVE_RESPONSE_TIMEOUT` seconds. Same marked-block pattern as Slack,
13. seeds `dashboard/.env` for the custom dashboard (never overwrites an existing one),
14. prints a **verification report**: cluster health, default creds disabled, RO
    account 200-on-read / 403-on-write, agent Active, authd password in force,
    retention policy attached, integrator running, active response configured.

### Active response — read before enabling

`ACTIVE_RESPONSE_ENABLED` defaults to **false**, unlike retention/Slack. Auto-blocking
a real IP has real consequences if a rule ever false-positives, so this needs a
deliberate opt-in:

1. Set `ACTIVE_RESPONSE_ALLOWLIST` in `.env` to your own management IP / VPN range /
   anything that must never be blocked, on top of the loopback + internal Docker
   network bootstrap always exempts.
2. Set `ACTIVE_RESPONSE_ENABLED=true` and re-run `./bootstrap.sh`.

**Known limitation of this lab's containers:** the vendored `wazuh/wazuh-agent` image
is a minimal Amazon Linux base with no `iptables` binary and no `NET_ADMIN` capability.
Wazuh will correctly detect the brute-force and invoke `firewall-drop`, but the
`iptables` call inside it will fail — visible in the agent's
`active-responses.log` as an execution error, not a config problem. Real Linux/Windows
endpoints (see [production-roadmap.md](../docs/production-roadmap.md) Phase 3) have a
firewall and root by default and will actually block. Deliberately not working around
this with a custom image + `NET_ADMIN` here, since that's a real capability increase
for a cosmetic win in a demo container.

**Login after deploy:** `admin` / your `INDEXER_PASSWORD` at https://localhost.
`SecretPassword` no longer works.

## Endpoints

| Service | URL / port | Notes |
|---------|-----------|-------|
| Wazuh Dashboard | https://localhost:443 | Built-in ops view; self-signed cert |
| Wazuh Indexer | https://localhost:9200 | OpenSearch API; the custom dashboard queries this |
| Manager | 1514/tcp, 1515/tcp | agent comms, enrollment |

## Common operations

```bash
cd wazuh-docker/single-node
docker compose ps                       # health
docker compose logs -f wazuh.manager    # manager logs
docker compose down                     # stop (keeps volumes/data)
docker compose down -v                  # stop + WIPE data (fresh start)
```

## How the password rotation works (automated by bootstrap)

Env vars only tell *clients* what to present; the indexer authenticates against the
bcrypt hash in `config/wazuh_indexer/internal_users.yml`, and once the `.security`
index is initialized a restart won't re-read that file — it must be pushed with
`securityadmin.sh`. Bootstrap does exactly that: `hash.sh` → patch the vendored-clone
YAML → `securityadmin.sh -f internal_users.yml -t internalusers` → force-recreate the
client containers. To rotate again later, change the password in `.env` and re-run
`./bootstrap.sh` — it detects that the `.env` password doesn't match and rotates.

The Wazuh API account (`wazuh-wui`, port 55000) is rotated too, but differently:
the API authenticates against its own RBAC store, so bootstrap logs in with the
current password (vendored default on first rotation) and changes it via
`PUT /security/users/{id}`, then recreates the built-in dashboard so it picks up
`API_PASSWORD` from the override env. On a fresh volume the manager seeds the
user from that env directly and no rotation is needed.

## Enrolling additional agents

Enrollment requires `AGENT_ENROLLMENT_PASSWORD` (authd password) after deploy. On a
real endpoint, install the Wazuh agent pinned to the same version and enroll against
this host with the password (e.g. env `WAZUH_REGISTRATION_PASSWORD` for the container
image / package deployment vars, or `agent-auth -m <host> -P <password>`). Already
enrolled agents keep their keys — the password only gates *new* enrollments.

## Read-only account for the custom dashboard (automated by bootstrap)

The custom dashboard ([../dashboard/](../dashboard/)) queries the indexer through a
least-privilege account (`detectionlab_ro`): read-only, scoped to `wazuh-alerts-*`, no
write and no access to other indices. Bootstrap creates/updates it from
`CUSTOM_DASHBOARD_RO_*` in `.env`; for reference, this is the equivalent manual
procedure via the security REST API (password policy: upper/lower/digit/special):

```bash
U=admin:SecretPassword
B=https://localhost:9200/_plugins/_security/api
RO_PASS="$CUSTOM_DASHBOARD_RO_PASSWORD"   # from infra/.env

# role: read-only on the alerts index
curl -sk -u "$U" -XPUT "$B/roles/detectionlab_ro_role" -H 'Content-Type: application/json' -d '{
  "cluster_permissions": ["cluster_composite_ops_ro"],
  "index_permissions": [{"index_patterns":["wazuh-alerts-*"],
    "allowed_actions":["read","indices:admin/mappings/get","indices:admin/get","indices:monitor/settings/get"]}]}'

# user (password auto-hashed) mapped to the role
curl -sk -u "$U" -XPUT "$B/internalusers/detectionlab_ro" -H 'Content-Type: application/json' -d "{
  \"password\":\"$RO_PASS\",\"opendistro_security_roles\":[\"detectionlab_ro_role\"]}"
```

Verify least privilege: read `wazuh-alerts-*` → 200; write or read another index → 403.

## Customization model

- **Never edit** files under `infra/wazuh-docker/` — that's the pinned vendored stack.
- All our changes live in `infra/docker-compose.override.yml` and the bind-mounted
  content under `detections/` and `generator/`.
- Bump the Wazuh version by changing **both** `WAZUH_DOCKER_TAG` (git tag, `v`-prefixed,
  e.g. `v4.14.6`) and `WAZUH_IMAGE_TAG` (Docker Hub tag, no `v`, e.g. `4.14.6`) in `.env`,
  deleting `infra/wazuh-docker/`, and re-running `bootstrap.sh`. They differ only by the
  leading `v`: git tags carry it, Docker Hub image tags don't.

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Indexer container exits immediately | `vm.max_map_count` too low; re-run bootstrap or set it manually |
| Indexer/dashboard OOM or host swaps hard | Lower `INDEXER_JAVA_OPTS` heap; raise WSL memory in `.wslconfig` |
| Agent tails file but no new events detected | Running from `/mnt/c` — move to WSL filesystem |
| Custom rule file mounted as a *directory* | The host file didn't exist at up time — ensure `detections/rules/local_rules.xml` exists |
| Dashboard shows cert warning | Expected; stack uses self-signed certs in the lab |
