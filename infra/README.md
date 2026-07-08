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

## Bring it up

```bash
cp .env.example .env      # then edit: set DETECTION_LAB_ROOT + all passwords
./bootstrap.sh
```

The bootstrap script:
1. loads and validates `.env`,
2. checks/sets `vm.max_map_count`,
3. clones `wazuh/wazuh-docker` at the pinned `WAZUH_DOCKER_TAG` into `wazuh-docker/`
   (gitignored — vendored files stay pristine),
4. copies our `docker-compose.override.yml` next to the vendored compose,
5. generates indexer TLS certs (one-time),
6. `docker compose up -d` with both compose files.

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
