#!/usr/bin/env bash
# Stand up the pinned Wazuh single-node stack with our detection-lab overlay.
# Run from the repo's infra/ directory inside WSL (Linux filesystem, not /mnt/c).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# --- Load and validate environment ------------------------------------------
if [[ ! -f .env ]]; then
  echo "ERROR: infra/.env not found. Run: cp .env.example .env  then edit it." >&2
  exit 1
fi
set -a; source .env; set +a

: "${WAZUH_DOCKER_TAG:?set WAZUH_DOCKER_TAG in .env}"
: "${DETECTION_LAB_ROOT:?set DETECTION_LAB_ROOT in .env (absolute WSL path to repo root)}"

if [[ "$DETECTION_LAB_ROOT" == /mnt/c/* ]]; then
  echo "WARNING: DETECTION_LAB_ROOT is on /mnt/c. File tailing (inotify) is unreliable" >&2
  echo "         across the Windows mount. Prefer a path under the WSL filesystem." >&2
fi

# --- Preflight: kernel setting the indexer needs -----------------------------
CURRENT_MMC="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
if (( CURRENT_MMC < 262144 )); then
  echo "vm.max_map_count is $CURRENT_MMC; the Wazuh indexer needs >= 262144."
  echo "Attempting to set it for this session (needs sudo)..."
  sudo sysctl -w vm.max_map_count=262144
  echo "To persist: add 'vm.max_map_count=262144' to /etc/sysctl.conf (in WSL)."
fi

# --- Fetch the pinned Wazuh stack (vendored, gitignored) ---------------------
VENDOR_DIR="$HERE/wazuh-docker"
if [[ ! -d "$VENDOR_DIR" ]]; then
  echo "Cloning wazuh/wazuh-docker @ ${WAZUH_DOCKER_TAG} ..."
  git clone --depth 1 --branch "$WAZUH_DOCKER_TAG" \
    https://github.com/wazuh/wazuh-docker.git "$VENDOR_DIR"
else
  echo "Using existing vendored stack at $VENDOR_DIR"
fi

SINGLE_NODE="$VENDOR_DIR/single-node"
[[ -f "$SINGLE_NODE/docker-compose.yml" ]] || {
  echo "ERROR: $SINGLE_NODE/docker-compose.yml missing (bad tag?)." >&2; exit 1; }

# Overlay our customization next to the vendored compose file.
cp "$HERE/docker-compose.override.yml" "$SINGLE_NODE/docker-compose.override.yml"
cp "$HERE/.env" "$SINGLE_NODE/.env"

cd "$SINGLE_NODE"

# --- Generate indexer certificates (one-time) --------------------------------
if [[ ! -d "$SINGLE_NODE/config/wazuh_indexer_ssl_certs" ]] || \
   [[ -z "$(ls -A "$SINGLE_NODE/config/wazuh_indexer_ssl_certs" 2>/dev/null || true)" ]]; then
  echo "Generating indexer certificates ..."
  docker compose -f generate-indexer-certs.yml run --rm generator
fi

# --- Bring up the stack with our overlay -------------------------------------
echo "Starting the stack ..."
docker compose -f docker-compose.yml -f docker-compose.override.yml up -d

cat <<EOF

Stack starting. Give the indexer ~1-2 minutes to go green.

  Wazuh Dashboard : https://localhost:443   (user: ${DASHBOARD_USERNAME:-admin})
  Wazuh Indexer   : https://localhost:9200
  Manager syslog  : 1514/tcp (agents), 1515/tcp (enrollment)

Check health:   docker compose ps
Manager logs:   docker compose logs -f wazuh.manager
EOF
