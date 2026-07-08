#!/usr/bin/env bash
# One-command deploy of the detection lab: pinned Wazuh single-node stack +
# detection-lab overlay, with credentials driven end-to-end from infra/.env —
# rotates the vendored default indexer passwords, enforces authenticated agent
# enrollment, creates the read-only dashboard account, and verifies the result.
# Idempotent: safe to re-run on a live stack.
# Run from the repo's infra/ directory inside WSL (Linux filesystem, not /mnt/c).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

log()  { printf '\n[bootstrap] %s\n' "$*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

# --- Load and validate environment ------------------------------------------
if [[ ! -f .env ]]; then
  fail "infra/.env not found. Run: cp .env.example .env  then edit it."
fi
set -a; source .env; set +a

: "${WAZUH_DOCKER_TAG:?set WAZUH_DOCKER_TAG in .env}"
: "${DETECTION_LAB_ROOT:?set DETECTION_LAB_ROOT in .env (absolute WSL path to repo root)}"

if [[ "$DETECTION_LAB_ROOT" == /mnt/c/* ]]; then
  echo "WARNING: DETECTION_LAB_ROOT is on /mnt/c. File tailing (inotify) is unreliable" >&2
  echo "         across the Windows mount. Prefer a path under the WSL filesystem." >&2
fi

# Refuse to deploy with vendored/placeholder secrets unless explicitly allowed.
require_secret() { # name value forbidden...
  local name=$1 value=$2; shift 2
  [[ -n "$value" ]] || fail "$name is empty in .env"
  local bad
  for bad in "$@"; do
    [[ "$value" == "$bad" ]] && fail \
      "$name still has the default/placeholder value '$bad'. Set a real secret in .env (or ALLOW_DEFAULT_CREDS=true for a throwaway lab)."
  done
  return 0
}
check_policy() { # name value — indexer accounts: 8+ chars, upper/lower/digit/special
  local p=$2
  [[ ${#p} -ge 8 && "$p" =~ [A-Z] && "$p" =~ [a-z] && "$p" =~ [0-9] && "$p" =~ [^a-zA-Z0-9] ]] \
    || fail "$1 must be 8+ chars with upper/lower/digit/special (indexer password policy)"
}
if [[ "${ALLOW_DEFAULT_CREDS:-false}" != "true" ]]; then
  require_secret INDEXER_PASSWORD "${INDEXER_PASSWORD:-}" SecretPassword CHANGE_ME_admin_password
  require_secret DASHBOARD_PASSWORD "${DASHBOARD_PASSWORD:-}" kibanaserver CHANGE_ME_kibanaserver_password
  require_secret CUSTOM_DASHBOARD_RO_PASSWORD "${CUSTOM_DASHBOARD_RO_PASSWORD:-}" CHANGE_ME_strong_password
  require_secret AGENT_ENROLLMENT_PASSWORD "${AGENT_ENROLLMENT_PASSWORD:-}" CHANGE_ME_enrollment_password
  check_policy INDEXER_PASSWORD "$INDEXER_PASSWORD"
  check_policy DASHBOARD_PASSWORD "$DASHBOARD_PASSWORD"
  check_policy CUSTOM_DASHBOARD_RO_PASSWORD "$CUSTOM_DASHBOARD_RO_PASSWORD"
else
  log "ALLOW_DEFAULT_CREDS=true — skipping secret validation (throwaway lab mode)."
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
  log "Cloning wazuh/wazuh-docker @ ${WAZUH_DOCKER_TAG} ..."
  git clone --depth 1 --branch "$WAZUH_DOCKER_TAG" \
    https://github.com/wazuh/wazuh-docker.git "$VENDOR_DIR"
else
  log "Using existing vendored stack at $VENDOR_DIR"
fi

SINGLE_NODE="$VENDOR_DIR/single-node"
[[ -f "$SINGLE_NODE/docker-compose.yml" ]] || \
  fail "$SINGLE_NODE/docker-compose.yml missing (bad tag?)."

# Overlay our customization next to the vendored compose file.
cp "$HERE/docker-compose.override.yml" "$SINGLE_NODE/docker-compose.override.yml"
cp "$HERE/.env" "$SINGLE_NODE/.env"

cd "$SINGLE_NODE"
compose() { docker compose -f docker-compose.yml -f docker-compose.override.yml "$@"; }

# --- Generate indexer certificates (one-time) --------------------------------
# The cert tool chowns the output dir away from the login user, making it
# unreadable — a plain `ls` then looks empty and would REGENERATE working certs
# on every re-run, breaking TLS for already-running containers (the indexer
# keeps the old certs in memory while recreated containers mount the new ones).
# An unreadable dir therefore MEANS the tool already ran: treat it as present.
CERT_DIR="$SINGLE_NODE/config/wazuh_indexer_ssl_certs"
if [[ ! -d "$CERT_DIR" ]]; then
  log "Generating indexer certificates ..."
  docker compose -f generate-indexer-certs.yml run --rm generator
elif [[ ! -r "$CERT_DIR" ]]; then
  log "Indexer certificates already present (dir is root-owned by the cert tool)."
elif [[ -z "$(ls -A "$CERT_DIR" 2>/dev/null || true)" ]]; then
  log "Generating indexer certificates ..."
  docker compose -f generate-indexer-certs.yml run --rm generator
else
  log "Indexer certificates already present."
fi

# --- Bring up the stack with our overlay -------------------------------------
log "Starting the stack ..."
compose up -d

MANAGER="single-node-wazuh.manager-1"
INDEXER="single-node-wazuh.indexer-1"
B="https://localhost:9200"

# HTTP status of an indexer request as the given user.
idx_code() { # user:pass path
  curl -sk -o /dev/null -w '%{http_code}' -u "$1" "$B$2" || echo 000
}

# --- Wait for the indexer API and detect the working admin password ----------
# ADMIN_PASS may legitimately end up empty here: when .env holds a brand-new
# password (re-rotation), neither it nor the vendored default matches the old
# one. That's fine — securityadmin authenticates with the admin TLS cert, so
# rotation below doesn't need the current password.
log "Waiting for the indexer API ..."
API_UP=""
ADMIN_PASS=""
for _ in $(seq 1 120); do
  c_env="$(idx_code "admin:${INDEXER_PASSWORD}" /)"
  if [[ "$c_env" == 200 ]]; then API_UP=yes; ADMIN_PASS="$INDEXER_PASSWORD"; break; fi
  c_def="$(idx_code "admin:SecretPassword" /)"
  if [[ "$c_def" == 200 ]]; then API_UP=yes; ADMIN_PASS="SecretPassword"; break; fi
  # Both rejected (401) means the API is up but the password is an older
  # custom one — proceed to rotation.
  if [[ "$c_env" == 401 && "$c_def" == 401 ]]; then API_UP=yes; break; fi
  sleep 5
done
[[ -n "$API_UP" ]] || fail "indexer API not reachable"

# --- Rotate the vendored default passwords (admin, kibanaserver) -------------
# The indexer authenticates against bcrypt hashes in internal_users.yml (a
# gitignored vendored-clone file we may patch); once the .security index is
# initialized the file is only re-read via securityadmin.sh.
if [[ "$ADMIN_PASS" != "$INDEXER_PASSWORD" ]]; then
  log "Rotating indexer passwords (admin, kibanaserver) ..."
  gen_hash() {
    docker exec "$INDEXER" bash -c \
      "JAVA_HOME=/usr/share/wazuh-indexer/jdk bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p '$1'" \
      | tail -1
  }
  ADMIN_HASH="$(gen_hash "$INDEXER_PASSWORD")"
  KIBANA_HASH="$(gen_hash "$DASHBOARD_PASSWORD")"
  [[ "$ADMIN_HASH" == \$2* && "$KIBANA_HASH" == \$2* ]] || fail "bcrypt hash generation failed"

  IU="$SINGLE_NODE/config/wazuh_indexer/internal_users.yml"
  patch_hash() { # user hash file — replace the hash: line inside the user's block.
    # Rewrite IN PLACE (cat >, not mv): the file is a per-file docker bind
    # mount, and replacing its inode breaks the mount until the container is
    # recreated (Docker Desktop pins bind sources by inode).
    awk -v user="$1:" -v hash="$2" '
      /^[^ ]/ { inblk = ($0 == user) }
      inblk && $1 == "hash:" { print "  hash: \"" hash "\""; next }
      { print }' "$3" > "$3.tmp" && cat "$3.tmp" > "$3" && rm "$3.tmp"
  }
  patch_hash admin "$ADMIN_HASH" "$IU"
  patch_hash kibanaserver "$KIBANA_HASH" "$IU"

  # Push ONLY the internal-users file: a full-directory push (-cd) would reset
  # roles/mappings to file state and wipe the REST-created read-only account.
  SA_OUT="$(docker exec "$INDEXER" bash -c '
    I=/usr/share/wazuh-indexer
    JAVA_HOME=$I/jdk bash $I/plugins/opensearch-security/tools/securityadmin.sh \
      -f $I/config/opensearch-security/internal_users.yml -t internalusers -icl -nhnv \
      -cacert $I/config/certs/root-ca.pem -cert $I/config/certs/admin.pem \
      -key $I/config/certs/admin-key.pem -h localhost -p 9200' 2>&1)" \
    || fail "securityadmin.sh failed:
$SA_OUT"

  [[ "$(idx_code "admin:${INDEXER_PASSWORD}" /)" == 200 ]] || fail "admin rotation did not take effect"
  [[ "$(idx_code "admin:SecretPassword" /)" == 401 ]] || fail "default admin password still works after rotation"
  ADMIN_PASS="$INDEXER_PASSWORD"

  # Recreate the clients so filebeat (manager) and the built-in dashboard pick
  # up the new INDEXER_PASSWORD / DASHBOARD_PASSWORD from the override env.
  log "Recreating manager + dashboard with the new credentials ..."
  compose up -d --force-recreate wazuh.manager wazuh.dashboard
else
  log "Indexer already uses the .env admin password — no rotation needed."
fi

# --- Wait for the manager's enrollment service (authd) ------------------------
log "Waiting for the manager's enrollment service (authd) ..."
for _ in $(seq 1 60); do
  if docker exec "$MANAGER" sh -c '/var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-authd is running"'; then
    break
  fi
  sleep 3
done

# --- Enforce authenticated agent enrollment ----------------------------------
if [[ -n "${AGENT_ENROLLMENT_PASSWORD:-}" ]]; then
  CURRENT_AUTHD="$(docker exec "$MANAGER" sh -c 'cat /var/ossec/etc/authd.pass 2>/dev/null' || true)"
  USE_PW="$(docker exec "$MANAGER" sh -c 'grep -c "<use_password>yes</use_password>" /var/ossec/etc/ossec.conf || true')"
  if [[ "$CURRENT_AUTHD" != "$AGENT_ENROLLMENT_PASSWORD" || "$USE_PW" == 0 ]]; then
    log "Enforcing authenticated agent enrollment (authd password) ..."
    docker exec "$MANAGER" sh -c \
      "echo '$AGENT_ENROLLMENT_PASSWORD' > /var/ossec/etc/authd.pass \
       && chown root:wazuh /var/ossec/etc/authd.pass && chmod 640 /var/ossec/etc/authd.pass \
       && sed -i 's#<use_password>no</use_password>#<use_password>yes</use_password>#' /var/ossec/etc/ossec.conf \
       && /var/ossec/bin/wazuh-control restart" >/dev/null
    log "authd now requires the enrollment password; already-enrolled agents keep their keys."
  else
    log "Authenticated enrollment already configured."
  fi
fi

# --- Ensure the agent's enrollment group exists (authd rejects unknown groups) -
AGENT_GROUP="detection-lab"
docker exec "$MANAGER" sh -c "mkdir -p /var/ossec/etc/shared/${AGENT_GROUP} \
  && chown -R wazuh:wazuh /var/ossec/etc/shared/${AGENT_GROUP}"
log "Ensured agent group '${AGENT_GROUP}' exists on the manager."

# --- Create/update the read-only account for the custom dashboard ------------
log "Creating/updating the read-only dashboard account (${CUSTOM_DASHBOARD_RO_USER}) ..."
API="$B/_plugins/_security/api"
AUTH="admin:${ADMIN_PASS}"
role_code=$(curl -sk -o /dev/null -w '%{http_code}' -u "$AUTH" -XPUT \
  "$API/roles/detectionlab_ro_role" -H 'Content-Type: application/json' -d '{
  "cluster_permissions": ["cluster_composite_ops_ro"],
  "index_permissions": [{"index_patterns":["wazuh-alerts-*"],
    "allowed_actions":["read","indices:admin/mappings/get","indices:admin/get","indices:monitor/settings/get"]}]}')
user_code=$(curl -sk -o /dev/null -w '%{http_code}' -u "$AUTH" -XPUT \
  "$API/internalusers/${CUSTOM_DASHBOARD_RO_USER}" -H 'Content-Type: application/json' -d "{
  \"password\":\"${CUSTOM_DASHBOARD_RO_PASSWORD}\",\"opendistro_security_roles\":[\"detectionlab_ro_role\"]}")
[[ "$role_code" =~ ^20[01]$ && "$user_code" =~ ^20[01]$ ]] \
  || fail "read-only account setup failed (role: $role_code, user: $user_code)"

# --- Retention / index lifecycle (ISM) ----------------------------------------
# Upserts a hot->delete ISM policy and attaches it to matching indices. The
# ism_template covers indices created later; the add/change_policy calls cover
# ones that already exist. Idempotent; a changed retention window in .env
# updates the policy and re-points managed indices at the new version.
ISM="$B/_plugins/_ism"
apply_retention() { # policy_id days patterns_json patterns_csv
  local id=$1 days=$2 patterns_json=$3 patterns_csv=$4
  [[ "$days" =~ ^[0-9]+$ ]] || fail "retention days for $id must be a number (got '$days')"
  if [[ "$days" == 0 ]]; then
    log "Retention for $patterns_csv disabled (0 days) — leaving indices unmanaged."
    return 0
  fi
  local body resp code seq prim
  body=$(cat <<JSON
{"policy":{"description":"detection-lab retention: delete ${days}d after index creation",
  "default_state":"hot",
  "states":[
    {"name":"hot","actions":[],
     "transitions":[{"state_name":"delete","conditions":{"min_index_age":"${days}d"}}]},
    {"name":"delete","actions":[{"delete":{}}],"transitions":[]}],
  "ism_template":[{"index_patterns":${patterns_json},"priority":10}]}}
JSON
)
  resp="$(curl -sk -u "$AUTH" "$ISM/policies/$id" -w '\n%{http_code}')"
  code="$(tail -1 <<<"$resp")"
  if [[ "$code" == 404 ]]; then
    log "Creating ISM policy $id (delete after ${days}d) ..."
    code=$(curl -sk -o /dev/null -w '%{http_code}' -u "$AUTH" -XPUT \
      "$ISM/policies/$id" -H 'Content-Type: application/json' -d "$body")
    [[ "$code" =~ ^20[01]$ ]] || fail "creating ISM policy $id failed (HTTP $code)"
  elif grep -q "\"min_index_age\":\"${days}d\"" <<<"$resp"; then
    log "ISM policy $id already at ${days}d."
  else
    log "Updating ISM policy $id to ${days}d ..."
    seq="$(grep -o '"_seq_no":[0-9]*' <<<"$resp" | head -1 | cut -d: -f2)"
    prim="$(grep -o '"_primary_term":[0-9]*' <<<"$resp" | head -1 | cut -d: -f2)"
    code=$(curl -sk -o /dev/null -w '%{http_code}' -u "$AUTH" -XPUT \
      "$ISM/policies/$id?if_seq_no=$seq&if_primary_term=$prim" \
      -H 'Content-Type: application/json' -d "$body")
    [[ "$code" =~ ^20[01]$ ]] || fail "updating ISM policy $id failed (HTTP $code)"
    # Re-point already-managed indices at the new policy version.
    curl -sk -o /dev/null -u "$AUTH" -XPOST "$ISM/change_policy/$patterns_csv" \
      -H 'Content-Type: application/json' -d "{\"policy_id\":\"$id\"}" || true
  fi
  # Attach to pre-existing unmanaged indices (already-managed ones are reported
  # as failures by the API and safely ignored).
  curl -sk -o /dev/null -u "$AUTH" -XPOST "$ISM/add/$patterns_csv" \
    -H 'Content-Type: application/json' -d "{\"policy_id\":\"$id\"}" || true
}
log "Applying retention policies ..."
apply_retention detectionlab-alerts-retention "${ALERTS_RETENTION_DAYS:-90}" \
  '["wazuh-alerts-*"]' 'wazuh-alerts-*'
apply_retention detectionlab-internal-retention "${INTERNAL_RETENTION_DAYS:-30}" \
  '["wazuh-monitoring-*","wazuh-statistics-*"]' 'wazuh-monitoring-*,wazuh-statistics-*'
# The ISM plugin creates its config index with 1 replica, which can never
# assign on a single-node cluster and turns health yellow. It is a protected
# system index (even admin gets 403 over basic auth), so drop the replica via
# the super-admin TLS cert from inside the indexer container.
docker exec "$INDEXER" bash -c '
  C=/usr/share/wazuh-indexer/config/certs
  curl -sk -o /dev/null --cert $C/admin.pem --key $C/admin-key.pem --cacert $C/root-ca.pem \
    -XPUT https://localhost:9200/.opendistro-ism-config/_settings \
    -H "Content-Type: application/json" -d "{\"index\":{\"number_of_replicas\":0}}"' || true

# --- Wait for the Linux agent to be Active ------------------------------------
log "Waiting for the Linux agent to enroll and go Active ..."
AGENT_OK=no
for _ in $(seq 1 40); do
  if docker exec "$MANAGER" /var/ossec/bin/agent_control -l 2>/dev/null | grep -q "Active"; then
    AGENT_OK=yes; break
  fi
  sleep 5
done

# --- Seed the custom dashboard's .env (never overwrites an existing one) ------
DASH_ENV="$DETECTION_LAB_ROOT/dashboard/.env"
if [[ ! -f "$DASH_ENV" ]]; then
  log "Writing $DASH_ENV (custom dashboard BFF config) ..."
  cat > "$DASH_ENV" <<EOF
INDEXER_URL=$B
INDEXER_RO_USER=${CUSTOM_DASHBOARD_RO_USER}
INDEXER_RO_PASSWORD=${CUSTOM_DASHBOARD_RO_PASSWORD}
ALERTS_INDEX=wazuh-alerts-*
PORT=8787
DASH_USER=admin
# Generate with: cd dashboard && npm run hash-password
DASH_PASSWORD_HASH=
EOF
fi

# --- Verification report -------------------------------------------------------
log "Verifying the deployment ..."
check() { printf '  %-46s %s\n' "$1" "$2"; }
HEALTH="$(curl -sk -u "$AUTH" "$B/_cluster/health" | grep -o '"status":"[a-z]*"' | cut -d'"' -f4)"
check "indexer cluster health" "${HEALTH:-unreachable}"
if [[ "${ALLOW_DEFAULT_CREDS:-false}" != "true" ]]; then
  [[ "$(idx_code admin:SecretPassword /)" == 401 ]] && check "default admin password disabled" "yes" \
    || check "default admin password disabled" "NO — STILL ACTIVE"
  [[ "$(idx_code kibanaserver:kibanaserver /)" == 401 ]] && check "default kibanaserver password disabled" "yes" \
    || check "default kibanaserver password disabled" "NO — STILL ACTIVE"
fi
RO="${CUSTOM_DASHBOARD_RO_USER}:${CUSTOM_DASHBOARD_RO_PASSWORD}"
RO_READ="$(idx_code "$RO" '/wazuh-alerts-*/_count')"
RO_WRITE="$(curl -sk -o /dev/null -w '%{http_code}' -u "$RO" -XPOST \
  "$B/wazuh-alerts-4.x-probe/_doc" -H 'Content-Type: application/json' -d '{"probe":1}')"
check "read-only account can read alerts" "$([[ "$RO_READ" == 200 ]] && echo yes || echo NO)"
check "read-only account denied writes" "$([[ "$RO_WRITE" == 403 ]] && echo yes || echo "NO ($RO_WRITE)")"
check "linux agent active" "$AGENT_OK"
if [[ "${ALERTS_RETENTION_DAYS:-90}" != 0 ]]; then
  MANAGED="$(curl -sk -u "$AUTH" "$ISM/explain/wazuh-alerts-*" | grep -o '"policy_id":"detectionlab-alerts-retention"' | wc -l)"
  check "alerts retention (${ALERTS_RETENTION_DAYS:-90}d) on indices" \
    "$([[ "$MANAGED" -gt 0 ]] && echo "yes ($MANAGED)" || echo NO)"
fi
if [[ -n "${AGENT_ENROLLMENT_PASSWORD:-}" ]]; then
  check "authenticated enrollment (authd.pass)" "$(docker exec "$MANAGER" sh -c 'test -s /var/ossec/etc/authd.pass && grep -q "<use_password>yes</use_password>" /var/ossec/etc/ossec.conf' && echo yes || echo NO)"
fi

cat <<EOF

Deploy complete.

  Wazuh Dashboard : https://localhost:443   (admin / INDEXER_PASSWORD from infra/.env)
  Wazuh Indexer   : https://localhost:9200
  Custom dashboard: see dashboard/README.md (BFF config seeded at dashboard/.env;
                    set DASH_PASSWORD_HASH via 'npm run hash-password' if empty)
  Enroll an agent : point it at this host, port 1515, with AGENT_ENROLLMENT_PASSWORD

Known remaining default: the Wazuh API account (wazuh-wui) still uses the vendored
password — internal to the compose network; rotation is a future hardening step.

Check health:   docker compose ps
Agent list:     docker exec ${MANAGER} /var/ossec/bin/agent_control -l
Manager logs:   docker compose logs -f wazuh.manager
EOF
