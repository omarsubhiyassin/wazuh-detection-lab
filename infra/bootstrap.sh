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
check_policy() { # name value — indexer/API accounts: 8+ chars, upper/lower/digit/special
  local p=$2
  [[ ${#p} -ge 8 && "$p" =~ [A-Z] && "$p" =~ [a-z] && "$p" =~ [0-9] && "$p" =~ [^a-zA-Z0-9] ]] \
    || fail "$1 must be 8+ chars with upper/lower/digit/special (password policy)"
  case "$p" in
    *[\"\']*|*\\*|*[[:space:]]*)
      fail "$1 must not contain quotes, backslashes or whitespace (embedded in shell/JSON)";;
  esac
}
if [[ "${ALLOW_DEFAULT_CREDS:-false}" != "true" ]]; then
  require_secret INDEXER_PASSWORD "${INDEXER_PASSWORD:-}" SecretPassword CHANGE_ME_admin_password
  require_secret DASHBOARD_PASSWORD "${DASHBOARD_PASSWORD:-}" kibanaserver CHANGE_ME_kibanaserver_password
  require_secret CUSTOM_DASHBOARD_RO_PASSWORD "${CUSTOM_DASHBOARD_RO_PASSWORD:-}" CHANGE_ME_strong_password
  require_secret AGENT_ENROLLMENT_PASSWORD "${AGENT_ENROLLMENT_PASSWORD:-}" CHANGE_ME_enrollment_password
  require_secret API_PASSWORD "${API_PASSWORD:-}" 'MyS3cr37P450r.*-' CHANGE_ME_api_password
  check_policy INDEXER_PASSWORD "$INDEXER_PASSWORD"
  check_policy DASHBOARD_PASSWORD "$DASHBOARD_PASSWORD"
  check_policy CUSTOM_DASHBOARD_RO_PASSWORD "$CUSTOM_DASHBOARD_RO_PASSWORD"
  check_policy API_PASSWORD "$API_PASSWORD"
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

# Create the backup dirs BEFORE compose up: the override bind-mounts
# ${BACKUP_DIR}/snapshots, and docker would otherwise create it root-owned.
BACKUP_DIR="${BACKUP_DIR:-/var/tmp/detection-lab-backups}"
mkdir -p "$BACKUP_DIR/snapshots" "$BACKUP_DIR/manager"

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

# --- Active response (auto-block brute-force sources) -------------------------
# Same marked-block pattern as Slack below: a distinct <ossec_config> section
# appended to the manager's ossec.conf, rewritten only on change, removed
# entirely (with a restart) when disabled. Uses the manager's already-shipped
# "firewall-drop" command (confirmed present by default) at <location>local</location>
# — meaning it runs on the agent that generated the triggering event, i.e. the
# host actually being brute-forced blocks the source at its own firewall.
AR_MARK="detection-lab:active-response"
is_ip_or_cidr() { [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ || "$1" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; }

if [[ "${ACTIVE_RESPONSE_ENABLED:-false}" == "true" ]]; then
  AR_RULES="${ACTIVE_RESPONSE_RULES:-5712,5763}"
  AR_TIMEOUT="${ACTIVE_RESPONSE_TIMEOUT:-600}"
  [[ "$AR_RULES" =~ ^[0-9]+(,[0-9]+)*$ ]] || fail "ACTIVE_RESPONSE_RULES must be a comma-separated list of rule IDs (got '$AR_RULES')"
  [[ "$AR_TIMEOUT" =~ ^[0-9]+$ ]] || fail "ACTIVE_RESPONSE_TIMEOUT must be a number of seconds (got '$AR_TIMEOUT')"

  # Safety allowlist: loopback + this compose project's internal network are
  # always exempt; anything in .env is added on top, after format validation
  # (these values are embedded into XML — reject anything that isn't a plain
  # IP/CIDR rather than pass it through unescaped).
  AR_NET="$(docker inspect "$MANAGER" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null)"
  AR_SUBNET="$(docker network inspect "$AR_NET" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null || true)"
  AR_WHITELIST_XML="  <white_list>127.0.0.1</white_list>
  <white_list>::1</white_list>"
  [[ -n "$AR_SUBNET" ]] && AR_WHITELIST_XML+="
  <white_list>${AR_SUBNET}</white_list>"
  if [[ -n "${ACTIVE_RESPONSE_ALLOWLIST:-}" ]]; then
    IFS=',' read -ra AR_EXTRA <<<"$ACTIVE_RESPONSE_ALLOWLIST"
    for ip in "${AR_EXTRA[@]}"; do
      ip="$(echo "$ip" | xargs)" # trim whitespace
      [[ -z "$ip" ]] && continue
      is_ip_or_cidr "$ip" || fail "ACTIVE_RESPONSE_ALLOWLIST entry '$ip' doesn't look like an IP or CIDR"
      AR_WHITELIST_XML+="
  <white_list>${ip}</white_list>"
    done
  fi

  DESIRED_AR=$(cat <<XML
<!-- ${AR_MARK}:start (managed by bootstrap — do not edit) -->
<ossec_config>
  <global>
${AR_WHITELIST_XML}
  </global>
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>${AR_RULES}</rules_id>
    <timeout>${AR_TIMEOUT}</timeout>
  </active-response>
</ossec_config>
<!-- ${AR_MARK}:end -->
XML
)
  CURRENT_AR="$(docker exec "$MANAGER" sh -c \
    "sed -n '/${AR_MARK}:start/,/${AR_MARK}:end/p' /var/ossec/etc/ossec.conf")"
  if [[ "$CURRENT_AR" != "$DESIRED_AR" ]]; then
    log "Configuring active response (auto-block on rules ${AR_RULES}, ${AR_TIMEOUT}s timeout) ..."
    docker exec -i "$MANAGER" sh -c "
      sed -i '/${AR_MARK}:start/,/${AR_MARK}:end/d' /var/ossec/etc/ossec.conf \
      && cat >> /var/ossec/etc/ossec.conf \
      && /var/ossec/bin/wazuh-control restart" <<<"$DESIRED_AR" >/dev/null
  else
    log "Active response already configured (rules ${AR_RULES}, ${AR_TIMEOUT}s timeout)."
  fi
  log "NOTE: this lab's agent container has no iptables/NET_ADMIN — the block will be"
  log "      correctly INVOKED but fail to execute here. Real Linux/Windows endpoints"
  log "      (Phase 3) have a firewall and root by default and will actually block."
else
  if docker exec "$MANAGER" grep -q "${AR_MARK}:start" /var/ossec/etc/ossec.conf 2>/dev/null; then
    log "ACTIVE_RESPONSE_ENABLED not true — removing the active-response config ..."
    docker exec "$MANAGER" sh -c "
      sed -i '/${AR_MARK}:start/,/${AR_MARK}:end/d' /var/ossec/etc/ossec.conf \
      && /var/ossec/bin/wazuh-control restart" >/dev/null
  else
    log "ACTIVE_RESPONSE_ENABLED not true — active response disabled."
  fi
fi

# --- Slack notifications (integrator) -----------------------------------------
# Managed as a marked block appended to the manager's ossec.conf (multiple
# <ossec_config> sections are valid). Idempotent: rewritten only on change,
# removed entirely when SLACK_WEBHOOK_URL is unset.
SLACK_MARK="detection-lab:slack"
if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
  NL="${NOTIFY_MIN_LEVEL:-12}"
  [[ "$NL" =~ ^[0-9]+$ ]] || fail "NOTIFY_MIN_LEVEL must be a number (got '$NL')"
  DESIRED_SLACK=$(cat <<XML
<!-- ${SLACK_MARK}:start (managed by bootstrap — do not edit) -->
<ossec_config>
  <integration>
    <name>slack</name>
    <hook_url>${SLACK_WEBHOOK_URL}</hook_url>
    <level>${NL}</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
<!-- ${SLACK_MARK}:end -->
XML
)
  CURRENT_SLACK="$(docker exec "$MANAGER" sh -c \
    "sed -n '/${SLACK_MARK}:start/,/${SLACK_MARK}:end/p' /var/ossec/etc/ossec.conf")"
  if [[ "$CURRENT_SLACK" != "$DESIRED_SLACK" ]]; then
    log "Configuring Slack notifications (alerts level >= ${NL}) ..."
    docker exec -i "$MANAGER" sh -c "
      sed -i '/${SLACK_MARK}:start/,/${SLACK_MARK}:end/d' /var/ossec/etc/ossec.conf \
      && cat >> /var/ossec/etc/ossec.conf \
      && /var/ossec/bin/wazuh-control restart" <<<"$DESIRED_SLACK" >/dev/null
  else
    log "Slack notifications already configured (level >= ${NL})."
  fi
else
  if docker exec "$MANAGER" grep -q "${SLACK_MARK}:start" /var/ossec/etc/ossec.conf 2>/dev/null; then
    log "SLACK_WEBHOOK_URL unset — removing the Slack notification config ..."
    docker exec "$MANAGER" sh -c "
      sed -i '/${SLACK_MARK}:start/,/${SLACK_MARK}:end/d' /var/ossec/etc/ossec.conf \
      && /var/ossec/bin/wazuh-control restart" >/dev/null
  else
    log "SLACK_WEBHOOK_URL not set — Slack notifications disabled."
  fi
fi

# --- Rotate the Wazuh API account (wazuh-wui) ----------------------------------
# The built-in dashboard talks to the manager API (55000) as wazuh-wui. On a
# fresh volume the manager seeds the user from the override's API_PASSWORD; on
# an existing stack we rotate via the API itself (JWT as the current password).
WAPI="https://localhost:55000"
API_PW_DESIRED="${API_PASSWORD:-MyS3cr37P450r.*-}"
api_auth_code() { curl -sk -o /dev/null -w '%{http_code}' -u "wazuh-wui:$1" -X POST "$WAPI/security/user/authenticate" || echo 000; }
log "Waiting for the manager API ..."
API_CUR=""
for _ in $(seq 1 60); do
  if [[ "$(api_auth_code "$API_PW_DESIRED")" == 200 ]]; then API_CUR="$API_PW_DESIRED"; break; fi
  if [[ "$(api_auth_code 'MyS3cr37P450r.*-')" == 200 ]]; then API_CUR='MyS3cr37P450r.*-'; break; fi
  sleep 5
done
[[ -n "$API_CUR" ]] || fail "manager API unreachable, or neither .env nor default wazuh-wui password works"
if [[ "$API_CUR" != "$API_PW_DESIRED" ]]; then
  log "Rotating the Wazuh API password (wazuh-wui) ..."
  API_TOKEN="$(curl -sk -u "wazuh-wui:$API_CUR" -X POST "$WAPI/security/user/authenticate?raw=true")"
  WUI_ID="$(curl -sk -H "Authorization: Bearer $API_TOKEN" "$WAPI/security/users?search=wazuh-wui" \
    | grep -o '"id": *[0-9]*' | head -1 | grep -o '[0-9]*')"
  [[ -n "$WUI_ID" ]] || fail "could not resolve the wazuh-wui user id from the API"
  code=$(curl -sk -o /dev/null -w '%{http_code}' -X PUT "$WAPI/security/users/$WUI_ID" \
    -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"password\":\"$API_PW_DESIRED\"}")
  [[ "$code" == 200 ]] || fail "wazuh-wui password rotation failed (HTTP $code)"
  [[ "$(api_auth_code "$API_PW_DESIRED")" == 200 ]] || fail "rotated API password does not authenticate"
  # The built-in dashboard reads API_PASSWORD from the override env — recreate
  # it so it talks to the API with the new credential.
  compose up -d --force-recreate wazuh.dashboard
else
  log "Wazuh API already uses the .env password — no rotation needed."
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
# The ISM/job-scheduler plugins create their internal indices (config, history,
# lock) with 1 replica, which can never assign on a single-node cluster and
# turns health yellow. Make future history indices replica-free via a cluster
# setting, and zero out the existing internal indices. They are protected
# system indices (even admin gets 403 over basic auth), so use the super-admin
# TLS cert from inside the indexer container.
curl -sk -o /dev/null -u "$AUTH" -XPUT "$B/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{"persistent":{"plugins.index_state_management.history.number_of_replicas":"0"}}' || true
docker exec "$INDEXER" bash -c '
  C=/usr/share/wazuh-indexer/config/certs
  curl -sk -o /dev/null --cert $C/admin.pem --key $C/admin-key.pem --cacert $C/root-ca.pem \
    -XPUT "https://localhost:9200/.opendistro-ism-config,.opendistro-ism-managed-index-history-*,.opendistro-job-scheduler-lock/_settings?expand_wildcards=all" \
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

# --- Backups: snapshot repository + daily cron ---------------------------------
# The override mounts ${BACKUP_DIR}/snapshots at /mnt/snapshots; the indexer
# additionally needs path.repo in its config (a bind-mounted vendored file —
# append IN PLACE, same inode rule as internal_users.yml) and a restart when
# that line is first added.
IYML="$SINGLE_NODE/config/wazuh_indexer/wazuh.indexer.yml"
if ! grep -q '^path\.repo' "$IYML"; then
  log "Enabling the snapshot path on the indexer (one-time indexer restart) ..."
  printf '\npath.repo: ["/mnt/snapshots"]\n' >> "$IYML"
  compose up -d --force-recreate wazuh.indexer
  for _ in $(seq 1 90); do
    [[ "$(idx_code "admin:${ADMIN_PASS}" /)" == 200 ]] && break
    sleep 5
  done
fi
repo_code=$(curl -sk -o /dev/null -w '%{http_code}' -u "$AUTH" -XPUT \
  "$B/_snapshot/detectionlab" -H 'Content-Type: application/json' \
  -d '{"type":"fs","settings":{"location":"/mnt/snapshots","compress":true}}')
[[ "$repo_code" =~ ^20[01]$ ]] || fail "snapshot repository registration failed (HTTP $repo_code)"
if command -v crontab >/dev/null 2>&1; then
  "$HERE/backup.sh" --install >/dev/null
  log "Backups: repository registered; daily 02:00 cron installed -> $BACKUP_DIR"
fi

# --- Self-monitoring: healthcheck on a cron schedule ---------------------------
if command -v crontab >/dev/null 2>&1; then
  "$HERE/healthcheck.sh" --install >/dev/null
  log "Healthcheck installed (cron, every 5 min; alerts to Slack on state change)."
else
  log "crontab not available — run infra/healthcheck.sh on a schedule yourself."
fi

# --- Custom dashboard: TLS cert + .env ----------------------------------------
# Self-signed pair for the BFF (same posture as the stack's own certs). The
# dashboard/certs dir is gitignored via the repo-wide **/certs/ rule.
DASH_CERT_DIR="$DETECTION_LAB_ROOT/dashboard/certs"
if [[ ! -s "$DASH_CERT_DIR/dashboard.pem" ]]; then
  log "Generating a self-signed TLS cert for the custom dashboard ..."
  mkdir -p "$DASH_CERT_DIR"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "$DASH_CERT_DIR/dashboard-key.pem" -out "$DASH_CERT_DIR/dashboard.pem" \
    -subj "/CN=detection-lab-dashboard" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
  chmod 600 "$DASH_CERT_DIR/dashboard-key.pem"
fi

# Seed dashboard/.env on first run; on existing files only append the TLS block
# if absent (never touches credentials).
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
DASH_TLS_CERT=$DASH_CERT_DIR/dashboard.pem
DASH_TLS_KEY=$DASH_CERT_DIR/dashboard-key.pem
DASH_COOKIE_SECURE=true
EOF
elif ! grep -q '^DASH_TLS_CERT=' "$DASH_ENV"; then
  log "Enabling TLS in the existing $DASH_ENV (restart the BFF to apply) ..."
  cat >> "$DASH_ENV" <<EOF
DASH_TLS_CERT=$DASH_CERT_DIR/dashboard.pem
DASH_TLS_KEY=$DASH_CERT_DIR/dashboard-key.pem
DASH_COOKIE_SECURE=true
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
  [[ "$(api_auth_code 'MyS3cr37P450r.*-')" == 401 ]] && check "default wazuh-wui API password disabled" "yes" \
    || check "default wazuh-wui API password disabled" "NO — STILL ACTIVE"
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
if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
  check "slack notifications (level >= ${NOTIFY_MIN_LEVEL:-12})" \
    "$(docker exec "$MANAGER" sh -c 'grep -q "<name>slack</name>" /var/ossec/etc/ossec.conf && /var/ossec/bin/wazuh-control status | grep -q "wazuh-integratord is running"' && echo yes || echo NO)"
fi
if [[ "${ACTIVE_RESPONSE_ENABLED:-false}" == "true" ]]; then
  check "active response (rules ${ACTIVE_RESPONSE_RULES:-5712,5763})" \
    "$(docker exec "$MANAGER" grep -q "${AR_MARK}:start" /var/ossec/etc/ossec.conf && echo yes || echo NO)"
fi

cat <<EOF

Deploy complete.

  Wazuh Dashboard : https://localhost:443   (admin / INDEXER_PASSWORD from infra/.env)
  Wazuh Indexer   : https://localhost:9200
  Custom dashboard: see dashboard/README.md (BFF config seeded at dashboard/.env;
                    set DASH_PASSWORD_HASH via 'npm run hash-password' if empty)
  Enroll an agent : point it at this host, port 1515, with AGENT_ENROLLMENT_PASSWORD

Check health:   docker compose ps
Agent list:     docker exec ${MANAGER} /var/ossec/bin/agent_control -l
Manager logs:   docker compose logs -f wazuh.manager
EOF
