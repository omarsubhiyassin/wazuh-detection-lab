#!/usr/bin/env bash
# Provision a fresh tenant's infra/.env with cryptographically-random secrets —
# the "new org = one command" step. Renders .env from .env.example, replacing
# every CHANGE_ME* secret with a strong generated value, sets DETECTION_LAB_ROOT
# and TENANT_NAME, generates the custom-dashboard admin password + hash, and
# writes a one-time credentials file for the operator's vault (nothing else
# records the plaintext — bootstrap stores only hashes).
#
#   ./provision-env.sh [--tenant NAME] [--root PATH] [--out FILE] [--force]
#
# Idempotent-safe: refuses to overwrite an existing --out unless --force.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
EXAMPLE="$HERE/.env.example"

TENANT="tenant-$(openssl rand -hex 3)"
ROOT="$REPO_ROOT"
OUT="$HERE/.env"
FORCE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tenant) TENANT="$2"; shift 2;;
    --root)   ROOT="$2"; shift 2;;
    --out)    OUT="$2"; shift 2;;
    --force)  FORCE=1; shift;;
    -h|--help) grep '^#' "$0" | sed -n '2,10p'; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

[[ -f "$EXAMPLE" ]] || { echo "ERROR: $EXAMPLE not found" >&2; exit 1; }
if [[ -f "$OUT" && "$FORCE" != 1 ]]; then
  echo "ERROR: $OUT already exists — refusing to overwrite (use --force)." >&2
  exit 1
fi

# Strong secret: <prefix>-<20 random alnum>-Aa1 guarantees upper/lower/digit/
# special, 8-64 chars, and no quote/backslash/space (bootstrap's policy).
gen() {
  local rand; rand="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20)"
  printf '%s-%s-Aa1' "$1" "$rand"
}
policy_ok() { # mirror bootstrap's check_policy so we never emit a rejected value
  local p="$1"
  [[ ${#p} -ge 8 && ${#p} -le 64 && "$p" =~ [A-Z] && "$p" =~ [a-z] && "$p" =~ [0-9] && "$p" =~ [^a-zA-Z0-9] ]] \
    && ! [[ "$p" =~ [\"\'\\[:space:]] ]]
}

INDEXER_PW="$(gen Idx)"
DASHBOARD_PW="$(gen Dsh)"
API_PW="$(gen Api)"
RO_PW="$(gen Ro)"
ENROLL_PW="$(gen Enr)"
DASH_ADMIN_PW="$(gen Dash)"
for s in "$INDEXER_PW" "$DASHBOARD_PW" "$API_PW" "$RO_PW" "$ENROLL_PW" "$DASH_ADMIN_PW"; do
  policy_ok "$s" || { echo "ERROR: generated a secret that fails policy — aborting" >&2; exit 1; }
done

# --- Render infra/.env from the example --------------------------------------
tmp="$(mktemp)"
sed \
  -e "s#^DETECTION_LAB_ROOT=.*#DETECTION_LAB_ROOT=${ROOT}#" \
  -e "s#^INDEXER_PASSWORD=.*#INDEXER_PASSWORD=${INDEXER_PW}#" \
  -e "s#^DASHBOARD_PASSWORD=.*#DASHBOARD_PASSWORD=${DASHBOARD_PW}#" \
  -e "s#^API_PASSWORD=.*#API_PASSWORD=${API_PW}#" \
  -e "s#^CUSTOM_DASHBOARD_RO_PASSWORD=.*#CUSTOM_DASHBOARD_RO_PASSWORD=${RO_PW}#" \
  -e "s#^AGENT_ENROLLMENT_PASSWORD=.*#AGENT_ENROLLMENT_PASSWORD=${ENROLL_PW}#" \
  "$EXAMPLE" > "$tmp"
# Add a tenant identifier (used by healthcheck's Slack messages for fleet view).
grep -q '^TENANT_NAME=' "$tmp" || printf '\n# --- Fleet identity (this deployment) ---\nTENANT_NAME=%s\n' "$TENANT" >> "$tmp"
install -m 600 "$tmp" "$OUT"; rm -f "$tmp"

# --- Dashboard admin password hash -------------------------------------------
DASH_HASH=""
if command -v node >/dev/null && [[ -f "$REPO_ROOT/dashboard/scripts/hash-password.mjs" ]]; then
  DASH_HASH="$(printf '%s' "$DASH_ADMIN_PW" | node "$REPO_ROOT/dashboard/scripts/hash-password.mjs" \
    | grep '^DASH_PASSWORD_HASH=' | cut -d= -f2- || true)"
fi

# --- One-time credentials file for the operator's vault ----------------------
CREDS="${OUT%.env}.provision-credentials.txt"
[[ "$CREDS" == "$OUT" ]] && CREDS="$OUT.provision-credentials.txt"
umask 077
cat > "$CREDS" <<EOF
# Detection-lab tenant credentials — generated $(date -u +%FT%TZ)
# Tenant: ${TENANT}
# STORE THESE IN YOUR SECRETS VAULT, THEN DELETE THIS FILE. bootstrap keeps only
# hashes; these plaintext values are not recorded anywhere else.

Indexer / Wazuh dashboard   admin        ${INDEXER_PW}
Dashboard service account   kibanaserver ${DASHBOARD_PW}
Wazuh API                   wazuh-wui    ${API_PW}
Read-only (custom dash)     detectionlab_ro ${RO_PW}
Agent enrollment password                ${ENROLL_PW}
Custom dashboard admin      admin        ${DASH_ADMIN_PW}
EOF
chmod 600 "$CREDS"

echo "Provisioned tenant '${TENANT}':"
echo "  .env         -> $OUT (mode 600)"
echo "  credentials  -> $CREDS (mode 600 — save to vault, then delete)"
if [[ -n "$DASH_HASH" ]]; then
  echo "  dashboard admin hash generated (add to dashboard/.env as DASH_PASSWORD_HASH):"
  echo "    DASH_PASSWORD_HASH=$DASH_HASH"
else
  echo "  (node not found — set the dashboard admin password later with 'npm run hash-password')"
fi
echo
echo "Next: ./bootstrap.sh   (validates + deploys the full stack from this .env)"
