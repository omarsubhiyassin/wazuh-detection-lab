#!/usr/bin/env bash
# Safe deploy of local_rules.xml to the running manager, with automatic
# rollback. A malformed rule takes analysisd down and with it the whole
# manager, so this backs up the live rules, restarts, verifies analysisd
# actually came back, runs the logtest harness as a smoke test, and reverts
# to the backup if anything fails.
#
#   detections/deploy-rules.sh
#
# The rules file is bind-mounted into the manager from this checkout, so
# "deploy" = (whatever is in detections/rules/local_rules.xml now) + restart.
# Update the file first (edit or `git pull`), then run this.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES="$HERE/rules/local_rules.xml"
MANAGER="${MANAGER:-single-node-wazuh.manager-1}"
BACKUP="$(mktemp /tmp/local_rules.XXXXXX.xml)"
export MSYS_NO_PATHCONV=1

log() { printf '\n[deploy] %s\n' "$*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null || fail "docker not found"
docker exec "$MANAGER" true 2>/dev/null || fail "manager container '$MANAGER' not running"
[[ -f "$RULES" ]] || fail "$RULES not found"

# 0. Pre-flight: XML must be well-formed (wrap the multi-root fragment). Use
# whatever validator the host has (python3 or xmllint); skip if neither.
xml_ok() {
  if command -v python3 >/dev/null; then
    { echo '<root>'; cat "$RULES"; echo '</root>'; } | \
      python3 -c 'import sys,xml.dom.minidom; xml.dom.minidom.parseString(sys.stdin.read())' 2>/dev/null
  elif command -v xmllint >/dev/null; then
    { echo '<root>'; cat "$RULES"; echo '</root>'; } | xmllint --noout - 2>/dev/null
  else
    echo "[deploy] no python3/xmllint for XML pre-check — relying on analysisd." >&2
    return 0
  fi
}
xml_ok || fail "local_rules.xml is not well-formed XML — aborting before touching the manager"

# 1. Back up the live rules (as analysisd currently sees them).
docker exec "$MANAGER" cat /var/ossec/etc/rules/local_rules.xml > "$BACKUP" 2>/dev/null \
  || fail "could not read the live rules for backup"
log "Backed up current live rules -> $BACKUP"

restart_and_wait() { # returns 0 if analysisd comes up within ~120s
  docker restart "$MANAGER" >/dev/null
  for _ in $(seq 1 30); do
    if docker exec "$MANAGER" sh -c '/var/ossec/bin/wazuh-control status 2>/dev/null \
        | grep -q "wazuh-analysisd is running"'; then return 0; fi
    sleep 4
  done
  return 1
}

rollback() {
  log "Rolling back to the pre-deploy rules ..."
  # Restore into the bind-mounted host file so the mount stays intact.
  cat "$BACKUP" > "$RULES"
  if restart_and_wait; then
    echo "[deploy] Rolled back; analysisd healthy again on the previous rules." >&2
  else
    echo "[deploy] ROLLBACK ALSO FAILED — manager is down. Investigate:" >&2
    echo "         docker logs $MANAGER | tail -40" >&2
  fi
}

# 2. Deploy: restart so analysisd loads the (bind-mounted) new rules.
log "Restarting the manager to load the new rules ..."
if ! restart_and_wait; then
  echo "[deploy] analysisd did NOT come up — the new rules likely crashed it." >&2
  rollback
  fail "deploy failed (rolled back)"
fi
log "analysisd is running with the new rules."

# 3. Smoke test: the frozen-sample harness must stay green.
log "Running the detection harness as a smoke test ..."
if MANAGER="$MANAGER" bash "$HERE/tests/run_logtest.sh" | tail -1 | grep -q 'failed=0'; then
  log "Smoke test passed. Deploy complete."
  rm -f "$BACKUP"
else
  echo "[deploy] Smoke test FAILED — rules loaded but a detection regressed." >&2
  rollback
  fail "deploy failed the smoke test (rolled back)"
fi
