#!/usr/bin/env bash
# Self-monitoring for the detection lab: checks the SIEM is actually alive and
# posts state CHANGES to Slack — one message on failure (with periodic
# reminders), one on recovery. A silent SIEM is false confidence.
#
#   ./healthcheck.sh            run the checks once (cron calls this)
#   ./healthcheck.sh --install  install a */5 cron entry for this script
#
# Reads infra/.env for SLACK_WEBHOOK_URL, INDEXER_PASSWORD and the knobs below.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$HERE/.env" ]] && { set -a; source "$HERE/.env"; set +a; }

DISK_ALERT_PCT="${DISK_ALERT_PCT:-80}"     # alert when indexer disk use exceeds this
EVENT_STALL_HOURS="${EVENT_STALL_HOURS:-0}" # alert when no new alerts for N hours (0 = off)
REMIND_HOURS="${REMIND_HOURS:-6}"          # re-post while still failing
STATE_FILE="$HERE/.healthcheck.state"

if [[ "${1:-}" == "--install" ]]; then
  ENTRY="*/5 * * * * $HERE/healthcheck.sh >> $HERE/.healthcheck.log 2>&1 # detection-lab-healthcheck"
  ( crontab -l 2>/dev/null | grep -v detection-lab-healthcheck; echo "$ENTRY" ) | crontab -
  echo "Installed cron entry (every 5 min): $ENTRY"
  exit 0
fi
B="https://localhost:9200"
AUTH="admin:${INDEXER_PASSWORD:-}"
MANAGER="single-node-wazuh.manager-1"
CONTAINERS=(single-node-wazuh.manager-1 single-node-wazuh.indexer-1
            single-node-wazuh.dashboard-1 single-node-wazuh.agent.linux-1)

FAILURES=()

# --- Checks -------------------------------------------------------------------
for c in "${CONTAINERS[@]}"; do
  state="$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)"
  [[ "$state" == "running" ]] || FAILURES+=("container $c is $state")
done

HEALTH="$(curl -sk -m 10 -u "$AUTH" "$B/_cluster/health" 2>/dev/null \
  | grep -o '"status":"[a-z]*"' | cut -d'"' -f4)"
if [[ -z "$HEALTH" ]]; then
  FAILURES+=("indexer API unreachable")
elif [[ "$HEALTH" != green ]]; then
  FAILURES+=("indexer cluster health is $HEALTH")
fi

if [[ -n "$HEALTH" ]]; then
  DISK="$(curl -sk -m 10 -u "$AUTH" "$B/_cat/allocation?h=disk.percent" 2>/dev/null \
    | tr -d ' ' | head -1)"
  if [[ "$DISK" =~ ^[0-9]+ ]] && (( ${DISK%%.*} >= DISK_ALERT_PCT )); then
    FAILURES+=("indexer disk at ${DISK}% (threshold ${DISK_ALERT_PCT}%)")
  fi
fi

if docker inspect -f '{{.State.Status}}' "$MANAGER" 2>/dev/null | grep -q running; then
  docker exec "$MANAGER" filebeat test output >/dev/null 2>&1 \
    || FAILURES+=("manager filebeat cannot ship to the indexer")
  AGENT_LIST="$(docker exec "$MANAGER" /var/ossec/bin/agent_control -l 2>/dev/null)"
  ACTIVE="$(grep -c Active <<<"$AGENT_LIST")"
  (( ACTIVE >= 1 )) || FAILURES+=("no agent is Active")
  # A previously-enrolled agent that is now Disconnected/Never connected is a
  # blind spot — name it. (id: 000 is the manager itself; skip it.)
  DISC="$(grep -E 'Disconnected|Never connected' <<<"$AGENT_LIST" | grep -v 'ID: 000' \
    | sed -E 's/.*Name: ([^,]+),.*/\1/' | paste -sd, - | sed 's/,/, /g')"
  [[ -n "$DISC" ]] && FAILURES+=("agent(s) not reporting: $DISC")
fi

if [[ "$EVENT_STALL_HOURS" =~ ^[1-9][0-9]*$ && -n "$HEALTH" ]]; then
  NEWEST="$(curl -sk -m 10 -u "$AUTH" "$B/wazuh-alerts-*/_search?size=1&sort=timestamp:desc&_source=timestamp" 2>/dev/null \
    | grep -o '"timestamp":"[^"]*"' | head -1 | cut -d'"' -f4)"
  if [[ -n "$NEWEST" ]]; then
    NEWEST_EPOCH="$(date -d "$NEWEST" +%s 2>/dev/null || echo 0)"
    (( $(date +%s) - NEWEST_EPOCH < EVENT_STALL_HOURS * 3600 )) \
      || FAILURES+=("no new alerts indexed for over ${EVENT_STALL_HOURS}h (last: $NEWEST)")
  fi
fi

# --- State transition + Slack -------------------------------------------------
notify() { # text (may be multi-line — escaped into a single JSON string)
  [[ -n "${SLACK_WEBHOOK_URL:-}" ]] || { echo "SLACK_WEBHOOK_URL unset — would send: $1"; return; }
  local esc="$1"
  esc="${esc//\\/\\\\}"; esc="${esc//\"/\\\"}"; esc="${esc//$'\n'/\\n}"
  local code
  code="$(curl -sk -m 10 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    -d "{\"text\":\"$esc\"}" "$SLACK_WEBHOOK_URL")"
  echo "slack delivery: HTTP $code"
}

NOW=$(date +%s)
PREV_STATUS="OK"; PREV_POST=0
[[ -f "$STATE_FILE" ]] && read -r PREV_STATUS PREV_POST < "$STATE_FILE" || true

HOST="$(hostname)"
# Fleet identity: with many tenants posting to one channel, name the tenant so
# alerts are attributable. Falls back to the hostname when TENANT_NAME is unset.
WHO="${TENANT_NAME:+$TENANT_NAME on }\`$HOST\`"
if (( ${#FAILURES[@]} > 0 )); then
  DETAIL="$(printf ' • %s\n' "${FAILURES[@]}")"
  echo "UNHEALTHY:"; printf '%s' "$DETAIL"
  if [[ "$PREV_STATUS" != FAIL ]] || (( NOW - PREV_POST >= REMIND_HOURS * 3600 )); then
    notify ":rotating_light: *detection-lab SIEM unhealthy* — $WHO
$DETAIL"
    echo "FAIL $NOW" > "$STATE_FILE"
  else
    echo "FAIL $PREV_POST" > "$STATE_FILE"
  fi
  exit 1
else
  echo "healthy"
  if [[ "$PREV_STATUS" == FAIL ]]; then
    notify ":white_check_mark: *detection-lab SIEM recovered* — $WHO — all checks passing."
  fi
  echo "OK $NOW" > "$STATE_FILE"
fi
