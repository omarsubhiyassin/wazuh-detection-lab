#!/usr/bin/env bash
# assert_alerts.sh — the other half of live atomic validation: after
# Invoke-AtomicValidation.ps1 detonates the atomics on the endpoint, confirm the
# expected rule IDs actually fired by querying the indexer.
#
# This is what closes the loop. Running the atomic proves the behaviour
# happened; this proves our detection SAW it. Without this step you have only
# assumed the pipeline works.
#
#   detections/atomics/assert_alerts.sh '<window-start-ISO>'   # from the PS1 output
#   detections/atomics/assert_alerts.sh '2026-07-31T20:00:00Z' 100700 100701
#
# Reads the read-only indexer creds from dashboard/.env (same account the BFF
# uses). Expected rule IDs default to the full atomic-mapped set.
set -uo pipefail

START="${1:-}"
[ -z "$START" ] && { echo "usage: $0 '<window-start-ISO>' [ruleId ...]" >&2; exit 2; }
shift || true

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${DASH_ENV_FILE:-$HERE/../../dashboard/.env}"
# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }

INDEXER="${INDEXER_URL:-https://localhost:9200}"
USER="${INDEXER_RO_USER:-detectionlab_ro}"
PASS="${INDEXER_RO_PASSWORD:-}"
[ -z "$PASS" ] && { echo "INDEXER_RO_PASSWORD not set (looked in $ENV_FILE)" >&2; exit 2; }

# The atomic-mapped detections (mirrors coverage.yml `mapped`). Override by
# passing rule IDs as extra args.
EXPECTED=("$@")
[ ${#EXPECTED[@]} -eq 0 ] && EXPECTED=(100101 100110 100120 100310 100410 100500 100600 100601 100700 100701)

echo "Checking for alerts since $START ..."
echo "------------------------------------------------------------"
pass=0; fail=0
for rid in "${EXPECTED[@]}"; do
  body="{\"size\":0,\"query\":{\"bool\":{\"filter\":[
      {\"term\":{\"rule.id\":\"$rid\"}},
      {\"range\":{\"timestamp\":{\"gte\":\"$START\"}}}]}}}"
  n=$(curl -sk -u "$USER:$PASS" -H 'Content-Type: application/json' \
        "$INDEXER/wazuh-alerts-*/_search" -d "$body" \
        | grep -oE '"total":\{"value":[0-9]+' | grep -oE '[0-9]+$' | head -1)
  n="${n:-0}"
  if [ "$n" -gt 0 ]; then
    printf '  rule %-7s FIRED  (%s alert(s))\n' "$rid" "$n"; pass=$((pass+1))
  else
    printf '  rule %-7s MISSING (no alert since window start)\n' "$rid"; fail=$((fail+1))
  fi
done
echo "------------------------------------------------------------"
echo "fired=$pass missing=$fail"
# Missing is a real failure: the atomic ran but the detection did not see it.
[ "$fail" -eq 0 ]
