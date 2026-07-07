#!/usr/bin/env bash
# Detection unit tests: pipe each frozen sample through `wazuh-logtest` on the
# running manager and assert the expected rule fires (or that benign samples
# stay at level 0). Run from anywhere with the lab stack up:
#
#   detections/tests/run_logtest.sh
#
# Override the manager container if needed:
#   MANAGER=my-manager detections/tests/run_logtest.sh
set -uo pipefail
export MSYS_NO_PATHCONV=1  # no-op on Linux; keeps Git Bash from mangling exec paths

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES="$HERE/samples"
CASES="$HERE/cases.tsv"
MANAGER="${MANAGER:-single-node-wazuh.manager-1}"
LOGTEST="/var/ossec/bin/wazuh-logtest"

if ! docker exec "$MANAGER" test -x "$LOGTEST" 2>/dev/null; then
  echo "ERROR: cannot reach $LOGTEST in container '$MANAGER'. Is the stack up?" >&2
  exit 2
fi

pass=0; fail=0
printf '%-28s %-9s %-9s %s\n' "SAMPLE" "EXPECT" "GOT" "RESULT"
printf '%.0s-' {1..70}; echo

while IFS=$'\t' read -r expected sample description; do
  case "$expected" in ''|'#'*) continue;; esac
  # wazuh-logtest writes its analysis to stderr, so merge it into stdout.
  out=$(docker exec -i "$MANAGER" "$LOGTEST" < "$SAMPLES/$sample" 2>&1)
  # Scope to the Phase 3 (rules) section so we read the fired RULE's id/level,
  # not decoded fields like dns.id or win.system.level from Phase 2.
  p3=$(printf '%s' "$out" | sed -n '/Phase 3/,$p')
  id=$(printf '%s' "$p3"    | grep -oE "id: '[0-9]+'"    | head -1 | grep -oE '[0-9]+')
  level=$(printf '%s' "$p3" | grep -oE "level: '[0-9]+'" | head -1 | grep -oE '[0-9]+')

  if [ "$expected" = "NOALERT" ]; then
    got="${id:-none}/L${level:-0}"
    if [ -z "$level" ] || [ "$level" = "0" ]; then ok=1; else ok=0; fi
  else
    got="${id:-none}"
    if [ "$id" = "$expected" ]; then ok=1; else ok=0; fi
  fi

  if [ "$ok" = 1 ]; then
    printf '%-28s %-9s %-9s PASS\n' "$sample" "$expected" "$got"; pass=$((pass+1))
  else
    printf '%-28s %-9s %-9s FAIL\n' "$sample" "$expected" "$got"; fail=$((fail+1))
  fi
done < "$CASES"

printf '%.0s-' {1..70}; echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
