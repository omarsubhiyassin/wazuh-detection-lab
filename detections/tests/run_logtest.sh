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
  # wazuh-logtest writes its analysis to stderr, so merge it into stdout. A
  # sample may contain multiple lines (composite/correlation rules fire on a
  # later line), and logtest keeps rule state across lines within one session.
  out=$(docker exec -i "$MANAGER" "$LOGTEST" < "$SAMPLES/$sample" 2>&1)

  # Collect every FIRED rule id/level. Anchor to lines that start (after
  # indentation) with "id:"/"level:" so we don't pick up decoded fields like
  # dns.id, mitre.id, or win.system.level.
  ids=$(printf '%s\n' "$out"    | grep -oE "^[[:space:]]+id: '[0-9]+'"    | grep -oE '[0-9]+')
  maxlevel=$(printf '%s\n' "$out" | grep -oE "^[[:space:]]+level: '[0-9]+'" | grep -oE '[0-9]+' | sort -n | tail -1)

  if [ "$expected" = "NOALERT" ]; then
    got="maxL${maxlevel:-0}"
    if [ -z "$maxlevel" ] || [ "$maxlevel" -eq 0 ]; then ok=1; else ok=0; fi
  else
    if printf '%s\n' "$ids" | grep -qx "$expected"; then
      ok=1; got="fired"
    else
      ok=0; got=$(printf '%s' "$ids" | tr '\n' ',' | sed 's/,$//'); got="${got:-none}"
    fi
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
