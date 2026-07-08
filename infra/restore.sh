#!/usr/bin/env bash
# Restore for the detection lab. Companion to backup.sh.
#
#   ./restore.sh --list                    show available snapshots + tarballs
#   ./restore.sh --rehearse <snapshot>     NON-destructive drill: restore under a
#                                          "restored-" prefix, compare doc counts,
#                                          then delete the copies
#   ./restore.sh --indices <snapshot>      DESTRUCTIVE: replace live wazuh-alerts-*
#                                          with the snapshot's contents
#   ./restore.sh --manager <tarball>       DESTRUCTIVE: restore manager state
#                                          (client.keys, ossec.conf, shared) + restart
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$HERE/.env" ]] && { set -a; source "$HERE/.env"; set +a; }

BACKUP_DIR="${BACKUP_DIR:-/var/tmp/detection-lab-backups}"
B="https://localhost:9200"
AUTH="admin:${INDEXER_PASSWORD:?INDEXER_PASSWORD not set — is infra/.env present?}"
MANAGER="single-node-wazuh.manager-1"

confirm() {
  read -r -p "$1 Type YES to proceed: " ans
  [[ "$ans" == "YES" ]] || { echo "aborted"; exit 1; }
}

case "${1:-}" in
  --list)
    echo "=== indexer snapshots (repository: detectionlab):"
    curl -sk -u "$AUTH" "$B/_snapshot/detectionlab/_all" \
      | grep -o '"snapshot":"snap-[^"]*"' | cut -d'"' -f4 | sort
    echo "=== manager state tarballs ($BACKUP_DIR/manager):"
    ls -1 "$BACKUP_DIR/manager/" 2>/dev/null || echo "(none)"
    ;;

  --rehearse)
    SNAP="${2:?usage: restore.sh --rehearse <snapshot>}"
    echo "Restoring $SNAP under the 'restored-' prefix (live data untouched) ..."
    RES="$(curl -sk -u "$AUTH" -XPOST \
      "$B/_snapshot/detectionlab/$SNAP/_restore?wait_for_completion=true" \
      -H 'Content-Type: application/json' -d '{
        "indices":"wazuh-alerts-*","include_global_state":false,
        "rename_pattern":"^(.+)$","rename_replacement":"restored-$1"}')"
    grep -q '"failed":0' <<<"$RES" || { echo "ERROR: restore failed: $RES" >&2; exit 1; }
    echo "--- doc counts, live vs restored:"
    curl -sk -u "$AUTH" "$B/_cat/indices/wazuh-alerts-*,restored-*?h=index,docs.count&s=index"
    echo "--- cleaning up the restored copies ..."
    curl -sk -o /dev/null -u "$AUTH" -XDELETE "$B/restored-wazuh-alerts-*?expand_wildcards=all"
    echo "rehearsal complete — snapshot $SNAP restores cleanly."
    ;;

  --indices)
    SNAP="${2:?usage: restore.sh --indices <snapshot>}"
    confirm "This DELETES live wazuh-alerts-* and restores them from $SNAP."
    curl -sk -o /dev/null -u "$AUTH" -XDELETE "$B/wazuh-alerts-*"
    RES="$(curl -sk -u "$AUTH" -XPOST \
      "$B/_snapshot/detectionlab/$SNAP/_restore?wait_for_completion=true" \
      -H 'Content-Type: application/json' \
      -d '{"indices":"wazuh-alerts-*","include_global_state":false}')"
    grep -q '"failed":0' <<<"$RES" || { echo "ERROR: restore failed: $RES" >&2; exit 1; }
    curl -sk -u "$AUTH" "$B/_cat/indices/wazuh-alerts-*?h=index,docs.count&s=index"
    echo "restore complete."
    ;;

  --manager)
    TGZ="${2:?usage: restore.sh --manager <tarball>}"
    [[ -f "$TGZ" ]] || TGZ="$BACKUP_DIR/manager/$TGZ"
    [[ -f "$TGZ" ]] || { echo "ERROR: $TGZ not found" >&2; exit 1; }
    confirm "This OVERWRITES the manager's client.keys/ossec.conf/shared from $TGZ and restarts it."
    docker exec -i "$MANAGER" tar xzf - -C / < "$TGZ"
    docker restart "$MANAGER" >/dev/null
    echo "manager state restored from $TGZ; manager restarting."
    ;;

  *)
    grep '^#' "$0" | sed -n '2,12p'; exit 1;;
esac
