#!/usr/bin/env bash
# Backup for the detection lab: an indexer snapshot of wazuh-alerts-* plus a
# manager-state tarball (client.keys, ossec.conf, shared groups) and the two
# secret-bearing config files (infra/.env, internal_users.yml).
#
#   ./backup.sh            run one backup now (cron calls this)
#   ./backup.sh --install  install a daily 02:00 cron entry
#
# BACKUP_DIR holds secrets (agent keys, passwords) — keep it out of the repo
# and off shared storage. Restore procedures: see restore.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$HERE/.env" ]] && { set -a; source "$HERE/.env"; set +a; }

BACKUP_DIR="${BACKUP_DIR:-/var/tmp/detection-lab-backups}"
KEEP="${BACKUP_KEEP:-14}"
B="https://localhost:9200"
AUTH="admin:${INDEXER_PASSWORD:?INDEXER_PASSWORD not set — is infra/.env present?}"
MANAGER="single-node-wazuh.manager-1"
IU="$HERE/wazuh-docker/single-node/config/wazuh_indexer/internal_users.yml"

if [[ "${1:-}" == "--install" ]]; then
  ENTRY="0 2 * * * $HERE/backup.sh >> $BACKUP_DIR/backup.log 2>&1 # detection-lab-backup"
  ( crontab -l 2>/dev/null | grep -v detection-lab-backup; echo "$ENTRY" ) | crontab -
  echo "Installed cron entry (daily 02:00): $ENTRY"
  exit 0
fi

mkdir -p "$BACKUP_DIR/manager"
STAMP="$(date +%Y%m%d-%H%M%S)"

# --- Indexer snapshot ----------------------------------------------------------
RES="$(curl -sk -u "$AUTH" -XPUT \
  "$B/_snapshot/detectionlab/snap-$STAMP?wait_for_completion=true" \
  -H 'Content-Type: application/json' \
  -d '{"indices":"wazuh-alerts-*","include_global_state":false}')"
grep -q '"state":"SUCCESS"' <<<"$RES" \
  || { echo "ERROR: snapshot failed: $RES" >&2; exit 1; }
echo "snapshot snap-$STAMP: SUCCESS"

# --- Manager state -------------------------------------------------------------
docker exec "$MANAGER" tar czf - -C / \
  var/ossec/etc/client.keys var/ossec/etc/ossec.conf var/ossec/etc/shared \
  > "$BACKUP_DIR/manager/manager-$STAMP.tgz"
cp "$HERE/.env" "$BACKUP_DIR/manager/env-$STAMP"
[[ -f "$IU" ]] && cp "$IU" "$BACKUP_DIR/manager/internal_users-$STAMP.yml"
chmod 600 "$BACKUP_DIR/manager/"*"$STAMP"*
echo "manager state: manager-$STAMP.tgz (+ env, internal_users)"

# --- Retention: keep the newest $KEEP of each -----------------------------------
SNAPS="$(curl -sk -u "$AUTH" "$B/_snapshot/detectionlab/_all" \
  | grep -o '"snapshot":"snap-[^"]*"' | cut -d'"' -f4 | sort)"
COUNT="$(wc -l <<<"$SNAPS")"
if (( COUNT > KEEP )); then
  head -n "$((COUNT - KEEP))" <<<"$SNAPS" | while read -r s; do
    curl -sk -o /dev/null -u "$AUTH" -XDELETE "$B/_snapshot/detectionlab/$s"
    echo "pruned old snapshot $s"
  done
fi
for prefix in manager- env- internal_users-; do
  ls -1 "$BACKUP_DIR/manager/${prefix}"* 2>/dev/null | sort | head -n -"$KEEP" \
    | while read -r f; do rm -f "$f"; echo "pruned $f"; done
done
echo "backup complete -> $BACKUP_DIR"
