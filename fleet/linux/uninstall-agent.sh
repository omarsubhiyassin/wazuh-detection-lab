#!/usr/bin/env bash
# Remove what install-agent.sh added: the Wazuh agent and the auditd ruleset.
#   sudo ./uninstall-agent.sh [--keep-auditd]
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo/root." >&2; exit 1; }

echo "[*] Removing the Wazuh agent ..."
systemctl disable --now wazuh-agent 2>/dev/null || true
DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq wazuh-agent 2>/dev/null || true

if [[ "${1:-}" != "--keep-auditd" ]]; then
  echo "[*] Removing the detection-lab audit ruleset ..."
  rm -f /etc/audit/rules.d/detection-lab.rules
  augenrules --load 2>/dev/null || true
fi
echo "[*] Done."
