#!/usr/bin/env bash
# Enroll a Linux host into the detection lab: install auditd + the curated
# ruleset and the pinned Wazuh agent, enrolled with the lab's authd password.
# Collection config (auth.log, syslog, audit.log) arrives from the group
# agent.conf, so this only installs collectors and enrolls.
#
#   sudo ./install-agent.sh -p '<AGENT_ENROLLMENT_PASSWORD>' [-m 127.0.0.1] [-n name]
#
# Uninstall: sudo ./uninstall-agent.sh
set -euo pipefail

MANAGER="127.0.0.1"
AGENT_NAME="$(hostname)"
AGENT_GROUP="detection-lab"
WAZUH_VERSION="4.14.6"
REG_PASSWORD=""
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while getopts "m:n:p:g:v:h" opt; do
  case "$opt" in
    m) MANAGER="$OPTARG";;      n) AGENT_NAME="$OPTARG";;
    p) REG_PASSWORD="$OPTARG";; g) AGENT_GROUP="$OPTARG";;
    v) WAZUH_VERSION="$OPTARG";;
    h) grep '^#' "$0" | sed -n '2,10p'; exit 0;;
    *) exit 1;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Run with sudo/root." >&2; exit 1; }
[[ -n "$REG_PASSWORD" ]] || { echo "Enrollment password required (-p). See AGENT_ENROLLMENT_PASSWORD in infra/.env." >&2; exit 1; }
command -v apt-get >/dev/null || { echo "This installer targets Debian/Ubuntu (apt)." >&2; exit 1; }

# --- 1. auditd + curated ruleset ----------------------------------------------
echo "[*] Installing auditd ..."
DEBIAN_FRONTEND=noninteractive apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq auditd audispd-plugins
install -m 640 "$HERE/audit.rules" /etc/audit/rules.d/detection-lab.rules
if augenrules --load 2>/dev/null && auditctl -l | grep -q dl_exec; then
  echo "[*] auditd rules loaded."
else
  echo "[!] auditd rules did not load — this kernel may lack audit netlink"
  echo "    delivery (common under WSL2). File/exec auditing will be unavailable;"
  echo "    auth.log/syslog collection still works. See fleet/README.md."
fi

# --- 2. Wazuh agent (pinned) --------------------------------------------------
echo "[*] Installing the Wazuh agent $WAZUH_VERSION ..."
ARCH="$(dpkg --print-architecture)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/wazuh-agent.deb" \
  "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}-1_${ARCH}.deb"
WAZUH_MANAGER="$MANAGER" WAZUH_REGISTRATION_SERVER="$MANAGER" \
  WAZUH_REGISTRATION_PASSWORD="$REG_PASSWORD" \
  WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_AGENT_GROUP="$AGENT_GROUP" \
  dpkg -i "$TMP/wazuh-agent.deb"

systemctl daemon-reload
systemctl enable --now wazuh-agent
echo ""
echo "[*] Done. $AGENT_NAME is enrolling into '$AGENT_GROUP'."
echo "    Verify: docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l"
