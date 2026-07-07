"""Benign background activity.

Without believable noise every detection is trivially true, so the baseline
mixes normal SSH logins, routine Windows process creation, and DNS lookups to
popular domains, clustered into business hours via a diurnal weight curve.
"""
from __future__ import annotations

from datetime import datetime, timezone
from functools import partial

from emitters import suricata, sshd, windows
from timeline import Timeline
from world import (BENIGN_DOMAINS, BENIGN_SRC_IPS, INTERNAL_RESOLVER, World)

# Relative activity weight per UTC hour (troughs overnight, business-hours peak).
_DIURNAL = [
    0.05, 0.04, 0.03, 0.03, 0.03, 0.04, 0.08, 0.15, 0.35, 0.70, 0.90, 1.00,
    0.95, 0.90, 0.95, 1.00, 0.90, 0.70, 0.45, 0.30, 0.22, 0.18, 0.12, 0.08,
]
_DIURNAL_MAX = max(_DIURNAL)

# Events per hour (scaled by the window length).
RATE_SSH_PER_HOST = 1.5
RATE_WIN_PROC_PER_HOST = 4.0
RATE_DNS = 40.0
RATE_HTTP = 18.0

_CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
# Benign web traffic to real hostnames. Includes a legit script fetch from a
# DOMAIN (raw.githubusercontent.com/...ps1) so the ingress-tool-transfer rule's
# bare-IP requirement is exercised against a true negative.
_BENIGN_HTTP = [
    ("www.google.com", "/", "142.250.72.196", _CHROME_UA),
    ("github.com", "/wazuh/wazuh", "140.82.113.3", _CHROME_UA),
    ("update.microsoft.com", "/v6/windowsupdate", "23.45.12.10", "Windows-Update-Agent/10.0"),
    ("api.datadoghq.com", "/api/v1/series", "3.233.150.10", "datadog-agent/7.51.0"),
    ("raw.githubusercontent.com", "/PowerShell/PowerShell/master/tools/install.ps1", "185.199.108.133", _CHROME_UA),
]

_BENIGN_WIN_PROCS = [
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Windows\explorer.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\services.exe"),
    (r"C:\Program Files\Microsoft VS Code\Code.exe", r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\cmd.exe", r"C:\Program Files\Git\bin\bash.exe"),
]


def _diurnal_offset(world: World, start_epoch: float, window: float) -> float:
    """Rejection-sample an offset whose UTC hour follows the diurnal curve."""
    rng = world.rng
    for _ in range(64):
        off = rng.uniform(0.0, window)
        hour = datetime.fromtimestamp(start_epoch + off, tz=timezone.utc).hour
        if rng.random() < _DIURNAL[hour] / _DIURNAL_MAX:
            return off
    return off


def generate(world: World, tl: Timeline, start_epoch: float, window: float) -> None:
    rng = world.rng
    hours = max(window / 3600.0, 0.1)

    # --- benign SSH logins (mostly key-based, occasional password typo) ------
    for host in world.linux_hosts:
        for _ in range(max(1, round(RATE_SSH_PER_HOST * hours))):
            off = _diurnal_offset(world, start_epoch, window)
            user = rng.choice(world.human_users + world.service_users).name
            src_ip = rng.choice(BENIGN_SRC_IPS)
            port = rng.randint(30000, 65000)
            pid = world.pid()
            if rng.random() < 0.12:
                tl.emit(off, "auth.log", partial(
                    sshd.failed_password, host=host.name, user=user, src_ip=src_ip, port=port, pid=pid))
            else:
                tl.emit(off, "auth.log", partial(
                    sshd.accepted_publickey, host=host.name, user=user, src_ip=src_ip, port=port, pid=pid))

    # --- benign Windows process creation -------------------------------------
    for host in world.windows_hosts:
        for _ in range(max(1, round(RATE_WIN_PROC_PER_HOST * hours))):
            off = _diurnal_offset(world, start_epoch, window)
            image, parent = rng.choice(_BENIGN_WIN_PROCS)
            user = f"CORP\\{rng.choice(world.human_users).name}"
            tl.emit(off, "windows_events.json", partial(
                windows.sysmon_process_create,
                computer=host.name, record_id=world.record_id(), image=image,
                command_line=f'"{image}"', parent_image=parent,
                parent_command_line=f'"{parent}"', user=user,
                process_guid=world.guid(), parent_process_guid=world.guid(),
                process_id=world.pid(), parent_process_id=world.pid()))

    # --- benign Windows network connections (Sysmon 3) -----------------------
    # Normal processes reaching out. These share no GUID with any encoded-PS
    # alert, so the download<->execution composite must not fire on them.
    for host in world.windows_hosts:
        for _ in range(max(1, round(RATE_WIN_PROC_PER_HOST * hours))):
            off = _diurnal_offset(world, start_epoch, window)
            image, _ = rng.choice(_BENIGN_WIN_PROCS)
            hostname, _url, dest_ip, _ua = rng.choice(_BENIGN_HTTP)
            tl.emit(off, "windows_events.json", partial(
                windows.sysmon_network_connection,
                computer=host.name, record_id=world.record_id(), process_guid=world.guid(),
                process_id=world.pid(), image=image, user=f"CORP\\{rng.choice(world.human_users).name}",
                source_ip=host.ip, source_port=rng.randint(40000, 60000),
                dest_ip=dest_ip, dest_port=rng.choice([80, 443]), dest_hostname=hostname))

    # --- benign DNS ----------------------------------------------------------
    for _ in range(max(1, round(RATE_DNS * hours))):
        off = _diurnal_offset(world, start_epoch, window)
        src = rng.choice(world.windows_hosts + world.linux_hosts)
        tl.emit(off, "eve.json", partial(
            suricata.dns_query, src_ip=src.ip, dest_ip=INTERNAL_RESOLVER,
            rrname=rng.choice(BENIGN_DOMAINS), rrtype="A",
            src_port=rng.randint(40000, 60000), tx_id=rng.randint(1, 65535)))

    # --- benign HTTP ---------------------------------------------------------
    for _ in range(max(1, round(RATE_HTTP * hours))):
        off = _diurnal_offset(world, start_epoch, window)
        src = rng.choice(world.windows_hosts + world.linux_hosts)
        hostname, url, dest_ip, ua = rng.choice(_BENIGN_HTTP)
        tl.emit(off, "eve.json", partial(
            suricata.http_request, src_ip=src.ip, dest_ip=dest_ip, hostname=hostname,
            url=url, src_port=rng.randint(40000, 60000), user_agent=ua,
            status=200, length=rng.randint(500, 250000)))
