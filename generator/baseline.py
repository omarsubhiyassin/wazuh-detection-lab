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

    # --- benign DNS ----------------------------------------------------------
    for _ in range(max(1, round(RATE_DNS * hours))):
        off = _diurnal_offset(world, start_epoch, window)
        src = rng.choice(world.windows_hosts + world.linux_hosts)
        tl.emit(off, "eve.json", partial(
            suricata.dns_query, src_ip=src.ip, dest_ip=INTERNAL_RESOLVER,
            rrname=rng.choice(BENIGN_DOMAINS), rrtype="A",
            src_port=rng.randint(40000, 60000), tx_id=rng.randint(1, 65535)))
