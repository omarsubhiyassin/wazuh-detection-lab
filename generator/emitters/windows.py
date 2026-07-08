"""Windows Event Log JSON in Wazuh's windows_eventchannel shape.

Wazuh's agent forwards Windows events as JSON:
    {"win": {"system": {...}, "eventdata": {...}}}
and lowercases the first letter of each Windows field name (Image -> image,
CommandLine -> commandLine, TaskName -> taskName). Custom Phase 3 rules match on
win.eventdata.* fields, so the field names here matter.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SYSMON_GUID = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
SEC_PROVIDER = "Microsoft-Windows-Security-Auditing"
SEC_GUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"
EVENTLOG_PROVIDER = "Microsoft-Windows-Eventlog"
EVENTLOG_GUID = "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"
WEVTUTIL = r"C:\Windows\System32\wevtutil.exe"

POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
SCHTASKS = r"C:\Windows\System32\schtasks.exe"


def _system(ts: float, *, provider: str, provider_guid: str, event_id: int, channel: str,
            computer: str, record_id: int, task: int = 0, level: str = "4",
            severity: str = "INFORMATION") -> dict:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return {
        "providerName": provider,
        "providerGuid": provider_guid,
        "eventID": str(event_id),
        "version": "5",
        "level": level,
        "task": str(task),
        "opcode": "0",
        "keywords": "0x8000000000000000",
        "systemTime": dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z",
        "eventRecordID": str(record_id),
        "processID": "0",
        "threadID": "0",
        "channel": channel,
        "computer": computer,
        "severityValue": severity,
        "message": "",
    }


def _event(system: dict, eventdata: dict) -> str:
    return json.dumps({"win": {"system": system, "eventdata": eventdata}}, separators=(",", ":"))


def _utc(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def sysmon_process_create(ts: float, *, computer: str, record_id: int, image: str,
                          command_line: str, parent_image: str, parent_command_line: str,
                          user: str, process_guid: str, parent_process_guid: str,
                          process_id: int, parent_process_id: int,
                          current_directory: str = "C:\\Users\\Public\\",
                          integrity_level: str = "Medium",
                          original_file_name: str | None = None,
                          hashes: str = "SHA256=6E1E4F0A...D9B3C2A1") -> str:
    ed = {
        "utcTime": _utc(ts),
        "processGuid": process_guid,
        "processId": str(process_id),
        "image": image,
        "originalFileName": original_file_name or image.rsplit("\\", 1)[-1],
        "commandLine": command_line,
        "currentDirectory": current_directory,
        "user": user,
        "integrityLevel": integrity_level,
        "hashes": hashes,
        "parentProcessGuid": parent_process_guid,
        "parentProcessId": str(parent_process_id),
        "parentImage": parent_image,
        "parentCommandLine": parent_command_line,
    }
    sysm = _system(ts, provider=SYSMON_PROVIDER, provider_guid=SYSMON_GUID, event_id=1,
                   channel="Microsoft-Windows-Sysmon/Operational", computer=computer,
                   record_id=record_id, task=1)
    return _event(sysm, ed)


def sysmon_network_connection(ts: float, *, computer: str, record_id: int, process_guid: str,
                              process_id: int, image: str, user: str, source_ip: str,
                              source_port: int, dest_ip: str, dest_port: int,
                              protocol: str = "tcp", initiated: str = "true",
                              dest_hostname: str = "") -> str:
    """Sysmon Event ID 3 -- network connection. Carries the connecting process's
    GUID, so it can be correlated back to the process-creation event."""
    ed = {
        "utcTime": _utc(ts),
        "processGuid": process_guid,
        "processId": str(process_id),
        "image": image,
        "user": user,
        "protocol": protocol,
        "initiated": initiated,
        "sourceIp": source_ip,
        "sourcePort": str(source_port),
        "destinationIp": dest_ip,
        "destinationPort": str(dest_port),
        "destinationHostname": dest_hostname,
    }
    sysm = _system(ts, provider=SYSMON_PROVIDER, provider_guid=SYSMON_GUID, event_id=3,
                   channel="Microsoft-Windows-Sysmon/Operational", computer=computer,
                   record_id=record_id, task=3)
    return _event(sysm, ed)


def sysmon_process_access(ts: float, *, computer: str, record_id: int, source_image: str,
                          target_image: str, granted_access: str, source_process_id: int,
                          target_process_id: int, user: str, source_process_guid: str,
                          target_process_guid: str,
                          call_trace: str = r"C:\Windows\SYSTEM32\ntdll.dll+9d1e4|C:\Windows\System32\KERNELBASE.dll+2c0a6") -> str:
    """Sysmon Event ID 10 -- process accessed another process's memory."""
    ed = {
        "utcTime": _utc(ts),
        "sourceProcessGUID": source_process_guid,
        "sourceProcessId": str(source_process_id),
        "sourceImage": source_image,
        "targetProcessGUID": target_process_guid,
        "targetProcessId": str(target_process_id),
        "targetImage": target_image,
        "grantedAccess": granted_access,
        "callTrace": call_trace,
        "sourceUser": user,
        "targetUser": "NT AUTHORITY\\SYSTEM",
    }
    sysm = _system(ts, provider=SYSMON_PROVIDER, provider_guid=SYSMON_GUID, event_id=10,
                   channel="Microsoft-Windows-Sysmon/Operational", computer=computer,
                   record_id=record_id, task=10)
    return _event(sysm, ed)


def security_log_cleared(ts: float, *, computer: str, record_id: int,
                         subject_user: str, subject_domain: str) -> str:
    """Security 1102 -- the audit log was cleared."""
    ed = {
        "subjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-1001",
        "subjectUserName": subject_user,
        "subjectDomainName": subject_domain,
        "subjectLogonId": "0x3e7",
    }
    sysm = _system(ts, provider=EVENTLOG_PROVIDER, provider_guid=EVENTLOG_GUID, event_id=1102,
                   channel="Security", computer=computer, record_id=record_id, task=104)
    return _event(sysm, ed)


def security_scheduled_task_created(ts: float, *, computer: str, record_id: int,
                                    subject_user: str, subject_domain: str,
                                    task_name: str, task_content: str) -> str:
    """Security 4698 -- A scheduled task was created."""
    ed = {
        "subjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-1001",
        "subjectUserName": subject_user,
        "subjectDomainName": subject_domain,
        "subjectLogonId": "0x3e7",
        "taskName": task_name,
        "taskContent": task_content,
    }
    sysm = _system(ts, provider=SEC_PROVIDER, provider_guid=SEC_GUID, event_id=4698,
                   channel="Security", computer=computer, record_id=record_id, task=12804)
    return _event(sysm, ed)
