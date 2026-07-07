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
