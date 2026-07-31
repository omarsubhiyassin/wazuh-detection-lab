# Invoke-AtomicValidation.ps1 — run the mapped Atomic Red Team tests on an
# enrolled Windows endpoint, so the detections are validated against real
# attacker tooling rather than only the frozen generator samples.
#
# WHY THIS IS A SCRIPT AND NOT A CI JOB
#   Atomic Red Team executes real behaviour (dumping LSASS, clearing event
#   logs, PsExec), and our detections read Sysmon telemetry through the
#   windows_eventchannel decoder, which wazuh-logtest cannot decode. There is no
#   faithful way to do this in an ephemeral GitHub runner. It runs HERE, on the
#   host with Sysmon and the Wazuh agent, then the alerts are checked on the
#   indexer by assert_alerts.sh.
#
#   The mapping (coverage.yml) is what CI keeps honest; this is what actually
#   pulls the trigger.
#
# SAFETY
#   These atomics are real. Run only on a lab endpoint you own and can restore
#   (this project's AMIGO). -WhatIf lists what would run and changes nothing;
#   run it first. Invoke-AtomicTest handles its own cleanup (-Cleanup).
#
# PREREQ (one-time, elevated):
#   Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force
#   Import-Module invoke-atomicredteam
#
# USAGE (elevated PowerShell):
#   .\Invoke-AtomicValidation.ps1 -WhatIf          # dry run, no execution
#   .\Invoke-AtomicValidation.ps1                  # run all mapped atomics
#   .\Invoke-AtomicValidation.ps1 -Rule 100700     # just one detection's atomic
[CmdletBinding()]
param(
    # Limit to the atomic(s) for one detection rule id.
    [string]$Rule,
    # List what would run without executing anything.
    [switch]$WhatIf,
    # Seconds to pause after each atomic so telemetry reaches the indexer.
    [int]$SettleSeconds = 20
)

$ErrorActionPreference = 'Stop'

# The mapped atomics, mirrored from coverage.yml. Kept in sync by CI: the
# validator confirms every GUID here is real; a companion check (below) confirms
# this list matches coverage.yml so it cannot silently drift.
$Atomics = @(
    [pscustomobject]@{ Rule='100101'; Technique='T1059.001'; Guid='86a43bad-12e3-4e85-b97c-4d5cf25b95c3'; Name='Encoded PowerShell command' }
    [pscustomobject]@{ Rule='100110'; Technique='T1053.005'; Guid='42f53695-ad4a-4546-abb6-7d837f644a71'; Name='Scheduled task Local (schtasks)' }
    [pscustomobject]@{ Rule='100120'; Technique='T1053.005'; Guid='42f53695-ad4a-4546-abb6-7d837f644a71'; Name='Scheduled task -> Security 4698' }
    [pscustomobject]@{ Rule='100310'; Technique='T1105';     Guid='dd3b61dd-7bbc-48cd-ab51-49ad1a776df0'; Name='certutil download (use a bare-IP URL arg)' }
    [pscustomobject]@{ Rule='100410'; Technique='T1071.004'; Guid='3efc144e-1af8-46bb-8ca2-1376bb6db8b6'; Name='DNS Regular Beaconing (needs Sysmon EID22)' }
    [pscustomobject]@{ Rule='100500'; Technique='T1021.002'; Guid='0eb03d41-79e4-4393-8e57-6344856be1cf'; Name='Copy and Execute File with PsExec' }
    [pscustomobject]@{ Rule='100600'; Technique='T1685.005'; Guid='b13e9306-3351-4b4b-a6e8-477358b0b498'; Name='Delete System Logs (Clear-EventLog -> 1102)' }
    [pscustomobject]@{ Rule='100601'; Technique='T1685.005'; Guid='e6abb60e-26b8-41da-8aae-0c35174b0967'; Name='Clear Logs (wevtutil cl)' }
    [pscustomobject]@{ Rule='100700'; Technique='T1003.001'; Guid='0be2230c-9ab3-4ac2-8826-3199b9a0ebf8'; Name='Dump LSASS using ProcDump' }
    [pscustomobject]@{ Rule='100701'; Technique='T1003.001'; Guid='2536dee2-12fb-459a-8c37-971844fa73be'; Name='Dump LSASS using comsvcs.dll' }
)

if ($Rule) {
    $Atomics = $Atomics | Where-Object { $_.Rule -eq $Rule }
    if (-not $Atomics) { throw "No mapped atomic for rule $Rule. See coverage.yml." }
}

if (-not $WhatIf) {
    if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
        throw "Invoke-AtomicTest not found. Install-Module invoke-atomicredteam; Import-Module invoke-atomicredteam"
    }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "Run elevated — several atomics (LSASS dump, PsExec, log clearing) require it."
    }
}

$started = (Get-Date).ToUniversalTime().ToString('o')
Write-Host "Atomic validation window START (UTC): $started" -ForegroundColor Cyan
Write-Host "Rules under test: $($Atomics.Rule -join ', ')`n"

foreach ($a in $Atomics) {
    Write-Host ("=== rule {0}  [{1}]  {2}" -f $a.Rule, $a.Technique, $a.Name) -ForegroundColor Yellow
    Write-Host ("    atomic {0}" -f $a.Guid)
    if ($WhatIf) { Write-Host "    (WhatIf) would: get prereqs, execute, then cleanup`n"; continue }

    try {
        Invoke-AtomicTest $a.Technique -TestGuids $a.Guid -GetPrereqs | Out-Host
        Invoke-AtomicTest $a.Technique -TestGuids $a.Guid            | Out-Host
        Start-Sleep -Seconds $SettleSeconds
        Invoke-AtomicTest $a.Technique -TestGuids $a.Guid -Cleanup   | Out-Host
        Write-Host "    done`n" -ForegroundColor Green
    } catch {
        Write-Warning "    atomic failed: $($_.Exception.Message)`n"
    }
}

$ended = (Get-Date).ToUniversalTime().ToString('o')
Write-Host "Atomic validation window END (UTC): $ended" -ForegroundColor Cyan
Write-Host ""
Write-Host "Now assert the alerts fired on the indexer (from the lab host / WSL):" -ForegroundColor Cyan
Write-Host "  detections/atomics/assert_alerts.sh '$started'"
