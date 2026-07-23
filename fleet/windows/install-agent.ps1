<#
.SYNOPSIS
  Enroll this Windows host into the detection lab: install Sysmon (curated
  config) + the pinned Wazuh agent, enrolled with the lab's authd password.

.DESCRIPTION
  Run in an ELEVATED PowerShell. Idempotent-ish: re-running upgrades the Sysmon
  config and re-installs the agent MSI. Sysmon events reach the manager via the
  group-pushed agent.conf (shared/detection-lab), so this script only needs to
  install the collector and enroll -- the collection config is centrally managed.

  Undo with uninstall-agent.ps1.

.PARAMETER Manager
  Manager address reachable from THIS host. With the lab stack on the same
  machine (Docker publishes 1514/1515), that is 127.0.0.1 (default).

.PARAMETER RegistrationPassword
  The AGENT_ENROLLMENT_PASSWORD from infra/.env. Required.

.PARAMETER AgentName
  Name to register as (default: this computer's hostname).

.EXAMPLE
  .\install-agent.ps1 -RegistrationPassword 'Enr-....'
#>
[CmdletBinding()]
param(
  [string]$Manager = "127.0.0.1",
  [Parameter(Mandatory = $true)][string]$RegistrationPassword,
  [string]$AgentName = $env:COMPUTERNAME,
  [string]$AgentGroup = "detection-lab",
  [string]$WazuhVersion = "4.14.6",
  [string]$WorkDir = "$env:TEMP\detection-lab-agent"
)
$ErrorActionPreference = "Stop"

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "Run this in an elevated (Administrator) PowerShell."
  }
}

Assert-Admin
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

# --- 1. Sysmon + curated config ----------------------------------------------
# SwiftOnSecurity's config is the community baseline: high-signal, low-noise,
# and it emits exactly the Event IDs our rules key on (1 process create,
# 3 network, 10 process access).
$sysmonZip = "$WorkDir\Sysmon.zip"
$sysmonDir = "$WorkDir\Sysmon"
$sysmonCfg = "$PSScriptRoot\sysmonconfig.xml"
if (-not (Test-Path $sysmonCfg)) {
  Write-Host "Fetching Sysmon config (SwiftOnSecurity baseline) ..."
  Invoke-WebRequest -UseBasicParsing -Uri `
    "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
    -OutFile $sysmonCfg
}
Write-Host "Fetching Sysmon ..."
Invoke-WebRequest -UseBasicParsing -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $sysmonZip
Expand-Archive -Force -Path $sysmonZip -DestinationPath $sysmonDir

if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
  Write-Host "Sysmon already installed - updating config ..."
  & "$sysmonDir\Sysmon64.exe" -c $sysmonCfg
} else {
  Write-Host "Installing Sysmon ..."
  & "$sysmonDir\Sysmon64.exe" -accepteula -i $sysmonCfg
}

# --- 1b. Audit policy --------------------------------------------------------
# Some detections key on Windows Security-channel events that are NOT audited by
# default. Enable the subcategories our rules depend on (Sysmon covers process /
# network / handle activity; this fills the Security-channel gaps). Subcategory
# GUIDs are used instead of names because names are localized. Idempotent.
Write-Host "Enabling required audit subcategories ..."
$auditSubs = @(
  # Other Object Access Events -> 4698/4699 scheduled-task create/delete (rules 100120/100121)
  '{0CCE9227-69AE-11D9-BED3-505054503030}'
)
foreach ($guid in $auditSubs) {
  & auditpol /set /subcategory:"$guid" /success:enable /failure:enable | Out-Null
}
# Note: 1102 (Security log cleared) is emitted regardless of audit policy.

# --- 2. Wazuh agent MSI -------------------------------------------------------
$msi = "$WorkDir\wazuh-agent-$WazuhVersion.msi"
Write-Host "Fetching Wazuh agent $WazuhVersion ..."
Invoke-WebRequest -UseBasicParsing `
  -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion-1.msi" -OutFile $msi

Write-Host "Installing + enrolling the Wazuh agent (manager $Manager, group $AgentGroup) ..."
$msiArgs = @(
  "/i", "`"$msi`"", "/q",
  "WAZUH_MANAGER=`"$Manager`"",
  "WAZUH_REGISTRATION_SERVER=`"$Manager`"",
  "WAZUH_REGISTRATION_PASSWORD=`"$RegistrationPassword`"",
  "WAZUH_AGENT_NAME=`"$AgentName`"",
  "WAZUH_AGENT_GROUP=`"$AgentGroup`""
)
$proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) { throw "msiexec failed with exit code $($proc.ExitCode)" }

Start-Service -Name WazuhSvc
Write-Host ""
Write-Host "Done. This host ($AgentName) is enrolling into '$AgentGroup'."
Write-Host "Verify on the manager:  docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l"
Write-Host "Sysmon collection is delivered by the group agent.conf; give it ~1 min to sync."
