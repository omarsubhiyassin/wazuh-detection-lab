<#
.SYNOPSIS
  Remove what install-agent.ps1 added: the Wazuh agent and Sysmon.
  Run in an ELEVATED PowerShell.
#>
[CmdletBinding()]
param([switch]$KeepSysmon)
$ErrorActionPreference = "Continue"

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)) {
  throw "Run this in an elevated (Administrator) PowerShell."
}

Write-Host "Stopping + uninstalling the Wazuh agent ..."
Stop-Service WazuhSvc -ErrorAction SilentlyContinue
$agent = Get-CimInstance Win32_Product -Filter "Name LIKE 'Wazuh Agent%'" -ErrorAction SilentlyContinue
if ($agent) { $agent | ForEach-Object { $_.Uninstall() | Out-Null } }
else { Write-Host "  (no Wazuh Agent MSI found)" }

if (-not $KeepSysmon) {
  $svc = Get-Service Sysmon64 -ErrorAction SilentlyContinue
  if ($svc) {
    $sm = Get-ChildItem "$env:TEMP\detection-lab-agent\Sysmon\Sysmon64.exe" -ErrorAction SilentlyContinue
    if ($sm) { & $sm.FullName -u force }
    else { Write-Host "  Sysmon service present but Sysmon64.exe not found; run 'Sysmon64.exe -u force' manually." }
  } else { Write-Host "  (Sysmon not installed)" }
}
Write-Host "Done."
