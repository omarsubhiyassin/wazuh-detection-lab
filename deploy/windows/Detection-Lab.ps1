<#
  Detection Lab launcher — double-click Detection-Lab.cmd (which calls this).
  Brings the whole stack up if needed, then opens the SOC dashboard in its own
  app window. Safe to run anytime; it only starts what isn't already running.
#>
$ErrorActionPreference = 'Continue'

# --- config (adjust if your setup differs) -----------------------------------
$Distro     = 'Ubuntu'
$SingleNode = '/home/amigo/detection-lab/infra/wazuh-docker/single-node'
$DashUrl    = 'https://localhost:8787'
$DockerExe  = "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"

function Info($m) { Write-Host "  $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  $m" -ForegroundColor Yellow }

Write-Host "`nDetection Lab" -ForegroundColor White

# 1. Docker Desktop / engine
if (-not (Get-Process 'Docker Desktop' -ErrorAction SilentlyContinue)) {
  Info 'starting Docker Desktop...'
  if (Test-Path $DockerExe) { Start-Process $DockerExe } else { Warn "Docker Desktop not found at $DockerExe" }
}
Info 'waiting for the Docker engine...'
$engine = $false
for ($i = 0; $i -lt 60; $i++) {
  docker info *> $null 2>&1
  if ($LASTEXITCODE -eq 0) { $engine = $true; break }
  Start-Sleep -Seconds 3
}
if (-not $engine) { Warn 'Docker engine did not come up. Open Docker Desktop and retry.'; Read-Host 'Press Enter to close'; exit 1 }

# 2. Bring the stack up (idempotent — starts only what is down)
Info 'starting the stack (indexer, manager, dashboards, agent)...'
wsl -d $Distro -e bash -lc "cd $SingleNode && docker compose -f docker-compose.yml -f docker-compose.override.yml up -d" *> $null 2>&1

# 3. Wait for the indexer to go green (else the dashboard opens to a 502 while
#    the indexer is still warming up). Password is read from .env inside WSL.
Info 'waiting for the indexer to be ready...'
wsl -d $Distro -e bash -lc 'PW=$(grep "^INDEXER_PASSWORD=" /home/amigo/detection-lab/infra/.env | cut -d= -f2); for i in $(seq 1 60); do s=$(curl -sk -u "admin:$PW" https://localhost:9200/_cluster/health 2>/dev/null | grep -o "\"status\":\"green\""); [ -n "$s" ] && exit 0; sleep 3; done; exit 1' *> $null 2>&1

# 4. Wait for the dashboard itself to answer
Info 'waiting for the dashboard...'
$up = $false
for ($i = 0; $i -lt 50; $i++) {
  $code = (wsl -d $Distro -e bash -lc "curl -sk -o /dev/null -w '%{http_code}' $DashUrl/ 2>/dev/null")
  if ($code -eq '200') { $up = $true; break }
  Start-Sleep -Seconds 3
}
if (-not $up) { Warn 'dashboard did not respond yet — opening anyway; give it a moment and refresh.' }

# 5. Open in an app window (own icon, no browser chrome)
$edge   = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
$chrome = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
if (Test-Path $edge)        { Start-Process $edge   "--app=$DashUrl" }
elseif (Test-Path $chrome)  { Start-Process $chrome "--app=$DashUrl" }
else                        { Start-Process $DashUrl }
Ok "opened $DashUrl"
Write-Host "  (first time: click 'Advanced -> continue' past the localhost certificate notice)`n" -ForegroundColor DarkGray
Start-Sleep -Seconds 2
