<#
.SYNOPSIS
  NetJump-Monitor -- live watcher for ethernet link up/down events and
  continuous ping loss, so you can capture exactly when the line drops.

.DESCRIPTION
  Polls Get-NetAdapter every second and pings the default gateway and
  1.1.1.1 in parallel. Any state change (link up/down, ping miss) is
  timestamped and appended to .\Reports\NetJump-Monitor-<date>.log.

  Leave this running. Come back after a flap and the log will show
  EXACTLY when it happened, for how long, and whether ping was lost
  at the same time (physical layer) or only pings failed while the
  link stayed up (driver / routing / upstream).

.PARAMETER Adapter
  Name of adapter to watch. If omitted, picks the first UP ethernet.

.PARAMETER Seconds
  Stop after N seconds. 0 = run forever. Default 0.

.EXAMPLE
  .\NetJump-Monitor.ps1
  .\NetJump-Monitor.ps1 -Seconds 3600   # 1 hour
#>

[CmdletBinding()]
param(
    [string]$Adapter,
    [int]$Seconds = 0
)

$ErrorActionPreference = 'SilentlyContinue'

$reportDir = Join-Path $PSScriptRoot 'Reports'
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir | Out-Null }
$logPath = Join-Path $reportDir ("NetJump-Monitor-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

function Pick-Adapter {
    $all = Get-NetAdapter | Where-Object { $_.HardwareInterface -and ($_.MediaType -eq '802.3' -or $_.PhysicalMediaType -match 'Ethernet|802.3') }
    $up = $all | Where-Object Status -eq 'Up' | Select-Object -First 1
    if ($up) { return $up }
    return $all | Select-Object -First 1
}

if (-not $Adapter) {
    $a = Pick-Adapter
    if (-not $a) { Write-Host 'No ethernet adapter found.' -ForegroundColor Red; exit 1 }
    $Adapter = $a.Name
}

$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop
if (-not $gw -or $gw -eq '0.0.0.0') { $gw = $null }

Write-Host ("NetJump-Monitor watching '{0}'. Gateway={1}. Log={2}" -f $Adapter, $gw, $logPath) -ForegroundColor Cyan
Write-Host 'Press Ctrl+C to stop.' -ForegroundColor DarkGray
"time,event,detail" | Set-Content $logPath

$ping = New-Object System.Net.NetworkInformation.Ping
$prevStatus    = $null
$prevLinkSpeed = $null
$prevGwOk      = $null
$prevCfOk      = $null
$downStart     = $null
$flapCount     = 0

$startTime = Get-Date

while ($true) {
    $now = Get-Date
    if ($Seconds -gt 0 -and (($now - $startTime).TotalSeconds -ge $Seconds)) { break }

    $na = Get-NetAdapter -Name $Adapter
    $status    = $na.Status
    $linkSpeed = $na.LinkSpeed

    $gwOk = $null
    if ($gw) {
        try { $gwOk = ($ping.Send($gw, 800).Status -eq 'Success') } catch { $gwOk = $false }
    }
    $cfOk = $null
    try { $cfOk = ($ping.Send('1.1.1.1', 800).Status -eq 'Success') } catch { $cfOk = $false }

    $ts = $now.ToString('yyyy-MM-dd HH:mm:ss.fff')

    if ($prevStatus -eq $null) {
        Write-Host ("{0}  baseline  status={1}  linkSpeed={2}  gw={3}  1.1.1.1={4}" -f $ts,$status,$linkSpeed,$gwOk,$cfOk)
        "$ts,baseline,status=$status linkSpeed=$linkSpeed gw=$gwOk cf=$cfOk" | Add-Content $logPath
    } else {
        if ($status -ne $prevStatus) {
            if ($status -ne 'Up') {
                $downStart = $now
                $flapCount++
                $msg = "LINK DOWN  (was {0}, now {1})  -- flap #{2}" -f $prevStatus, $status, $flapCount
                Write-Host ("{0}  {1}" -f $ts, $msg) -ForegroundColor Red
                "$ts,link_down,$msg" | Add-Content $logPath
            } else {
                $dur = if ($downStart) { (($now - $downStart).TotalSeconds).ToString('N1') } else { '?' }
                $msg = "LINK UP    (was {0}, now {1} at {2})  down for {3}s" -f $prevStatus, $status, $linkSpeed, $dur
                Write-Host ("{0}  {1}" -f $ts, $msg) -ForegroundColor Green
                "$ts,link_up,$msg" | Add-Content $logPath
                $downStart = $null
            }
        }
        if ($linkSpeed -ne $prevLinkSpeed -and $status -eq 'Up') {
            $msg = "SPEED CHANGE  {0} -> {1}" -f $prevLinkSpeed, $linkSpeed
            Write-Host ("{0}  {1}" -f $ts, $msg) -ForegroundColor Yellow
            "$ts,speed_change,$msg" | Add-Content $logPath
        }
        if ($gwOk -ne $prevGwOk) {
            $msg = "GATEWAY " + $(if ($gwOk) {'OK'} else {'LOST'}) + " (ping $gw)"
            $color = if ($gwOk) { 'Green' } else { 'Red' }
            Write-Host ("{0}  {1}" -f $ts, $msg) -ForegroundColor $color
            "$ts,gateway,$msg" | Add-Content $logPath
        }
        if ($cfOk -ne $prevCfOk) {
            $msg = "1.1.1.1 " + $(if ($cfOk) {'OK'} else {'LOST'})
            $color = if ($cfOk) { 'Green' } else { 'Red' }
            Write-Host ("{0}  {1}" -f $ts, $msg) -ForegroundColor $color
            "$ts,cloudflare,$msg" | Add-Content $logPath
        }
    }

    $prevStatus    = $status
    $prevLinkSpeed = $linkSpeed
    $prevGwOk      = $gwOk
    $prevCfOk      = $cfOk

    Start-Sleep -Seconds 1
}

Write-Host ''
Write-Host ("Stopped. {0} link-down event(s) recorded." -f $flapCount) -ForegroundColor Cyan
Write-Host ("Log: {0}" -f $logPath) -ForegroundColor Green
