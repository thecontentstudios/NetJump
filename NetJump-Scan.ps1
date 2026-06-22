<#
.SYNOPSIS
  NetJump-Scan -- Deep ethernet / network diagnostic for Windows.

.DESCRIPTION
  Runs a battery of checks aimed at finding WHY an ethernet connection
  flaps (goes up/down repeatedly). Produces a human-readable report
  in the console and a timestamped log + HTML file in .\Reports.

  Categories checked:
    1.  System & adapter inventory
    2.  Link flap history (Event Log)
    3.  NIC error / discard counters
    4.  Advanced adapter properties (EEE, Green Ethernet, power saving)
    5.  Device Manager power management ("allow computer to turn off")
    6.  Driver info & age
    7.  NDIS filter / Light-Weight Filter drivers (VPNs, AV, malware)
    8.  Link quality test (ping jitter / loss to gateway + public DNS)
    9.  DNS health
    10. Active connections & listening ports
    11. Basic malware indicators (hosts file, proxy hijack,
        suspicious processes with network activity, odd scheduled tasks)
    12. Recent driver / Windows updates
    13. ARP table sanity
    14. Service health
  Each finding is tagged OK / INFO / WARN / FAIL and includes a short
  explanation + suggested fix.

.PARAMETER PingSeconds
  How long to run the live ping stability test. Default 20 seconds.

.PARAMETER SkipPing
  Skip the ping stability test (useful on a totally-down link).

.NOTES
  Run as Administrator for full results. Read-only -- makes no changes.
#>

[CmdletBinding()]
param(
    [int]$PingSeconds = 20,
    [switch]$SkipPing
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# ---------- output plumbing ----------
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:ReportDir = Join-Path $PSScriptRoot 'Reports'
if (-not (Test-Path $script:ReportDir)) { New-Item -ItemType Directory -Path $script:ReportDir | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:LogPath  = Join-Path $script:ReportDir "NetJump-$stamp.log"
$script:HtmlPath = Join-Path $script:ReportDir "NetJump-$stamp.html"
Start-Transcript -Path $script:LogPath -Force | Out-Null

function Write-Banner($text) {
    $line = '=' * 72
    Write-Host ''
    Write-Host $line     -ForegroundColor DarkCyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host $line     -ForegroundColor DarkCyan
}

function Add-Finding {
    param(
        [ValidateSet('OK','INFO','WARN','FAIL')] [string]$Level,
        [string]$Category,
        [string]$Message,
        [string]$Fix = ''
    )
    $script:Findings.Add([pscustomobject]@{
        Level    = $Level
        Category = $Category
        Message  = $Message
        Fix      = $Fix
        Time     = Get-Date
    })
    $color = @{OK='Green';INFO='Gray';WARN='Yellow';FAIL='Red'}[$Level]
    Write-Host ("  [{0,-4}] " -f $Level) -NoNewline -ForegroundColor $color
    Write-Host $Message
    if ($Fix) { Write-Host "         Fix: $Fix" -ForegroundColor DarkGray }
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------- header ----------
Clear-Host
Write-Host @'
 _   _      _      _
| \ | | ___| |_   | |_   _ _ __ ___  _ __
|  \| |/ _ \ __|  | | | | | '_ ` _ \| '_ \
| |\  |  __/ |_ |_| | |_| | | | | | | |_) |
|_| \_|\___|\__(_)___/\__,_|_| |_| |_| .__/
                                     |_|
  Deep ethernet / network diagnostic
'@ -ForegroundColor Cyan

$admin = Test-Admin
if ($admin) {
    Write-Host "Running elevated (Administrator). Full checks enabled." -ForegroundColor Green
} else {
    Write-Host "NOT elevated. Some checks will be skipped. Re-run as Administrator for full results." -ForegroundColor Yellow
}
Write-Host "Report will be saved to: $script:ReportDir" -ForegroundColor DarkGray

# ---------- 1. SYSTEM & ADAPTER INVENTORY ----------
Write-Banner '1. System & adapter inventory'
$os  = Get-CimInstance Win32_OperatingSystem
$cs  = Get-CimInstance Win32_ComputerSystem
Write-Host ("  Host      : {0}" -f $cs.Name)
Write-Host ("  OS        : {0} (build {1})" -f $os.Caption, $os.BuildNumber)
Write-Host ("  Uptime    : {0:dd\.hh\:mm\:ss}" -f ((Get-Date) - $os.LastBootUpTime))

$adapters = Get-NetAdapter | Where-Object { $_.HardwareInterface }
if (-not $adapters) {
    Add-Finding FAIL 'Inventory' 'No physical network adapters found.'
} else {
    foreach ($a in $adapters) {
        $line = "  {0,-28} {1,-12} {2,-15} {3}" -f `
            $a.Name, $a.Status, ($a.LinkSpeed), $a.InterfaceDescription
        Write-Host $line
    }
}

$ethAdapters = $adapters | Where-Object {
    $_.MediaType -eq '802.3' -or $_.PhysicalMediaType -match 'Ethernet|802.3'
}
if (-not $ethAdapters) {
    Add-Finding WARN 'Inventory' 'No wired (ethernet) adapter detected -- scan will still run for all NICs.'
    $ethAdapters = $adapters
}

$primary = $ethAdapters | Where-Object Status -eq 'Up' | Select-Object -First 1
if (-not $primary) {
    $primary = $ethAdapters | Select-Object -First 1
    Add-Finding FAIL 'Link' ("Primary ethernet adapter '{0}' is {1}." -f $primary.Name, $primary.Status) `
        'Check the cable, try a different port/cable, and confirm the switch/router LED is lit.'
} else {
    Add-Finding OK 'Link' ("Primary ethernet adapter '{0}' is UP at {1}." -f $primary.Name, $primary.LinkSpeed)
}

# ---------- 2. LINK FLAP HISTORY ----------
Write-Banner '2. Link flap history (last 72 hours)'
$since = (Get-Date).AddHours(-72)

# NDIS events 27/10400 = link state change
$ndisFlaps = Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = @('Microsoft-Windows-NDIS','Microsoft-Windows-Kernel-PnP','e1dexpress','e1iexpress','e1rexpress','RtNicProp','NETwNs64','iaLPSS2i_GPIO2','Tcpip')
    StartTime    = $since
} -MaxEvents 500 2>$null

# fall back to broad search if provider filter missed some
if (-not $ndisFlaps) {
    $ndisFlaps = Get-WinEvent -LogName System -MaxEvents 2000 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $since -and $_.Message -match 'network|link|media\s+disconnected|media\s+connected|adapter' }
}

$downEvents = @($ndisFlaps | Where-Object { $_.Message -match 'disconnect|down|media\s+has\s+been\s+disconnected|link\s+down' })
$upEvents   = @($ndisFlaps | Where-Object { $_.Message -match 'connect(ed)?|up|media\s+connect|link\s+up' })

Write-Host ("  Link-down events in last 72h : {0}" -f $downEvents.Count)
Write-Host ("  Link-up   events in last 72h : {0}" -f $upEvents.Count)

if ($downEvents.Count -ge 5) {
    Add-Finding FAIL 'Flaps' ("Detected {0} link-down events in 72h -- this confirms flapping." -f $downEvents.Count) `
        'Most common causes (in order): bad cable, failing switch port, Energy-Efficient Ethernet / Green Ethernet driver bug, NIC power-saving, or a buggy driver. See sections 4-7 below.'
    $recent = $downEvents | Sort-Object TimeCreated -Descending | Select-Object -First 8
    foreach ($e in $recent) {
        Write-Host ("    {0}  id={1}  {2}" -f $e.TimeCreated, $e.Id, ($e.Message -replace '\s+',' ' | ForEach-Object { $_.Substring(0,[Math]::Min(90,$_.Length)) }))
    }
} elseif ($downEvents.Count -gt 0) {
    Add-Finding WARN 'Flaps' ("Detected {0} link-down events in 72h." -f $downEvents.Count) `
        'A small number can be normal (sleep/wake, reboots). If this increases, investigate further.'
} else {
    Add-Finding OK 'Flaps' 'No link-down events recorded in System log in the last 72h.'
}

# ---------- 3. NIC ERROR / DISCARD COUNTERS ----------
Write-Banner '3. NIC error & discard counters'
foreach ($a in $ethAdapters) {
    $s = Get-NetAdapterStatistics -Name $a.Name
    if (-not $s) { continue }
    $rxErr  = [int64]$s.ReceivedDiscardedPackets + [int64]$s.ReceivedPacketErrors
    $txErr  = [int64]$s.OutboundDiscardedPackets + [int64]$s.OutboundPacketErrors
    $rxPkts = [int64]$s.ReceivedUnicastPackets + [int64]$s.ReceivedMulticastPackets + [int64]$s.ReceivedBroadcastPackets
    $txPkts = [int64]$s.SentUnicastPackets     + [int64]$s.SentMulticastPackets     + [int64]$s.SentBroadcastPackets

    Write-Host ("  {0}" -f $a.Name) -ForegroundColor White
    Write-Host ("     RX : {0,15:N0} pkts  errors={1:N0}  discards={2:N0}" -f $rxPkts, $s.ReceivedPacketErrors, $s.ReceivedDiscardedPackets)
    Write-Host ("     TX : {0,15:N0} pkts  errors={1:N0}  discards={2:N0}" -f $txPkts, $s.OutboundPacketErrors, $s.OutboundDiscardedPackets)

    $ratio = if ($rxPkts -gt 0) { $rxErr / $rxPkts } else { 0 }
    if ($ratio -gt 0.001) {
        Add-Finding FAIL 'Counters' ("{0}: RX error/discard rate {1:P3} -- physical-layer problem." -f $a.Name, $ratio) `
            'Replace the ethernet cable with a known-good Cat5e or better. Try a different port on the switch/router. If your cable runs past patch panels or keystones, reseat every connector.'
    } elseif ($rxErr -gt 100) {
        Add-Finding WARN 'Counters' ("{0}: {1} RX errors/discards accumulated." -f $a.Name, $rxErr) `
            'Not catastrophic but worth watching. Consider cable/port swap if it grows.'
    } else {
        Add-Finding OK 'Counters' ("{0}: clean error counters." -f $a.Name)
    }
}

# ---------- 4. ADVANCED ADAPTER PROPERTIES ----------
Write-Banner '4. Advanced adapter properties (known flap causes)'
$culpritKeywords = @(
    @{ Pattern='Energy.*Efficient|EEE';         Name='Energy-Efficient Ethernet'; BadIf='enabled' }
    @{ Pattern='Green\s*Ethernet';               Name='Green Ethernet';            BadIf='enabled' }
    @{ Pattern='Power\s*Saving|Ultra\s*Low\s*Power'; Name='Power Saving Mode';     BadIf='enabled' }
    @{ Pattern='Selective\s*Suspend';            Name='Selective Suspend';         BadIf='enabled' }
    @{ Pattern='Wake\s*on\s*(pattern|magic)';    Name='Wake-on-LAN';               BadIf=''        }
    @{ Pattern='Speed.*Duplex';                  Name='Speed & Duplex';            BadIf=''        }
    @{ Pattern='Flow\s*Control';                 Name='Flow Control';              BadIf=''        }
    @{ Pattern='Jumbo';                          Name='Jumbo Packet';              BadIf=''        }
    @{ Pattern='Interrupt\s*Moderation';         Name='Interrupt Moderation';      BadIf=''        }
    @{ Pattern='Large\s*Send\s*Offload|LSO';    Name='Large Send Offload';         BadIf=''        }
    @{ Pattern='Receive\s*Side\s*Scaling|RSS';  Name='Receive Side Scaling';       BadIf=''        }
)

foreach ($a in $ethAdapters) {
    Write-Host ("  {0}" -f $a.Name) -ForegroundColor White
    $props = Get-NetAdapterAdvancedProperty -Name $a.Name 2>$null
    if (-not $props) {
        Write-Host '     (no advanced properties exposed by driver)' -ForegroundColor DarkGray
        continue
    }
    foreach ($c in $culpritKeywords) {
        $match = $props | Where-Object { $_.DisplayName -match $c.Pattern -or $_.RegistryKeyword -match $c.Pattern }
        foreach ($m in $match) {
            $val = $m.DisplayValue
            Write-Host ("     {0,-35} = {1}" -f $m.DisplayName, $val)
            if ($c.BadIf -and $val -match $c.BadIf) {
                Add-Finding WARN 'AdvProps' ("{0} is '{1}' on {2} -- frequent cause of ethernet flapping." -f $m.DisplayName, $val, $a.Name) `
                    ("Disable in Device Manager → {0} → Properties → Advanced → '{1}' → Disabled. Or in PowerShell: Set-NetAdapterAdvancedProperty -Name '{0}' -DisplayName '{1}' -DisplayValue 'Disabled'" -f $a.Name, $m.DisplayName)
            }
        }
    }
    if (-not ($props | Where-Object { $_.DisplayName -match 'Energy.*Efficient|Green' })) {
        Write-Host '     (no EEE/Green Ethernet knobs -- driver hides them)' -ForegroundColor DarkGray
    }
}

# ---------- 5. DEVICE MANAGER POWER MANAGEMENT ----------
Write-Banner '5. Device Manager power management'
foreach ($a in $ethAdapters) {
    $pm = Get-NetAdapterPowerManagement -Name $a.Name 2>$null
    if (-not $pm) { continue }
    Write-Host ("  {0}" -f $a.Name) -ForegroundColor White
    Write-Host ("     AllowComputerToTurnOffDevice : {0}" -f $pm.AllowComputerToTurnOffDevice)
    Write-Host ("     SelectiveSuspend             : {0}" -f $pm.SelectiveSuspend)
    Write-Host ("     DeviceSleepOnDisconnect      : {0}" -f $pm.DeviceSleepOnDisconnect)
    Write-Host ("     WakeOnMagicPacket            : {0}" -f $pm.WakeOnMagicPacket)
    if ($pm.AllowComputerToTurnOffDevice -eq 'Enabled') {
        Add-Finding WARN 'Power' ("{0}: 'Allow the computer to turn off this device' is ENABLED -- classic cause of random drops." -f $a.Name) `
            "Device Manager → Network adapters → $($a.InterfaceDescription) → Properties → Power Management → uncheck it. PowerShell: Disable-NetAdapterPowerManagement -Name '$($a.Name)' -AllowComputerToTurnOffDevice"
    } else {
        Add-Finding OK 'Power' ("{0}: computer cannot power down the NIC." -f $a.Name)
    }
}

# ---------- 6. DRIVER INFO & AGE ----------
Write-Banner '6. Driver info & age'
foreach ($a in $ethAdapters) {
    $d = $a | Select-Object -ExpandProperty DriverDate, DriverVersionString, DriverProvider, DriverDescription -ErrorAction SilentlyContinue
    $dd = $a.DriverDate
    $dv = $a.DriverVersionString
    $dp = $a.DriverProvider
    Write-Host ("  {0}" -f $a.Name) -ForegroundColor White
    Write-Host ("     Provider : {0}" -f $dp)
    Write-Host ("     Version  : {0}" -f $dv)
    Write-Host ("     Date     : {0}" -f $dd)
    if ($dd) {
        $ageYears = ((Get-Date) - $dd).TotalDays / 365.25
        if ($ageYears -gt 3) {
            Add-Finding WARN 'Driver' ("{0}: driver is {1:N1} years old." -f $a.Name, $ageYears) `
                "Update from the NIC vendor's site (Intel, Realtek, Killer, etc.) -- NOT just Windows Update, which often keeps older drivers. Find the chipset in 'Interface description' above."
        } elseif ($ageYears -gt 1.5) {
            Add-Finding INFO 'Driver' ("{0}: driver is {1:N1} years old -- may be worth updating." -f $a.Name, $ageYears)
        } else {
            Add-Finding OK 'Driver' ("{0}: driver age {1:N1} years -- current." -f $a.Name, $ageYears)
        }
    }
}

# ---------- 7. NDIS FILTER / LIGHTWEIGHT FILTER DRIVERS ----------
Write-Banner '7. NDIS filter drivers bound to NIC (VPN / AV / malware hook points)'
$bindings = Get-NetAdapterBinding -AllBindings:$false | Where-Object { $_.Enabled -and $_.Name -in $ethAdapters.Name }
$lwfs = $bindings | Group-Object ComponentID | ForEach-Object { $_.Group[0] }
$knownGood = @(
    'ms_msclient','ms_pacer','ms_server','ms_lldp','ms_rspndr','ms_lltdio',
    'ms_tcpip6','ms_tcpip','ms_implat','ms_ndisuio','ms_wfplwfs','ms_wfplwf_upper','ms_wfplwf_lower',
    'ms_netbios','ms_bridgemp','ms_ndiscap','ms_hypernet'
)
foreach ($a in $ethAdapters) {
    Write-Host ("  {0}" -f $a.Name) -ForegroundColor White
    $ab = Get-NetAdapterBinding -Name $a.Name | Where-Object Enabled
    foreach ($b in $ab) {
        $odd = $b.ComponentID -notin $knownGood
        $color = if ($odd) { 'Yellow' } else { 'DarkGray' }
        Write-Host ("     {0,-35} {1}" -f $b.DisplayName, $b.ComponentID) -ForegroundColor $color
        if ($odd) {
            Add-Finding INFO 'NDIS' ("Non-standard filter bound to {0}: {1} ({2})" -f $a.Name, $b.DisplayName, $b.ComponentID) `
                'This is usually a VPN, antivirus, virtualization, or packet-inspection product. Temporarily disable to test if the flapping stops. Malware rarely installs here but it is possible.'
        }
    }
}

# ---------- 8. LINK QUALITY (PING STABILITY) ----------
if (-not $SkipPing) {
    Write-Banner ("8. Link quality test ({0}s)" -f $PingSeconds)
    $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric | Select-Object -First 1).NextHop
    $targets = @()
    if ($gw -and $gw -ne '0.0.0.0') { $targets += @{Name='Gateway ('+$gw+')'; Host=$gw} }
    $targets += @{Name='Cloudflare (1.1.1.1)'; Host='1.1.1.1'}
    $targets += @{Name='Google (8.8.8.8)';     Host='8.8.8.8'}

    foreach ($t in $targets) {
        Write-Host ("  Pinging {0} ..." -f $t.Name) -ForegroundColor White
        $rtts = New-Object System.Collections.Generic.List[double]
        $loss = 0
        $sent = 0
        $deadline = (Get-Date).AddSeconds($PingSeconds / $targets.Count)
        while ((Get-Date) -lt $deadline) {
            $sent++
            try {
                $r = (New-Object System.Net.NetworkInformation.Ping).Send($t.Host, 1000)
                if ($r.Status -eq 'Success') { $rtts.Add($r.RoundtripTime) } else { $loss++ }
            } catch { $loss++ }
            Start-Sleep -Milliseconds 200
        }
        if ($rtts.Count -gt 0) {
            $avg = ($rtts | Measure-Object -Average).Average
            $max = ($rtts | Measure-Object -Maximum).Maximum
            $min = ($rtts | Measure-Object -Minimum).Minimum
            $jitter = $max - $min
            $lossPct = if ($sent -gt 0) { ($loss / $sent) * 100 } else { 0 }
            Write-Host ("     sent={0}  loss={1}  avg={2:N1}ms  min={3}ms  max={4}ms  jitter={5}ms" -f $sent,$loss,$avg,$min,$max,$jitter)
            if ($lossPct -gt 2) {
                Add-Finding FAIL 'Quality' ("{0}: {1:N1}% packet loss." -f $t.Name, $lossPct) `
                    'Any loss above ~1% to your own gateway points at cabling, switch port, or NIC power-saving. Loss only to public targets but not the gateway points at ISP/router.'
            } elseif ($jitter -gt 80) {
                Add-Finding WARN 'Quality' ("{0}: high jitter {1}ms." -f $t.Name, $jitter) `
                    'Jitter spikes during a scan of your NIC often mean interrupt moderation / power management is cycling.'
            } else {
                Add-Finding OK 'Quality' ("{0}: loss={1:N1}%, jitter={2}ms." -f $t.Name, $lossPct, $jitter)
            }
        } else {
            Add-Finding FAIL 'Quality' ("{0}: 100% packet loss ({1} attempts)." -f $t.Name, $sent) `
                'Cannot reach target. If only public targets fail, it is an upstream/DNS issue; if the gateway also fails, the link itself is broken.'
        }
    }
} else {
    Write-Banner '8. Link quality test (SKIPPED)'
}

# ---------- 9. DNS HEALTH ----------
Write-Banner '9. DNS health'
$dnsClients = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses
foreach ($d in $dnsClients | Where-Object InterfaceAlias -in $ethAdapters.Name) {
    Write-Host ("  {0} DNS servers: {1}" -f $d.InterfaceAlias, ($d.ServerAddresses -join ', '))
}
$testHosts = 'www.microsoft.com','www.cloudflare.com','www.google.com'
foreach ($h in $testHosts) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r  = Resolve-DnsName $h -Type A -ErrorAction SilentlyContinue | Select-Object -First 1
    $sw.Stop()
    if ($r) {
        $ms = $sw.ElapsedMilliseconds
        $tag = if ($ms -gt 500) { 'WARN' } else { 'OK' }
        Add-Finding $tag 'DNS' ("Resolved {0} in {1}ms -> {2}" -f $h, $ms, $r.IPAddress)
    } else {
        Add-Finding FAIL 'DNS' ("Failed to resolve {0}." -f $h) `
            'Try: ipconfig /flushdns ; set DNS to 1.1.1.1 + 8.8.8.8 temporarily to isolate ISP DNS problems.'
    }
}

# ---------- 10. ACTIVE CONNECTIONS & LISTENERS ----------
Write-Banner '10. Active connections summary'
$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
Write-Host ("  Established TCP connections: {0}" -f $conns.Count)
$byProc = $conns | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 10
foreach ($g in $byProc) {
    $p = Get-Process -Id $g.Name -ErrorAction SilentlyContinue
    $pname = if ($p) { $p.ProcessName } else { 'pid='+$g.Name }
    Write-Host ("     {0,5}  {1}" -f $g.Count, $pname)
}

# ---------- 11. BASIC MALWARE INDICATORS ----------
Write-Banner '11. Basic malware / tamper indicators'

# 11a. hosts file
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    $hostsLines = Get-Content $hostsPath | Where-Object { $_ -and $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }
    if ($hostsLines.Count -eq 0) {
        Add-Finding OK 'Malware' 'Hosts file has no non-default entries.'
    } else {
        Add-Finding WARN 'Malware' ("Hosts file has {0} active entries -- review for tampering." -f $hostsLines.Count) `
            "Open $hostsPath as admin. Entries redirecting microsoft.com, windowsupdate, or security vendors to weird IPs are a strong malware signal."
        $hostsLines | Select-Object -First 15 | ForEach-Object { Write-Host "     $_" -ForegroundColor DarkGray }
    }
}

# 11b. proxy hijack
$proxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
if ($proxy -and $proxy.ProxyEnable -eq 1 -and $proxy.ProxyServer) {
    Add-Finding WARN 'Malware' ("System proxy is ENABLED: {0}" -f $proxy.ProxyServer) `
        'If you did not set this, it is classic adware/malware behaviour. Disable via Settings → Network → Proxy, or: Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" ProxyEnable 0'
} else {
    Add-Finding OK 'Malware' 'No system proxy configured.'
}

# 11c. suspicious processes with network activity
$susPaths = @('\AppData\Local\Temp\','\AppData\Roaming\','\Users\Public\','\Windows\Temp\','\ProgramData\')
$susHits  = @()
foreach ($c in $conns | Select-Object -Unique OwningProcess) {
    $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    if (-not $p -or -not $p.Path) { continue }
    foreach ($sp in $susPaths) {
        if ($p.Path -like "*$sp*") {
            $susHits += [pscustomobject]@{Name=$p.ProcessName; PID=$p.Id; Path=$p.Path}
            break
        }
    }
}
if ($susHits) {
    foreach ($h in $susHits | Sort-Object Path -Unique) {
        Add-Finding WARN 'Malware' ("Process from suspicious path has network activity: {0} (pid {1}) -- {2}" -f $h.Name, $h.PID, $h.Path) `
            'Could be legitimate (updaters, installers) or malware. Right-click → Properties → check digital signature. If unsigned and from Temp, scan it.'
    }
} else {
    Add-Finding OK 'Malware' 'No network-active processes running from Temp/AppData paths.'
}

# 11d. Defender status + last scan
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mp) {
    Write-Host ("  Defender real-time : {0}" -f $mp.RealTimeProtectionEnabled)
    Write-Host ("  Signature age      : {0} day(s)" -f $mp.AntivirusSignatureAge)
    Write-Host ("  Last quick scan    : {0}" -f $mp.QuickScanEndTime)
    Write-Host ("  Last full scan     : {0}" -f $mp.FullScanEndTime)
    if (-not $mp.RealTimeProtectionEnabled) {
        Add-Finding WARN 'Malware' 'Defender real-time protection is OFF.' 'Re-enable unless you have another AV installed.'
    }
    if ($mp.AntivirusSignatureAge -gt 7) {
        Add-Finding WARN 'Malware' ("AV signatures are {0} days old." -f $mp.AntivirusSignatureAge) 'Run Windows Update and: Update-MpSignature'
    }
}

# 11e. odd scheduled tasks pointing at user-writable paths
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
$sus = @()
foreach ($t in $tasks) {
    $actions = $t.Actions | Where-Object { $_.Execute }
    foreach ($act in $actions) {
        $exe = $act.Execute
        foreach ($sp in $susPaths) {
            if ($exe -like "*$sp*") {
                $sus += "$($t.TaskPath)$($t.TaskName) -> $exe"
            }
        }
    }
}
if ($sus) {
    Add-Finding WARN 'Malware' ("Found {0} scheduled task(s) running binaries from Temp/AppData." -f $sus.Count) `
        'Review in Task Scheduler. Installers leave some legit ones (Chrome, Edge updater) but random names there are suspicious.'
    $sus | Select-Object -First 10 | ForEach-Object { Write-Host "     $_" -ForegroundColor DarkGray }
} else {
    Add-Finding OK 'Malware' 'No scheduled tasks running from Temp/AppData.'
}

# ---------- 12. RECENT UPDATES ----------
Write-Banner '12. Recent Windows / driver updates (last 14 days)'
$hotfix = Get-HotFix | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-14) } | Sort-Object InstalledOn -Descending
if ($hotfix) {
    foreach ($h in $hotfix) {
        Write-Host ("  {0}  {1}  {2}" -f $h.InstalledOn.ToString('yyyy-MM-dd'), $h.HotFixID, $h.Description)
    }
    Add-Finding INFO 'Updates' ("{0} Windows update(s) installed in last 14 days -- a recent one could have shipped a new NIC driver." -f $hotfix.Count) `
        'If flapping started right after a specific update, try: Settings → Windows Update → Update history → Uninstall updates. Or roll back the NIC driver in Device Manager.'
} else {
    Add-Finding OK 'Updates' 'No Windows updates in the last 14 days.'
}

# ---------- 13. ARP TABLE SANITY ----------
Write-Banner '13. ARP table'
$arp = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.State -in 'Reachable','Stale','Permanent' -and
        $_.LinkLayerAddress -and
        $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and
        $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' -and
        $_.LinkLayerAddress -notmatch '^(01-00-5E|33-33)' -and
        $_.IPAddress -notmatch '^(224\.|225\.|226\.|227\.|228\.|229\.|23\d\.|255\.)'
    }
$dupMac = $arp | Group-Object LinkLayerAddress | Where-Object Count -gt 1
if ($dupMac) {
    foreach ($g in $dupMac) {
        Add-Finding WARN 'ARP' ("MAC {0} claims multiple IPs: {1}" -f $g.Name, (($g.Group.IPAddress) -join ', ')) `
            'Could be a VM, could be ARP spoofing. On a home LAN with only physical devices, unexpected duplicates are suspicious.'
    }
} else {
    Add-Finding OK 'ARP' ("ARP table clean ({0} entries, no duplicate MACs)." -f $arp.Count)
}

# ---------- 14. SERVICE HEALTH ----------
Write-Banner '14. Network service health'
$mustRun = 'Dhcp','Dnscache','NlaSvc','netprofm','nsi','LanmanServer','LanmanWorkstation'
foreach ($s in $mustRun) {
    $svc = Get-Service $s -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne 'Running') {
            Add-Finding WARN 'Services' ("{0} ({1}) is {2}." -f $svc.DisplayName, $s, $svc.Status) `
                "Start-Service $s"
        } else {
            Write-Host ("  OK  {0,-12} {1}" -f $s, $svc.DisplayName) -ForegroundColor DarkGray
        }
    }
}

# ---------- SUMMARY ----------
Write-Banner 'SUMMARY'
$bucket = $script:Findings | Group-Object Level | Sort-Object Name
foreach ($b in $bucket) {
    $color = @{OK='Green';INFO='Gray';WARN='Yellow';FAIL='Red'}[$b.Name]
    Write-Host ("  {0,-4} : {1}" -f $b.Name, $b.Count) -ForegroundColor $color
}

Write-Host ''
Write-Host 'TOP SUSPECTS (in order of likelihood for your symptom -- ethernet up/down flapping):' -ForegroundColor Cyan
$ranked = @(
    'Cable/port (run a different cable, try another switch port) -- #1 cause of intermittent flaps',
    'Energy-Efficient Ethernet / Green Ethernet (see section 4)',
    '"Allow computer to turn off this device" (see section 5)',
    'Outdated or buggy NIC driver (see section 6)',
    'Third-party NDIS filter driver, often VPN or AV (see section 7)',
    'Recent Windows update shipped a broken NIC driver (see section 12)'
)
$ranked | ForEach-Object { Write-Host "   - $_" }

Write-Host ''
Write-Host 'IMPORTANT OPEN FINDINGS:' -ForegroundColor Cyan
$open = $script:Findings | Where-Object Level -in 'WARN','FAIL'
if ($open) {
    foreach ($o in $open) {
        $color = @{WARN='Yellow';FAIL='Red'}[$o.Level]
        Write-Host ("  [{0}] {1,-8} {2}" -f $o.Level, $o.Category, $o.Message) -ForegroundColor $color
        if ($o.Fix) { Write-Host "          -> $($o.Fix)" -ForegroundColor DarkGray }
    }
} else {
    Write-Host '  None. If you are still seeing drops, re-run during an active flap.' -ForegroundColor Green
}

# ---------- HTML REPORT ----------
$html = @"
<!doctype html><html><head><meta charset="utf-8"><title>NetJump report $stamp</title>
<style>
 body{font-family:Segoe UI,Arial;background:#0e1116;color:#d7dde6;margin:24px;}
 h1{color:#58a6ff;} h2{color:#7ee787;border-bottom:1px solid #30363d;padding-bottom:4px;margin-top:32px;}
 table{border-collapse:collapse;width:100%;margin-top:8px;}
 th,td{padding:6px 10px;border-bottom:1px solid #30363d;text-align:left;vertical-align:top;}
 .OK{color:#3fb950} .INFO{color:#8b949e} .WARN{color:#d29922} .FAIL{color:#f85149;font-weight:bold}
 code{background:#161b22;padding:1px 5px;border-radius:4px;}
</style></head><body>
<h1>NetJump report</h1>
<p>Host: <code>$($cs.Name)</code> &nbsp; OS: <code>$($os.Caption) build $($os.BuildNumber)</code> &nbsp; Scan time: <code>$(Get-Date)</code></p>
<h2>Findings</h2>
<table><tr><th>Level</th><th>Category</th><th>Message</th><th>Fix</th></tr>
$(
  ($script:Findings | ForEach-Object {
    "<tr><td class='$($_.Level)'>$($_.Level)</td><td>$($_.Category)</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.Message))</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.Fix))</td></tr>"
  }) -join "`n"
)
</table>
<h2>How to read this</h2>
<ul>
<li><span class='OK'>OK</span> -- good, nothing to do.</li>
<li><span class='INFO'>INFO</span> -- context, not a problem.</li>
<li><span class='WARN'>WARN</span> -- likely contributor to the symptom, worth fixing.</li>
<li><span class='FAIL'>FAIL</span> -- confirmed problem, fix this first.</li>
</ul>
</body></html>
"@
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
$html | Set-Content -Path $script:HtmlPath -Encoding UTF8

Write-Host ''
Write-Host ("Console log : {0}" -f $script:LogPath)  -ForegroundColor Green
Write-Host ("HTML report : {0}" -f $script:HtmlPath) -ForegroundColor Green
Write-Host ''
Write-Host 'Next step: run NetJump-Monitor.ps1 to watch link state live and capture exact flap timestamps.' -ForegroundColor Cyan

Stop-Transcript | Out-Null
