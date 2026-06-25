# =============================================================================
# src/22-geoip.ps1 — GeoIP database (DB-IP Lite Country, IPv4)
# =============================================================================
# Migrated from NetJump-Dashboard.ps1 ("# ---------- GeoIP (DB-IP Lite Country) ----------")
# in v1.3 as the proof-of-pattern for the src/ migration. Pure function definitions + script
# variables; no calls into UI. Loaded by the dot-source loader at the top of the main file.
#
# Source: https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz (no auth, monthly).
# Replaces the hardcoded $script:CountryCoords 40-entry table for actual country attribution.
# IPv4 only for now; IPv6 lookups in Get-IpCountry fall through to $null.
# =============================================================================

# Path computed from $PSScriptRoot directly (not $script:ThreatIntelDir which is defined later
# in the main file). This keeps the src/ module loadable before main-file state init.
$script:GeoIpDbPath        = Join-Path $PSScriptRoot 'Reports\ThreatIntel\geoip-country.csv'
$script:GeoIpFeedUrlFormat = 'https://download.db-ip.com/free/dbip-country-lite-{0}.csv.gz'
$script:GeoIpTtlHours      = 720    # 30-day refresh; the data only changes meaningfully each month.
$script:GeoIpRangesV4      = $null  # array of [pscustomobject]@{Lo;Hi;CC} sorted by Lo
$script:GeoIpLoaded        = $false
$script:GeoIpLastRefresh   = $null

function Load-GeoIpDatabase {
    $script:GeoIpRangesV4 = $null
    $script:GeoIpLoaded   = $false
    if (-not (Test-Path $script:GeoIpDbPath)) { return $false }
    try {
        $age = (Get-Date) - (Get-Item $script:GeoIpDbPath).LastWriteTime
        # Allow up to 2x TTL before discarding - 60-day-old country data is still mostly accurate.
        if ($age.TotalHours -gt ($script:GeoIpTtlHours * 2)) { return $false }
        $script:GeoIpLastRefresh = (Get-Item $script:GeoIpDbPath).LastWriteTime
        $v4 = New-Object System.Collections.Generic.List[psobject]
        $reader = [System.IO.File]::OpenText($script:GeoIpDbPath)
        try {
            while ($null -ne ($line = $reader.ReadLine())) {
                if (-not $line) { continue }
                # CSV format: start_ip,end_ip,country_code (DB-IP Lite). No header, no quoting.
                # IPv6 rows have ':' in the addresses - skip them (v6 lookup falls through to null).
                if ($line.IndexOf(':') -ge 0) { continue }
                $parts = $line -split ','
                if ($parts.Count -lt 3) { continue }
                $s = $parts[0]; $e = $parts[1]; $cc = $parts[2].Trim()
                if ($s -notmatch '^(\d+)\.(\d+)\.(\d+)\.(\d+)$') { continue }
                $lo = ([uint32]$matches[1] -shl 24) -bor ([uint32]$matches[2] -shl 16) -bor ([uint32]$matches[3] -shl 8) -bor [uint32]$matches[4]
                if ($e -notmatch '^(\d+)\.(\d+)\.(\d+)\.(\d+)$') { continue }
                $hi = ([uint32]$matches[1] -shl 24) -bor ([uint32]$matches[2] -shl 16) -bor ([uint32]$matches[3] -shl 8) -bor [uint32]$matches[4]
                $v4.Add([pscustomobject]@{ Lo=$lo; Hi=$hi; CC=$cc })
            }
        } finally { $reader.Close() }
        # DB-IP Lite is already sorted by start_ip; sort again defensively (cheap on already-sorted).
        $script:GeoIpRangesV4 = @($v4 | Sort-Object Lo)
        $script:GeoIpLoaded = $true
        return $true
    } catch {
        try { Add-Event warn ("GeoIP load failed: $($_.Exception.Message)") } catch {}
        return $false
    }
}

function Update-GeoIpDatabase {
    # Async fetch via Start-Job. Decompresses inline to the destination CSV.
    if ($script:State -and $script:State.GeoIpJob) {
        Add-Event scan 'GeoIP database update already in progress.'
        return
    }
    $now = Get-Date
    $month1 = $now.ToString('yyyy-MM')
    $month2 = $now.AddMonths(-1).ToString('yyyy-MM')
    Add-Event scan ("GeoIP: fetching db-ip.com country-lite ({0})..." -f $month1)
    $url1 = $script:GeoIpFeedUrlFormat -f $month1
    $url2 = $script:GeoIpFeedUrlFormat -f $month2
    $dest = $script:GeoIpDbPath
    $job = Start-Job -Name 'NetJump-GeoIp' -ScriptBlock {
        param($Url1, $Url2, $Dest)
        $tmp = "$Dest.gz"
        try {
            try { Invoke-WebRequest -Uri $Url1 -OutFile $tmp -TimeoutSec 180 -UseBasicParsing -ErrorAction Stop }
            catch { Invoke-WebRequest -Uri $Url2 -OutFile $tmp -TimeoutSec 180 -UseBasicParsing -ErrorAction Stop }
            $inF  = [System.IO.File]::OpenRead($tmp)
            $gz   = New-Object System.IO.Compression.GZipStream($inF, [System.IO.Compression.CompressionMode]::Decompress)
            $outF = [System.IO.File]::Create($Dest)
            $gz.CopyTo($outF)
            $outF.Close(); $gz.Close(); $inF.Close()
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            return @{ Ok=$true; SizeKB = [int]((Get-Item $Dest).Length / 1024) }
        } catch {
            try { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } catch {}
            return @{ Ok=$false; Error="$_" }
        }
    } -ArgumentList $url1, $url2, $dest
    if ($script:State) { $script:State.GeoIpJob = $job }
}

function Get-IpCountry {
    param([string]$Ip)
    if (-not $Ip -or -not $script:GeoIpLoaded -or -not $script:GeoIpRangesV4) { return $null }
    if ($Ip -notmatch '^(\d+)\.(\d+)\.(\d+)\.(\d+)$') { return $null }
    $u = ([uint32]$matches[1] -shl 24) -bor ([uint32]$matches[2] -shl 16) -bor ([uint32]$matches[3] -shl 8) -bor [uint32]$matches[4]
    # Binary search: find the range where Lo <= u <= Hi.
    $lo = 0
    $hi = $script:GeoIpRangesV4.Count - 1
    while ($lo -le $hi) {
        $mid = [int](($lo + $hi) / 2)
        $r = $script:GeoIpRangesV4[$mid]
        if ($u -lt $r.Lo)      { $hi = $mid - 1 }
        elseif ($u -gt $r.Hi)  { $lo = $mid + 1 }
        else                   { return $r.CC }
    }
    return $null
}
