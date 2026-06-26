# =============================================================================
# src/23-ip-asn.ps1 — DB-IP ASN Lite (IPv4) lookup
# =============================================================================
# Mirrors the GeoIP feature in src/22-geoip.ps1 but for AS Number + organization.
# Source: https://download.db-ip.com/free/dbip-asn-lite-YYYY-MM.csv.gz
# CSV format: start_ip,end_ip,asn_number,asn_org_name
# IPv4 only for now; v6 lookups fall through to $null gracefully.
# =============================================================================

$script:IpAsnDbPath        = Join-Path $PSScriptRoot 'Reports\ThreatIntel\ip-asn.csv'
$script:IpAsnFeedUrlFormat = 'https://download.db-ip.com/free/dbip-asn-lite-{0}.csv.gz'
$script:IpAsnTtlHours      = 720    # 30-day refresh (same as GeoIP)
$script:IpAsnRangesV4      = $null  # array of [pscustomobject]@{Lo;Hi;Asn;Org} sorted by Lo
$script:IpAsnLoaded        = $false
$script:IpAsnLastRefresh   = $null

function Load-IpAsnDatabase {
    $script:IpAsnRangesV4 = $null
    $script:IpAsnLoaded   = $false
    if (-not (Test-Path $script:IpAsnDbPath)) { return $false }
    try {
        $age = (Get-Date) - (Get-Item $script:IpAsnDbPath).LastWriteTime
        if ($age.TotalHours -gt ($script:IpAsnTtlHours * 2)) { return $false }
        $script:IpAsnLastRefresh = (Get-Item $script:IpAsnDbPath).LastWriteTime
        $v4 = New-Object System.Collections.Generic.List[psobject]
        $reader = [System.IO.File]::OpenText($script:IpAsnDbPath)
        try {
            while ($null -ne ($line = $reader.ReadLine())) {
                if (-not $line) { continue }
                if ($line.IndexOf(':') -ge 0) { continue }   # skip IPv6 rows
                # CSV may contain commas in the org name when quoted; use a simple 3-split that
                # collapses everything after the 3rd comma into the org field.
                $parts = $line -split ',', 4
                if ($parts.Count -lt 4) { continue }
                $s = $parts[0]; $e = $parts[1]; $asn = $parts[2]; $org = ($parts[3] -replace '^"|"$','').Trim()
                if ($s -notmatch '^(\d+)\.(\d+)\.(\d+)\.(\d+)$') { continue }
                $lo = ([uint32]$matches[1] -shl 24) -bor ([uint32]$matches[2] -shl 16) -bor ([uint32]$matches[3] -shl 8) -bor [uint32]$matches[4]
                if ($e -notmatch '^(\d+)\.(\d+)\.(\d+)\.(\d+)$') { continue }
                $hi = ([uint32]$matches[1] -shl 24) -bor ([uint32]$matches[2] -shl 16) -bor ([uint32]$matches[3] -shl 8) -bor [uint32]$matches[4]
                $v4.Add([pscustomobject]@{ Lo=$lo; Hi=$hi; Asn=[int]$asn; Org=$org })
            }
        } finally { $reader.Close() }
        $script:IpAsnRangesV4 = @($v4 | Sort-Object Lo)
        $script:IpAsnLoaded = $true
        return $true
    } catch {
        try { Add-Event warn ("IP-ASN load failed: $($_.Exception.Message)") } catch {}
        return $false
    }
}

function Update-IpAsnDatabase {
    if ($script:State -and $script:State.IpAsnJob) {
        Add-Event scan 'IP-ASN database update already in progress.'
        return
    }
    $now = Get-Date
    $month1 = $now.ToString('yyyy-MM')
    $month2 = $now.AddMonths(-1).ToString('yyyy-MM')
    Add-Event scan ("IP-ASN: fetching db-ip.com asn-lite ({0})..." -f $month1)
    $url1 = $script:IpAsnFeedUrlFormat -f $month1
    $url2 = $script:IpAsnFeedUrlFormat -f $month2
    $dest = $script:IpAsnDbPath
    $job = Start-Job -Name 'NetJump-IpAsn' -ScriptBlock {
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
    if ($script:State) { $script:State.IpAsnJob = $job }
}

function Get-IpAsn {
    param([string]$Ip)
    if (-not $Ip -or -not $script:IpAsnLoaded -or -not $script:IpAsnRangesV4) { return $null }
    if ($Ip -notmatch '^(\d+)\.(\d+)\.(\d+)\.(\d+)$') { return $null }
    $u = ([uint32]$matches[1] -shl 24) -bor ([uint32]$matches[2] -shl 16) -bor ([uint32]$matches[3] -shl 8) -bor [uint32]$matches[4]
    $lo = 0; $hi = $script:IpAsnRangesV4.Count - 1
    while ($lo -le $hi) {
        $mid = [int](($lo + $hi) / 2)
        $r = $script:IpAsnRangesV4[$mid]
        if ($u -lt $r.Lo)      { $hi = $mid - 1 }
        elseif ($u -gt $r.Hi)  { $lo = $mid + 1 }
        else                   { return @{ Asn = $r.Asn; Org = $r.Org } }
    }
    return $null
}
