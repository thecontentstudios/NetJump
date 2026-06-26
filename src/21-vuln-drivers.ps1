# =============================================================================
# src/21-vuln-drivers.ps1 — Vulnerable-driver list (loldrivers.io)
# =============================================================================
# Migrated from NetJump-Dashboard.ps1's "# ---------- Dynamic vulnerable-driver
# list (loldrivers.io) ----------" block as part of the v1.5 src/ migration.
# Augments the curated $script:ByovdBlocklist with a regularly-refreshed list
# pulled from https://www.loldrivers.io/api/drivers.json. Curated entries
# always win on name collision because their Vendor/CVE/Note text is hand-
# written and richer. Dynamic list adds 400-500 long-tail entries.
# =============================================================================

$script:VulnDriverCache       = Join-Path $PSScriptRoot 'Reports\ThreatIntel\loldrivers.json'
$script:VulnDriverTtlHours    = 168    # 7-day TTL - the list moves slowly; weekly refresh is plenty.
$script:VulnDriverFeedUrl     = 'https://www.loldrivers.io/api/drivers.json'
$script:VulnDriverDynamic     = @{}    # filename(lowercase .sys) -> @{Vendor;CVE;Note;Source}
$script:VulnDriverLoaded      = $false
$script:VulnDriverLastRefresh = $null

function Load-VulnerableDriverList {
    $script:VulnDriverDynamic = @{}
    $script:VulnDriverLoaded  = $false
    if (-not (Test-Path $script:VulnDriverCache)) { return $false }
    try {
        $obj = Get-Content $script:VulnDriverCache -Raw | ConvertFrom-Json
        if ($obj.timestamp) {
            $age = (Get-Date) - [datetime]$obj.timestamp
            # Allow up to 2x TTL for stale cache (i.e. 14 days) before we discard - the curated
            # list remains useful past TTL, we just won't have the latest entries.
            if ($age.TotalHours -gt ($script:VulnDriverTtlHours * 2)) { return $false }
            $script:VulnDriverLastRefresh = [datetime]$obj.timestamp
        }
        if ($obj.drivers) {
            foreach ($d in $obj.drivers) {
                $name = ([string]$d.Filename).ToLower()
                if (-not $name) { continue }
                $script:VulnDriverDynamic[$name] = @{
                    Vendor = [string]$d.Vendor
                    CVE    = [string]$d.CVE
                    Note   = [string]$d.Note
                    Source = 'loldrivers'
                }
            }
        }
        $script:VulnDriverLoaded = $true
        return $true
    } catch { return $false }
}

function Save-VulnerableDriverList {
    try {
        $rows = @($script:VulnDriverDynamic.GetEnumerator() | ForEach-Object {
            [pscustomobject]@{
                Filename = $_.Key
                Vendor   = $_.Value.Vendor
                CVE      = $_.Value.CVE
                Note     = $_.Value.Note
            }
        })
        $obj = [pscustomobject]@{
            timestamp = (Get-Date).ToString('o')
            source    = $script:VulnDriverFeedUrl
            count     = $rows.Count
            drivers   = $rows
        }
        $obj | ConvertTo-Json -Depth 4 | Set-Content $script:VulnDriverCache -Encoding UTF8
    } catch {
        try { Add-Event warn ("Vulnerable-driver cache write failed: {0}" -f $_.Exception.Message) } catch {}
    }
}

function Update-VulnerableDriverList {
    # Async fetch (~600 KB JSON) via Start-Job to avoid blocking UI. Job parses each entry's
    # KnownVulnerableSamples[].Filename and returns a hashtable. Tick polls for completion the
    # same way it polls ThreatIntelJob, then calls Save-VulnerableDriverList.
    if ($script:State -and $script:State.VulnDriverJob) {
        Add-Event scan 'Vulnerable-driver list update already in progress.'
        return
    }
    Add-Event scan 'Vulnerable-driver list: refreshing from loldrivers.io...'
    $job = Start-Job -Name 'NetJump-VulnDrivers' -ScriptBlock {
        param($Url)
        try {
            $r = Invoke-WebRequest -Uri $Url -TimeoutSec 60 -UseBasicParsing -ErrorAction Stop
            # loldrivers.io JSON contains case-collision keys (e.g. 'init' AND 'INIT') that the
            # default ConvertFrom-Json refuses to parse. JavaScriptSerializer is case-sensitive and
            # ships in System.Web.Extensions on every Windows PowerShell install.
            Add-Type -AssemblyName System.Web.Extensions
            $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $ser.MaxJsonLength = [int]::MaxValue   # default 2 MB; the feed is ~30 MB.
            $list = $ser.DeserializeObject($r.Content)
            $out = @{}
            foreach ($entry in @($list)) {
                $cveTag = $null
                if ($entry['Tags']) {
                    $cveTag = (@($entry['Tags']) | Where-Object { $_ -match '^CVE-' } | Select-Object -First 1)
                }
                if (-not $cveTag) {
                    foreach ($s in @($entry['KnownVulnerableSamples'])) {
                        if ($s -and $s['CVEs']) {
                            $first = @($s['CVEs']) | Where-Object { $_ -match '^CVE-' } | Select-Object -First 1
                            if ($first) { $cveTag = $first; break }
                        }
                    }
                }
                foreach ($s in @($entry['KnownVulnerableSamples'])) {
                    if (-not $s -or -not $s['Filename']) { continue }
                    $fn = ([string]$s['Filename']).ToLower().Trim()
                    if ($fn -notmatch '\.sys$') { continue }   # kernel drivers only
                    $vendor = if ($s['Company'])              { [string]$s['Company'] }
                              elseif ($s['Product'])          { [string]$s['Product'] }
                              elseif ($s['OriginalFilename']) { [string]$s['OriginalFilename'] }
                              else { '' }
                    $desc = if ($s['Description'])         { [string]$s['Description'] }
                            elseif ($s['FileDescription']) { [string]$s['FileDescription'] }
                            elseif ($entry['Category'])    { [string]$entry['Category'] }
                            else { 'vulnerable driver (loldrivers.io)' }
                    if ($desc.Length -gt 140) { $desc = $desc.Substring(0,140) + '...' }
                    if (-not $out.ContainsKey($fn)) {
                        $out[$fn] = @{
                            Vendor = $vendor
                            CVE    = if ($cveTag) { [string]$cveTag } else { 'multiple' }
                            Note   = $desc
                            Source = 'loldrivers'
                        }
                    }
                }
            }
            return @{ Ok=$true; Drivers=$out; Count=$out.Count }
        } catch {
            return @{ Ok=$false; Error="$_"; Count=0 }
        }
    } -ArgumentList $script:VulnDriverFeedUrl
    if ($script:State) { $script:State.VulnDriverJob = $job }
}
