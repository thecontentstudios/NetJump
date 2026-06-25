# =============================================================================
# src/45-pktmon-presets.ps1 — pktmon filter presets in Diagnose menu
# =============================================================================
# Wraps Microsoft's built-in pktmon CLI behind named capture presets so users
# don't have to remember the filter / start / stop incantations. Three presets
# ship today: DNS only (53/853/5353), TLS handshakes only (443/853), and ICMP.
#
# Each preset:
#   1. Stops any pktmon session NetJump might have started earlier.
#   2. Clears existing filters.
#   3. Adds the preset's filter rules.
#   4. Starts a real-time capture written to Reports\Pktmon-Captures\NN-name-{stamp}.etl
#   5. Sets a timer that stops the capture after $DurationSec seconds.
#
# The user can also stop early via Diagnose -> "Stop preset capture now". All
# captures stay in Reports\Pktmon-Captures\ for offline analysis (open in
# `pktmon format` or convert to .pcapng with `pktmon etl2pcap`).
# =============================================================================

$script:PktmonPresetDir = Join-Path $PSScriptRoot 'Reports\Pktmon-Captures'
if (-not (Test-Path $script:PktmonPresetDir)) { New-Item -ItemType Directory -Path $script:PktmonPresetDir -Force | Out-Null }
$script:_PktmonPresetActive = $null   # @{ Path; StopAt; PresetName } when a capture is running

function _Pktmon-Stop-Quiet {
    if (-not $script:HasPktmon -or -not $script:IsAdmin) { return }
    try { & pktmon stop 2>&1 | Out-Null } catch {}
}

function _Pktmon-FilterReset {
    if (-not $script:HasPktmon -or -not $script:IsAdmin) { return }
    try { & pktmon filter remove 2>&1 | Out-Null } catch {}
}

function Start-PktmonPreset {
    param(
        [Parameter(Mandatory)] [ValidateSet('DNS','TLS','ICMP')] [string]$Preset,
        [int]$DurationSec = 120
    )
    if (-not $script:HasPktmon) {
        [System.Windows.MessageBox]::Show($window, 'pktmon.exe not found. Pktmon ships with Windows 10 1903+ but may be missing on stripped server SKUs.', 'Not available', 'OK', 'Warning') | Out-Null
        return
    }
    if (-not $script:IsAdmin) {
        [System.Windows.MessageBox]::Show($window, 'pktmon requires Administrator. Re-launch via Run-NetJump.bat.', 'Not elevated', 'OK', 'Warning') | Out-Null
        return
    }
    # Pause the rolling NetJump capture so we don't fight it.
    try { Stop-PktmonCapture } catch {}
    _Pktmon-Stop-Quiet
    _Pktmon-FilterReset

    # Preset definitions: each is a list of `pktmon filter add` arg arrays.
    $filters = switch ($Preset) {
        'DNS'  { @(
            @('-p', '53'),
            @('-p', '853'),
            @('-p', '5353')
        ) }
        'TLS'  { @(
            @('-p', '443'),
            @('-p', '853')
        ) }
        'ICMP' { @(
            @('--ip-protocol', '1'),
            @('--ip-protocol', '58')  # ICMPv6
        ) }
    }
    foreach ($f in $filters) {
        try { & pktmon filter add @f 2>&1 | Out-Null } catch {}
    }
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $outPath = Join-Path $script:PktmonPresetDir ("preset-$Preset-$stamp.etl")
    try {
        & pktmon start --capture --pkt-size 0 --file-name $outPath 2>&1 | Out-Null
    } catch {
        Add-Event warn ("pktmon start failed: $($_.Exception.Message)")
        return
    }
    $script:_PktmonPresetActive = @{ Path=$outPath; StopAt=(Get-Date).AddSeconds($DurationSec); PresetName=$Preset }
    Add-Event scan ("pktmon preset '$Preset' capturing to $(Split-Path $outPath -Leaf) for ${DurationSec}s...")
    # Schedule the auto-stop via a one-shot DispatcherTimer.
    $t = New-Object System.Windows.Threading.DispatcherTimer
    $t.Interval = [TimeSpan]::FromSeconds($DurationSec)
    $t.Add_Tick({
        param($s, $e)
        try { $s.Stop() } catch {}
        Stop-PktmonPreset
    }.GetNewClosure())
    $t.Start()
}

function Stop-PktmonPreset {
    if (-not $script:_PktmonPresetActive) { return }
    $info = $script:_PktmonPresetActive
    $script:_PktmonPresetActive = $null
    _Pktmon-Stop-Quiet
    _Pktmon-FilterReset
    if (Test-Path $info.Path) {
        $sizeKb = [int]((Get-Item $info.Path).Length / 1024)
        Add-Event recovery ("pktmon preset '$($info.PresetName)' stopped. Capture: $(Split-Path $info.Path -Leaf) ($sizeKb KB)")
    } else {
        Add-Event warn 'pktmon preset stopped but no capture file was written.'
    }
    # Resume the rolling NetJump capture so flap dossiers keep working.
    try { if ($script:HasPktmon -and $script:IsAdmin) { Start-PktmonCapture | Out-Null } } catch {}
}
