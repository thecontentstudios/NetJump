# =============================================================================
# src/33-posture-and-forensics.ps1 — BitLocker / Windows Update / suspicious-port
#                                    scan checks + base64 PowerShell decoder
# =============================================================================
# Four scan helpers wired into Invoke-Diagnostics:
#
#   Get-BitLockerFindings        — Get-BitLockerVolume on every drive; flag
#                                  decrypted system drive as WARN; report
#                                  encryption method + key protectors.
#   Get-WindowsUpdateFindings    — Win32_QuickFixEngineering; flag if no
#                                  updates in last 30 days as WARN.
#   Get-SuspiciousPortFindings   — Get-NetTCPConnection -State Listen against
#                                  a small list of well-known C2 ports.
#   Decode-EncodedPowerShellCommand — given a CommandLine string, returns the
#                                  decoded plaintext when -EncodedCommand /
#                                  -enc is present; $null otherwise.
# =============================================================================

function Get-BitLockerFindings {
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $vols = @(Get-BitLockerVolume -ErrorAction Stop)
    } catch {
        # Get-BitLockerVolume requires admin + the BitLocker feature; silent skip on home SKUs.
        return $out
    }
    $sysDrive = (Get-Item $env:SystemRoot).PSDrive.Name + ':'
    foreach ($v in $vols) {
        $isSys = ([string]$v.MountPoint).TrimEnd('\') -ieq $sysDrive
        $proto = ($v.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType }) -join ', '
        if ($v.VolumeStatus -ne 'FullyEncrypted') {
            $lvl = if ($isSys) { 'WARN' } else { 'INFO' }
            $out.Add((Add-Finding $lvl 'Hardening' ("BitLocker: {0} is {1} (encryption method: {2})" -f $v.MountPoint, $v.VolumeStatus, $v.EncryptionMethod) `
                "Enable-BitLocker -MountPoint '$($v.MountPoint)' -EncryptionMethod XtsAes256 -UsedSpaceOnly  (then back up the recovery key)" `
                "Volume-level encryption protects data-at-rest if the device is lost or stolen. System drive especially - VBS + Secure Boot work in concert with BitLocker measured boot."))
        } else {
            $out.Add((Add-Finding 'OK' 'Hardening' ("BitLocker: {0} encrypted ({1}); protectors: {2}" -f $v.MountPoint, $v.EncryptionMethod, $proto)))
        }
    }
    return $out
}

function Get-WindowsUpdateFindings {
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $hot = @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop |
                 Where-Object { $_.InstalledOn } |
                 Sort-Object InstalledOn -Descending)
    } catch {
        return $out
    }
    if ($hot.Count -eq 0) {
        $out.Add((Add-Finding 'WARN' 'Updates' 'No Windows updates recorded in Win32_QuickFixEngineering.' `
            'Run Windows Update from Settings, or: UsoClient StartScan' `
            "Win32_QuickFixEngineering lists installed KBs / fixes. Empty result is unusual on a real install; could indicate logging tamper or a brand-new image."))
        return $out
    }
    $latest = $hot[0].InstalledOn
    $age = (Get-Date) - $latest
    if ($age.TotalDays -gt 60) {
        $out.Add((Add-Finding 'FAIL' 'Updates' ("Last Windows update was {0} days ago (KB: {1})." -f [int]$age.TotalDays, $hot[0].HotFixID) `
            'Run Windows Update immediately. Devices unpatched >60 days are exposed to known exploited CVEs.' `
            "Microsoft publishes monthly Patch Tuesday updates. 60+ days unpatched means at least 2 rolls of critical fixes are missing."))
    } elseif ($age.TotalDays -gt 30) {
        $out.Add((Add-Finding 'WARN' 'Updates' ("Last Windows update was {0} days ago (KB: {1})." -f [int]$age.TotalDays, $hot[0].HotFixID) `
            'Open Windows Update from Settings; install pending fixes.' `
            "Patches are normally available within 30 days of last reboot. Outside that window, check for stalled updates."))
    } else {
        $out.Add((Add-Finding 'OK' 'Updates' ("Windows up to date - last KB {0} on {1:yyyy-MM-dd}." -f $hot[0].HotFixID, $latest)))
    }
    return $out
}

# Curated list of ports that show up routinely in malware C2 setups. Not exhaustive (many use
# 443 to blend in), but unusual listeners on these are worth a second look.
$script:SuspiciousListenPorts = @(1080, 1337, 3333, 4444, 5555, 6666, 6667, 7777, 8888, 9001, 9050, 12345, 31337)
function Get-SuspiciousPortFindings {
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -notmatch '^(127\.|::1)$' -and $script:SuspiciousListenPorts -contains [int]$_.LocalPort })
    } catch { return $out }
    foreach ($l in $listeners) {
        $proc = try { Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue } catch { $null }
        $procName = if ($proc) { $proc.ProcessName } else { '?' }
        $procPath = if ($proc) { $proc.Path } else { '' }
        $out.Add((Add-Finding 'WARN' 'Listeners' ("Suspicious listener: {0} (pid {1}) on port {2} bound to {3}" -f $procName, $l.OwningProcess, $l.LocalPort, $l.LocalAddress) `
            "Kill the process if unexpected: Stop-Process -Id $($l.OwningProcess)  (verify path: $procPath)" `
            "Port $($l.LocalPort) is on NetJump's curated suspicious-listener watchlist - widely used by RAT / backdoor / proxy malware (Metasploit default $($l.LocalPort), miner / bouncer ports, etc.). Legitimate apps almost never bind to these." `
            'c2-suspicious'))
    }
    return $out
}

function Decode-EncodedPowerShellCommand {
    param([Parameter(Mandatory)] [string]$CommandLine)
    if (-not $CommandLine) { return $null }
    # Match -EncodedCommand or -enc / -ec / -e (case-insensitive) followed by a base64 blob.
    # The blob runs until the next whitespace; PowerShell accepts it up to end-of-line.
    if ($CommandLine -notmatch '(?i)\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+(\S+)') {
        return $null
    }
    $b64 = $matches[1]
    try {
        $bytes = [Convert]::FromBase64String($b64)
        # PowerShell -EncodedCommand expects UTF-16LE.
        $text = [System.Text.Encoding]::Unicode.GetString($bytes)
        # Strip null bytes (sometimes present from PS string conversion artifacts) and trim.
        $text = $text.TrimEnd("`0").Trim()
        if (-not $text) { return $null }
        return $text
    } catch { return $null }
}
