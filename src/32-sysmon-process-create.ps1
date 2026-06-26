# =============================================================================
# src/32-sysmon-process-create.ps1 — Sysmon Event 1 (ProcessCreate) detector
# =============================================================================
# Reads Microsoft-Windows-Sysmon/Operational for Event ID 1 over the last N
# minutes and flags two classic attack-chain patterns:
#
#   * Office macro spawn: WINWORD / EXCEL / POWERPNT / OUTLOOK / VISIO spawning
#     a script-host or download tool (cmd, powershell, wscript, cscript,
#     mshta, curl, certutil, bitsadmin). Maldoc tradecraft.
#
#   * LOLBin chain: a script host (cmd, powershell, wscript, cscript, mshta)
#     spawning a download or living-off-the-land binary (curl, certutil,
#     bitsadmin, regsvr32, rundll32, mshta). Initial-access -> stage 2 chain.
#
# Both are widely-used IOCs; SwiftOnSecurity/sysmon-config and
# olafhartong/sysmon-modular both enable Event 1 by default. The detector is
# silently no-op when Sysmon isn't running.
# =============================================================================

function Get-SysmonProcessCreateFindings {
    param([int]$Minutes = 30, [int]$Max = 3000)
    $out = New-Object System.Collections.Generic.List[object]
    $sm = Get-SysmonStatus
    if (-not $sm -or $sm.Status -ne 'Running') { return $out }
    try {
        $since = (Get-Date).AddMinutes(-$Minutes)
        $events = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$since} -MaxEvents $Max -ErrorAction SilentlyContinue)
        if ($events.Count -eq 0) { return $out }

        $officeLeaves = @('winword.exe','excel.exe','powerpnt.exe','outlook.exe','visio.exe','msaccess.exe','wordpad.exe')
        $scriptLeaves = @('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe')
        $lolbinLeaves = @('curl.exe','certutil.exe','bitsadmin.exe','regsvr32.exe','rundll32.exe','mshta.exe','installutil.exe','regasm.exe','regsvcs.exe','msbuild.exe')

        $seen = @{}
        foreach ($e in $events) {
            $msg = [string]$e.Message
            $img    = ''
            $parImg = ''
            $cmd    = ''
            $userTxt = ''
            if ($msg -match '(?m)^Image:\s*(.+)$')        { $img    = $matches[1].Trim() }
            if ($msg -match '(?m)ParentImage:\s*(.+)$')   { $parImg = $matches[1].Trim() }
            if ($msg -match '(?m)CommandLine:\s*(.+)$')   { $cmd    = $matches[1].Trim() }
            if ($msg -match '(?m)^User:\s*(.+)$')         { $userTxt = $matches[1].Trim() }
            if (-not $img -or -not $parImg) { continue }

            $imgLeaf = (Split-Path $img -Leaf).ToLower()
            $parLeaf = (Split-Path $parImg -Leaf).ToLower()

            # Office macro spawn pattern
            $isOffice  = $officeLeaves -contains $parLeaf
            $isScript  = $scriptLeaves -contains $imgLeaf
            $isLolbin  = $lolbinLeaves -contains $imgLeaf

            $matched = $null
            $mitre = ''
            if ($isOffice -and ($isScript -or $isLolbin)) {
                $matched = ('Office maldoc spawn: {0} -> {1}' -f $parLeaf, $imgLeaf)
                $mitre = 'unsigned-extern'
            } elseif (($scriptLeaves -contains $parLeaf) -and $isLolbin -and ($parLeaf -ne $imgLeaf)) {
                $matched = ('LOLBin chain: {0} -> {1}' -f $parLeaf, $imgLeaf)
                $mitre = 'unsigned-extern'
            }
            if (-not $matched) { continue }

            $key = "$parLeaf|$imgLeaf|$($cmd.Substring(0, [Math]::Min(60, $cmd.Length)))"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true

            $shortCmd = $cmd
            if ($shortCmd.Length -gt 120) { $shortCmd = $shortCmd.Substring(0,120) + '...' }
            # v1.5: if the command-line has -EncodedCommand / -enc, decode and inline. Common
            # malware tradecraft: base64-encode the actual payload to evade scanning.
            $decoded = $null
            try { $decoded = Decode-EncodedPowerShellCommand -CommandLine $cmd } catch {}
            $detail = "Sysmon Event 1 caught a parent->child chain matching a well-known attack pattern. User: $userTxt. Inspect the full command-line + binary signing on the PROCESSES tab."
            if ($decoded) {
                $shortDecoded = if ($decoded.Length -gt 400) { $decoded.Substring(0,400) + '...' } else { $decoded }
                $detail += "`n`nDecoded -EncodedCommand:`n$shortDecoded"
            }
            [void]$out.Add((Add-Finding 'WARN' 'Sysmon' ("{0}  ({1})" -f $matched, $shortCmd) `
                "Kill the child process if you didn't trigger it. Review parent doc for macros: open in Protected View, disable macros, scan with Defender." `
                $detail `
                $mitre))
        }
    } catch {
        try { Add-Event warn ("Sysmon ProcessCreate scan failed: $($_.Exception.Message)") } catch {}
    }
    return $out
}
