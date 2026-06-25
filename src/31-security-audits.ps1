# =============================================================================
# src/31-security-audits.ps1 — Security audit scan checks (Defender + LSA)
# =============================================================================
# Two scan-time security audits surfaced as findings during Invoke-Diagnostics:
#
#   * Get-DefenderExclusionFindings: reads Get-MpPreference for ExclusionPath /
#     ExclusionExtension / ExclusionProcess and flags any entry whose path is
#     under a user-writable directory (AppData / Temp / ProgramData / Public /
#     Users\<name>\Downloads). Classic malware persistence technique:
#     register an exclusion for a folder you can write to, drop your payload
#     there, and Defender will never look.
#
#   * Get-LsaAuthPackageFindings: reads
#     HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages
#     and ...\Notification Packages. Flags any entry not in the curated
#     Microsoft allowlist. Classic credential-theft persistence ("custom
#     password filter DLL") technique.
#
# Both fire under the existing "Hardening posture" / "Auth" categories so they
# integrate with the Defender / Auth filter chips users already have.
# =============================================================================

function Get-DefenderExclusionFindings {
    $out = New-Object System.Collections.Generic.List[object]
    try { $mp = Get-MpPreference -ErrorAction Stop } catch { return $out }
    $userPathRx = '\\AppData\\|\\Users\\Public\\|\\ProgramData\\|\\Windows\\Temp\\|\\Users\\[^\\]+\\Downloads\\|\\Users\\[^\\]+\\Desktop\\'
    $suspectPaths = @()
    foreach ($p in @($mp.ExclusionPath)) {
        if (-not $p) { continue }
        if ([string]$p -match $userPathRx) { $suspectPaths += [string]$p }
    }
    if ($suspectPaths.Count -gt 0) {
        $list = ($suspectPaths | Select-Object -First 3) -join '  ;  '
        $more = if ($suspectPaths.Count -gt 3) { " (+$($suspectPaths.Count - 3) more)" } else { '' }
        $out.Add((Add-Finding 'WARN' 'Defender' ("Defender ExclusionPath includes user-writable folder(s): {0}{1}" -f $list, $more) `
            "Review each exclusion in Settings -> Update & Security -> Windows Security -> Virus & threat protection -> Manage settings -> Exclusions. Remove any you didn't add intentionally." `
            "Malware sometimes uses Add-MpPreference -ExclusionPath to register a Defender exclusion for a user-writable folder, then drops payloads there knowing Defender won't scan them. Legitimate exclusions are usually for IDE / build / network-shared folders, not AppData / Temp / Downloads." `
            'defender-off'))
    }
    foreach ($p in @($mp.ExclusionProcess)) {
        if (-not $p) { continue }
        if ([string]$p -match $userPathRx -or [string]$p -match '\.exe$' -and [string]$p -notmatch '^[A-Z]:\\') {
            $out.Add((Add-Finding 'WARN' 'Defender' ("Defender ExclusionProcess includes suspicious binary: {0}" -f $p) `
                "Remove with: Remove-MpPreference -ExclusionProcess '$p'" `
                "ExclusionProcess tells Defender to skip scanning the named binary. Legitimate use is rare (gaming anti-cheats, some VPN clients). User-path binaries should not be on this list." `
                'defender-off'))
        }
    }
    # Extension-level exclusions are blunt instruments. .exe / .dll / .ps1 should never appear here.
    $dangerousExt = @('.exe','.dll','.ps1','.js','.vbs','.bat','.cmd','.scr','.msi')
    foreach ($ext in @($mp.ExclusionExtension)) {
        if (-not $ext) { continue }
        $normalized = if ([string]$ext -notlike '.*') { ('.' + $ext) } else { [string]$ext }
        if ($dangerousExt -contains $normalized.ToLower()) {
            $out.Add((Add-Finding 'FAIL' 'Defender' ("Defender ExclusionExtension whitelists executable type '{0}'" -f $ext) `
                "Remove with: Remove-MpPreference -ExclusionExtension '$ext'" `
                "Excluding executable file extensions from Defender scanning is almost certainly a misconfiguration; legitimate exclusions are data file types (e.g. database, video). A '$ext' exclusion lets any file with that extension run unscanned." `
                'defender-off'))
        }
    }
    return $out
}

function Get-LsaAuthPackageFindings {
    # Allowlist of known-Microsoft LSA Auth + Notification packages. Anything else gets WARN'd.
    $okAuth = @('msv1_0','kerberos','schannel','wdigest','tspkg','pku2u','cloudap','negoexts','livessp')
    $okNotif = @('scecli','rassfm') # rassfm = Microsoft's password expiry notification
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $auth   = (Get-ItemProperty -Path $lsaKey -Name 'Authentication Packages' -ErrorAction Stop).'Authentication Packages'
        $notif  = (Get-ItemProperty -Path $lsaKey -Name 'Notification Packages' -ErrorAction SilentlyContinue).'Notification Packages'
        foreach ($pkg in @($auth)) {
            $name = ([string]$pkg).ToLower()
            if (-not $name) { continue }
            if ($okAuth -notcontains $name) {
                $out.Add((Add-Finding 'WARN' 'Auth' ("Unknown LSA Authentication Package: '{0}'" -f $pkg) `
                    "Inspect %SystemRoot%\System32\$pkg.dll - verify signer + recent file timestamps. Remove only after confirming with vendor." `
                    "Custom auth packages can be used by red-team / malware as a credential-harvesting persistence ('password filter DLL'). Microsoft's standard packages are: $($okAuth -join ', ')." `
                    'unsigned-extern'))
            }
        }
        foreach ($pkg in @($notif)) {
            $name = ([string]$pkg).ToLower()
            if (-not $name) { continue }
            if ($okNotif -notcontains $name) {
                $out.Add((Add-Finding 'WARN' 'Auth' ("Unknown LSA Notification Package: '{0}'" -f $pkg) `
                    "Inspect %SystemRoot%\System32\$pkg.dll - notification packages see every password change. Verify before keeping." `
                    "Notification packages intercept password-change events. Mimikatz's 'rpc::password' module and similar persistence relies on this hook. Microsoft's standard ones: $($okNotif -join ', ')." `
                    'unsigned-extern'))
            }
        }
    } catch {
        # Can't read LSA key (most likely not admin). Don't surface as a failure.
    }
    return $out
}
