# =============================================================================
# src/30-kernel-driver-and-boot.ps1 — Kernel driver enum + boot posture
# =============================================================================
# Two scan checks integrated into Invoke-Diagnostics:
#
#   Get-LoadedKernelDriverFindings:
#     Lists every running kernel driver (Win32_SystemDriver State='Running'),
#     runs each through Get-AuthenticodeSignature, classifies as MS-signed /
#     3rd-party-signed / unsigned, and emits an INFO summary plus a WARN for
#     each unsigned non-Microsoft driver. Read-only; complements the existing
#     BYOVD scanner which only knows the curated + loldrivers.io list.
#
#   Get-BootPostureFindings:
#     Surfaces Secure Boot, TPM presence + readiness, Virtualization-Based
#     Security state, and Hypervisor-protected Code Integrity enforcement.
#     Each posture item is OK or WARN with a one-line fix where applicable.
# =============================================================================

function Get-LoadedKernelDriverFindings {
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $drivers = @(Get-CimInstance Win32_SystemDriver -Filter "State='Running'" -ErrorAction Stop)
    } catch {
        return $out
    }
    $msSigners = @('Microsoft Windows','Microsoft Corporation','Microsoft Windows Hardware Compatibility','Microsoft Windows Publisher','Microsoft Windows Third Party Component Publisher')
    $unsigned = New-Object System.Collections.Generic.List[string]
    $thirdParty = New-Object System.Collections.Generic.List[psobject]
    $sigCache = @{}
    foreach ($d in $drivers) {
        if (-not $d.PathName) { continue }
        $path = $d.PathName -replace '^\\\?\?\\',''
        $name = Split-Path $path -Leaf
        if (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) { continue }
        $sig = $null
        if ($sigCache.ContainsKey($path)) { $sig = $sigCache[$path] }
        else {
            try { $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue } catch {}
            $sigCache[$path] = $sig
        }
        $status = if ($sig) { [string]$sig.Status } else { 'unknown' }
        $signer = ''
        if ($sig -and $sig.SignerCertificate) {
            $cn = ($sig.SignerCertificate.Subject -split ',' | Where-Object { $_ -match '^\s*CN=' } | Select-Object -First 1) -replace '^\s*CN=',''
            $signer = $cn.Trim().Trim('"')
        }
        if ($status -eq 'NotSigned') {
            [void]$unsigned.Add("$name ($path)")
        } elseif ($status -eq 'Valid' -and ($signer -and ($msSigners | Where-Object { $signer -like "$_*" }).Count -eq 0)) {
            # 3rd-party signed: name + signer for transparency.
            [void]$thirdParty.Add([pscustomobject]@{ Name=$name; Signer=$signer; Path=$path })
        }
    }
    if ($unsigned.Count -gt 0) {
        $sample = ($unsigned | Select-Object -First 3) -join '  ;  '
        $more = if ($unsigned.Count -gt 3) { " (+$($unsigned.Count - 3) more)" } else { '' }
        $out.Add((Add-Finding 'WARN' 'Driver' ("Unsigned running kernel driver(s): {0}{1}" -f $sample, $more) `
            'Inspect each driver in PROCESSES tab signing column. Unsigned kernel drivers in modern Windows are rare; usually only legacy hardware utilities or shim/test drivers.' `
            "Authenticode-Valid drivers are signed by a CA-trusted publisher. Unsigned drivers shouldn't normally load on a 64-bit Windows install with kernel-mode code-signing enforcement. Pair with VBS/HVCI to block them outright." `
            'driver-bsod'))
    }
    if ($thirdParty.Count -gt 0) {
        $list = ($thirdParty | Select-Object -First 5 | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Signer }) -join '  ;  '
        $more = if ($thirdParty.Count -gt 5) { " (+$($thirdParty.Count - 5) more)" } else { '' }
        $out.Add((Add-Finding 'INFO' 'Driver' ("Third-party signed kernel drivers loaded ({0} total): {1}{2}" -f $thirdParty.Count, $list, $more) '' `
            "Listed for transparency. Hardware vendor utilities (Intel, AMD, NVIDIA, Realtek, etc.) and AV products are normal; unfamiliar entries deserve a second look against the BYOVD scanner."))
    } else {
        $out.Add((Add-Finding 'OK' 'Driver' ("All {0} running kernel drivers are Microsoft-signed (no 3rd-party kernel modules loaded)." -f $drivers.Count)))
    }
    return $out
}

function Get-BootPostureFindings {
    $out = New-Object System.Collections.Generic.List[object]

    # Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) {
            $out.Add((Add-Finding 'OK' 'Hardening' 'Secure Boot is enabled.'))
        } else {
            $out.Add((Add-Finding 'WARN' 'Hardening' 'Secure Boot is disabled.' `
                'Enable in UEFI firmware setup. Required for VBS / HVCI to provide meaningful protection.' `
                "Secure Boot validates the bootloader chain against a hardware-rooted key store. Disabling it lets a malicious bootloader survive a reinstall."))
        }
    } catch [System.PlatformNotSupportedException] {
        $out.Add((Add-Finding 'WARN' 'Hardening' 'Legacy BIOS boot detected (no Secure Boot).' `
            'Re-install Windows in UEFI mode. Legacy BIOS does not support Secure Boot / TPM 2.0 attestation / VBS.' `
            "Modern Windows security (BitLocker measured boot, VBS, HVCI) all assume UEFI + Secure Boot."))
    } catch {
        # Other errors mean we couldn't query (probably not admin); skip silently.
    }

    # TPM
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if (-not $tpm.TpmPresent) {
            $out.Add((Add-Finding 'WARN' 'Hardening' 'No TPM present.' '' `
                "TPM 2.0 is required by Windows 11 and enables BitLocker measured boot, virtualization-based security, and Windows Hello for Business attestation."))
        } elseif (-not $tpm.TpmReady) {
            $out.Add((Add-Finding 'WARN' 'Hardening' 'TPM present but not ready.' `
                'Run tpm.msc and follow the Initialize TPM wizard.' `
                "An uninitialized TPM cannot be used by BitLocker or VBS attestation."))
        } else {
            $out.Add((Add-Finding 'OK' 'Hardening' "TPM 2.0 present and ready (manufacturer: $($tpm.ManufacturerIdTxt))."))
        }
    } catch {}

    # VBS + HVCI
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
        $vbsRunning = ($dg.VirtualizationBasedSecurityStatus -eq 2)
        if ($vbsRunning) {
            $out.Add((Add-Finding 'OK' 'Hardening' 'Virtualization-Based Security (VBS) is running.'))
            # HVCI is reported in SecurityServicesRunning (array of integers; 2 = HVCI).
            $hvciOn = @($dg.SecurityServicesRunning) -contains 2
            if ($hvciOn) {
                $out.Add((Add-Finding 'OK' 'Hardening' 'HVCI (Memory integrity) is enforcing.'))
            } else {
                $out.Add((Add-Finding 'WARN' 'Hardening' 'VBS running but HVCI (Memory integrity) is OFF.' `
                    'Settings -> Privacy & security -> Windows Security -> Device security -> Core isolation -> Memory integrity ON.' `
                    "HVCI prevents kernel-mode code-injection attacks by enforcing W^X on kernel pages. The complement to VBS at the page-protection level."))
            }
        } else {
            $out.Add((Add-Finding 'WARN' 'Hardening' "VBS is not running (status code $($dg.VirtualizationBasedSecurityStatus))." `
                'Enable Hyper-V + Memory integrity in Settings -> Privacy & security -> Windows Security -> Device security -> Core isolation.' `
                "VBS uses Hyper-V to isolate kernel-mode security primitives. Without it, HVCI / Credential Guard / etc. cannot enforce their guarantees."))
        }
    } catch {}

    return $out
}
