# =============================================================================
# src/35-evasion-checks.ps1 — WMI persistence + AMSI bypass detection
# =============================================================================
# Two defense-evasion checks:
#
#   Get-WmiPersistenceFindings — Get-CimInstance in root\subscription for
#       __EventConsumer / __EventFilter / __FilterToConsumerBinding. Any
#       subscription here is rare in normal Windows; common in malware
#       (used as a fileless persistence mechanism). Each non-Microsoft
#       subscription surfaces as a WARN finding.
#
#   Get-AmsiBypassFindings — checks the AmsiScanBuffer entry-point bytes
#       in the currently-loaded amsi.dll. If the first few bytes have been
#       patched to one of the well-known no-op / fail-return patterns,
#       flag as FAIL. This is a heuristic; the patcher technique is widely
#       documented and Defender already catches the common ones, but a
#       custom variant can still slip past.
# =============================================================================

function Get-WmiPersistenceFindings {
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $consumers = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop)
    } catch { return $out }
    try { $filters = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction Stop) } catch { $filters = @() }
    try { $bindings = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop) } catch { $bindings = @() }

    # Microsoft ships a small number of subscriptions OOB (SCM_Event_Log_Filter, BVT* on some SKUs).
    $msAllow = @('SCM Event Log Consumer','SCM Event Log Filter','BVTConsumer','BVTFilter')
    foreach ($c in $consumers) {
        $name = [string]$c.Name
        if ($msAllow -contains $name) { continue }
        # Try to enrich with the linked filter name + command-line via bindings.
        $linked = ($bindings | Where-Object { [string]$_.Consumer -like "*Name=`"$name`"*" } | Select-Object -First 1)
        $filterName = ''
        if ($linked) {
            $filterMatch = [string]$linked.Filter
            if ($filterMatch -match 'Name="([^"]+)"') { $filterName = $matches[1] }
        }
        $cmdLine = ''
        if ($c.PSObject.Properties['CommandLineTemplate'] -and $c.CommandLineTemplate) { $cmdLine = [string]$c.CommandLineTemplate }
        elseif ($c.PSObject.Properties['ScriptText']           -and $c.ScriptText)           { $cmdLine = [string]$c.ScriptText }
        if ($cmdLine.Length -gt 160) { $cmdLine = $cmdLine.Substring(0,160) + '...' }
        $out.Add((Add-Finding 'WARN' 'Persistence' ("WMI persistence subscription: consumer '{0}' (class {1}) bound to filter '{2}'" -f $name, [string]$c.CimClass.CimClassName, $filterName) `
            "Inspect with: Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -Filter `"Name = '$name'`"  -or-  remove with Remove-CimInstance after confirmation." `
            "WMI Event Subscriptions are a stealthy persistence channel - the consumer runs whenever its bound filter matches (e.g. 'every 5 min', 'on user logon'). Cmd: $cmdLine" `
            'persist-wmi'))
    }
    return $out
}

# AmsiScanBuffer is amsi.dll's main entrypoint. After Windows loads amsi.dll, the function's first
# bytes look like the prologue Microsoft compiled. Common patcher techniques rewrite the first 6-12
# bytes to immediately return E_INVALIDARG (0x80070057) so every scan is bypassed silently.
# We compare against a small set of well-known patcher signatures. Heuristic only.
function Get-AmsiBypassFindings {
    $out = New-Object System.Collections.Generic.List[object]
    $proc = Get-Process -Id $PID
    $amsiMod = $proc.Modules | Where-Object { $_.ModuleName -eq 'amsi.dll' } | Select-Object -First 1
    if (-not $amsiMod) { return $out }   # AMSI not loaded into this process; nothing to verify.

    $sigCode = @'
using System;
using System.Runtime.InteropServices;
public static class NjAmsi {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandleW(string lpModuleName);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    public static byte[] ReadBytes(IntPtr addr, int count) {
        byte[] buf = new byte[count];
        Marshal.Copy(addr, buf, 0, count);
        return buf;
    }
}
'@
    if (-not ('NjAmsi' -as [type])) {
        try { Add-Type -TypeDefinition $sigCode -ErrorAction Stop } catch { return $out }
    }
    try {
        $hMod = [NjAmsi]::GetModuleHandleW('amsi.dll')
        if ($hMod -eq [IntPtr]::Zero) { return $out }
        $addr = [NjAmsi]::GetProcAddress($hMod, 'AmsiScanBuffer')
        if ($addr -eq [IntPtr]::Zero) { return $out }
        $first = [NjAmsi]::ReadBytes($addr, 8)
        $hex = ($first | ForEach-Object { '{0:X2}' -f $_ }) -join ''

        # Known patcher patterns (as hex strings, first 6+ bytes):
        #   B857000780 C3            -> mov eax, 80070057h; ret  (classic Cobalt Strike / pentester one-liner)
        #   B857000780 C20800        -> mov eax, 80070057h; ret 8  (32-bit variant with stack cleanup)
        #   B800800007 C3            -> swap of bytes; some shellcode tutorials
        $patcherSigs = @('B857000780C3', 'B857000780C20800', 'B800800007C3', 'B857000780C2080')
        $matched = $patcherSigs | Where-Object { $hex.StartsWith($_) } | Select-Object -First 1
        if ($matched) {
            $out.Add((Add-Finding 'FAIL' 'Hardening' ("amsi.dll!AmsiScanBuffer appears patched (first bytes: 0x{0}). PowerShell scanning is bypassed." -f $hex) `
                'Restart the affected process / PowerShell session. If the patch persists across launches, scan the host with Defender + Sysmon image-load events for amsi.dll.' `
                "Pattern '$matched' matches a public AMSI-bypass technique that overwrites AmsiScanBuffer to immediately return E_INVALIDARG (0x80070057). Means every subsequent ScriptBlock evaluation in this process passes scanning regardless of content." `
                'defender-off'))
        }
    } catch {}
    return $out
}
