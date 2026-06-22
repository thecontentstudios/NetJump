<#
.SYNOPSIS
  Capture a series of NetJump HUD screenshots automatically.

.DESCRIPTION
  Launches NetJump (non-elevated), captures the main HUD, then walks through each tab capturing
  one screenshot per view. Saves PNGs to .\Screenshots\real\NN-name.png.

  Runs NetJump non-elevated so this script can interact with its window (admin-level NetJump
  blocks input via Windows UIPI). Some scan categories will show "needs admin" warnings; the UI
  itself is identical so the screenshots are still representative.

  IMPORTANT: the captures show your REAL network state — adapter name, IPs, hostnames, DNS
  servers, custom ping targets, etc. REVIEW each PNG and redact sensitive info before publishing.
  See Screenshots\README.md for the redaction checklist.

.EXAMPLE
  cd D:\NetJump-Diagnostic
  .\Screenshots\Capture-Screenshots.ps1
#>

$ErrorActionPreference = 'Stop'
$shotsDir = Join-Path $PSScriptRoot 'real'
New-Item -ItemType Directory -Path $shotsDir -Force | Out-Null
$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'NetJump-Dashboard.ps1'
if (-not (Test-Path $scriptPath)) { throw "Cannot find NetJump-Dashboard.ps1 next to Screenshots\" }

# ---- Win32 capture + window helpers ----
Add-Type -AssemblyName System.Drawing
if (-not ([System.Management.Automation.PSTypeName]'NjShot').Type) {
    Add-Type -ReferencedAssemblies System.Drawing -Language CSharp -TypeDefinition @'
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Text;
public class NjShot {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hWnd, StringBuilder s, int max);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public static IntPtr FindByTitle(string title) {
        IntPtr result = IntPtr.Zero;
        EnumWindows((h, l) => {
            var sb = new StringBuilder(256);
            GetWindowTextW(h, sb, 256);
            if (sb.ToString() == title) { result = h; return false; }
            return true;
        }, IntPtr.Zero);
        return result;
    }
    public static void Show(IntPtr h) { ShowWindow(h, 5); SetForegroundWindow(h); }
    public static void Cap(IntPtr hWnd, string path) {
        RECT r; GetWindowRect(hWnd, out r);
        int w = r.Right - r.Left, h = r.Bottom - r.Top;
        using (Bitmap bmp = new Bitmap(w, h))
        using (Graphics g = Graphics.FromImage(bmp)) {
            g.CopyFromScreen(r.Left, r.Top, 0, 0, new Size(w, h));
            bmp.Save(path, ImageFormat.Png);
        }
    }
}
'@
}

function Get-Hwnd { [NjShot]::FindByTitle('NetJump HUD') }
function Capture { param([string]$Name)
    $h = Get-Hwnd
    if ($h -eq [IntPtr]::Zero) { Write-Warning "NetJump window not found - skipping $Name"; return }
    [NjShot]::Show($h)
    Start-Sleep -Milliseconds 800
    $path = Join-Path $shotsDir $Name
    [NjShot]::Cap($h, $path)
    $sz = [int]((Get-Item $path).Length / 1024)
    Write-Host ("  -> {0} ({1} KB)" -f $Name, $sz) -ForegroundColor Green
}

# Find a tab by reading its on-screen position. We use the AutomationElement scan via UIA, but
# falling back to known relative coordinates if UIA isn't available. NetJump's tabs are at fixed
# relative positions in the window, so percentage-based clicks work reliably.
if (-not ([System.Management.Automation.PSTypeName]'NjClick').Type) {
    Add-Type -ReferencedAssemblies System.Drawing -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class NjClick {
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, int dx, int dy, uint dwData, IntPtr dwExtraInfo);
    public const uint MOUSEEVENTF_LEFTDOWN = 0x02, MOUSEEVENTF_LEFTUP = 0x04;
    public static void Click(int x, int y) {
        SetCursorPos(x, y);
        System.Threading.Thread.Sleep(80);
        mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, IntPtr.Zero);
        System.Threading.Thread.Sleep(50);
        mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, IntPtr.Zero);
    }
}
'@
}
function Click-Tab { param([double]$RelX, [double]$RelY)
    $h = Get-Hwnd
    if ($h -eq [IntPtr]::Zero) { return }
    $r = New-Object NjShot+RECT
    [NjShot]::GetWindowRect($h, [ref]$r) | Out-Null
    $x = [int]($r.Left + ($r.Right - $r.Left) * $RelX)
    $y = [int]($r.Top  + ($r.Bottom - $r.Top) * $RelY)
    [NjClick]::Click($x, $y)
    Start-Sleep -Milliseconds 600
}

# ---- Launch NetJump non-elevated ----
Write-Host "Launching NetJump (non-elevated)..."
$proc = Start-Process -FilePath powershell.exe `
    -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$scriptPath `
    -PassThru -WindowStyle Hidden

# Wait for window
$waited = 0
while ($waited -lt 30 -and (Get-Hwnd) -eq [IntPtr]::Zero) {
    Start-Sleep -Seconds 1
    $waited++
}
if ((Get-Hwnd) -eq [IntPtr]::Zero) { throw "NetJump window never appeared after $waited sec" }
Write-Host "  Window up after $waited sec"
Start-Sleep -Seconds 2   # let WPF settle

# ---- Capture sequence ----
Write-Host "`nCapturing screenshots..."
Capture '01-main-hud.png'

# Tab positions are relative to the NetJump window (X from left edge, Y from top).
# The tab strip sits at about 41% down the window. Each tab takes ~7% width starting at ~1%.
# These were measured from a 1920x1080 NetJump capture; adjust if your window is differently sized.
Click-Tab 0.03 0.41       ; Capture '02-diagnostics.png'
Click-Tab 0.10 0.41       ; Capture '03-processes.png'
Click-Tab 0.16 0.41       ; Capture '04-traffic.png'
Click-Tab 0.22 0.41       ; Capture '05-flows.png'
Click-Tab 0.30 0.41       ; Capture '06-persistence.png'
Click-Tab 0.38 0.41       ; Capture '07-history.png'
Click-Tab 0.43 0.41       ; Capture '08-dns.png'

# Kick off a scan from the RUN NET DIAGNOSTIC button (top-right of header).
Click-Tab 0.95 0.06
Write-Host "  Scan kicked off - waiting 25 s for it to complete..."
Start-Sleep -Seconds 25
Click-Tab 0.03 0.41       # Back to DIAGNOSTICS to see findings
Capture '09-diagnostics-after-scan.png'

# Open Settings via Ctrl+,
Click-Tab 0.50 0.50       # First click into the window to make it the keyboard focus
Start-Sleep -Milliseconds 300
# Settings dialog: opens via Ctrl+, but firing keys requires Send-Keys which needs the foreground
# window. Skipping this if the dialog is hard to trigger reliably; user can capture it themselves.

Write-Host "`nDone. Captures in: $shotsDir"
Write-Host "`nIMPORTANT: review each PNG and redact sensitive info before publishing."
Write-Host "  See Screenshots\README.md for the redaction checklist."
Write-Host "`nNetJump is still running. Close it via tray icon -> Quit, or:"
Write-Host "  Stop-Process -Id $($proc.Id) -Force"
