# Window capture helper. Dot-source: . .\Screenshots\_capture-helper.ps1
# Usage:
#   Capture-NetJump 'foo.png'
#   Resize-NetJump 1920 1080
#   Bring-NetJumpForward

Add-Type -AssemblyName System.Drawing
if (-not ([System.Management.Automation.PSTypeName]'NjCap').Type) {
    Add-Type -ReferencedAssemblies System.Drawing -Language CSharp -TypeDefinition @'
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
public class NjCap {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
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

function Get-NetJumpHwnd {
    $p = Get-Process | Where-Object { $_.MainWindowTitle -eq 'NetJump HUD' } | Select-Object -First 1
    if (-not $p) { throw "NetJump not running" }
    return $p.MainWindowHandle
}

function Bring-NetJumpForward {
    $h = Get-NetJumpHwnd
    [NjCap]::ShowWindow($h, 9) | Out-Null   # SW_RESTORE
    Start-Sleep -Milliseconds 200
    [NjCap]::SetForegroundWindow($h) | Out-Null
    Start-Sleep -Milliseconds 200
}

function Resize-NetJump { param([int]$W = 1920, [int]$H = 1080, [int]$X = 0, [int]$Y = 0)
    $h = Get-NetJumpHwnd
    [NjCap]::ShowWindow($h, 1) | Out-Null
    Start-Sleep -Milliseconds 200
    [NjCap]::MoveWindow($h, $X, $Y, $W, $H, $true) | Out-Null
    Start-Sleep -Milliseconds 200
    [NjCap]::SetForegroundWindow($h) | Out-Null
    Start-Sleep -Milliseconds 200
}

function Capture-NetJump { param([Parameter(Mandatory)] [string]$Path)
    Bring-NetJumpForward
    Start-Sleep -Milliseconds 300
    [NjCap]::Cap((Get-NetJumpHwnd), $Path)
    $i = Get-Item $Path
    Write-Host ("Saved: {0} ({1} KB)" -f $i.Name, [int]($i.Length/1024))
}
