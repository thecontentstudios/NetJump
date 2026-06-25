# =============================================================================
# src/82-history-wifi-roaming.ps1 — HISTORY tab Wi-Fi roaming timeline
# =============================================================================
# Renders $script:WifiBssidHistory (populated by Get-WifiInfoCached in the main
# file) as a horizontal timeline of colored dots on the WifiRoamingCanvas
# control. Each dot = one BSSID change. x = time, color = signal %.
# Card stays Collapsed when there's no roaming history (= wired adapter).
# =============================================================================

function Redraw-WifiRoamingTimeline {
    if (-not $controls -or -not $controls.WifiRoamingCanvas) { return }
    $canvas = $controls.WifiRoamingCanvas
    $canvas.Children.Clear()
    if (-not $script:WifiBssidHistory -or $script:WifiBssidHistory.Count -eq 0) {
        if ($controls.WifiRoamingCard) { $controls.WifiRoamingCard.Visibility = 'Collapsed' }
        return
    }
    if ($controls.WifiRoamingCard) { $controls.WifiRoamingCard.Visibility = 'Visible' }

    # Use the canvas's actual width when laid out; fall back to 800 if not yet measured.
    $w = if ($canvas.ActualWidth -gt 0) { $canvas.ActualWidth } else { 800.0 }
    $h = 60.0
    $marginX = 8.0
    $usable = $w - ($marginX * 2)

    # Window the timeline to the last 24h (or all data if newer).
    $now    = Get-Date
    $window = [TimeSpan]::FromHours(24)
    $entries = @($script:WifiBssidHistory | Where-Object { ($now - $_.Time) -le $window })
    if ($entries.Count -eq 0) { $entries = @($script:WifiBssidHistory) }
    $tMin = ($entries | Sort-Object Time | Select-Object -First 1).Time
    $tMax = ($entries | Sort-Object Time -Descending | Select-Object -First 1).Time
    $span = ($tMax - $tMin).TotalSeconds
    if ($span -lt 60) { $span = 60.0 }   # avoid divide-by-zero on a brand-new history

    # Background baseline strip.
    $baseline = New-Object System.Windows.Shapes.Line -Property @{
        X1 = $marginX; Y1 = $h / 2; X2 = $marginX + $usable; Y2 = $h / 2
        Stroke = [System.Windows.Media.Brushes]::DimGray
        StrokeThickness = 1; Opacity = 0.3
    }
    [void]$canvas.Children.Add($baseline)

    # Per-entry dot.
    $uniqBssids = @{}
    foreach ($e in $entries) {
        $tSec = ($e.Time - $tMin).TotalSeconds
        $x = $marginX + ($tSec / $span) * $usable
        $pct = if ($e.PSObject.Properties['Signal']) { [int]$e.Signal } else { 0 }
        $hex = if ($pct -ge 76) { '#3fb950' } elseif ($pct -ge 51) { '#d29922' } else { '#f85149' }
        $brush = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($hex))
        $brush.Freeze()
        $dot = New-Object System.Windows.Shapes.Ellipse -Property @{
            Width = 8; Height = 8
            Fill = $brush
            Stroke = [System.Windows.Media.Brushes]::White
            StrokeThickness = 0.5
        }
        $tip = ("{0}  {1}  BSSID {2}  signal {3}%" -f $e.Time.ToString('HH:mm:ss'), $e.SSID, $e.BSSID, $pct)
        $dot.ToolTip = $tip
        [System.Windows.Controls.Canvas]::SetLeft($dot, $x - 4)
        [System.Windows.Controls.Canvas]::SetTop($dot, ($h / 2) - 4)
        [void]$canvas.Children.Add($dot)
        if ($e.BSSID) { $uniqBssids[[string]$e.BSSID] = $true }
    }

    # Endpoints text.
    $tStartLbl = New-Object System.Windows.Controls.TextBlock
    $tStartLbl.Text = $tMin.ToString('HH:mm')
    $tStartLbl.Foreground = [System.Windows.Media.Brushes]::DimGray
    $tStartLbl.FontSize = 9
    [System.Windows.Controls.Canvas]::SetLeft($tStartLbl, $marginX)
    [System.Windows.Controls.Canvas]::SetTop($tStartLbl, $h - 14)
    [void]$canvas.Children.Add($tStartLbl)
    $tEndLbl = New-Object System.Windows.Controls.TextBlock
    $tEndLbl.Text = $tMax.ToString('HH:mm')
    $tEndLbl.Foreground = [System.Windows.Media.Brushes]::DimGray
    $tEndLbl.FontSize = 9
    [System.Windows.Controls.Canvas]::SetLeft($tEndLbl, $marginX + $usable - 28)
    [System.Windows.Controls.Canvas]::SetTop($tEndLbl, $h - 14)
    [void]$canvas.Children.Add($tEndLbl)

    if ($controls.WifiRoamingStats) {
        $controls.WifiRoamingStats.Text = ("{0} roams across {1} distinct AP(s) in last 24h" -f $entries.Count, $uniqBssids.Count)
    }
}
