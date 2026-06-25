# =============================================================================
# src/72-snapshot-diff.ps1 — Snapshot diff viewer
# =============================================================================
# Diagnose menu -> "Diff two snapshots..." picks two snapshot JSONs from
# Reports\Snapshots\, opens a side-by-side compare with three buckets:
#   * ONLY IN A    (resolved between A and B)
#   * ONLY IN B    (appeared between A and B)
#   * IN BOTH      (persisted across both)
# Useful for "what changed since Monday?" investigations.
# =============================================================================

function _SnapKey { param($F) ("{0}|{1}" -f [string]$F.Category, [string]$F.Message) }

function Show-SnapshotDiffDialog {
    Add-Type -AssemblyName System.Windows.Forms

    function _Pick { param([string]$Title)
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.InitialDirectory = $script:SnapshotsDir
        $dlg.Filter = 'NetJump snapshot (*.json)|snapshot-*.json|All files (*.*)|*.*'
        $dlg.Title  = $Title
        if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
        return $dlg.FileName
    }

    $pathA = _Pick 'Pick snapshot A (the earlier / baseline snapshot)'
    if (-not $pathA) { return }
    $pathB = _Pick 'Pick snapshot B (the later / current snapshot)'
    if (-not $pathB) { return }

    try {
        $snapA = Get-Content -LiteralPath $pathA -Raw | ConvertFrom-Json
        $snapB = Get-Content -LiteralPath $pathB -Raw | ConvertFrom-Json
    } catch {
        [System.Windows.MessageBox]::Show($window, "Snapshot parse failed:`n$_", 'Error', 'OK', 'Error') | Out-Null
        return
    }

    # Key by Category|Message for diff purposes. Synthesize three buckets.
    $aMap = @{}
    foreach ($f in @($snapA.findings)) { $k = _SnapKey $f; if ($k) { $aMap[$k] = $f } }
    $bMap = @{}
    foreach ($f in @($snapB.findings)) { $k = _SnapKey $f; if ($k) { $bMap[$k] = $f } }
    $onlyA = @($aMap.Keys | Where-Object { -not $bMap.ContainsKey($_) } | ForEach-Object { $aMap[$_] })
    $onlyB = @($bMap.Keys | Where-Object { -not $aMap.ContainsKey($_) } | ForEach-Object { $bMap[$_] })
    $both  = @($aMap.Keys | Where-Object {     $bMap.ContainsKey($_) } | ForEach-Object { $bMap[$_] })

    $tsA = if ($snapA.timestamp) { ([datetime]$snapA.timestamp).ToString('yyyy-MM-dd HH:mm:ss') } else { '?' }
    $tsB = if ($snapB.timestamp) { ([datetime]$snapB.timestamp).ToString('yyyy-MM-dd HH:mm:ss') } else { '?' }

    function _RenderBucket { param([string]$Title, [string]$Color, $List)
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append("<TextBlock Foreground='$Color' FontWeight='Bold' FontSize='11' Margin='0,8,0,4'>")
        [void]$sb.Append([System.Net.WebUtility]::HtmlEncode("$Title  ($($List.Count))"))
        [void]$sb.Append('</TextBlock>')
        if ($List.Count -eq 0) {
            [void]$sb.Append("<TextBlock Foreground='#6e7681' FontSize='10' Margin='8,2,0,0'><Italic>(none)</Italic></TextBlock>")
            return $sb.ToString()
        }
        foreach ($f in $List) {
            $lvl = [string]$f.Level
            $lvlHex = switch ($lvl) { 'FAIL' {'#f85149'} 'WARN' {'#d29922'} 'INFO' {'#58a6ff'} default {'#3fb950'} }
            [void]$sb.Append("<Border Background='#1a2030' BorderBrush='#2a3142' BorderThickness='1' CornerRadius='3' Padding='6,4' Margin='8,2,0,2'>")
            [void]$sb.Append("<StackPanel>")
            [void]$sb.Append("<StackPanel Orientation='Horizontal'>")
            [void]$sb.Append("<Border Background='$lvlHex' CornerRadius='2' Padding='3,1' Margin='0,0,6,0'>")
            [void]$sb.Append("<TextBlock Foreground='White' FontSize='9' FontWeight='Bold'>")
            [void]$sb.Append([System.Net.WebUtility]::HtmlEncode($lvl))
            [void]$sb.Append('</TextBlock></Border>')
            [void]$sb.Append("<TextBlock Foreground='#8b95a8' FontSize='10' Margin='0,1,0,0'>")
            [void]$sb.Append([System.Net.WebUtility]::HtmlEncode([string]$f.Category))
            [void]$sb.Append('</TextBlock></StackPanel>')
            [void]$sb.Append("<TextBlock Foreground='#d7dde6' FontSize='11' Margin='0,2,0,0' TextWrapping='Wrap'>")
            [void]$sb.Append([System.Net.WebUtility]::HtmlEncode([string]$f.Message))
            [void]$sb.Append('</TextBlock></StackPanel></Border>')
        }
        return $sb.ToString()
    }

    $bodyAxaml = _RenderBucket 'ONLY IN A — resolved since A'   '#3fb950' $onlyA
    $bodyBxaml = _RenderBucket 'ONLY IN B — appeared since A'   '#f85149' $onlyB
    $bodyCxaml = _RenderBucket 'IN BOTH — persisted'            '#58a6ff' $both

    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="NetJump Snapshot Diff" Width="1080" Height="720" WindowStartupLocation="CenterOwner"
        Background="{DynamicResource BrushWindowBg}" Foreground="{DynamicResource BrushFgPrimary}" FontFamily="Segoe UI">
    <Grid Margin="18">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <StackPanel Grid.Row="0">
            <TextBlock Text="Snapshot diff" Foreground="#58a6ff" FontSize="16" FontWeight="Bold"/>
            <TextBlock Foreground="{DynamicResource BrushFgMuted}" FontSize="11" Margin="0,4,0,0">
                <Run Text="A:  "/><Run FontFamily="Consolas">$([System.Net.WebUtility]::HtmlEncode((Split-Path $pathA -Leaf))) ($tsA)</Run>
            </TextBlock>
            <TextBlock Foreground="{DynamicResource BrushFgMuted}" FontSize="11" Margin="0,2,0,0">
                <Run Text="B:  "/><Run FontFamily="Consolas">$([System.Net.WebUtility]::HtmlEncode((Split-Path $pathB -Leaf))) ($tsB)</Run>
            </TextBlock>
        </StackPanel>
        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Background="{DynamicResource BrushDeepBg}" Padding="12" Margin="0,12,0,0">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" Margin="0,0,8,0">$bodyAxaml</StackPanel>
                <StackPanel Grid.Column="1" Margin="4,0,4,0">$bodyBxaml</StackPanel>
                <StackPanel Grid.Column="2" Margin="8,0,0,0">$bodyCxaml</StackPanel>
            </Grid>
        </ScrollViewer>
        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
            <Button x:Name="CloseBtn" Content="Close" Padding="14,5" Background="#1f6feb" Foreground="#ffffff"/>
        </StackPanel>
    </Grid>
</Window>
"@
    try {
        [xml]$x = $xaml
        $rdr = New-Object System.Xml.XmlNodeReader $x
        $w = [Windows.Markup.XamlReader]::Load($rdr)
        if ($window) { $w.Owner = $window }
        try { Wire-DialogEscClose $w } catch {}
        try { Apply-ThemeToChild $w } catch {}
        $w.FindName('CloseBtn').Add_Click({ $w.Close() })
        $w.ShowDialog() | Out-Null
    } catch {
        [System.Windows.MessageBox]::Show($window, "Diff dialog failed:`n$_", 'Error', 'OK', 'Error') | Out-Null
    }
}
