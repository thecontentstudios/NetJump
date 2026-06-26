# =============================================================================
# src/84-suppressed-findings-ui.ps1 — Manage suppressed findings dialog
# =============================================================================
# View menu adds "Manage suppressed findings..." that opens a list of every
# currently-suppressed finding (loaded from $script:SuppressedKeys, the
# in-memory state populated by Load-Suppressed). The user can select rows
# and remove them, which un-suppresses them everywhere.
# =============================================================================

function Show-SuppressedFindingsDialog {
    $items = New-Object System.Collections.Generic.List[psobject]
    if (-not $script:SuppressedKeys -or $script:SuppressedKeys.Count -eq 0) {
        [System.Windows.MessageBox]::Show($window, 'No findings are currently suppressed.', 'Empty allowlist', 'OK', 'Information') | Out-Null
        return
    }
    foreach ($k in $script:SuppressedKeys.Keys) {
        $v = $script:SuppressedKeys[$k]
        $parts = $k -split '\|', 2
        $cat = if ($parts.Count -gt 0) { $parts[0] } else { '?' }
        $msg = if ($parts.Count -gt 1) { $parts[1] } else { $k }
        $exp = if ($v.Expires) { ([datetime]$v.Expires).ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
        $items.Add([pscustomobject]@{
            Key      = $k
            Category = $cat
            Message  = $msg
            Mode     = [string]$v.Mode
            Expires  = $exp
        })
    }
    $items = @($items | Sort-Object Category, Message)

    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Manage suppressed findings" Width="960" Height="540" WindowStartupLocation="CenterOwner"
        Background="{DynamicResource BrushWindowBg}" Foreground="{DynamicResource BrushFgPrimary}" FontFamily="Segoe UI">
    <Grid Margin="18">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <StackPanel Grid.Row="0" Margin="0,0,0,12">
            <TextBlock Text="Suppressed findings" Foreground="#58a6ff" FontSize="16" FontWeight="Bold"/>
            <TextBlock Foreground="{DynamicResource BrushFgMuted}" FontSize="11" Margin="0,4,0,0" TextWrapping="Wrap"
                       Text="Every finding you have hidden via the DIAGNOSTICS right-click 'Suppress' actions. Select one or more rows and click 'Unsuppress' to make them visible again. Session-mode entries auto-expire when NetJump closes; 24h entries expire on their listed date."/>
        </StackPanel>
        <ListView Grid.Row="1" x:Name="SuppressList" Background="{DynamicResource BrushDeepBg}" Foreground="{DynamicResource BrushFgPrimary}" SelectionMode="Extended" FontSize="11">
            <ListView.View>
                <GridView>
                    <GridViewColumn Header="Category" Width="160" DisplayMemberBinding="{Binding Category}"/>
                    <GridViewColumn Header="Message"  Width="560" DisplayMemberBinding="{Binding Message}"/>
                    <GridViewColumn Header="Mode"     Width="90"  DisplayMemberBinding="{Binding Mode}"/>
                    <GridViewColumn Header="Expires"  Width="140" DisplayMemberBinding="{Binding Expires}"/>
                </GridView>
            </ListView.View>
        </ListView>
        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
            <Button x:Name="UnsuppressBtn" Content="Unsuppress selected" Padding="10,5" Margin="0,0,8,0"/>
            <Button x:Name="UnsuppressAllBtn" Content="Unsuppress ALL" Padding="10,5" Margin="0,0,8,0" Foreground="#f85149"/>
            <Button x:Name="CloseBtn" Content="Close" Padding="14,5" Background="#1f6feb" Foreground="#ffffff"/>
        </StackPanel>
    </Grid>
</Window>
'@
    try {
        [xml]$x = $xaml
        $rdr = New-Object System.Xml.XmlNodeReader $x
        $w = [Windows.Markup.XamlReader]::Load($rdr)
        if ($window) { $w.Owner = $window }
        try { Wire-DialogEscClose $w } catch {}
        try { Apply-ThemeToChild $w } catch {}
        $list = $w.FindName('SuppressList')
        $list.ItemsSource = $items
        $w.FindName('UnsuppressBtn').Add_Click({
            $selected = @($list.SelectedItems)
            if ($selected.Count -eq 0) { return }
            foreach ($it in $selected) {
                try { Unsuppress-Finding -Key $it.Key } catch {}
            }
            try { Apply-FindingsFilter } catch {}
            $w.Close()
        }.GetNewClosure())
        $w.FindName('UnsuppressAllBtn').Add_Click({
            $r = [System.Windows.MessageBox]::Show($w, "Unsuppress ALL $($items.Count) finding(s)?", 'Confirm', 'YesNo', 'Warning')
            if ($r -ne 'Yes') { return }
            foreach ($it in $items) {
                try { Unsuppress-Finding -Key $it.Key } catch {}
            }
            try { Apply-FindingsFilter } catch {}
            $w.Close()
        }.GetNewClosure())
        $w.FindName('CloseBtn').Add_Click({ $w.Close() })
        $w.ShowDialog() | Out-Null
    } catch {
        [System.Windows.MessageBox]::Show($window, "Suppressed findings dialog failed:`n$_", 'Error', 'OK', 'Error') | Out-Null
    }
}
