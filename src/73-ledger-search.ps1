# =============================================================================
# src/73-ledger-search.ps1 — Connection ledger search dialog
# =============================================================================
# Searchable view over $script:Ledger (the long-running connection history that
# survives across launches). Lets the user filter by process, IP, country code,
# threat-intel tag, or any column substring. Menu entry: Export -> Search ledger...
# =============================================================================

function Show-LedgerSearchDialog {
    if (-not $script:Ledger -or $script:Ledger.Count -eq 0) {
        [System.Windows.MessageBox]::Show($window, 'The connection ledger is empty. Run NetJump for a while and remote-connection traffic will accumulate.', 'Empty ledger', 'OK', 'Information') | Out-Null
        return
    }
    # Enrich each ledger row with country (Get-IpCountry from src/22-geoip.ps1) + threat tag.
    $rows = New-Object System.Collections.Generic.List[psobject]
    foreach ($k in $script:Ledger.Keys) {
        $v = $script:Ledger[$k]
        $cc = ''
        try { $cc = Get-IpCountry $v.ip } catch {}
        $threat = ''
        try { $threat = Test-IpThreat -Ip $v.ip } catch {}
        $asnText = ''
        try {
            $asn = Get-IpAsn -Ip $v.ip
            if ($asn) {
                $orgShort = [string]$asn.Org
                if ($orgShort.Length -gt 35) { $orgShort = $orgShort.Substring(0,35) + '...' }
                $asnText = "AS$($asn.Asn)  $orgShort"
            }
        } catch {}
        $rows.Add([pscustomobject]@{
            Process   = [string]$v.proc
            IP        = [string]$v.ip
            Port      = [int]$v.port
            Country   = if ($cc) { [string]$cc } else { '' }
            ASN       = $asnText
            Threat    = if ($threat) { [string]$threat } else { '' }
            FirstSeen = [string]$v.firstSeen
            LastSeen  = [string]$v.lastSeen
            Samples   = [int]$v.samples
            Label     = [string]$v.label
        })
    }
    $rows = @($rows | Sort-Object Samples -Descending)

    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Connection ledger search" Width="1080" Height="640" WindowStartupLocation="CenterOwner"
        Background="{DynamicResource BrushWindowBg}" Foreground="{DynamicResource BrushFgPrimary}" FontFamily="Segoe UI">
    <Grid Margin="18">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <StackPanel Grid.Row="0">
            <TextBlock Text="Connection ledger search" Foreground="#58a6ff" FontSize="16" FontWeight="Bold"/>
            <TextBlock Foreground="{DynamicResource BrushFgMuted}" FontSize="11" Margin="0,4,0,0"
                       Text="Every (process, remote IP, port) tuple NetJump has seen, with first/last-seen timestamps and sample count. Search filters across all columns case-insensitively. Type a process name, IP, port, country code, or threat-intel tag."/>
        </StackPanel>
        <Border Grid.Row="1" Background="{DynamicResource BrushDeepBg}" BorderBrush="{DynamicResource BrushBorder}" BorderThickness="1" CornerRadius="6" Padding="8,4" Margin="0,12,0,8">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock Grid.Column="0" Text="🔍" FontSize="12" Foreground="{DynamicResource BrushFgMuted}" VerticalAlignment="Center" Margin="0,0,6,0"/>
                <TextBox Grid.Column="1" x:Name="SearchBox" BorderThickness="0" Background="Transparent" Foreground="{DynamicResource BrushFgPrimary}" CaretBrush="{DynamicResource BrushFgPrimary}" FontSize="12" VerticalAlignment="Center"/>
                <TextBlock Grid.Column="2" x:Name="CountText" Text="" FontSize="10" Foreground="{DynamicResource BrushFgFaint}" VerticalAlignment="Center" Margin="10,0,0,0"/>
            </Grid>
        </Border>
        <ListView Grid.Row="2" x:Name="LedgerList" Background="{DynamicResource BrushDeepBg}" Foreground="{DynamicResource BrushFgPrimary}" BorderThickness="0" FontFamily="Consolas" FontSize="11">
            <ListView.View>
                <GridView>
                    <GridViewColumn Header="Process" Width="180" DisplayMemberBinding="{Binding Process}"/>
                    <GridViewColumn Header="IP"      Width="150" DisplayMemberBinding="{Binding IP}"/>
                    <GridViewColumn Header="Port"    Width="70"  DisplayMemberBinding="{Binding Port}"/>
                    <GridViewColumn Header="CC"      Width="50"  DisplayMemberBinding="{Binding Country}"/>
                    <GridViewColumn Header="ASN"     Width="220" DisplayMemberBinding="{Binding ASN}"/>
                    <GridViewColumn Header="Threat"  Width="120" DisplayMemberBinding="{Binding Threat}"/>
                    <GridViewColumn Header="Samples" Width="80"  DisplayMemberBinding="{Binding Samples}"/>
                    <GridViewColumn Header="Last Seen" Width="170" DisplayMemberBinding="{Binding LastSeen}"/>
                    <GridViewColumn Header="Label"   Width="160" DisplayMemberBinding="{Binding Label}"/>
                </GridView>
            </ListView.View>
        </ListView>
        <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
            <Button x:Name="ExportBtn" Content="Export visible as CSV" Padding="10,5" Margin="0,0,8,0"/>
            <Button x:Name="CloseBtn"  Content="Close"                 Padding="14,5" Background="#1f6feb" Foreground="#ffffff"/>
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
        $list = $w.FindName('LedgerList')
        $searchBox = $w.FindName('SearchBox')
        $count = $w.FindName('CountText')
        $apply = {
            $f = ([string]$searchBox.Text).Trim().ToLower()
            if (-not $f) {
                $list.ItemsSource = $rows
                $count.Text = ("{0} entries" -f $rows.Count)
                return
            }
            $filtered = @($rows | Where-Object {
                $hay = ("{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f $_.Process, $_.IP, $_.Port, $_.Country, $_.ASN, $_.Threat, $_.Label).ToLower()
                $hay.Contains($f)
            })
            $list.ItemsSource = $filtered
            $count.Text = ("{0} of {1} entries" -f $filtered.Count, $rows.Count)
        }
        & $apply
        $searchBox.Add_TextChanged({ & $apply }.GetNewClosure())
        $w.FindName('ExportBtn').Add_Click({
            Add-Type -AssemblyName System.Windows.Forms
            $dlg = New-Object System.Windows.Forms.SaveFileDialog
            $dlg.FileName = ("NetJump-ledger-search-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            $dlg.Filter = 'CSV (*.csv)|*.csv'
            if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $items = $list.ItemsSource
                $items | Select-Object Process,IP,Port,Country,ASN,Threat,Samples,FirstSeen,LastSeen,Label | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
                try { Add-Event info ("Ledger export: $($dlg.FileName)") } catch {}
            }
        }.GetNewClosure())
        $w.FindName('CloseBtn').Add_Click({ $w.Close() })
        $w.ShowDialog() | Out-Null
    } catch {
        [System.Windows.MessageBox]::Show($window, "Ledger search dialog failed:`n$_", 'Error', 'OK', 'Error') | Out-Null
    }
}
