# =============================================================================
# src/85-keyboard-shortcuts.ps1 — Keyboard shortcuts cheatsheet dialog
# =============================================================================
# Help menu -> "Keyboard shortcuts..." opens this dialog. Pure UI; no script-state
# dependencies. First feature written directly into src/ (instead of migrated from
# the main file) - proves the dot-source pattern for greenfield additions.
# =============================================================================

function Show-KeyboardShortcutsDialog {
    # Each row: @{Group; Keys; Action}. Grouped + rendered as a tidy list in the dialog.
    $rows = @(
        @{ Group='Scanning'; Keys='Ctrl+R or F5'; Action='Re-scan diagnostics' }
        @{ Group='Scanning'; Keys='F1';            Action='Open Glossary' }
        @{ Group='Scanning'; Keys='Ctrl+/';        Action='This shortcuts dialog' }
        @{ Group='Export';   Keys='Ctrl+S';        Action='Save HTML report' }
        @{ Group='Export';   Keys='Ctrl+E';        Action='Export current tab as CSV' }
        @{ Group='Events';   Keys='Ctrl+L';        Action='Clear LIVE EVENTS feed' }
        @{ Group='Events';   Keys='Ctrl+P';        Action='Pause / resume LIVE EVENTS' }
        @{ Group='Tabs';     Keys='Ctrl+1..7';     Action='Switch to DIAGNOSTICS / PROCESSES / TRAFFIC / FLOWS / PERSISTENCE / HISTORY / DNS' }
        @{ Group='UI';       Keys='Ctrl+T';        Action='Toggle dark / light theme' }
        @{ Group='UI';       Keys='Ctrl+M';        Action='Mute / unmute notifications' }
        @{ Group='UI';       Keys='Ctrl+,';        Action='Open Settings' }
        @{ Group='Window';   Keys='Esc';           Action='Close most dialogs' }
        @{ Group='Window';   Keys='Alt+F4';        Action='Quit NetJump (or close to tray)' }
    )

    $bodyXaml = New-Object System.Text.StringBuilder
    $groups = $rows | Group-Object Group
    foreach ($g in $groups) {
        [void]$bodyXaml.Append("<TextBlock Foreground='#58a6ff' FontWeight='Bold' FontSize='11' Margin='0,12,0,4'>")
        [void]$bodyXaml.Append([System.Net.WebUtility]::HtmlEncode($g.Name))
        [void]$bodyXaml.Append('</TextBlock>')
        foreach ($r in $g.Group) {
            [void]$bodyXaml.Append("<Grid Margin='4,2,0,2'>")
            [void]$bodyXaml.Append("<Grid.ColumnDefinitions><ColumnDefinition Width='160'/><ColumnDefinition Width='*'/></Grid.ColumnDefinitions>")
            [void]$bodyXaml.Append("<Border Grid.Column='0' Background='#1a2030' BorderBrush='#2a3142' BorderThickness='1' CornerRadius='3' Padding='6,2'>")
            [void]$bodyXaml.Append("<TextBlock Foreground='#d7dde6' FontFamily='Consolas' FontSize='11'>")
            [void]$bodyXaml.Append([System.Net.WebUtility]::HtmlEncode($r.Keys))
            [void]$bodyXaml.Append('</TextBlock></Border>')
            [void]$bodyXaml.Append("<TextBlock Grid.Column='1' Margin='10,0,0,0' VerticalAlignment='Center' Foreground='#d7dde6' FontSize='11'>")
            [void]$bodyXaml.Append([System.Net.WebUtility]::HtmlEncode($r.Action))
            [void]$bodyXaml.Append('</TextBlock></Grid>')
        }
    }

    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="NetJump Keyboard Shortcuts" Width="640" Height="640" WindowStartupLocation="CenterOwner"
        Background="{DynamicResource BrushWindowBg}" Foreground="{DynamicResource BrushFgPrimary}" FontFamily="Segoe UI">
    <Grid Margin="18">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <StackPanel Grid.Row="0">
            <TextBlock Text="Keyboard shortcuts" Foreground="#58a6ff" FontSize="16" FontWeight="Bold"/>
            <TextBlock Foreground="{DynamicResource BrushFgMuted}" FontSize="11" Margin="0,4,0,0"
                       Text="Most actions in the HUD have a keyboard binding so you can drive a scan / export / tab-switch without touching the mouse. F1 opens the Glossary which explains terminology rather than commands."/>
        </StackPanel>
        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Background="{DynamicResource BrushDeepBg}" Padding="12" Margin="0,12,0,0">
            <StackPanel>$($bodyXaml.ToString())</StackPanel>
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
        try { [System.Windows.MessageBox]::Show($window, "Keyboard shortcuts dialog failed:`n$_", 'Error', 'OK', 'Error') | Out-Null } catch {}
    }
}
