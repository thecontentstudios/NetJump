# =============================================================================
# src/86-compliance-mappings.ps1 — NIST CSF 2.0 + CIS Controls v8 mappings
# =============================================================================
# View menu adds two dialogs:
#   * "NIST CSF coverage..."   -> Show-ComplianceCoverageDialog -Framework NIST
#   * "CIS Controls coverage..." -> Show-ComplianceCoverageDialog -Framework CIS
#
# Each shows a control-by-control grid: green pill = NetJump can detect at least
# one finding tagged for that control today; gray = not covered. Hover for the
# NetJump rule names that cover it. The mapping is editorial - tight enough to
# be useful, loose enough that we don't claim full coverage.
# =============================================================================

# NIST CSF 2.0: 6 functions, each with a small set of representative subcategories.
# Mapping: NetJump's $script:AttackMap.Code -> CSF subcategory (or list).
$script:NistCsfFramework = [ordered]@{
    'GV (Govern)' = @(
        @{ Id='GV.OC-03'; Name='Legal / regulatory requirements understood';     Rules=@() }
        @{ Id='GV.RM-04'; Name='Risk response decisions documented';             Rules=@() }
    )
    'ID (Identify)' = @(
        @{ Id='ID.AM-02'; Name='Software platforms inventoried';                 Rules=@('persist-run','persist-startup','persist-service','persist-task','persist-wmi') }
        @{ Id='ID.RA-01'; Name='Vulnerabilities identified and documented';      Rules=@('byovd','driver-bsod','posture-smb1','posture-wdigest') }
        @{ Id='ID.RA-05'; Name='Threats to assets identified';                   Rules=@('unsigned-extern','unsigned-temp') }
    )
    'PR (Protect)' = @(
        @{ Id='PR.AA-01'; Name='Identities & credentials issued / managed';      Rules=@('posture-llmnr') }
        @{ Id='PR.AC-01'; Name='Access permissions managed';                     Rules=@() }
        @{ Id='PR.PS-01'; Name='Configuration management practices';             Rules=@('posture-smb1','posture-llmnr','posture-wdigest','hosts-tamper','proxy-hijack') }
        @{ Id='PR.PS-05'; Name='Endpoint defenses configured and monitored';     Rules=@('defender-off') }
    )
    'DE (Detect)' = @(
        @{ Id='DE.AE-02'; Name='Adverse event analysis (anomalies)';             Rules=@('beaconing','arp-spoof') }
        @{ Id='DE.AE-03'; Name='Detected events analyzed (compromise hypothesis)';Rules=@('dll-hijack','c2-suspicious') }
        @{ Id='DE.CM-01'; Name='Networks & network services monitored';          Rules=@('threat-intel','dns-suspicious','dns-dga','doh-evasion','c2-dns') }
        @{ Id='DE.CM-09'; Name='Computing devices / software monitored';         Rules=@('byovd','unsigned-extern') }
    )
    'RS (Respond)' = @(
        @{ Id='RS.MA-02'; Name='Response actions triggered automatically';       Rules=@() }
        @{ Id='RS.AN-03'; Name='Incident scope analyzed';                        Rules=@() }
    )
    'RC (Recover)' = @(
        @{ Id='RC.RP-01'; Name='Recovery plans executed during/after event';     Rules=@() }
    )
}

# CIS Critical Controls v8: 18 controls, each shown at the top-level safeguard for brevity.
$script:CisControlsFramework = [ordered]@{
    'Basic Cyber Hygiene (1-6)' = @(
        @{ Id='CIS 1';  Name='Inventory of Enterprise Assets';                 Rules=@() }
        @{ Id='CIS 2';  Name='Inventory of Software Assets';                   Rules=@('persist-run','persist-startup','persist-service','persist-task','persist-wmi') }
        @{ Id='CIS 4';  Name='Secure Configuration of Enterprise Assets/Software'; Rules=@('posture-smb1','posture-llmnr','posture-wdigest','defender-off') }
        @{ Id='CIS 5';  Name='Account Management';                              Rules=@() }
        @{ Id='CIS 6';  Name='Access Control Management';                       Rules=@() }
    )
    'Foundational (7-12)' = @(
        @{ Id='CIS 7';  Name='Continuous Vulnerability Management';             Rules=@('byovd','driver-bsod') }
        @{ Id='CIS 8';  Name='Audit Log Management';                            Rules=@() }
        @{ Id='CIS 9';  Name='Email & Web Browser Protections';                 Rules=@() }
        @{ Id='CIS 10'; Name='Malware Defenses';                                Rules=@('defender-off','byovd') }
        @{ Id='CIS 12'; Name='Network Infrastructure Management';               Rules=@('arp-spoof','hosts-tamper','proxy-hijack') }
        @{ Id='CIS 13'; Name='Network Monitoring and Defense';                  Rules=@('threat-intel','dns-suspicious','dns-dga','doh-evasion','beaconing','c2-dns','c2-suspicious','dll-hijack') }
    )
    'Organizational (14-18)' = @(
        @{ Id='CIS 14'; Name='Security Awareness and Skills Training';          Rules=@() }
        @{ Id='CIS 17'; Name='Incident Response Management';                    Rules=@() }
    )
}

function Show-ComplianceCoverageDialog {
    param([Parameter(Mandatory)] [ValidateSet('NIST','CIS')] [string]$Framework)

    $matrix = if ($Framework -eq 'NIST') { $script:NistCsfFramework } else { $script:CisControlsFramework }
    $title  = if ($Framework -eq 'NIST') { 'NIST CSF 2.0 coverage' }      else { 'CIS Critical Controls v8 coverage' }
    $blurb  = if ($Framework -eq 'NIST') {
        "Maps NetJump's detection rules to NIST Cybersecurity Framework 2.0 subcategories. Editorial mapping - tight enough to be useful, loose enough that we don't over-claim. Green pill = NetJump can detect at least one finding tagged for that subcategory today."
    } else {
        "Maps NetJump's detection rules to the CIS Critical Security Controls v8. Top-level controls only (each has multiple safeguards). Green pill = NetJump can detect at least one finding tagged for that control today."
    }

    # Bucket all known rule keys by which Framework subcategory references them.
    $coveredRules = @{}
    foreach ($k in $script:AttackMap.Keys) { $coveredRules[$k] = $true }

    $bodyXaml = New-Object System.Text.StringBuilder
    $covered = 0; $total = 0
    foreach ($group in $matrix.Keys) {
        $items = $matrix[$group]
        [void]$bodyXaml.Append("<TextBlock Foreground='#58a6ff' FontWeight='Bold' FontSize='12' Margin='0,12,0,4'>")
        [void]$bodyXaml.Append([System.Net.WebUtility]::HtmlEncode($group))
        [void]$bodyXaml.Append('</TextBlock>')
        foreach ($it in $items) {
            $total++
            $isCovered = (@($it.Rules) | Where-Object { $coveredRules.ContainsKey($_) }).Count -gt 0
            if ($isCovered) { $covered++ }
            $bg = if ($isCovered) { '#143a23' } else { '#1a2030' }
            $bd = if ($isCovered) { '#3fb950' } else { '#3a4255' }
            $fg = if ($isCovered) { '#7ee787' } else { '#8b95a8' }
            $tip = if ($isCovered) { "Detected via: " + (($it.Rules | Where-Object { $coveredRules.ContainsKey($_) }) -join ', ') } else { 'Not yet covered.' }
            [void]$bodyXaml.Append("<Grid Margin='8,2,0,2'>")
            [void]$bodyXaml.Append("<Grid.ColumnDefinitions><ColumnDefinition Width='100'/><ColumnDefinition Width='*'/></Grid.ColumnDefinitions>")
            [void]$bodyXaml.Append("<Border Grid.Column='0' Background='$bg' BorderBrush='$bd' BorderThickness='1' CornerRadius='3' Padding='6,2' VerticalAlignment='Top' ToolTip='")
            [void]$bodyXaml.Append([System.Net.WebUtility]::HtmlEncode($tip))
            [void]$bodyXaml.Append("'><TextBlock Foreground='$fg' FontFamily='Consolas' FontSize='11'>")
            [void]$bodyXaml.Append([System.Net.WebUtility]::HtmlEncode($it.Id))
            [void]$bodyXaml.Append('</TextBlock></Border>')
            [void]$bodyXaml.Append("<TextBlock Grid.Column='1' Margin='10,2,0,0' VerticalAlignment='Top' Foreground='#d7dde6' FontSize='11' TextWrapping='Wrap'>")
            [void]$bodyXaml.Append([System.Net.WebUtility]::HtmlEncode($it.Name))
            [void]$bodyXaml.Append('</TextBlock></Grid>')
        }
    }

    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$title" Width="780" Height="640" WindowStartupLocation="CenterOwner"
        Background="{DynamicResource BrushWindowBg}" Foreground="{DynamicResource BrushFgPrimary}" FontFamily="Segoe UI">
    <Grid Margin="18">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <StackPanel Grid.Row="0">
            <TextBlock Text="$title" Foreground="#58a6ff" FontSize="16" FontWeight="Bold"/>
            <TextBlock Foreground="{DynamicResource BrushFgMuted}" FontSize="11" Margin="0,4,0,0" TextWrapping="Wrap" Text="$blurb"/>
            <TextBlock Foreground="{DynamicResource BrushFgFaint}" FontSize="11" Margin="0,4,0,0" Text="Coverage: $covered of $total controls listed."/>
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
        try { [System.Windows.MessageBox]::Show($window, "Coverage dialog failed:`n$_", 'Error', 'OK', 'Error') | Out-Null } catch {}
    }
}
