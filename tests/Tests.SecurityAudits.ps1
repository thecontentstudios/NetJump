# Pester 5 tests for src/31-security-audits.ps1

BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    # The module calls Add-Finding which lives in the main file. Stub it: just return the inputs
    # as a hashtable so we can introspect.
    function global:Add-Finding {
        param($Level, $Category, $Message, $Fix='', $Detail='', $Mitre='')
        return [pscustomobject]@{ Level=$Level; Category=$Category; Message=$Message; Fix=$Fix; Detail=$Detail; Mitre=$Mitre }
    }
    function global:Add-Event { param($Type, $Text, $Source='system'); return $null }
    . (Join-Path $repoRoot 'src\31-security-audits.ps1')
}

Describe 'Get-DefenderExclusionFindings' {
    It 'flags an ExclusionPath under AppData' {
        Mock Get-MpPreference {
            [pscustomobject]@{
                ExclusionPath      = @('C:\Users\Alice\AppData\Local\suspect')
                ExclusionExtension = @()
                ExclusionProcess   = @()
            }
        }
        $findings = @(Get-DefenderExclusionFindings)
        ($findings | Where-Object { $_.Category -eq 'Defender' -and $_.Message -like '*AppData*' }).Count | Should -BeGreaterOrEqual 1
    }

    It 'flags ExclusionExtension for .exe as FAIL' {
        Mock Get-MpPreference {
            [pscustomobject]@{
                ExclusionPath      = @()
                ExclusionExtension = @('.exe')
                ExclusionProcess   = @()
            }
        }
        $findings = @(Get-DefenderExclusionFindings)
        $exeFinding = $findings | Where-Object { $_.Message -like '*exe*' } | Select-Object -First 1
        $exeFinding | Should -Not -BeNullOrEmpty
        $exeFinding.Level | Should -Be 'FAIL'
    }

    It 'is silent when no problematic exclusions exist' {
        Mock Get-MpPreference {
            [pscustomobject]@{
                ExclusionPath      = @('C:\Program Files\LegitApp')
                ExclusionExtension = @('.dat')
                ExclusionProcess   = @()
            }
        }
        $findings = @(Get-DefenderExclusionFindings)
        $findings.Count | Should -Be 0
    }

    It 'returns empty when Get-MpPreference fails' {
        Mock Get-MpPreference { throw 'simulated failure' }
        $findings = @(Get-DefenderExclusionFindings)
        $findings.Count | Should -Be 0
    }
}
