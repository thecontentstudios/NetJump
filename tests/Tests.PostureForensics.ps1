# Pester 5 tests for src/33-posture-and-forensics.ps1 and src/23-ip-asn.ps1

BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    # Stub Add-Finding / Add-Event so the module's helpers don't blow up on the missing main-file functions.
    function global:Add-Finding {
        param($Level, $Category, $Message, $Fix='', $Detail='', $Mitre='')
        return [pscustomobject]@{ Level=$Level; Category=$Category; Message=$Message; Fix=$Fix; Detail=$Detail; Mitre=$Mitre }
    }
    function global:Add-Event { param($Type, $Text, $Source='system'); return $null }
    . (Join-Path $repoRoot 'src\33-posture-and-forensics.ps1')
    . (Join-Path $repoRoot 'src\23-ip-asn.ps1')
}

Describe 'Decode-EncodedPowerShellCommand' {
    It 'decodes a canonical -EncodedCommand blob' {
        $plain = 'Write-Host "hi"'
        $b64   = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($plain))
        $cmd   = "powershell -NoProfile -EncodedCommand $b64"
        Decode-EncodedPowerShellCommand -CommandLine $cmd | Should -Be $plain
    }

    It 'decodes the short -enc form' {
        $plain = 'Get-Process | Where-Object Name -eq lsass'
        $b64   = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($plain))
        Decode-EncodedPowerShellCommand -CommandLine "powershell -enc $b64" | Should -Be $plain
    }

    It 'returns null when no encoded segment is present' {
        Decode-EncodedPowerShellCommand -CommandLine 'powershell -NoProfile -File foo.ps1' | Should -BeNullOrEmpty
    }

    It 'returns null on malformed base64 input' {
        Decode-EncodedPowerShellCommand -CommandLine 'powershell -EncodedCommand !!!notbase64!!!' | Should -BeNullOrEmpty
    }
}

Describe 'Get-IpAsn binary search' {
    BeforeEach {
        # Synthetic ASN dataset.
        # 1.0.0.0 - 1.0.0.255   -> AS 13335 / Cloudflare
        # 8.8.8.0 - 8.8.8.255   -> AS 15169 / Google
        $script:IpAsnRangesV4 = @(
            [pscustomobject]@{ Lo = [uint32]0x01000000; Hi = [uint32]0x010000FF; Asn = 13335; Org = 'Cloudflare, Inc.' }
            [pscustomobject]@{ Lo = [uint32]0x08080800; Hi = [uint32]0x080808FF; Asn = 15169; Org = 'Google LLC' }
        )
        $script:IpAsnLoaded = $true
    }

    It 'returns the ASN+Org for an IP in the middle of a range' {
        $r = Get-IpAsn -Ip '8.8.8.42'
        $r.Asn | Should -Be 15169
        $r.Org | Should -Be 'Google LLC'
    }

    It 'returns null for an IP outside every range' {
        Get-IpAsn -Ip '127.0.0.1' | Should -BeNullOrEmpty
    }

    It 'returns null for IPv6 input (falls through gracefully)' {
        Get-IpAsn -Ip '2001:db8::1' | Should -BeNullOrEmpty
    }

    It 'returns null when the database is not loaded' {
        $script:IpAsnLoaded = $false; $script:IpAsnRangesV4 = $null
        Get-IpAsn -Ip '8.8.8.42' | Should -BeNullOrEmpty
    }
}
