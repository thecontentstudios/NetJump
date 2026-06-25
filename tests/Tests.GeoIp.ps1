# Pester 5 tests for src/22-geoip.ps1

BeforeAll {
    # Source the module under test. It uses $PSScriptRoot (the src/ dir at runtime) for its
    # default DB path; we override $script:GeoIpDbPath after sourcing.
    $repoRoot = Split-Path $PSScriptRoot -Parent
    . (Join-Path $repoRoot 'src\22-geoip.ps1')
}

Describe 'Get-IpCountry binary search' {
    BeforeEach {
        # Build a synthetic 3-range dataset directly into the module's state.
        # 1.0.0.0 - 1.0.0.255 = US     (0x01000000 .. 0x010000FF)
        # 8.8.8.0 - 8.8.8.255 = NL     (0x08080800 .. 0x080808FF)
        # 200.0.0.0 - 200.255.255.255 = BR (0xC8000000 .. 0xC8FFFFFF)
        $script:GeoIpRangesV4 = @(
            [pscustomobject]@{ Lo = [uint32]0x01000000; Hi = [uint32]0x010000FF; CC = 'US' }
            [pscustomobject]@{ Lo = [uint32]0x08080800; Hi = [uint32]0x080808FF; CC = 'NL' }
            [pscustomobject]@{ Lo = [uint32]0xC8000000; Hi = [uint32]0xC8FFFFFF; CC = 'BR' }
        )
        $script:GeoIpLoaded = $true
    }

    It 'returns the country code for an IP in the middle of a range' {
        Get-IpCountry '8.8.8.128' | Should -Be 'NL'
    }

    It 'returns the country code at the exact low boundary' {
        Get-IpCountry '1.0.0.0' | Should -Be 'US'
    }

    It 'returns the country code at the exact high boundary' {
        Get-IpCountry '200.255.255.255' | Should -Be 'BR'
    }

    It 'returns null for an IP outside every range' {
        Get-IpCountry '127.0.0.1' | Should -BeNullOrEmpty
    }

    It 'returns null for an IPv6 address (falls through gracefully)' {
        Get-IpCountry '::1' | Should -BeNullOrEmpty
    }

    It 'returns null for a malformed input' {
        Get-IpCountry 'not-an-ip' | Should -BeNullOrEmpty
        Get-IpCountry '' | Should -BeNullOrEmpty
    }

    It 'returns null when the database is not loaded' {
        $script:GeoIpLoaded = $false
        $script:GeoIpRangesV4 = $null
        Get-IpCountry '8.8.8.128' | Should -BeNullOrEmpty
    }
}

Describe 'Load-GeoIpDatabase CSV parser' {
    It 'parses a minimal valid CSV' {
        $tmp = New-TemporaryFile
        # Force the file LastWriteTime to current so the TTL check passes.
        @(
            '1.0.0.0,1.0.0.255,US'
            '8.8.8.0,8.8.8.255,NL'
            '200.0.0.0,200.255.255.255,BR'
        ) | Set-Content -LiteralPath $tmp.FullName -Encoding ASCII

        $script:GeoIpDbPath = $tmp.FullName
        $loaded = Load-GeoIpDatabase
        $loaded | Should -BeTrue
        $script:GeoIpRangesV4.Count | Should -Be 3
        Get-IpCountry '8.8.8.7' | Should -Be 'NL'
        Remove-Item $tmp.FullName -Force -ErrorAction SilentlyContinue
    }

    It 'skips IPv6 rows silently' {
        $tmp = New-TemporaryFile
        @(
            '1.0.0.0,1.0.0.255,US'
            '2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE'
            '8.8.8.0,8.8.8.255,NL'
        ) | Set-Content -LiteralPath $tmp.FullName -Encoding ASCII
        $script:GeoIpDbPath = $tmp.FullName
        $loaded = Load-GeoIpDatabase
        $loaded | Should -BeTrue
        $script:GeoIpRangesV4.Count | Should -Be 2  # IPv6 row was skipped
        Remove-Item $tmp.FullName -Force -ErrorAction SilentlyContinue
    }

    It 'returns $false when the file does not exist' {
        $script:GeoIpDbPath = (Join-Path $env:TEMP ('netjump-nonexistent-' + [guid]::NewGuid()))
        Load-GeoIpDatabase | Should -BeFalse
        $script:GeoIpLoaded | Should -BeFalse
    }
}
