<#
.SYNOPSIS
  Run the NetJump Pester 5 test suite.

.DESCRIPTION
  Ensures Pester 5.x is available (installs to CurrentUser scope if missing),
  invokes Pester against this directory, and optionally writes NUnit-XML for
  CI integration (-NunitXmlPath).

.PARAMETER NunitXmlPath
  When supplied, Pester writes the test results in NUnit-XML format here. Used
  by the GitHub Actions CI workflow to surface failures as PR annotations.

.PARAMETER FailNoTests
  If set, exit code 1 when zero tests ran. Default: exit 0 (useful while the
  test set is still small).

.EXAMPLE
  .\tests\Run-Tests.ps1

.EXAMPLE
  # CI invocation:
  .\tests\Run-Tests.ps1 -NunitXmlPath .\test-results.xml -FailNoTests
#>

[CmdletBinding()]
param(
    [string]$NunitXmlPath,
    [switch]$FailNoTests
)

$ErrorActionPreference = 'Stop'

# Ensure Pester 5.x. PS 5.1 ships with Pester 3.4 which is incompatible.
$installed = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1
if (-not $installed -or $installed.Version.Major -lt 5) {
    Write-Host 'Installing Pester 5.x (CurrentUser scope)...'
    Install-Module -Name Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction Stop
}
Import-Module Pester -MinimumVersion 5.0.0 -Force

$testDir = $PSScriptRoot
$cfg = [PesterConfiguration]::Default
$cfg.Run.Path        = $testDir
$cfg.Run.PassThru    = $true
$cfg.Output.Verbosity = 'Detailed'
if ($NunitXmlPath) {
    $cfg.TestResult.Enabled       = $true
    $cfg.TestResult.OutputFormat  = 'NUnitXml'
    $cfg.TestResult.OutputPath    = $NunitXmlPath
}

$result = Invoke-Pester -Configuration $cfg

if ($result.FailedCount -gt 0) {
    Write-Host ("`n{0} test(s) failed." -f $result.FailedCount) -ForegroundColor Red
    exit 1
}
if ($result.TotalCount -eq 0 -and $FailNoTests) {
    Write-Host 'No tests ran.' -ForegroundColor Yellow
    exit 1
}
Write-Host ("`n{0} test(s) passed." -f $result.PassedCount) -ForegroundColor Green
exit 0
