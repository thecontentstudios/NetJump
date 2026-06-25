<#
.SYNOPSIS
  Cut a NetJump release: bump version, rebuild installer, commit, tag, and publish a GitHub release.

.DESCRIPTION
  Automates the v1.x.y release dance so you don't have to remember the steps.

  1. Bumps MyAppVersion in NetJump.iss to the supplied -Version (semver: MAJOR.MINOR.PATCH).
  2. Runs ISCC.exe NetJump.iss to rebuild the installer (signed if NETJUMP_SIGN_CERT_PATH is set
     via Build-Installer.ps1 - this script just delegates the build).
  3. Parse-validates NetJump-Dashboard.ps1 + runs the -Json headless smoke test (skip with
     -SkipSmokeTest if Defender RTP is blocking spawns).
  4. git commit with "Release vX.Y.Z" message, git tag vX.Y.Z.
  5. git push origin main + the tag.
  6. gh release create vX.Y.Z with NetJump-Setup-X.Y.Z.exe attached as the asset, using either the
     -ReleaseNotes string or a default note pointing at the CHANGELOG.

.PARAMETER Version
  Target semver string. Required. Must be greater than the current value (lexically OK; only checks
  string inequality so 1.0.10 vs 1.0.9 needs you to think about ordering).

.PARAMETER ReleaseNotes
  Body for the GitHub release. Defaults to a generic "See CHANGELOG.md" if omitted.

.PARAMETER SkipSmokeTest
  Skip the headless -Json verification step. Use when Defender RTP is on and blocking spawns.

.PARAMETER DryRun
  Do everything except the irreversible bits (no git commit / push / tag / gh release create). Use
  to preview the version bump + see the rebuilt installer before committing to the release.

.EXAMPLE
  .\Release-NetJump.ps1 -Version 1.2.0 -ReleaseNotes "Phase A+B+C of the v1.2 roadmap shipped."

.EXAMPLE
  # Preview without publishing:
  .\Release-NetJump.ps1 -Version 1.3.0 -DryRun
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^\d+\.\d+\.\d+$')] [string]$Version,
    [string]$ReleaseNotes,
    [switch]$SkipSmokeTest,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# Resolve tool paths.
$gh = @(
    "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\GitHub.cli_Microsoft.Winget.Source_8wekyb3d8bbwe\bin\gh.exe"
    'C:\Users\GameSpace\AppData\Local\Microsoft\WinGet\Packages\GitHub.cli_Microsoft.Winget.Source_8wekyb3d8bbwe\bin\gh.exe'
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $gh) {
    $cmd = Get-Command gh -ErrorAction SilentlyContinue
    if ($cmd) { $gh = $cmd.Source }
}
if (-not $gh) { throw "gh CLI not found. Install with: winget install GitHub.cli" }

$iscc = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    'C:\Users\GameSpace\AppData\Local\Programs\Inno Setup 6\ISCC.exe'
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup not found. Install with: winget install JRSoftware.InnoSetup" }

# 1. Bump version in NetJump.iss.
$issPath = Join-Path $PSScriptRoot 'NetJump.iss'
if (-not (Test-Path $issPath)) { throw "NetJump.iss not found at $issPath" }
$iss = Get-Content -LiteralPath $issPath -Raw
if ($iss -notmatch '#define\s+MyAppVersion\s+"(?<v>\d+\.\d+\.\d+)"') {
    throw "Couldn't find MyAppVersion in NetJump.iss"
}
$current = $matches['v']
if ($current -eq $Version) {
    Write-Warning "MyAppVersion is already $Version. Nothing to bump."
} elseif ($current -gt $Version) {
    throw "Target version $Version is lower than current $current. Refusing to downgrade."
} else {
    Write-Host "Bumping MyAppVersion: $current -> $Version"
    $iss = $iss -replace '(#define\s+MyAppVersion\s+")(\d+\.\d+\.\d+)(")', "`${1}$Version`${3}"
    Set-Content -LiteralPath $issPath -Value $iss -Encoding UTF8
}

# 2. Parse-validate main script.
Write-Host 'Parse-validating NetJump-Dashboard.ps1...'
$errs = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'NetJump-Dashboard.ps1'), [ref]$null, [ref]$errs)
if ($errs -and $errs.Count -gt 0) {
    $errs | Select-Object -First 5 | ForEach-Object { Write-Error "$($_.Extent.StartLineNumber): $($_.Message)" }
    throw "Parse errors in NetJump-Dashboard.ps1. Aborting release."
}
Write-Host '  OK'

# 3. Headless -Json smoke test.
if (-not $SkipSmokeTest) {
    Write-Host 'Running -Json smoke test...'
    $tmp = New-TemporaryFile
    $err = New-TemporaryFile
    $p = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'NetJump-Dashboard.ps1'),'-Json' `
        -RedirectStandardOutput $tmp.FullName -RedirectStandardError $err.FullName `
        -PassThru -Wait -WindowStyle Hidden
    if ($p.ExitCode -ne 0) {
        $stderr = Get-Content $err.FullName -Raw
        throw "Headless smoke test failed (exit $($p.ExitCode)). STDERR: $stderr"
    }
    Remove-Item $tmp.FullName, $err.FullName -Force -ErrorAction SilentlyContinue
    Write-Host '  OK'
} else {
    Write-Host 'Skipping smoke test (-SkipSmokeTest).'
}

# 4. Rebuild installer.
Write-Host "Building installer via ISCC..."
& $iscc $issPath
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE" }
$installer = Join-Path $PSScriptRoot ("Installer\NetJump-Setup-$Version.exe")
if (-not (Test-Path $installer)) { throw "Expected installer not found at $installer" }
Write-Host "  Built $installer ($([int]((Get-Item $installer).Length / 1024)) KB)"

if ($DryRun) {
    Write-Host "`nDry-run complete. No git commits / push / gh release performed." -ForegroundColor Yellow
    Write-Host "  Updated NetJump.iss MyAppVersion to $Version"
    Write-Host "  Built installer: $installer"
    return
}

# 5. git commit + tag.
Write-Host "git commit + tag v$Version..."
& git -c user.email=recordscontent@gmail.com -c user.name="NetJump" add NetJump.iss
& git -c user.email=recordscontent@gmail.com -c user.name="NetJump" commit -m ("Release v$Version") | Out-Null
& git tag -a "v$Version" -m "NetJump v$Version" | Out-Null

# 6. Push branch + tag.
Write-Host "git push origin main + v$Version..."
& git push origin main
& git push origin "v$Version"

# 7. gh release create.
$notes = if ($ReleaseNotes) { $ReleaseNotes } else { "See [CHANGELOG.md](CHANGELOG.md) for the full feature list shipped in v$Version." }
Write-Host "gh release create v$Version..."
& $gh release create "v$Version" $installer --title "NetJump $Version" --notes $notes
if ($LASTEXITCODE -ne 0) { throw "gh release create failed (exit $LASTEXITCODE). Tag was pushed; re-run with: gh release create v$Version $installer --title 'NetJump $Version' --notes '...'" }

Write-Host "`nRelease v$Version published." -ForegroundColor Green
Write-Host "  https://github.com/thecontentstudios/NetJump/releases/tag/v$Version"
