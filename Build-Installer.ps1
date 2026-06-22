<#
.SYNOPSIS
  Build the NetJump Inno Setup installer, optionally signing it with Authenticode.

.DESCRIPTION
  Wraps ISCC.exe (Inno Setup compiler). If a code-signing certificate is available, also signs
  the installer .exe with signtool.exe so users don't see "Unknown publisher" in SmartScreen.

  Signing is OPT-IN via environment variables:
    NETJUMP_SIGN_CERT_PATH    Full path to a .pfx file (PKCS#12 cert + private key)
    NETJUMP_SIGN_CERT_PASS    Password for the .pfx (read at runtime, never logged)
    NETJUMP_SIGN_TIMESTAMP    RFC 3161 timestamp URL (default: http://timestamp.digicert.com)

  Without those, the installer is built unsigned (same as today). With them, the installer is
  signed at the end of the build step.

  Acquire a cert from Sectigo / DigiCert / SSL.com (typical: ~$200/yr OV, ~$400/yr EV with token).

.EXAMPLE
  # Plain unsigned build (default).
  .\Build-Installer.ps1

.EXAMPLE
  # Signed build - reads $env:NETJUMP_SIGN_CERT_PATH and $env:NETJUMP_SIGN_CERT_PASS.
  $env:NETJUMP_SIGN_CERT_PATH = 'C:\certs\netjump-codesign.pfx'
  $env:NETJUMP_SIGN_CERT_PASS = (Read-Host -AsSecureString 'cert password') |
    ConvertFrom-SecureString -AsPlainText
  .\Build-Installer.ps1
#>

[CmdletBinding()]
param(
    [string]$IssFile = 'NetJump.iss',
    [switch]$SkipSign
)

$ErrorActionPreference = 'Stop'

function Find-Iscc {
    $candidates = @(
        'C:\Users\GameSpace\AppData\Local\Programs\Inno Setup 6\ISCC.exe'
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
    )
    foreach ($p in $candidates) { if (Test-Path $p) { return $p } }
    $cmd = Get-Command iscc -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "Inno Setup not found. Install with: winget install JRSoftware.InnoSetup"
}

function Find-Signtool {
    # signtool ships with the Windows SDK. Look in common SDK install dirs.
    $sdkRoots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
        "$env:ProgramFiles\Windows Kits\10\bin"
    )
    foreach ($root in $sdkRoots) {
        if (-not (Test-Path $root)) { continue }
        $found = Get-ChildItem -Path $root -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match 'x64\\signtool.exe$' } |
            Sort-Object { $_.VersionInfo.FileVersion } -Descending |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

# ---- Compile ----
$iscc = Find-Iscc
Write-Host "Using ISCC: $iscc"
& $iscc $IssFile
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE" }

# Locate the produced installer.
$installer = Get-ChildItem 'Installer\NetJump-Setup-*.exe' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $installer) { throw "No installer found in Installer\" }
Write-Host "Built: $($installer.FullName)  ($([int]($installer.Length/1024)) KB)"

# ---- Sign (optional) ----
if ($SkipSign) {
    Write-Host "Signing skipped (-SkipSign). Installer is unsigned." -ForegroundColor Yellow
    return
}

$certPath = $env:NETJUMP_SIGN_CERT_PATH
$certPass = $env:NETJUMP_SIGN_CERT_PASS
$tsUrl    = if ($env:NETJUMP_SIGN_TIMESTAMP) { $env:NETJUMP_SIGN_TIMESTAMP } else { 'http://timestamp.digicert.com' }

if (-not $certPath -or -not $certPass) {
    Write-Host "No signing cert configured (NETJUMP_SIGN_CERT_PATH / _PASS not set)." -ForegroundColor Yellow
    Write-Host "Installer is unsigned. SmartScreen will warn users on first launch." -ForegroundColor Yellow
    Write-Host "  To enable signing, see the comment block at the top of Build-Installer.ps1." -ForegroundColor DarkGray
    return
}

if (-not (Test-Path $certPath)) {
    throw "Cert path NETJUMP_SIGN_CERT_PATH does not exist: $certPath"
}

$signtool = Find-Signtool
if (-not $signtool) {
    throw "signtool.exe not found. Install the Windows 10/11 SDK (Visual Studio Installer -> Individual components -> Windows 10 SDK)."
}
Write-Host "Using signtool: $signtool"

# Sign with SHA-256 + RFC 3161 timestamp (modern signing convention).
& $signtool sign `
    /f $certPath `
    /p $certPass `
    /fd SHA256 `
    /tr $tsUrl /td SHA256 `
    /d 'NetJump installer' `
    /du 'https://github.com/thecontentstudios/NetJump' `
    $installer.FullName

if ($LASTEXITCODE -ne 0) { throw "signtool sign failed with exit code $LASTEXITCODE" }

# Verify the signature took.
& $signtool verify /pa $installer.FullName
if ($LASTEXITCODE -ne 0) { throw "Signature verification failed - the installer may be unusable" }

Write-Host "Installer signed and verified: $($installer.FullName)" -ForegroundColor Green
