<#
.SYNOPSIS
  Build NetJump-Dashboard.ps1 from per-module sources under src/.

.DESCRIPTION
  Concatenates src/*.ps1 in lexical filename order, writes the result to
  NetJump-Dashboard.ps1, parse-validates the output, and (with -SmokeTest)
  runs `-Json` headless to confirm the rebuilt script still executes end
  to end.

  The single-file shipping model is preserved: users still only ever see
  the one `NetJump-Dashboard.ps1` file (and the installer that bundles
  it). The src/ tree is for developers only.

.PARAMETER SrcDir
  Source directory containing the module .ps1 files. Defaults to .\src.

.PARAMETER Output
  Destination single-file script. Defaults to .\NetJump-Dashboard.ps1.

.PARAMETER SmokeTest
  After writing the output, run it with -Json and verify exit 0 + JSON
  parse. Adds ~15 seconds.

.PARAMETER SkipPreserve
  By default the existing NetJump-Dashboard.ps1 is backed up to
  .build-backup-{stamp}.ps1 before being overwritten. -SkipPreserve
  disables that.

.EXAMPLE
  # Standard rebuild + smoke test:
  .\Build-NetJump.ps1 -SmokeTest

.EXAMPLE
  # Rebuild to a different path (for diff/comparison):
  .\Build-NetJump.ps1 -Output .\out.ps1 -SkipPreserve

.NOTES
  STATUS: scaffolding. Until the migration to src/ is complete, the
  existing 19k-line NetJump-Dashboard.ps1 is treated as the source of
  truth. This script will refuse to overwrite a non-trivial output file
  if no src/ files exist yet.
#>

[CmdletBinding()]
param(
    [string]$SrcDir = (Join-Path $PSScriptRoot 'src'),
    [string]$Output = (Join-Path $PSScriptRoot 'NetJump-Dashboard.ps1'),
    [switch]$SmokeTest,
    [switch]$SkipPreserve
)

$ErrorActionPreference = 'Stop'

# Discover source modules. Lexical sort, .ps1 only, README.md and similar excluded.
$srcFiles = @(Get-ChildItem -Path $SrcDir -Filter '*.ps1' -ErrorAction SilentlyContinue | Sort-Object Name)
if ($srcFiles.Count -eq 0) {
    Write-Warning "No .ps1 modules found in $SrcDir."
    Write-Warning "Migration to src/ is still in progress; NetJump-Dashboard.ps1 remains the source of truth."
    Write-Warning "See src\README.md for the migration plan."
    exit 0
}

Write-Host "Concatenating $($srcFiles.Count) module(s) from $SrcDir..."
$sb = New-Object System.Text.StringBuilder
foreach ($f in $srcFiles) {
    Write-Host ("  + {0}" -f $f.Name)
    [void]$sb.AppendLine("# === src/$($f.Name) ===")
    [void]$sb.Append((Get-Content -LiteralPath $f.FullName -Raw))
    if (-not ((Get-Content -LiteralPath $f.FullName -Raw).EndsWith("`n"))) { [void]$sb.AppendLine() }
}
$combined = $sb.ToString()

# Parse-validate before we overwrite anything.
$parseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput($combined, [ref]$null, [ref]$parseErrors)
if ($parseErrors -and @($parseErrors).Count -gt 0) {
    Write-Error "Parse-validation failed on combined output. First error: $($parseErrors[0].Extent.StartLineNumber):$($parseErrors[0].Extent.StartColumnNumber) $($parseErrors[0].Message)"
    exit 2
}

# Backup the existing output before overwrite.
if ((Test-Path $Output) -and -not $SkipPreserve) {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $bak = "$Output.build-backup-$stamp"
    Copy-Item -LiteralPath $Output -Destination $bak -Force
    Write-Host "Backed up existing output to $bak"
}

Set-Content -LiteralPath $Output -Value $combined -Encoding UTF8
$sizeKb = [int]((Get-Item $Output).Length / 1024)
Write-Host "Wrote $Output ($sizeKb KB)"

if ($SmokeTest) {
    Write-Host "Running -Json smoke test..."
    $tmp = New-TemporaryFile
    $err = New-TemporaryFile
    $p = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$Output,'-Json' `
        -RedirectStandardOutput $tmp.FullName -RedirectStandardError $err.FullName `
        -PassThru -Wait -WindowStyle Hidden
    Write-Host "  Exit code: $($p.ExitCode)"
    $stderr = Get-Content $err.FullName -Raw -ErrorAction SilentlyContinue
    if ($stderr) { Write-Warning "STDERR: $stderr" }
    $stdout = Get-Content $tmp.FullName -Raw -ErrorAction SilentlyContinue
    try {
        $stdout | ConvertFrom-Json | Out-Null
        Write-Host '  JSON output parses cleanly.' -ForegroundColor Green
    } catch {
        Write-Error "JSON parse failed: $_"
        exit 3
    }
    Remove-Item $tmp.FullName, $err.FullName -Force -ErrorAction SilentlyContinue
}
