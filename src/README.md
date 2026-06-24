# NetJump source modules

This directory is the **target** for the module-split work tracked in
the [v1.2 roadmap](../CHANGELOG.md). The goal:

- Today: `NetJump-Dashboard.ps1` is one ~19k-line file. Hard to navigate,
  hard to diff cleanly in PRs, hard to lint per-section.
- Future: each module here is a focused ~1-2k-line `.ps1` file.
  `Build-NetJump.ps1` concatenates them in dependency order to produce
  the single distributable. Same one-file ship, vastly better dev story.

## Module layout (planned)

| File | Contents (approximate) |
|---|---|
| `00-header.ps1` | SYNOPSIS, `param()`, `Add-Type -AssemblyName ...`, `Test-Admin` |
| `01-state.ps1` | `$script:State` initialization, settings load/save, mutex |
| `10-helpers.ps1` | Color brushes, format functions, small utility wrappers |
| `15-pktmon.ps1` | pktmon rolling capture + flap dossier writers |
| `20-intel-threat.ps1` | Threat-intel feed importer + cache + `Test-IpThreat` (IPv4 + IPv6) |
| `21-intel-vuln-drivers.ps1` | loldrivers.io fetcher + `Scan-ByovdDrivers` |
| `22-intel-geoip.ps1` | DB-IP Lite fetcher + `Get-IpCountry` |
| `30-scan-engine.ps1` | `Update-Findings` + scan orchestration |
| `31-scan-checks.ps1` | Per-category scan functions (Adapter, Power, Driver, DNS, Auth, ...) |
| `40-fixes.ps1` | Fix picker, audit log, three-tier classifier |
| `50-flows.ps1` | `Sample-Flows`, FLOWS tab logic |
| `51-processes.ps1` | `ProcScanScript`, EDR ancestry walker |
| `52-persistence.ps1` | Persistence scan + disable handlers |
| `60-http-server.ps1` | HttpListener + `/metrics` + `/status.json` etc. |
| `70-retrans-investigator.ps1` | Pattern analysis + dialog |
| `80-ui-xaml.ps1` | The big WPF XAML block + control registration |
| `90-events-tick.ps1` | DispatcherTimer, `Tick`, sub-tickers, schedulers |
| `99-cli-entry.ps1` | Tail: `if ($CliMode) {...}` + `$window.ShowDialog()` |

## Build process

```powershell
.\Build-NetJump.ps1
# Reads src/*.ps1 in lexical order, concatenates, writes NetJump-Dashboard.ps1
# Parse-validates the output. Headless smoke-tests.
```

## Migration approach (incremental, low-risk)

Until the full migration is complete, the existing `NetJump-Dashboard.ps1`
is the source of truth. New features can live in `src/` from day one by
having the main file **dot-source** them at the end of script load:

```powershell
# At the bottom of NetJump-Dashboard.ps1 (before $window.ShowDialog()):
$srcDir = Join-Path $PSScriptRoot 'src'
if (Test-Path $srcDir) {
    Get-ChildItem $srcDir -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
        try { . $_.FullName } catch { Write-Host "Failed to load $($_.Name): $_" }
    }
}
```

This means:

- **New features**: write them as `src/NN-short-name.ps1` from the start.
  Copy `src/TEMPLATE-feature.ps1` and fill in. The dot-source picks them
  up automatically.
- **Existing features**: extract one at a time. Cut the section out of
  the main file, paste into `src/NN-name.ps1`, run `Build-NetJump.ps1
  -SmokeTest`. If parse + headless pass, commit.
- **Distribution**: still one `.ps1` file. The installer bundles the
  main file; `src/` is dev-only and ships in the Git tree but the
  Inno Setup installer doesn't include it (intentional — end users
  don't need it).

Once enough is extracted that the main file is mostly orchestration,
flip `Build-NetJump.ps1` to be the canonical builder: it concatenates
`src/*.ps1` in lexical order into a fresh `NetJump-Dashboard.ps1` for
release.

## Naming convention

| Prefix | Role |
|---|---|
| `00-` | Script header, params, Add-Type assemblies, `Test-Admin` |
| `01-09` | Script-level state ($script:State, settings, mutex) |
| `10-19` | Helpers (colors, formatters, small utilities) |
| `20-29` | Threat-intel / GeoIP / vuln-driver feed plumbing |
| `30-39` | Scan engine + per-category scan checks |
| `40-49` | Fix engine, audit log, fix picker |
| `50-59` | FLOWS, processes, persistence sampling |
| `60-69` | HTTP server, Prometheus, webhooks |
| `70-79` | Retransmit investigator, dialog windows |
| `80-89` | UI XAML, control registration |
| `90-99` | DispatcherTimer, Tick, schedulers |
| `99-` | CLI entry, ShowDialog tail |

Don't sweat the exact numbering — leave gaps between files so new ones
can be inserted without renumbering.

## Why not just refactor in place?

The `NetJump-Dashboard.ps1` file currently parses cleanly, runs headless,
and is the distributable users download via the installer. A bad
refactor breaks the install. The build-script approach lets us migrate
piece-by-piece while keeping the single-file `.ps1` the only thing users
ever see.
