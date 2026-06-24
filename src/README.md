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

## Migration approach

Each file is extracted in a separate commit, one at a time:

1. Copy the target lines to `src/NN-name.ps1`.
2. Run `Build-NetJump.ps1` to regenerate `NetJump-Dashboard.ps1`.
3. Diff the regenerated file against the prior one — should be byte-identical
   except for the section that moved (which now lives in `src/`).
4. Headless smoke test passes → commit.

Until all modules are extracted, the build script must be re-runnable
against partial state (some sections in `src/`, others still inline in
the main file). Keep `99-core-residual.ps1` as the catch-all for
unmigrated sections.

## Why not just refactor in place?

The `NetJump-Dashboard.ps1` file currently parses cleanly, runs headless,
and is the distributable users download via the installer. A bad
refactor breaks the install. The build-script approach lets us migrate
piece-by-piece while keeping the single-file `.ps1` the only thing users
ever see.
