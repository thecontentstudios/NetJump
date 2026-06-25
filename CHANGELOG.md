# Changelog

All notable changes to NetJump are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added (v1.3 roadmap)
- **Module migration kickoff**: GeoIP block (`Update-GeoIpDatabase`, `Load-GeoIpDatabase`, `Get-IpCountry`) extracted to `src/22-geoip.ps1` as the proof-of-pattern for the gradual `src/` migration. The dot-source loader moved from end-of-file to right after `Add-Type` so extracted modules' functions are visible to the main file's init code. Source-of-truth is the main `NetJump-Dashboard.ps1` — `src/` files dot-source on top.
- **Defender exclusion offered at install** — `NetJump.iss` Tasks page now has an opt-in "Add Microsoft Defender exclusion for the install folder (recommended)" checkbox. The `[Run]` section calls `Add-MpPreference -ExclusionPath` for `{app}` when ticked; the `[UninstallRun]` removes it cleanly. Mirrors the standard practice for legitimate SOC tooling (Wireshark / BloodHound).
- **Notification grouping** — `Add-Event` now coalesces repeat warn/info messages within a 30-second window. First fire passes through unchanged; subsequent identical events are silenced until the window closes, then emit a single "(N similar events suppressed since HH:mm:ss)" rollup. Prevents retransmit storms or beacon-detection bursts from drowning the LIVE EVENTS feed.
- **Keyboard shortcuts cheatsheet** (`src/85-keyboard-shortcuts.ps1`). View → "Keyboard shortcuts…" or **Ctrl+/** opens a polished list of every `Ctrl+X` / F-key binding grouped by category.
- **Remove all NetJump-managed firewall rules** — Remediate menu → "Remove all NetJump-managed firewall rules…" enumerates every rule whose Description starts with `NetJump-managed` (every quick-block + process-block) and deletes them in one shot with a confirmation summary.
- **HISTORY tab Wi-Fi roaming timeline** (`src/82-history-wifi-roaming.ps1`). Renders the `$script:WifiBssidHistory` ring buffer as colored dots on a 24-hour horizontal canvas; color = signal-% (green/amber/red); hover for SSID + BSSID + signal. Card is `Collapsed` when the active adapter is wired.
- **Snapshot diff viewer** (`src/72-snapshot-diff.ps1`). Diagnose menu → "Diff two snapshots…" picks two JSONs from `Reports\Snapshots\`, renders three buckets side-by-side: ONLY IN A (resolved), ONLY IN B (appeared), IN BOTH (persisted).
- **Connection ledger search** (`src/73-ledger-search.ps1`). Export menu → "Search ledger…" opens a sortable / filterable `ListView` over `$script:Ledger` with GeoIP country and threat-intel tag enrichment per row. Type-as-you-go filter; export visible rows as CSV.
- **Latency anomaly detection** — `Tick-AutoEmitters` checks Gateway and Cloudflare ping histories every 60 seconds; if the last-5-sample mean exceeds 2× the overall baseline AND ≥ 50 ms absolute, emits an INFO event. Catches ISP / neighbor-congestion spikes before they become flaps.
- **`Release-NetJump.ps1`** — single-shot release automation. Bumps `MyAppVersion` in `NetJump.iss`, parse-validates the main script, runs the headless smoke test (skippable), rebuilds the installer via ISCC, commits + tags + pushes, and `gh release create`s with the installer attached. `-DryRun` for preview.
- **Defender exclusion audit** (`src/31-security-audits.ps1`). `Get-DefenderExclusionFindings` reads `Get-MpPreference` and flags `ExclusionPath` entries under user-writable directories (AppData / Temp / ProgramData / Public / Downloads), `ExclusionProcess` entries pointing at suspicious binaries, and `ExclusionExtension` entries for executable file types (FAIL — almost certainly malicious config).
- **LSA Authentication Package check** (`src/31-security-audits.ps1`). `Get-LsaAuthPackageFindings` reads `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages` and `Notification Packages`, flags anything not in the curated Microsoft allowlist as WARN. Classic credential-theft persistence (password filter DLL / mimikatz) lives here.

### Added (v1.2 roadmap)
- **Process integrity level** on the PROCESSES tab. P/Invoke `OpenProcessToken` + `GetTokenInformation(TokenIntegrityLevel)`; maps the SID's last RID to a color-coded pill (Untrusted / Low / Medium / Medium+ / High / System / Protected).
- **MITRE ATT&CK coverage panel** (View → MITRE ATT&CK coverage…). Lists every technique NetJump can detect, grouped by tactic, with green/gray pills indicating coverage status. Hover for the detection rule name.
- **Wi-Fi roaming history** — ring buffer of BSSID changes; `Detect-WifiRoaming` flags 3+ BSSIDs in 5 min as a roaming storm (mesh thrashing / rogue-AP indicator).
- **Fix-script export** — Fix Picker dialog now has an "Export selected as .ps1" button. Writes a fully-commented, auditable PowerShell script with `-WhatIf` support.
- **Subnet topology discovery** (Diagnose → Subnet scan…). Fan-out ICMP across the local /24, read the populated ARP table, reverse-DNS each. Saves snapshot to `Reports\Topology\`. Refuses to run on /16 or wider to avoid ICMP storms.
- **DLL hijacking detector** — `Get-SysmonDllHijackFindings` parses Sysmon Event 7 (ImageLoad) for DLLs loaded from user-writable paths (AppData / Temp / ProgramData) that have a legitimate `System32` counterpart of the same name. Classic search-order hijack signature.
- **Persistence diffing** — daily baselines under `Reports\Baselines\persistence-YYYY-MM-DD.json`; NEW persistence entries (entries not in the most-recent older baseline) emit a high-priority WARN event.
- **Process-level firewall rules** — PROCESSES right-click → "Block this process's outbound traffic" → for 1 hour / 24 hours / permanently. Reversible via wf.msc or `Remove-NetFirewallRule -DisplayName 'NetJump block process *'`.
- **Quick-block timed IP rules** — FLOWS right-click → "Quick-block this remote IP" → 10 min / 1 hour / 24 hours / permanent. Per-tick janitor automatically removes rules past their expiry timestamp.
- **Sub-second flap detection** via `System.Net.NetworkInformation.NetworkChange` events. Replaces 2-second polling baseline with sub-100ms link-state events. Thread-safe `ConcurrentQueue` decouples the event callback (worker thread) from the UI thread that consumes them.
- **Module-split infrastructure**: `NetJump-Dashboard.ps1` now dot-sources `src/*.ps1` at startup, so new features can live in `src/NN-feature.ps1` from day one without rebuilding. `src/TEMPLATE-feature.ps1` is the copy-this starter; `src/README.md` documents the naming convention + migration recipe. Single-file distribution preserved (installer doesn't bundle `src/`).
- **Light theme** (existed in earlier code) — confirmed and documented; View → Theme menu toggles dark/light, persisted across launches.

### Added (v1.1 roadmap, Phases A and B)
- **Wi-Fi metrics** in LOCAL NET INFO sidebar when on a wireless adapter (SSID, BSSID, channel, signal % + estimated dBm, auth/cipher) via `netsh wlan show interfaces`.
- **Auto-trigger first scan on launch** after a configurable delay (default 8 seconds). Settings: `AutoScanOnLaunch`, `AutoScanDelaySec`.
- **Differential scan view** on DIAGNOSTICS tab: new ComboBox filters by NEW / RESOLVED (rendered as green ghost rows) / Changed since the previous scan.
- **GeoIP database** auto-fetched monthly from DB-IP Lite (~330k IPv4 ranges). Binary-search `Get-IpCountry`; `Get-IpLabel` now falls back to GeoIP when no cloud cluster matches.
- **Webhook templates** per service: `generic` (default JSON), `slack` (blocks + markdown), `discord` (colored embeds), `ntfy` (plain body + headers). `Send-FlapWebhook` routes through the new `Send-WebhookEvent` helper.
- **Custom-rule sandbox**: each `Reports\Rules\*.ps1` is parse-validated, run in a child runspace with a 5-second timeout, and result-validated. Bad rules can no longer crash scans.
- **Threshold-triggered auto-scan**: when TCP retrans > N/s for M seconds, auto-fire `Update-Findings` and optionally open the Retransmit Investigator. Cooldown prevents re-trigger storms.
- **EDR-style process ancestry** on the PROCESSES tab. Walks `Win32_Process` parent chain up to 6 levels; surfaces as `explorer(1) -> svchost(820) -> ...`. Suspicious chains render in red.
- **Jitter-tolerant beacon detection**: three orthogonal detectors run in parallel (CV, MAD/median, lag-1 autocorrelation). Catches randomized-interval beacons that CV-only misses.
- **DNS sinkhole subscription**: opt-in mode that maintains a NetJump-managed section of the system hosts file from a public blocklist (default: StevenBlack/hosts). Atomic write + automatic backup to `Reports\Sinkhole\`.
- **Replay mode**: every scan snapshots state to `Reports\Snapshots\snapshot-*.json` (rolling cap 30). Diagnose menu → Replay snapshot... reloads any snapshot, prefixes findings with `[REPLAY]`, status bar shows a purple banner.
- **Build script + module-split scaffolding** (`Build-NetJump.ps1` + `src/`): infrastructure for the planned migration from the monolithic `NetJump-Dashboard.ps1` into focused per-module `.ps1` files. The build script concatenates `src/*.ps1` in dependency order and parse-validates. Migration itself is incremental.

### Added (Phase C)
- **TLS process-behavior detector**: `Detect-TlsAnomalies` lists every (process, remote IP:443) pair from `Get-NetTCPConnection` and grades it against a built-in expectation table. Processes that should never make outbound TLS (`cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`) raise a `FAIL` finding with the `c2-suspicious` MITRE tag; unknown TLS-active processes with 3+ destinations raise an `INFO` finding for triage.
- **JA3 framework stub**: `Get-Ja3Fingerprint` exists with the right shape (`param([byte[]]$ClientHelloBytes)` → `@{Ja3; Md5}`) so the full pktmon ClientHello parser is a drop-in addition without rewriting callers.
- **Sysmon Event 22 (DnsQuery) integration**: `Get-SysmonDnsFindings` parses the Microsoft-Windows-Sysmon/Operational log when Sysmon is running. Three finding types: (1) `WARN` per process+IP combination when a DNS resolution maps to a threat-intel-flagged address; (2) `WARN` when a non-browser process resolves a public DoH endpoint (`cloudflare-dns.com`, `dns.google`, `dns.quad9.net`, etc.); (3) `INFO` top-5 DNS-active processes for triage.

### Notes
- **Defender exclusions:** NetJump's feature mix (process enumeration + TLS introspection + Sysmon parsing + hosts-file manipulation + threat-intel correlation) looks like a SOC tool — which is exactly what it is. Windows Defender's ML PowerShell heuristic (`Trojan:Win32/Powbr.A!MTB`) flags the script under default real-time protection. This is the same false-positive pattern that hits Wireshark, BloodHound, and other legitimate Windows security tooling. The standard practice is to add a Defender exclusion for the install directory. From an elevated PowerShell:
  ```powershell
  Add-MpPreference -ExclusionPath "$env:LocalAppData\Programs\NetJump"
  Add-MpPreference -ExclusionPath "$env:ProgramFiles\NetJump"
  ```
  Or via Settings → Update & Security → Windows Security → Virus & threat protection → Manage settings → Add or remove exclusions → Add an exclusion → Folder.


## [1.0.1] - 2026-06-22

### Added
- **Installer polish**: Start Menu shortcut is now unconditional (was opt-in in 1.0.0).
- **Uninstaller prompt**: asks whether to also delete the `Reports\` data folder (audit log, ledger, threat-intel cache, flap dossiers); defaults to No to prevent accidental forensic-history loss.
- **Custom installer icon** (`netjump.ico`) used by the installer `.exe`, shortcuts, and the Apps & Features uninstall entry.
- **Embedded version info** in the installer `.exe` properties (`ProductName`, `ProductVersion`, `CompanyName`, `FileDescription`).
- **Restart Manager integration** to close NetJump cleanly during install / uninstall.
- **GitHub publication**: source under MIT license, installer attached as release asset.

### Application changes since 1.0.0
- **MS Vulnerable Driver Blocklist (loldrivers.io)** ingested weekly via background job; ~460 dynamic entries merged with the curated 27-driver list. Uses `JavaScriptSerializer` instead of `ConvertFrom-Json` (the feed JSON has case-collision keys that PowerShell 5.1 chokes on).
- **Auto-refresh scheduler** for threat-intel + vulnerable-driver feeds, with ±25% jitter so multiple installs don't hammer feed mirrors simultaneously. Defaults: 12 h for threat-intel, 168 h (weekly) for vuln-drivers.
- **IPv6 threat-intel** — `BigInteger`-backed CIDR matching, full v4 + v6 parity in `Test-IpThreat`, feed parser, ledger, and `Load`/`Save-ThreatIntel`.
- **Prometheus `/metrics` exporter** added to the existing `localhost:8765` HTTP server. 18 metric types with `host=` labels (adapter state, link speed, ping RTT, retransmits, finding counts by severity, threat-intel sizes, vuln-driver count, cache ages, ledger size, beacons).
- **Scheduled re-scan + rolling digest** — settings-driven interval (min 5 min), optional per-cycle HTML + CSV write to `Reports\Digests\`.
- **Settings dialog ADVANCED section** with toggles for vulnerable-driver list, scheduled scan, and digest writer. Changes apply immediately without restart.
- **README + APP-INFO** rewritten to document the HTTP API, scheduled scans, IPv6 coverage, and updated BYOVD / threat-intel rows.

### Distribution
- Inno Setup 6 installer builds to `Installer\NetJump-Setup-<version>.exe`.
- Per-user install default (`%LocalAppData%\Programs\NetJump\`, no UAC at install time); per-machine available via the elevation page.
- Sanity check blocks install if Windows PowerShell 5.1 is missing.

## [1.0.0] - 2026-06-22

### Added
- First packaged release. Bundles `NetJump-Dashboard.ps1`, `Run-NetJump.bat`, `README.md`, and legacy `NetJump-Scan.ps1` / `NetJump-Monitor.ps1` (kept for reference).
- Inno Setup 6 installer (`NetJump-Setup-1.0.0.exe`, ~2.2 MB).
- Per-user install + opt-in desktop shortcut, opt-in Start Menu shortcut, post-install launch checkbox.

### Application baseline at 1.0.0
- ~21 diagnostic scan categories (link, counters, power, driver, NDIS filters, DNS, auth, hardening, BYOVD, threat-intel, beaconing, malware indicators, Sysmon, persistence, ARP, updates, custom rules, etc.).
- Three-tier fix engine (SAFE / MODERATE / DISRUPTIVE) with tamper-evident audit log.
- Continuous live monitoring: ping chart, sparkline counters, activity ribbon, tray icon, multi-target ping (up to 4 custom).
- Retransmit Investigator with pattern matching against known Windows recurring intervals (NetBIOS broadcast, TCP keepalive, SCCM check-in, GPO refresh, etc.).
- Local HTTP server with `/status.json`, `/health`, `/findings.json`, `/causes.json`, `/ledger.json`, and an HTML mini-dashboard at `/`.
- Headless modes: `-Json`, `-Headless`, `-DailyDigest`, `-Monitor` (long-running with Task Scheduler integration).
- pktmon-based 50 MB rolling packet capture saved automatically on flap events.
- STIX 2.1 export for SOAR/SIEM ingest.
- Custom-rules loader (drop `.ps1` files into `.\Reports\Rules\`).

[Unreleased]: https://github.com/thecontentstudios/NetJump/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/thecontentstudios/NetJump/releases/tag/v1.0.1
[1.0.0]: https://github.com/thecontentstudios/NetJump/releases/tag/v1.0.0
