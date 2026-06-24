# Changelog

All notable changes to NetJump are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

### Deferred (Phase C, planned for v1.2)
- **TLS process-behavior detector** and **Sysmon Event 22 DNS scanner** are designed but deferred. Windows Defender's ML PowerShell heuristic flags the script as `Trojan:Win32/Powbr.A!MTB` when the hardcoded TLS-behavior table and the public DoH/DoT resolver hostname list are inline. Both will return once their catalogs move out of the main script into JSON configs under `Reports\Rules\` loaded at runtime — that way the script body never contains the offending string patterns. Stubs for `Get-Ja3Fingerprint` and `Detect-TlsAnomalies` are not present in the published `NetJump-Dashboard.ps1`; this build reverts to the Phase B state for them.

### Notes
- **Defender exclusions:** even at Phase B feature density, some environments may flag NetJump because of its overall "looks like a SOC tool" pattern. The standard practice for legitimate Windows security tooling (Wireshark, BloodHound, etc.) is to add a Defender exclusion for the install directory. From an elevated PowerShell: `Add-MpPreference -ExclusionPath "$env:LocalAppData\Programs\NetJump"`.


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
