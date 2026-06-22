# Changelog

All notable changes to NetJump are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
