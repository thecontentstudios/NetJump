# NetJump

**Real-time network + security HUD for Windows.**
Continuous link / NIC / DNS / threat-intel monitoring with one-click remediation, in a single PowerShell file.

---

## At a glance

- **What it is:** A live dashboard that watches your Ethernet adapter, DNS resolver, TCP retransmit rate, listening processes, persistence entries, and external connections — all at once. Surfaces anomalies as graded findings with one-line fixes.
- **What it solves:** Originally built to chase intermittent ethernet flaps. Grew into a SOC-lite tool for spotting beaconing C2, vulnerable kernel drivers, malicious persistence, and DNS hijacks on a single Windows machine.
- **How it ships:** Single PowerShell file (`NetJump-Dashboard.ps1`) + a self-elevating launcher (`Run-NetJump.bat`). No install required for the script. The Inno Setup installer (`NetJump-Setup-1.0.1.exe`) is a convenience wrapper that adds Start Menu integration.
- **License:** MIT — see [LICENSE](LICENSE).
- **Source:** https://github.com/thecontentstudios/NetJump

---

## Feature highlights

### Continuous live monitoring
| Element | What it shows |
|---|---|
| Link-state indicator | A/B/C/D/F health grade + glowing dot (green = Up, red = Down, amber = transitional) |
| 6 metric tiles | STATUS · LINK SPEED · UPTIME · FLAPS · LAST INCIDENT · TOP CAUSE |
| 60-second ping chart | Gateway + Cloudflare + up to 4 user-configured targets, color-coded |
| Sparkline strip | RX errors / RX discards / throughput / TCP retransmits / max-core CPU% / memory% — 60-sample histories |
| Activity ribbon | 60-minute event timeline (flaps, scans, fixes, alerts as colored dots) |
| LOCAL NET INFO sidebar | Adapter, IPv4, mask, gateway, MAC, DNS, DHCP, lease, public IP, MTU, MSS, plus RESET buttons |
| Tray icon + balloon notifications | Mute toggle, run-scan, pause-events, all from the tray context menu |

### ~20-category diagnostic scan
Click **▶ RUN NET DIAGNOSTIC** to scan. Each finding tagged **OK / INFO / WARN / FAIL** with a one-line fix.

- **Adapter / Link / Counters / Power management / Driver / NDIS filters / Cable health**
- **DNS** — resolver latency, broken resolution, DNS-over-HTTPS detection
- **Auth** — NTLMv1, Kerberos RC4 (Kerberoasting), failed-logon spikes, privileged logon, explicit credential use
- **Hardening posture** — SMBv1, LLMNR, NBT-NS, WDigest cleartext, PowerShell v2, BitLocker, Defender, Credential Guard
- **BYOVD** — 27 hand-curated vulnerable drivers **plus** ~460 entries auto-refreshed weekly from loldrivers.io
- **Threat intel** — IPv4 + IPv6 CIDR ranges and bare IPs from configurable feeds (FireHOL Level 1, Feodo Tracker by default), auto-refresh every 12 h with ±25 % jitter
- **Beaconing** — periodicity detection on connection patterns (CV-based)
- **Malware indicators** — hosts-file tampering, system proxy hijack, Temp/AppData processes, stale Defender signatures
- **Sysmon** — installation + service status
- **Persistence** — Run-keys, scheduled tasks, services, IFEO debugger, COM hijack, AppInit_DLLs
- **ARP** — duplicate-MAC spoofing
- **Updates** — recent Windows hotfixes (a fresh cumulative often ships a NIC driver)
- **Custom rules** — drop a `.ps1` under `.\Reports\Rules\` and it runs on every scan

### Live tabs
- **DIAGNOSTICS** — findings grouped by severity, inline filter + search, ATT&CK technique tags
- **PROCESSES** — network-active processes with risk score; right-click for kill / block-remote-IP / open binary / details
- **TRAFFIC** — per-protocol rate sparklines (TCP/UDP/ICMP) + RX/TX direction + top-talker list with per-process I/O
- **FLOWS** — real-time TCP/UDP socket diff stream (NOW / NEW / STATE / CLOSED rows every 2 s)
- **PERSISTENCE** — autorun entries with disable/open-binary actions
- **HISTORY** — heatmap of past flaps + ledger of remote endpoints with geo / cloud-provider / threat-intel tags
- **DNS** — resolution log with TTL / RTT / hit count; right-click for traceroute / TLS probe / WHOIS / VirusTotal / AbuseIPDB

### Retransmit Investigator
When TCP retransmits cross HIGH/CRITICAL, a panel slides in listing suspect connections. The **Investigator** dialog shows:
- Cumulative-since-boot ratio + rolling 60s ratio with verdict
- 60-sample trend sparkline + stability metric
- **Pattern Analysis** — detects CLOCKWORK / PERIODIC / IRREGULAR cycles, matches against known Windows intervals (NetBIOS broadcast, TCP keepalive, SCCM check-in, GPO refresh, etc.)
- **Cause analysis** with confidence chips
- Action toolbar: Auto-fix SAFE / Open Fix Picker / Path Inspect / Probe MTU

### Apply Fixes (three-tier safety)
- **SAFE** — reversible, no service restarts. DNS flush, ARP flush, autotuning resets, hosts entries.
- **MODERATE** — service restarts, registry tweaks. Reviewable individually.
- **DISRUPTIVE** — TCP/IP stack reset, NIC restart. Per-action confirmation required.

**AUTO-APPLY ALL SAFE** runs every SAFE fix in one batch and starts a 10-minute verify watch that re-scans afterward to confirm issues cleared. Every fix is logged to a tamper-evident audit trail.

### Scheduled re-scans + digests
Settings → ADVANCED → enable scheduled diagnostic re-scan + pick an interval (5 min – 1440 min). Optional per-cycle HTML + CSV digest writer dumps to `Reports\Digests\`.

### Local HTTP API + Prometheus endpoint
Every launch starts a `localhost`-only HTTP server (port 8765 by default):

| Path | Purpose |
|---|---|
| `/` | Phone-friendly HTML dashboard, 5 s auto-refresh |
| `/status.json` | Full snapshot |
| `/findings.json` | Last-scan findings |
| `/causes.json` | Ranked root causes |
| `/ledger.json` | Top 50 connection ledger entries |
| `/health` | Plain text `OK` (200) or `DOWN` (503) — uptime probe |
| `/metrics` | **Prometheus exposition format** — 18 metric types with `host=` labels |

Drop into a homelab Grafana with one scrape config block. See README.md for the full metric list.

### Headless / unattended modes
- `-Headless` — console report, no UI
- `-Json` — JSON to stdout
- `-DailyDigest` — one-shot HTML report
- `-Monitor` — long-running flap watcher with webhook + Task Scheduler integration

---

## System requirements

| | |
|---|---|
| **OS** | Windows 10 (1809+) or Windows 11 |
| **PowerShell** | 5.1 (ships with the OS) |
| **.NET Framework** | 4.7.2+ (ships with the OS) |
| **Admin** | Required for event-log reads, NIC driver inspection, BYOVD checks, Apply Fixes. The launcher self-elevates via UAC. |
| **Network** | Optional outbound HTTPS for threat-intel feeds (FireHOL, Feodo Tracker) and the loldrivers.io vulnerable-driver list. NetJump runs fully offline if you disable both. |
| **Disk** | ~3 MB for the script + ~30–50 MB for caches and rolling pktmon ring buffer |

---

## What gets installed (1.0.1)

When `NetJump-Setup-1.0.1.exe` runs, files land at `%LocalAppData%\Programs\NetJump\` (per-user) or `%ProgramFiles%\NetJump\` (per-machine):

```
NetJump\
├── NetJump-Dashboard.ps1     ← the application (single file)
├── Run-NetJump.bat           ← self-elevating launcher
├── README.md                 ← full documentation
├── netjump.ico               ← shortcut + uninstaller icon
├── NetJump-Scan.ps1          ← legacy (kept for reference)
├── NetJump-Monitor.ps1       ← legacy (kept for reference)
├── unins000.exe              ← uninstaller (auto-generated by Inno Setup)
└── Reports\                  ← created on first run (user data)
    ├── settings.json
    ├── Sessions\
    ├── Flaps\
    ├── Actions\              ← audit log
    ├── Digests\              ← scheduled-scan output
    ├── ThreatIntel\
    │   ├── cache.json        ← IPv4 + IPv6 threat-intel
    │   └── loldrivers.json   ← vulnerable-driver list
    └── Monitor\              ← daily rolling logs (Monitor mode)
```

**Start Menu:** NetJump · NetJump README · Uninstall NetJump.
**Desktop shortcut:** optional via Tasks checkbox during install.
**HTTP server:** binds to `localhost` only — never exposed to the network.

---

## Uninstalling

Three equivalent paths, all running the same `unins000.exe`:

1. Settings → Apps → Installed apps → NetJump → Uninstall
2. Start Menu → NetJump → Uninstall NetJump
3. Run `unins000.exe` directly from the install folder

The uninstaller prompts: *"Also delete the NetJump data folder?"*  Default is **No** — keeps your audit log, ledger, threat-intel cache, and flap dossiers. You can always delete `Reports\` manually later.

---

## Privacy & security

- **All data stays local.** No telemetry, no analytics, no account, no cloud.
- **HTTP server binds to `127.0.0.1`** — not accessible from the LAN.
- **Outbound network is opt-out.** Threat-intel and vulnerable-driver list fetches are disabled with one checkbox each.
- **Read-only by default.** The HUD only writes when:
  - You click Apply Fixes (each fix confirms)
  - You right-click PROCESSES / FLOWS / TRAFFIC / DNS rows and confirm a kill / block / hosts edit
  - You use the LOCAL NET INFO RESET buttons (DHCP / DNS / ARP / MTU / STACK)
  - The kill-switch is armed by a critical finding
- **Audit trail is tamper-evident.** Every fix that runs writes a timestamped JSON to `Reports\Actions\`.

---

## Version history

### 1.0.1 (this build)
- Always-on Start Menu shortcut (was opt-in in 1.0.0)
- Uninstaller prompts before deleting `Reports\` data folder
- Custom `netjump.ico` for installer .exe, shortcuts, and Apps & Features entry
- Embedded version info in installer .exe properties (ProductName / ProductVersion / CompanyName)

### 1.0.0
- First packaged release (Inno Setup 6)
- Per-user install default; per-machine available via the elevation page
- Bundles: NetJump-Dashboard.ps1, Run-NetJump.bat, README.md, legacy scripts

### Application changelog (recent)
- **MS Vulnerable Driver Blocklist** auto-refreshed weekly from loldrivers.io (~460 entries)
- **Auto-refresh scheduler** for threat-intel + vuln-driver feeds with jitter
- **IPv6 threat-intel** — BigInteger-backed CIDR matching, full v4 + v6 parity
- **Prometheus `/metrics` endpoint** on the existing localhost HTTP server
- **Scheduled re-scan + rolling digest** writes HTML + CSV per cycle to `Reports\Digests\`
- **Settings UI ADVANCED section** with toggles for all of the above

---

## Credits

- **[loldrivers.io](https://www.loldrivers.io/)** — community-maintained vulnerable driver catalog
- **FireHOL Level 1** + **Feodo Tracker (abuse.ch)** — default threat-intel feeds
- **Microsoft pktmon** — rolling 50 MB packet capture engine
- **MITRE ATT&CK®** — technique tagging in findings
