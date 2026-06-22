# NetJump

Real-time network + security HUD for Windows. Originally built to chase
intermittent ethernet flaps; grew into a continuously-running diagnostic
console with live socket tracing, threat-intel correlation, scheduled
re-scans, a local Prometheus endpoint, and one-click remediation.

Single PowerShell file (`NetJump-Dashboard.ps1`), single WPF window,
no install, no service. Self-elevates via `Run-NetJump.bat`.

## Quick start

1. Double-click **`Run-NetJump.bat`**.
2. Click **Yes** on the UAC prompt (admin needed for event-log reads,
   firewall fixes, NIC driver inspection, BYOVD checks, and Apply Fixes).
3. The HUD opens. The link-state indicator, ping chart, and live counters
   start streaming immediately.
4. Click **▶ RUN NET DIAGNOSTIC** to execute the full ~20-category scan.
   Results populate the **DIAGNOSTICS** tab.
5. Click **Apply Fixes** at the bottom to review recommendations and
   apply them selectively, or click **AUTO-APPLY ALL SAFE** inside the
   dialog to apply every SAFE-tier fix in one shot.

## What the HUD shows continuously

| Element | What it tells you |
|---|---|
| **Health grade** (A–F circle, top-left) | Per-category capped scoring of all live findings + flap counter. Reserves F for actually-broken systems (link down, vulnerable driver, malicious traffic) — hardening hints don't crater the grade. |
| **Adapter combo** | Auto-populates with the active ethernet NIC. Click to switch; list refreshes on dropdown open so newly plugged NICs appear immediately. |
| **6 metric tiles** | STATUS · LINK SPEED · UPTIME · FLAPS · LAST INCIDENT · TOP CAUSE — all live. |
| **60-second ping chart** | Gateway + 1.1.1.1 + up to 4 custom targets. Click **Targets…** to add hostnames or `host:port`. |
| **LOCAL NET INFO sidebar** | Adapter, IPv4, mask, gateway, MAC, DNS, DHCP, lease, public IP, MTU, MSS. RESET row: DHCP / DNS / ARP / MTU probe / TCP stack reset. |
| **Sparkline tile strip** | RX errors / RX discards / throughput / TCP retransmits / max-core CPU% / memory% — 60-sample histories. |
| **Activity ribbon** | 60-minute event timeline (flaps, scans, fixes, alerts as colored dots). |

## Bottom-half tabs

| Tab | Purpose |
|---|---|
| **DIAGNOSTICS** | Findings from the last scan grouped by severity (CRITICAL / WARN / INFO / OK / muted). Each finding carries a one-line fix and an ATT&CK technique tag where relevant. Filter and search inline. |
| **PROCESSES** | Network-active processes with risk score (red/amber/blue). Right-click for connection details, kill, block-remote-IP, copy details, open binary location. |
| **TRAFFIC** | Per-protocol rate sparklines (TCP / UDP / ICMP) + RX/TX direction tile + top-talker list with per-process I/O bytes/s and connection counts. |
| **FLOWS** | Real-time TCP/UDP socket diff stream. Click ▶ Start to begin: dumps every existing endpoint as `NOW` rows, then emits `NEW` / `STATE` / `CLOSED` rows every 2 s, plus a `TICK` heartbeat row so the sampler is always visibly alive. Sortable, drag-resizable columns; right-click to filter. |
| **PERSISTENCE** | Autorun entries (Run-keys, scheduled tasks, services). Right-click: disable, open binary location, copy command. |
| **HISTORY** | Heatmap of past flaps + ledger of remote endpoints with geo / cloud-provider / threat-intel tags. |
| **DNS** | Resolution log with TTL / RTT / hit count. Right-click: time query, traceroute, TLS probe, block via hosts file, find resolving process, WHOIS, VirusTotal, AbuseIPDB. |

## TOP RETRANS SUSPECTS + Investigator

When TCP retransmits cross the HIGH/CRITICAL threshold, a panel slides
in above LIVE EVENTS listing the suspect connections (STUCK / FLAPPING /
PEND / EST / COOL). Click **🔬 investigate** to open the Retransmit
Investigator:

- Cumulative-since-boot ratio + last-60s rolling ratio with verdict
- 60-sample trend sparkline + stability metric
- **Pattern Analysis card**: detects whether the retrans cycle is
  CLOCKWORK / PERIODIC / IRREGULAR; pattern-matches the cycle length
  against well-known Windows recurring intervals (NetBIOS broadcast,
  TCP keepalive, SCCM check-in, Group Policy refresh, etc.); pulls
  per-process attribution from event text
- **Cause analysis** with confidence chips for the top candidates
- Action toolbar: Auto-fix SAFE, Open Fix Picker, Path Inspect top
  remote (continuous traceroute), Probe MTU

## LIVE EVENTS feed

Sortable column-based grid (TIME · TYPE · LEVEL · DESCRIPTION) on the
right. Drag column edges to resize, click headers to sort. Six color-coded
sources (DNS / FLOWS / TRAFC / PROCS / PERSI / SYSTM) and four severity
levels (CRITICAL / HIGH / LOW / OK). Per-source feed checkboxes and an
inline text filter at the top. Right-click any row for copy / filter to
source / filter to severity / clear filter.

## What gets scanned

| Category | Examples |
|---|---|
| **Adapter / Link** | Hardware status, link speed, flap history (NDIS event log, last 72 h). |
| **Counters** | RX errors / discards from `Get-NetAdapterStatistics`. |
| **Power management** | NIC power-save settings, "Allow computer to turn off this device", Selective Suspend. |
| **Driver** | Driver age, vendor, BSOD references in last 30 d. |
| **NDIS filters** | VPN / antivirus / endpoint products bound to the NIC. |
| **DNS** | Resolver latency for several well-known hosts; broken resolution. |
| **Auth** | NTLMv1 fallback, RestrictAnonymousSAM, Kerberos RC4 (Kerberoasting indicator), failed logon spikes. |
| **Hardening posture** | SMBv1, LLMNR, NBT-NS, WDigest cleartext, PowerShell v2, Defender state, BitLocker. |
| **BYOVD** | Loaded drivers cross-referenced against a curated 27-driver blocklist **plus** ~460 entries auto-refreshed weekly from [loldrivers.io](https://www.loldrivers.io/). Curated entries (hand-written CVE / vendor notes) win on filename collision. |
| **Threat intel** | Active connections checked against configurable IP blocklists. Defaults: FireHOL Level 1, Feodo Tracker. Adds Spamhaus / EmergingThreats / custom feeds via Settings → Manage feeds…. **IPv4 + IPv6** CIDR ranges and bare IPs both supported. Auto-refresh every 12 h with ±25% jitter. |
| **Beaconing** | Periodicity analysis on connection patterns to flag possible C2. |
| **Malware indicators** | Hosts-file tampering, system proxy hijack, processes from Temp/AppData, stale Defender signatures. |
| **Sysmon** | Installation + service status. |
| **Persistence** | Run-keys, scheduled tasks, service installs, autorun entries. |
| **ARP** | Duplicate MACs (spoofing / rogue device). |
| **Updates** | Recent Windows hotfixes (a fresh cumulative often ships a NIC driver). |
| **Custom rules** | Drop a `.ps1` under `.\Rules\` and it runs on every scan. |

Every finding is tagged **OK / INFO / WARN / FAIL** with a one-line fix.

## Apply Fixes

Bottom button opens the picker dialog with three severity buckets:

- **SAFE** — reversible, no service restarts. DNS flush, ARP flush, hosts entries, autotuning resets, etc.
- **MODERATE** — service restarts, registry tweaks. Reviewable, but click each one explicitly.
- **DISRUPTIVE** — TCP/IP stack reset, NIC restart, BSOD-likely operations. Each requires individual confirmation.

The **AUTO-APPLY ALL SAFE** button inside the dialog runs every SAFE
fix in one batch with a single confirmation, then kicks off a 10-minute
verify watch that re-scans afterward to confirm the issues cleared.

Every fix that runs is logged to a tamper-evident audit trail under
`.\Reports\`.

## Scheduled re-scans + rolling digests

Settings → ADVANCED has a checkbox for **Scheduled diagnostic re-scan**.
Enable it and pick an interval in minutes (minimum 5; typical 60 for
hourly, 1440 for daily). The HUD will then re-run the full diagnostic
on its own without anyone clicking RUN NET DIAGNOSTIC. Findings get
diffed against the previous scan and surfaced in the normal panel.

Tick the **also write Reports\Digests\digest-\*.html + CSV** box and
each scheduled scan also dumps:

- `digest-{timestamp}.html` — KPI bar (FAIL / WARN / INFO / OK / flap
  count) and a table of every non-OK finding, in a dark theme matching
  the daily digest.
- `findings-{timestamp}.csv` — same findings as CSV (`Level, Category,
  Message, Fix, MitreId`), suitable for Excel / Pandas trend analysis.

The on-demand `-DailyDigest` flag still writes its own report to
`.\Reports\`; the two artifact streams are independent so you can
delete `Reports\Digests\` without nuking the user-facing dailies.

## HTTP API + Prometheus metrics

Every HUD launch starts a local HTTP server on port **8765** (configurable
in Settings → HTTP STATUS PORT). It binds to `localhost` only — never
exposed to the network. Endpoints:

| Path | Format | Purpose |
|---|---|---|
| `/` | HTML | Phone-friendly mini-dashboard. Auto-refreshes every 5 s. |
| `/status.json` | JSON | Full snapshot: adapter, ping, flap count, sparkline counters, findings, causes, ledger. |
| `/findings.json` | JSON | Last-scan findings only. |
| `/causes.json` | JSON | Ranked root causes. |
| `/ledger.json` | JSON | Top 50 connection ledger entries by sample count. |
| `/health` | text | `OK` (200) if adapter is Up, `DOWN` (503) otherwise. Suitable for uptime probes. |
| `/metrics` | text | **Prometheus exposition format (v0.0.4).** Scrape from Grafana / Prometheus / VictoriaMetrics. |

Exposed Prometheus metrics (all labeled `host="..."`):

```
netjump_adapter_up                              # 1=Up, 0=other
netjump_link_speed_bits_per_second              # 1e9 for 1 Gbps, etc.
netjump_flap_count                              # session counter
netjump_session_uptime_seconds
netjump_ping_rtt_milliseconds{target="gateway|cloudflare"}
netjump_rx_errors_per_second
netjump_tcp_retransmits_per_second
netjump_cpu_max_core_percent
netjump_memory_percent
netjump_findings{severity="OK|INFO|WARN|FAIL"}
netjump_threat_intel_ranges{family="v4|v6"}
netjump_threat_intel_ips{family="v4|v6"}
netjump_threat_intel_cache_age_seconds
netjump_vulnerable_driver_entries
netjump_vulnerable_driver_cache_age_seconds
netjump_ledger_entries
netjump_beacon_alerts
```

Quick scrape config for a homelab Prometheus:

```yaml
scrape_configs:
  - job_name: netjump
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:8765']
```

## Layout persistence

Resize panels, drag splitters, pick a tab, toggle the LIVE EVENTS feed
checkboxes — all of it saves to `.\Reports\settings.json` on close and
restores on next launch. The middle splitter sits right below the LOCAL
NET INFO sidebar by default; the bottom right column gives ~14% to TOP
RETRANS SUSPECTS and ~86% to LIVE EVENTS.

## CLI / headless modes

`NetJump-Dashboard.ps1` accepts these flags for unattended use:

| Flag | What it does |
|---|---|
| `-Headless` | Run the diagnostic scan and print a console report. No UI. Exits when done. |
| `-Json` | Same as `-Headless` but emits a JSON document on stdout suitable for piping into other tools. |
| `-DailyDigest` | Generate a daily digest HTML report (last 24 h of flaps, top causes, applied fixes) and open it. |
| `-Monitor` | Long-running monitor mode — watches the link, logs flap events to `.\Reports\NetJump-Monitor-*.log`, fires webhooks if configured. Never returns until killed. |

Examples:

```powershell
# One-shot scan, JSON to stdout, pipe through jq
powershell -NoProfile -ExecutionPolicy Bypass -File NetJump-Dashboard.ps1 -Json | jq '.findings'

# Scrape Prometheus metrics from the running HUD (GUI must be open)
curl http://localhost:8765/metrics

# Health probe for uptime monitoring (200 if link Up, 503 if Down)
curl -fsS http://localhost:8765/health || echo "adapter down"
```

## Most likely causes of "ethernet jumping up and down"

In order of prevalence:

1. **Physical layer** — try a known-good Cat5e/Cat6 and a different switch port. Swap this first.
2. **Energy-Efficient Ethernet (EEE) / Green Ethernet** — driver feature that lowers link speed when idle; negotiation bugs cause flaps. Section flagged in scan.
3. **"Allow the computer to turn off this device"** in the NIC's Power Management tab.
4. **Outdated or buggy NIC driver** — especially Realtek. Update from the vendor site, not Windows Update.
5. **Third-party NDIS filter driver** — VPN, antivirus, endpoint product, or adware.
6. **Recent Windows update shipped a broken NIC driver** — section 12 lists hotfixes.
7. **Failing NIC, motherboard, or PSU** — persistent flapping despite fixing everything above. Test on another port / cable / switch; if it still flaps, swap hardware (a USB 3.0 ethernet adapter is a ~$15 test).

## Is it malware?

Section 11 of the scan checks the usual indicators (hosts-file tampering,
system proxy hijack, network-active processes from Temp/AppData, stale
Defender signatures, BYOVD vulnerable drivers, threat-intel-matching
connections, periodic beaconing). For a deeper sweep:

```powershell
Start-MpScan -ScanType FullScan
```

…and consider a second-opinion scanner like Malwarebytes or ESET.

## Reports & data

- All HTML / JSON / CSV exports land in `.\Reports\`. Safe to delete any time.
- `.\Reports\settings.json` — UI state, threat-intel feed list, custom-target list, scheduled-scan flags, port settings.
- `.\Reports\Sessions\*.json` — per-app-launch session log (flaps, ledger).
- `.\Reports\Flaps\*\` — flap dossier folders (one per flap event: manifest, pktmon capture, process snapshot).
- `.\Reports\Actions\action-*.json` — every applied fix with timestamp + outcome (tamper-evident audit trail).
- `.\Reports\Digests\digest-*.html` + `findings-*.csv` — per-cycle output from scheduled scans (only if scheduled scan + digest are enabled).
- `.\Reports\ThreatIntel\cache.json` — IPv4 + IPv6 threat-intel ranges and IPs (72 h TTL).
- `.\Reports\ThreatIntel\loldrivers.json` — vulnerable-driver list cache from loldrivers.io (7-day TTL).
- `.\Reports\Monitor\monitor-*.log` — daily rolling log when running headless `-Monitor` mode.

## Read-only by default

The HUD is read-only **except** for:

- Apply Fixes (you click the dialog button)
- Right-click actions on PROCESSES / FLOWS / TRAFFIC / DNS that execute kill / block / hosts-edit (each click confirms)
- The RESET row buttons in the LOCAL NET INFO sidebar (DHCP / DNS / ARP / MTU / STACK)
- The kill-switch panel that arms when a critical scan finding triggers it

Nothing happens silently. The audit log shows exactly what ran and when.

## Notes

- WPF requires .NET Framework 4.7.2+ (every supported Windows version).
- Some checks fetch updates over HTTPS at startup, cached locally afterward:
  - **Threat-intel feeds** (FireHOL / Feodo / user-added) — toggle in Settings → Threat-intel feeds; manage URL list via Settings → Manage feeds….
  - **Vulnerable-driver list** (loldrivers.io) — toggle in Settings → ADVANCED → Vulnerable-driver list.
  If your environment forbids outbound HTTP, untick both and NetJump falls back to its curated hardcoded BYOVD list and no IP/threat correlation.
- The HTTP server (port **8765** by default, configurable in Settings) binds to `localhost` only. It does **not** accept connections from the network.
- The legacy `NetJump-Scan.ps1` and `NetJump-Monitor.ps1` are kept in the
  repo for reference but are superseded by `NetJump-Dashboard.ps1`. The
  HUD covers everything they did and more.
- If `Run-NetJump.bat` bounces because of execution policy, it runs
  PowerShell with `-ExecutionPolicy Bypass` scoped to that one
  invocation — nothing persists in your global policy.
