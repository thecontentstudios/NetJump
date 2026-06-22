# NetJump Screenshots

This folder holds the marketing/distribution screenshots for NetJump.

## What's here

| File | Type | Purpose |
|---|---|---|
| `01-hud-overview.svg` | SVG mockup | Main HUD layout — adapter combo, health grade, metric tiles, sparkline strip, ping chart, findings panel, LIVE EVENTS feed. Sanitized example data, not a real screenshot. |
| `02-fix-picker.svg` | SVG mockup | Apply Fixes dialog showing the SAFE / MODERATE / DISRUPTIVE three-tier picker with example commands. |

SVG opens in any modern browser. To convert to PNG for places that require raster images (Microsoft Store, GitHub social preview, etc.):

```powershell
# In Chrome / Edge: drag the .svg into a new tab, right-click → Save image as → PNG
# Or via PowerShell + Inkscape (if installed):
inkscape 01-hud-overview.svg --export-type=png --export-filename=01-hud-overview.png --export-width=1600
```

## Taking real screenshots from a running NetJump

The SVG mockups are good enough for a project page or marketplace listing. If you want **real** screenshots from a live HUD, follow this checklist so you don't accidentally leak network info.

### Views worth capturing (priority order)

1. **Main HUD overview** — full window, link Up, after a fresh scan completed.
2. **DIAGNOSTICS tab** — shown after a scan with some WARN findings; the colored severity pills demo the design well.
3. **PROCESSES tab** — right-click context menu open over a process to show the kill / block / details actions.
4. **FLOWS tab** — Start button pressed, NEW / STATE / CLOSED rows visible.
5. **Retransmit Investigator dialog** — open from the TOP RETRANS SUSPECTS panel (will require some real retransmit activity, or you can stage it by saturating the link briefly).
6. **Fix Picker dialog** — Apply Fixes → shows the three-tier severity buckets with real fixes.
7. **Settings dialog (Ctrl+,)** — ADVANCED section visible showing the new toggles.
8. **HISTORY tab** — heatmap of past flaps (only useful if your machine has actually flapped recently).
9. **Mobile dashboard** — open `http://localhost:8765/` in a phone browser to capture the phone-friendly HTML view.

### Redaction checklist BEFORE publishing

Sensitive data the HUD will display on **your** machine that you almost certainly don't want in a marketing screenshot:

- [ ] **Hostname** — title bar, LIVE EVENTS rows, "Host" tile. Find/replace with `DESKTOP-EXAMPLE`.
- [ ] **MAC address** — LOCAL NET INFO sidebar. Replace last 6 hex chars with `..:..` (already done in the mockup).
- [ ] **Public IP** — sidebar. Replace with `203.0.113.x` (TEST-NET-3 reserved for documentation).
- [ ] **Internal IPs** — sidebar + flows. `192.168.1.x` is fine; replace anything more specific.
- [ ] **Domain names in DNS tab** — replace with `example.com` / `internal.lan`.
- [ ] **Process names that reveal personal info** — e.g. browser tabs in title bar text. Either kill those processes pre-screenshot or open a clean Chrome profile.
- [ ] **Custom ping targets** — sidebar shows targets you've added. Reset to defaults (gateway + 1.1.1.1) before capture.
- [ ] **Webhook URL in Settings** — clear it before opening the Settings dialog.
- [ ] **Threat-intel matches** — if real, the IPs match real-world bad actors but might also include sensitive context. Use the example feed match (`185.220.101.42` is a known Tor exit, safe to show).
- [ ] **Adapter description** — `Realtek PCIe GbE Family Controller #2` is fine; redact if it's an exotic enterprise NIC.

### Capture mechanics

- **Sharp text:** capture at the screen's native resolution. Don't shrink-then-upscale. Windows `Win+Shift+S` works fine; for high-DPI displays use `Snipping Tool` set to "Whole window" mode.
- **Right colors:** use the screen's color profile, not a "Vivid"-mode laptop display. NetJump's dark theme has subtle hex differences (`#0f1420` vs `#1a2030`) that get crushed on cheap panels.
- **Aspect:** 16:9 (1920×1080) or 16:10 works everywhere. The HUD's native layout adapts up to ~3840×2160.
- **Format:** PNG (lossless, ~200–400 KB per view). JPEG eats the dark-theme gradients and looks terrible.
- **Filename convention:** `NN-short-description.png` so they sort in capture order.

### After capture

Drop the PNGs in this folder alongside the SVG mockups. Then update `APP-INFO.md` and `README.md` to reference them:

```markdown
![NetJump main HUD](Screenshots/01-hud-overview.png)
```
