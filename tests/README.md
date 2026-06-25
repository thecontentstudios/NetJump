# NetJump tests

Pester 5 tests for the pure-function pieces of NetJump. Run locally:

```powershell
.\tests\Run-Tests.ps1
```

CI runs the same script on every push / PR via `.github/workflows/ci.yml`.

## What's tested

| File | Functions / behavior |
|---|---|
| `Tests.GeoIp.ps1` | `Get-IpCountry` binary search; `Load-GeoIpDatabase` CSV parser with a tiny synthetic CSV; boundary IPs at range edges; IPv6 falls through to `$null`. |
| `Tests.SecurityAudits.ps1` | `Get-DefenderExclusionFindings` flags user-writable paths but not Program Files; ExclusionExtension flagging for executable types. |
| `Tests.ComplianceMappings.ps1` | The framework matrices are well-formed (every entry has Id/Name/Rules); rule keys referenced by the matrix actually exist in `$script:AttackMap`. |

## What is NOT tested (yet)

The main file (`NetJump-Dashboard.ps1`) wires WPF + DispatcherTimer at the top level, so dot-sourcing it for unit tests is fragile. Pure helpers that still live in the monolith (e.g. `_IpToUInt32`, `Format-WebhookPayload`) need to migrate into `src/` first.

## Pester version

Pester 5.x. PS 5.1 ships with Pester 3.4 (incompatible). `Run-Tests.ps1` checks the available version and installs from PSGallery into the current-user scope if needed.
