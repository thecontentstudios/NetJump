# =============================================================================
# src/87-compliance-report.ps1 — Compliance report HTML export
# =============================================================================
# Export menu adds "Compliance report (HTML)…". Renders the current findings
# against the NIST CSF 2.0 and CIS Controls v8 frameworks defined in
# src/86-compliance-mappings.ps1. Output: a single self-contained HTML file
# with embedded CSS - usable as audit evidence or for change tickets.
# =============================================================================

$script:ComplianceDir = Join-Path $PSScriptRoot 'Reports\Compliance'
if (-not (Test-Path $script:ComplianceDir)) { New-Item -ItemType Directory -Path $script:ComplianceDir -Force | Out-Null }

function Export-ComplianceReport {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $path  = Join-Path $script:ComplianceDir ("compliance-$stamp.html")

    # Bucket the current findings by the rules they tag.
    $findingsByRule = @{}
    foreach ($f in @($script:AllFindings)) {
        $mit = [string]$f.MitreId
        if (-not $mit) { continue }
        # Find the rule code (key in AttackMap) whose Id matches this MitreId.
        foreach ($k in $script:AttackMap.Keys) {
            if ($script:AttackMap[$k].Id -eq $mit) {
                if (-not $findingsByRule.ContainsKey($k)) { $findingsByRule[$k] = New-Object System.Collections.Generic.List[object] }
                [void]$findingsByRule[$k].Add($f)
            }
        }
    }

    # Build the per-framework section.
    function _RenderFrameworkSection {
        param([string]$Title, $Matrix)
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("<h2 class='frame'>$([System.Net.WebUtility]::HtmlEncode($Title))</h2>")
        foreach ($group in $Matrix.Keys) {
            [void]$sb.AppendLine("<h3>$([System.Net.WebUtility]::HtmlEncode($group))</h3>")
            [void]$sb.AppendLine("<table><thead><tr><th>Control</th><th>Description</th><th>NetJump rules</th><th>Findings (current scan)</th></tr></thead><tbody>")
            foreach ($it in $Matrix[$group]) {
                $covered = @($it.Rules | Where-Object { $script:AttackMap.ContainsKey($_) })
                $rowFindings = New-Object System.Collections.Generic.List[object]
                foreach ($r in $covered) {
                    if ($findingsByRule.ContainsKey($r)) {
                        foreach ($f in $findingsByRule[$r]) { [void]$rowFindings.Add($f) }
                    }
                }
                $cls = if ($covered.Count -gt 0) { 'covered' } else { 'uncovered' }
                $rulesCell = if ($covered.Count -gt 0) { ($covered -join ', ') } else { '<span class="dim">(no rules wired)</span>' }
                $findCellSb = New-Object System.Text.StringBuilder
                if ($rowFindings.Count -eq 0) {
                    [void]$findCellSb.Append('<span class="dim">(no findings this scan)</span>')
                } else {
                    foreach ($f in $rowFindings) {
                        $sevCls = "sev-$([string]$f.Level)"
                        [void]$findCellSb.Append("<div class='find $sevCls'>")
                        [void]$findCellSb.Append("<span class='pill'>$([System.Net.WebUtility]::HtmlEncode([string]$f.Level))</span> ")
                        [void]$findCellSb.Append([System.Net.WebUtility]::HtmlEncode([string]$f.Message))
                        [void]$findCellSb.Append('</div>')
                    }
                }
                [void]$sb.AppendLine("<tr class='$cls'><td><code>$([System.Net.WebUtility]::HtmlEncode($it.Id))</code></td><td>$([System.Net.WebUtility]::HtmlEncode($it.Name))</td><td>$rulesCell</td><td>$($findCellSb.ToString())</td></tr>")
            }
            [void]$sb.AppendLine('</tbody></table>')
        }
        return $sb.ToString()
    }

    $nistHtml = _RenderFrameworkSection 'NIST CSF 2.0' $script:NistCsfFramework
    $cisHtml  = _RenderFrameworkSection 'CIS Critical Controls v8' $script:CisControlsFramework

    $a = $script:State.Adapter
    $hostBlock = ("<dt>Host</dt><dd><code>{0}</code></dd><dt>Adapter</dt><dd><code>{1}</code> ({2})</dd><dt>Generated</dt><dd>{3}</dd><dt>Findings count</dt><dd>{4}</dd>" -f `
        $env:COMPUTERNAME, `
        $(if ($a) { [System.Net.WebUtility]::HtmlEncode([string]$a.Name) } else { 'n/a' }), `
        $(if ($a) { [System.Net.WebUtility]::HtmlEncode([string]$a.Status) } else { '' }), `
        (Get-Date), `
        @($script:AllFindings).Count)

    $html = @"
<!doctype html><html><head><meta charset='utf-8'>
<title>NetJump compliance report - $stamp</title>
<style>
 body{font:14px/1.45 Segoe UI,Arial,sans-serif;background:#0f1420;color:#d7dde6;margin:24px}
 h1{color:#58a6ff;margin:0 0 4px}
 h2.frame{color:#7ee787;border-bottom:1px solid #30363d;padding-bottom:4px;margin-top:32px}
 h3{color:#bf6dff;margin:18px 0 6px}
 dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:8px 0 24px}
 dt{color:#8b95a8;font-size:11px;text-transform:uppercase}
 table{width:100%;border-collapse:collapse;background:#1a2030;border-radius:8px;overflow:hidden;margin-bottom:18px}
 th,td{padding:8px 12px;border-bottom:1px solid #2a3142;text-align:left;vertical-align:top;font-size:12px}
 th{background:#2a3142;color:#8b95a8;font-size:11px;text-transform:uppercase}
 tr.covered code{background:#143a23;color:#7ee787;padding:2px 6px;border-radius:3px;border:1px solid #3fb950}
 tr.uncovered code{background:#1a2030;color:#8b95a8;padding:2px 6px;border-radius:3px;border:1px solid #2a3142}
 .dim{color:#6e7681;font-style:italic}
 .find{margin:2px 0;font-size:11px}
 .pill{display:inline-block;padding:1px 5px;border-radius:3px;font-weight:bold;font-size:10px;color:#fff;margin-right:4px}
 .sev-FAIL .pill{background:#f85149}
 .sev-WARN .pill{background:#d29922}
 .sev-INFO .pill{background:#58a6ff}
 .sev-OK   .pill{background:#3fb950}
 code{font-family:Consolas,monospace}
 footer{margin-top:32px;color:#6e7681;font-size:11px}
</style></head><body>
<h1>NetJump compliance report</h1>
<dl>$hostBlock</dl>
$nistHtml
$cisHtml
<footer>Generated by NetJump on $(Get-Date). Mapping is editorial - controls listed represent NetJump's current detection scope, not full framework coverage.</footer>
</body></html>
"@
    Set-Content -LiteralPath $path -Value $html -Encoding UTF8
    Add-Event recovery ("Compliance report written: $(Split-Path $path -Leaf) (Reports\Compliance\)")
    try { Start-Process explorer.exe ('/select,"' + $path + '"') } catch {}
    return $path
}
