# =============================================================================
# src/34-scheduled-task-baseline.ps1 — Scheduled task baseline + diff
# =============================================================================
# Mirrors src/31-security-audits.ps1's persistence baseline pattern but for
# Get-ScheduledTask. Each scan writes today's snapshot to
# Reports\Baselines\scheduled-tasks-YYYY-MM-DD.json (overwrites within the
# day; one per day overall, 60-day rolling). Diff vs the most-recent OLDER
# baseline surfaces NEW task entries as WARN findings - the typical first
# stage of malware persistence beyond Run keys.
# =============================================================================

$script:TaskBaselineDir = Join-Path $PSScriptRoot 'Reports\Baselines'
if (-not (Test-Path $script:TaskBaselineDir)) { New-Item -ItemType Directory -Path $script:TaskBaselineDir -Force | Out-Null }

function _TaskKey {
    param($T)
    # Combine TaskPath + TaskName + first Action's Execute - matches "is this the same task" without
    # tripping on benign state-only changes (LastRunTime etc).
    $exec = ''
    if ($T.Actions -and $T.Actions.Count -gt 0) {
        $exec = [string]$T.Actions[0].Execute
        if ($T.Actions[0].Arguments) { $exec += ' ' + [string]$T.Actions[0].Arguments }
    }
    return ("{0}{1}|{2}|{3}" -f [string]$T.TaskPath, [string]$T.TaskName, [string]$T.Author, $exec)
}

function Get-ScheduledTaskBaselineFindings {
    $out = New-Object System.Collections.Generic.List[object]
    $current = $null
    try {
        $current = @(Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.State -ne 'Disabled' } |
            Select-Object TaskName, TaskPath, Author, Description, State, @{n='Actions';e={ @($_.Actions | Select-Object Execute, Arguments) }})
    } catch { return $out }
    if (-not $current -or $current.Count -eq 0) { return $out }

    # Write today's baseline (overwrites any earlier same-day file).
    try {
        $today = (Get-Date).ToString('yyyy-MM-dd')
        $path  = Join-Path $script:TaskBaselineDir ("scheduled-tasks-$today.json")
        @{
            timestamp = (Get-Date).ToString('o')
            host      = $env:COMPUTERNAME
            tasks     = $current
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding UTF8
        # Roll baselines to last 60 days.
        $old = @(Get-ChildItem $script:TaskBaselineDir -Filter 'scheduled-tasks-*.json' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -Skip 60)
        foreach ($f in $old) { try { Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue } catch {} }
    } catch { try { Add-Event warn ("Scheduled task baseline save failed: $($_.Exception.Message)") } catch {} }

    # Diff vs the most-recent OLDER baseline.
    try {
        $today = (Get-Date).ToString('yyyy-MM-dd')
        $baselines = @(Get-ChildItem $script:TaskBaselineDir -Filter 'scheduled-tasks-*.json' -ErrorAction SilentlyContinue |
            Where-Object { $_.BaseName -ne "scheduled-tasks-$today" } |
            Sort-Object LastWriteTime -Descending)
        if ($baselines.Count -eq 0) { return $out }
        $prev = $null
        try { $prev = Get-Content -LiteralPath $baselines[0].FullName -Raw | ConvertFrom-Json } catch { return $out }
        $prevKeys = @{}
        foreach ($t in @($prev.tasks)) { $k = _TaskKey $t; if ($k) { $prevKeys[$k] = $true } }
        $newTasks = New-Object System.Collections.Generic.List[psobject]
        foreach ($t in $current) {
            $k = _TaskKey $t
            if ($k -and -not $prevKeys.ContainsKey($k)) {
                # Filter out routine Microsoft Update / Defender scheduled tasks - those churn a lot.
                if ([string]$t.TaskPath -like '\Microsoft\Windows\UpdateOrchestrator\*' -or
                    [string]$t.TaskPath -like '\Microsoft\Windows\Windows Defender\*' -or
                    [string]$t.TaskPath -like '\Microsoft\Windows\Servicing\*') { continue }
                [void]$newTasks.Add($t)
            }
        }
        foreach ($t in $newTasks) {
            $exec = ''
            if ($t.Actions -and $t.Actions.Count -gt 0) {
                $exec = [string]$t.Actions[0].Execute
                if ($t.Actions[0].Arguments) { $exec += ' ' + [string]$t.Actions[0].Arguments }
            }
            $out.Add((Add-Finding 'WARN' 'Persistence' ("NEW scheduled task since last baseline: {0}{1}  (Author: {2})  =>  {3}" -f $t.TaskPath, $t.TaskName, $t.Author, $exec) `
                "Inspect with: Get-ScheduledTask -TaskName '$($t.TaskName)' | Get-ScheduledTaskInfo  -or-  Disable-ScheduledTask -TaskName '$($t.TaskName)'" `
                "A scheduled task that wasn't present in your most-recent older baseline. Newly-added Microsoft/Defender/Update tasks are filtered out; everything else is a typical malware persistence channel." `
                'persist-task'))
        }
    } catch { try { Add-Event warn ("Scheduled task diff failed: $($_.Exception.Message)") } catch {} }
    return $out
}
