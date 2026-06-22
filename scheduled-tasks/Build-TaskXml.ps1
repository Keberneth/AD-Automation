<#
.SYNOPSIS
Generate import-ready Scheduled Task XML files for every AD-Automation script.

.DESCRIPTION
Builds each task with the Windows Task Scheduler COM API and writes the
canonical XML (ITaskDefinition.XmlText) to this folder - one file per script,
named ADAuto-<Key>.xml. Because the XML comes from the scheduler itself it is
guaranteed schema-valid and imports cleanly via Task Scheduler ("Import Task..."),
schtasks /create /xml, or Register-ScheduledTask -Xml.

Nothing is registered and no elevation is required - this only serialises task
definitions to disk. Re-run it whenever you want to change the run-as account,
the script location, or the schedule, then re-import the files.

The triggers and arguments mirror Install-ADAutomationScheduledTask.ps1. The two
destructive jobs (DisableInactive, DeleteDisabled) are written in -DryRun; change
their Args below (or edit the <Arguments> line to -Scheduled) to go live.

.EXAMPLE
# Regenerate the committed files (SYSTEM, scripts in C:\AD-Automation, DryRun)
.\Build-TaskXml.ps1

.EXAMPLE
# Point the tasks at where the scripts actually live and run as a gMSA
.\Build-TaskXml.ps1 -ScriptRoot 'D:\Tools\AD-Automation' -RunAs 'CORP\adauto$'
#>
[CmdletBinding()]
param(
    # Folder on the TARGET host where the Invoke-AD*.ps1 scripts live.
    [string]$ScriptRoot = 'C:\AD-Automation',

    # Where to write the .xml files (default: next to this script).
    [string]$OutDir = $PSScriptRoot,

    # Run-as identity baked into each task. 'SYSTEM' = simplest on a DC (no
    # password). A gMSA ('CORP\adauto$') or service account ('CORP\svc-adauto')
    # is logon-type Password; for a plain service account you still supply the
    # password at import time.
    [string]$RunAs = 'SYSTEM',

    # PowerShell host. 5.1 is preferred (RSAT AD + DSInternals are most reliable).
    [string]$PowerShellExe = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
)

$ErrorActionPreference = 'Stop'

# Fixed, in-the-past anchor date. Only the time-of-day (and weekday) matters for
# recurring triggers; the scheduler rolls forward to the next occurrence.
$anchor = '2025-01-01'

# TASK_TRIGGER_TYPE2 / logon / runlevel / instance constants
$T_TIME = 1; $T_DAILY = 2; $T_WEEKLY = 3
$LOGON_PASSWORD = 1; $LOGON_SERVICE = 5
$RUNLEVEL_HIGHEST = 1
$INSTANCES_IGNORENEW = 2
$ACTION_EXEC = 0
$DOW_SUNDAY = 1   # DaysOfWeek bitmask: Sun=1, Mon=2, Tue=4, ...

# One row per scheduled task. Schedule shapes:
#   @{ Type='Daily';  At='HH:mm' }
#   @{ Type='Weekly'; At='HH:mm'; Dow=<bitmask> }
#   @{ Type='Minute'; Every=<minutes> }
$tasks = @(
    [pscustomobject]@{ Key = 'PasswordExpiry'; Script = 'Invoke-ADPasswordExpiryNotify.ps1'; Args = '-Run'; Desc = 'AD-Automation: warn users before their password expires'; Sched = @{ Type = 'Daily'; At = '07:00' } }
    [pscustomobject]@{ Key = 'DisableWarning'; Script = 'Invoke-ADDisableInactiveWarning.ps1'; Args = '-Run'; Desc = 'AD-Automation: warn the manager before an inactive user is disabled'; Sched = @{ Type = 'Daily'; At = '07:30' } }
    [pscustomobject]@{ Key = 'Lockout'; Script = 'Invoke-ADLockoutNotify.ps1'; Args = '-Run -LookbackMinutes 20'; Desc = 'AD-Automation: alert on account lockouts (event 4740)'; Sched = @{ Type = 'Minute'; Every = 15 } }
    [pscustomobject]@{ Key = 'DuplicatePassword'; Script = 'Invoke-ADDuplicatePasswordNotify.ps1'; Args = '-Run'; Desc = 'AD-Automation: alert when a new account reuses another account password'; Sched = @{ Type = 'Minute'; Every = 30 } }
    [pscustomobject]@{ Key = 'PasswordChangeAudit'; Script = 'Invoke-ADPasswordChangeAudit.ps1'; Args = '-Run'; Desc = 'AD-Automation: on password change, run duplicate + Have I Been Pwned checks'; Sched = @{ Type = 'Minute'; Every = 30 } }
    [pscustomobject]@{ Key = 'DisableInactive'; Script = 'Invoke-ADHygieneDisableInactive.ps1'; Args = '-DryRun'; Desc = 'AD-Automation: disable inactive users/computers (DryRun - switch to -Scheduled to go live)'; Sched = @{ Type = 'Daily'; At = '02:00' } }
    [pscustomobject]@{ Key = 'DeleteDisabled'; Script = 'Invoke-ADHygieneDeleteDisabledUsers.ps1'; Args = '-DryRun'; Desc = 'AD-Automation: delete users disabled for >= N days (DryRun - switch to -Scheduled to go live)'; Sched = @{ Type = 'Weekly'; At = '03:00'; Dow = $DOW_SUNDAY } }
    [pscustomobject]@{ Key = 'ServerGroups'; Script = 'Invoke-ADServerGroupProvisioning.ps1'; Args = ''; Desc = 'AD-Automation: create per-server Admin/RDP groups and nest baselines'; Sched = @{ Type = 'Daily'; At = '04:00' } }
)

if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$svc = New-Object -ComObject Schedule.Service
$svc.Connect()

foreach ($t in $tasks) {
    $td = $svc.NewTask(0)

    # --- Registration info ---
    $td.RegistrationInfo.Description = $t.Desc
    $td.RegistrationInfo.Author = 'AD-Automation'

    # --- Trigger ---
    switch ($t.Sched.Type) {
        'Daily' {
            $trg = $td.Triggers.Create($T_DAILY)
            $trg.StartBoundary = '{0}T{1}:00' -f $anchor, $t.Sched.At
            $trg.DaysInterval = 1
        }
        'Weekly' {
            $trg = $td.Triggers.Create($T_WEEKLY)
            $trg.StartBoundary = '{0}T{1}:00' -f $anchor, $t.Sched.At
            $trg.DaysOfWeek = $t.Sched.Dow
            $trg.WeeksInterval = 1
        }
        'Minute' {
            $trg = $td.Triggers.Create($T_TIME)
            $trg.StartBoundary = '{0}T00:00:00' -f $anchor
            $trg.Repetition.Interval = 'PT{0}M' -f $t.Sched.Every
            $trg.Repetition.Duration = 'P3650D'      # ~10 years (matches the installer)
            $trg.Repetition.StopAtDurationEnd = $false
        }
    }
    $trg.Enabled = $true

    # --- Action ---
    $act = $td.Actions.Create($ACTION_EXEC)
    $act.Path = $PowerShellExe
    $scriptFull = Join-Path $ScriptRoot $t.Script
    $act.Arguments = ('-NoProfile -ExecutionPolicy Bypass -File "{0}" {1}' -f $scriptFull, $t.Args).Trim()
    $act.WorkingDirectory = $ScriptRoot

    # --- Principal ---
    $td.Principal.UserId = $RunAs
    $td.Principal.RunLevel = $RUNLEVEL_HIGHEST
    $td.Principal.LogonType = if ($RunAs -eq 'SYSTEM') { $LOGON_SERVICE } else { $LOGON_PASSWORD }

    # --- Settings (mirror the installer) ---
    $s = $td.Settings
    $s.MultipleInstances = $INSTANCES_IGNORENEW
    $s.StartWhenAvailable = $true
    $s.ExecutionTimeLimit = 'PT2H'
    $s.DisallowStartIfOnBatteries = $false
    $s.StopIfGoingOnBatteries = $false
    $s.RestartCount = 2
    $s.RestartInterval = 'PT5M'
    $s.IdleSettings.StopOnIdleEnd = $false
    $s.Enabled = $true

    # --- Serialise as UTF-8 with a declaration-less prolog ---
    # The file is UTF-8 (default) so git diffs stay readable and any editor opens it
    # cleanly. We DROP the "encoding=" attribute on purpose: an explicit UTF-8
    # declaration on an in-memory wide string makes MSXML throw "unable to switch the
    # encoding", which would break `Register-ScheduledTask -Xml (Get-Content -Raw)`.
    # No declaration => imports cleanly both as a file (GUI / schtasks) and as a string.
    $outFile = Join-Path $OutDir ('ADAuto-{0}.xml' -f $t.Key)
    $xml = $td.XmlText -replace '\s+encoding="UTF-16"', ''
    [System.IO.File]::WriteAllText($outFile, $xml, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("wrote {0}" -f $outFile)
}

Write-Host ''
Write-Host ("Done. {0} task XML files in {1}" -f $tasks.Count, $OutDir) -ForegroundColor Green
