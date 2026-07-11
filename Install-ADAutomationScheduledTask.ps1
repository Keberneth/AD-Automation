<#
.SYNOPSIS
Register (or preview) Windows Scheduled Tasks for the AD-Automation scripts so the
whole library runs unattended.

.DESCRIPTION
Creates one scheduled task per script under a task folder (default \AD-Automation),
running Windows PowerShell with -NoProfile -ExecutionPolicy Bypass -File <script>.
Use -WhatIf or -ListOnly to preview without changing anything.

The tasks run as the account you specify:
  - A group Managed Service Account (recommended):  -GmsaUser 'CORP\adauto$'
  - A normal service account:                       -RunAsUser 'CORP\svc-adauto' -Password (Read-Host -AsSecureString)
  - SYSTEM (only on a DC, simplest):                -UseSystem

Defaults are deliberately SAFE: the destructive jobs (disable / delete) are
registered in -DryRun so nothing changes until you review the reports and switch
them to their live arguments (just '-Scheduled' for hands-off operation - no
approval list to maintain; see -DisableInactiveArgs / -DeleteDisabledArgs).

.EXAMPLE
# Preview everything as a gMSA
.\Install-ADAutomationScheduledTask.ps1 -GmsaUser 'CORP\adauto$' -ListOnly

.EXAMPLE
# Install the notification jobs only, running as SYSTEM on a DC
.\Install-ADAutomationScheduledTask.ps1 -UseSystem -Include PasswordExpiry,Lockout,DisableWarning

.NOTES
- Run this elevated (Administrator). Requires the ScheduledTasks module (built in
  on Windows 8/Server 2012+).
- The password-hash jobs (DuplicatePassword / PasswordChangeAudit) require
  DSInternals + replication rights on the run-as account.
- For TRUE event-driven runs of the hash jobs (on account-created / password-change
  events) see docs\SCHEDULED-TASKS.md.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$ScriptRoot = $PSScriptRoot,
    [string]$TaskFolder = '\AD-Automation',

    # Run-as identity (choose one).
    [string]$GmsaUser,
    [string]$RunAsUser,
    [securestring]$Password,
    [switch]$UseSystem,

    # Which tasks to install. Default = all.
    [ValidateSet('PasswordExpiry', 'Lockout', 'DisableWarning', 'DisableInactive', 'DeleteDisabled', 'DuplicatePassword', 'PasswordChangeAudit', 'ServerGroups')]
    [string[]]$Include,

    # Override the arguments of the AD-writing jobs once you are ready to go live.
    [string[]]$DisableInactiveArgs = @('-DryRun'),
    [string[]]$DeleteDisabledArgs = @('-DryRun'),
    [string[]]$ServerGroupsArgs = @('-WhatIf'),

    [switch]$ListOnly
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name ScheduledTasks)) {
    throw 'ScheduledTasks module not available (needs Windows 8 / Server 2012 or later).'
}
Import-Module ScheduledTasks -ErrorAction Stop

# Prefer Windows PowerShell 5.1 (RSAT AD + DSInternals are most reliable there).
$psExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $psExe)) { $psExe = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source }
if (-not $psExe) { $psExe = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source }
if (-not $psExe) { throw 'No PowerShell host (powershell.exe / pwsh.exe) found.' }

# --- Task catalogue ---------------------------------------------------------
# Each entry: Key, Script, Args, and a Trigger scriptblock returning a trigger object.
$catalogue = @(
    [pscustomobject]@{ Key = 'PasswordExpiry'; Script = 'Invoke-ADPasswordExpiryNotify.ps1'; Args = @('-Run'); Trigger = { New-ScheduledTaskTrigger -Daily -At 7:00am } }
    [pscustomobject]@{ Key = 'Lockout'; Script = 'Invoke-ADLockoutNotify.ps1'; Args = @('-Run', '-LookbackMinutes', '20'); Trigger = { $t = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddHours(0); $t.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration ([TimeSpan]::MaxValue)).Repetition; $t } }
    [pscustomobject]@{ Key = 'DisableWarning'; Script = 'Invoke-ADDisableInactiveWarning.ps1'; Args = @('-Run'); Trigger = { New-ScheduledTaskTrigger -Daily -At 7:30am } }
    [pscustomobject]@{ Key = 'DisableInactive'; Script = 'Invoke-ADHygieneDisableInactive.ps1'; Args = $DisableInactiveArgs; Trigger = { New-ScheduledTaskTrigger -Daily -At 2:00am } }
    [pscustomobject]@{ Key = 'DeleteDisabled'; Script = 'Invoke-ADHygieneDeleteDisabledUsers.ps1'; Args = $DeleteDisabledArgs; Trigger = { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3:00am } }
    [pscustomobject]@{ Key = 'DuplicatePassword'; Script = 'Invoke-ADDuplicatePasswordNotify.ps1'; Args = @('-Run'); Trigger = { $t = New-ScheduledTaskTrigger -Once -At (Get-Date).Date; $t.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration ([TimeSpan]::MaxValue)).Repetition; $t } }
    [pscustomobject]@{ Key = 'PasswordChangeAudit'; Script = 'Invoke-ADPasswordChangeAudit.ps1'; Args = @('-Run'); Trigger = { $t = New-ScheduledTaskTrigger -Once -At (Get-Date).Date; $t.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration ([TimeSpan]::MaxValue)).Repetition; $t } }
    [pscustomobject]@{ Key = 'ServerGroups'; Script = 'Invoke-ADServerGroupProvisioning.ps1'; Args = $ServerGroupsArgs; Trigger = { New-ScheduledTaskTrigger -Daily -At 4:00am } }
)

# The destructive hygiene jobs get NO restart-on-failure: a restart after a partial
# run would let a failed job resume and delete/disable the NEXT batch, multiplying
# the per-run MaxDeletes/MaxChanges safety cap. They cap blast radius per PROCESS.
$noRestartKeys = @('DisableInactive', 'DeleteDisabled')

if ($Include) { $catalogue = $catalogue | Where-Object { $Include -contains $_.Key } }

# --- Principal --------------------------------------------------------------
function New-Principal {
    if ($UseSystem) { return (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) }
    if ($GmsaUser) { return (New-ScheduledTaskPrincipal -UserId $GmsaUser -LogonType Password -RunLevel Highest) }
    if ($RunAsUser) { return (New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType Password -RunLevel Highest) }
    throw 'Specify a run-as identity: -UseSystem, -GmsaUser, or -RunAsUser (with -Password).'
}

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) -DontStopOnIdleEnd -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 5)
# Same settings but WITHOUT restart-on-failure, for the destructive jobs.
$settingsNoRestart = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) -DontStopOnIdleEnd

Write-Host "AD-Automation scheduled-task installer" -ForegroundColor Cyan
Write-Host ("ScriptRoot : {0}" -f $ScriptRoot)
Write-Host ("Task folder: {0}" -f $TaskFolder)
Write-Host ("Run-as     : {0}" -f $(if ($UseSystem) { 'SYSTEM' } elseif ($GmsaUser) { "$GmsaUser (gMSA)" } else { $RunAsUser }))
Write-Host ("PowerShell : {0}" -f $psExe)
Write-Host ''

foreach ($t in $catalogue) {
    $scriptPath = Join-Path $ScriptRoot $t.Script
    if (-not (Test-Path -LiteralPath $scriptPath)) { Write-Warning "Script not found, skipping: $scriptPath"; continue }

    $argLine = ('-NoProfile -ExecutionPolicy Bypass -File "{0}" {1}' -f $scriptPath, ($t.Args -join ' ')).Trim()
    $taskName = "ADAuto-$($t.Key)"

    Write-Host ("[{0}] {1}" -f $t.Key, $taskName) -ForegroundColor Yellow
    Write-Host ("    {0} {1}" -f $psExe, $argLine)

    if ($ListOnly) { continue }

    $action = New-ScheduledTaskAction -Execute $psExe -Argument $argLine -WorkingDirectory $ScriptRoot
    $trigger = & $t.Trigger
    $principal = New-Principal

    if ($PSCmdlet.ShouldProcess($taskName, 'Register scheduled task')) {
        $taskSettings = if ($noRestartKeys -contains $t.Key) { $settingsNoRestart } else { $settings }
        $regParams = @{
            TaskName    = $taskName
            TaskPath    = $TaskFolder
            Action      = $action
            Trigger     = $trigger
            Settings    = $taskSettings
            Principal   = $principal
            Description = "AD-Automation: $($t.Script)"
            Force       = $true
            ErrorAction = 'Stop'
        }
        if ($RunAsUser -and -not $UseSystem -and -not $GmsaUser) {
            if (-not $Password) { throw "Provide -Password for -RunAsUser '$RunAsUser' (a SecureString)." }
            $plain = [System.Net.NetworkCredential]::new('', $Password).Password
            $regParams.Remove('Principal')
            $regParams['User'] = $RunAsUser
            $regParams['Password'] = $plain
            $regParams['RunLevel'] = 'Highest'
        }
        try {
            Register-ScheduledTask @regParams | Out-Null
            Write-Host "    registered." -ForegroundColor Green
        }
        catch { Write-Warning "    failed to register $taskName : $($_.Exception.Message)" }
    }
}

# --- Windows Event Log (Applications and Services Logs > AD-Automation) ------
# Pre-register the custom event log and one source per script while we are
# elevated, so every scheduled run can mirror its log lines to Event Viewer from
# the first execution. Best-effort: the scripts also self-register when running
# as SYSTEM/gMSA, and degrade to console+file logging if the log is unavailable.
if (-not $ListOnly) {
    $modulePath = Join-Path $ScriptRoot 'ADAutomation.psd1'
    if ((Test-Path -LiteralPath $modulePath) -and $PSCmdlet.ShouldProcess('AD-Automation event log', 'Register log + per-script sources')) {
        try {
            Import-Module $modulePath -Force -ErrorAction Stop
            $sources = @(
                'ADPasswordExpiry', 'ADLockout', 'ADDisableInactiveWarning',
                'ADHygiene-DisableInactive', 'ADHygiene-DeleteDisabledUsers',
                'ADDuplicatePassword', 'ADPasswordChangeAudit', 'ADServerGroupProvisioning'
            )
            if (Register-ADAutomationEventLog -LogName 'AD-Automation' -Sources $sources) {
                Write-Host "Event log 'AD-Automation' registered (one source per script) - see Event Viewer > Applications and Services Logs." -ForegroundColor Green
            }
            else {
                Write-Warning "Event log registration incomplete (see warnings above); scripts will retry when running elevated/SYSTEM."
            }
        }
        catch { Write-Warning "Could not register the AD-Automation event log: $($_.Exception.Message)" }
    }
}

Write-Host ''
Write-Host 'Done. Review tasks in Task Scheduler under the task folder above.' -ForegroundColor Cyan
if (($catalogue | Where-Object { $_.Key -in 'DisableInactive', 'DeleteDisabled' }) -and ($DisableInactiveArgs -contains '-DryRun' -or $DeleteDisabledArgs -contains '-DryRun')) {
    Write-Host 'NOTE: DisableInactive/DeleteDisabled are registered in -DryRun. Review their reports, then re-run this installer with live args for hands-off operation, e.g. -DisableInactiveArgs ''-Scheduled'' -DeleteDisabledArgs ''-Scheduled''.' -ForegroundColor Yellow
}
if (($catalogue | Where-Object { $_.Key -eq 'ServerGroups' }) -and ($ServerGroupsArgs -contains '-WhatIf')) {
    Write-Host 'NOTE: ServerGroups is registered with -WhatIf (preview only, no group changes). Review its log, then re-run with -ServerGroupsArgs @() to go live.' -ForegroundColor Yellow
}
