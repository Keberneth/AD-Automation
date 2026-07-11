# Scheduling AD-Automation for full automation

This guide shows how to run every script unattended with Windows Scheduled Tasks:
the easy way (the bundled installer), the manual way (`Register-ScheduledTask`),
the recommended cadence, a least-privilege run-as account, and **event-driven**
triggers for the password jobs.

> Run all task registration **elevated** (Administrator). Decide *which host*
> runs the tasks: a DC (simplest – local Security log + replication are local) or
> a dedicated admin/management server with RSAT (then the lockout job reads the DC
> Security logs remotely).

---

## 1. The easy way – the installer

`Install-ADAutomationScheduledTask.ps1` registers one task per script under a
task folder (default `\AD-Automation`).

```powershell
# Preview only – shows the exact command line for each task, changes nothing
.\Install-ADAutomationScheduledTask.ps1 -GmsaUser 'CORP\adauto$' -ListOnly

# Install everything as a gMSA (recommended)
.\Install-ADAutomationScheduledTask.ps1 -GmsaUser 'CORP\adauto$'

# Install everything as SYSTEM (only sensible on a DC)
.\Install-ADAutomationScheduledTask.ps1 -UseSystem

# Install as a normal service account with a password
$pw = Read-Host 'Service account password' -AsSecureString
.\Install-ADAutomationScheduledTask.ps1 -RunAsUser 'CORP\svc-adauto' -Password $pw

# Install a subset only
.\Install-ADAutomationScheduledTask.ps1 -UseSystem -Include PasswordExpiry,Lockout,DisableWarning
```

**Safe by default:** the destructive jobs (`DisableInactive`, `DeleteDisabled`)
are registered in `-DryRun`. Review their reports under
`C:\ProgramData\AD-Automation`, then re-run the installer with live arguments:

```powershell
.\Install-ADAutomationScheduledTask.ps1 -UseSystem `
  -Include DisableInactive,DeleteDisabled `
  -DisableInactiveArgs '-Scheduled' `
  -DeleteDisabledArgs  '-Scheduled'
```

> `-RequireApprovalList` is **optional** on both jobs - add it only if you want a
> manual change-control step. For hands-off operation leave it off; the disabled-
> for-N-days threshold, the per-run cap (`-MaxDeletes`/`-MaxChanges`) and the
> ignore lists are the automatic safeguards and need no curation.

---

## 1b. Import-ready XML (no installer)

If you'd rather import tasks by hand — or push them out with Group Policy /
`schtasks` — the [`scheduled-tasks/`](../scheduled-tasks/) folder has one
ready-made `.xml` per script (`ADAuto-*.xml`), with the same triggers and
arguments the installer uses. They're generated from the Task Scheduler API, so
they're schema-valid and import cleanly.

Defaults: run-as **SYSTEM** (simplest on a DC) and the two destructive jobs in
**`-DryRun`**. Scripts are assumed to be in `C:\AD-Automation`.

```powershell
# Import all of them under \AD-Automation, as SYSTEM (run elevated)
Get-ChildItem .\scheduled-tasks\ADAuto-*.xml | ForEach-Object {
    Register-ScheduledTask -Xml (Get-Content $_.FullName -Raw) `
        -TaskName $_.BaseName -TaskPath '\AD-Automation' -Force
}
```

Or in the GUI: `taskschd.msc` → **Action → Import Task…**. To change the run-as
account, the script location, or flip the destructive jobs to `-Scheduled`, re-run
`scheduled-tasks\Build-TaskXml.ps1` (e.g. `-RunAs 'CORP\adauto$' -ScriptRoot
'D:\AD-Automation'`) or edit the file before importing. Full details:
[scheduled-tasks/README.md](../scheduled-tasks/README.md).

---

## 2. Recommended schedule

| Task | Suggested trigger | Arguments |
|---|---|---|
| Password expiry notify | Daily 07:00 | `-Run` |
| Disable-inactive **warning** | Daily 07:30 | `-Run` |
| Lockout notify | Every 15 min | `-Run -LookbackMinutes 20` |
| Disable inactive | Daily 02:00 | `-Scheduled` |
| Delete disabled users | Weekly Sun 03:00 | `-Scheduled` |
| Duplicate-password notify | Every 30 min *or* on event 4720 | `-Run` |
| Password-change audit | Every 30 min *or* on event 4723/4724 | `-Run` |
| Server group provisioning | Daily 04:00 | `-WhatIf` (preview; remove to go live) |

> Set `-LookbackMinutes` **>=** the lockout run interval (e.g. interval 15 min,
> `-LookbackMinutes 20`) so a delayed or skipped cycle is still covered. The script
> keeps a per-DC high-water mark so the overlap never produces duplicate e-mails,
> catches up from the last successful run, and resets the mark if a DC's Security
> log is cleared/recreated.

---

## 3. The manual way – `Register-ScheduledTask`

Example: password-expiry notifier, daily at 07:00, as SYSTEM on a DC.

```powershell
$root   = 'C:\AD-Automation'   # where the scripts live
$psExe  = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$script = Join-Path $root 'Invoke-ADPasswordExpiryNotify.ps1'

$action  = New-ScheduledTaskAction -Execute $psExe `
            -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -Run" `
            -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -Daily -At 7:00am
$princ   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$set     = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
            -ExecutionTimeLimit (New-TimeSpan -Hours 2)

Register-ScheduledTask -TaskName 'ADAuto-PasswordExpiry' -TaskPath '\AD-Automation' `
  -Action $action -Trigger $trigger -Principal $princ -Settings $set -Force
```

A 15-minute repeating trigger (lockout job):

```powershell
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date
$trigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 15) `
    -RepetitionDuration (New-TimeSpan -Days 3650)).Repetition
```

Run as a **gMSA** instead of SYSTEM:

```powershell
$princ = New-ScheduledTaskPrincipal -UserId 'CORP\adauto$' -LogonType Password -RunLevel Highest
```

---

## 4. Event-driven runs (password jobs)

The two password-hash scripts accept `-SamAccountName`, so you can trigger them on
the *exact* security event and audit only the account involved – near real-time,
no polling.

- **New account created → event 4720** → `Invoke-ADDuplicatePasswordNotify.ps1`
- **Password change/reset → events 4723 / 4724** → `Invoke-ADPasswordChangeAudit.ps1`

These events are written to the **DC Security log**, so register the task **on a
DC** (or subscribe remotely). The trick is an XML *event trigger* with a **value
query** that pulls the target SAM from the event and passes it as `-SamAccountName`.

1. Create the task action (note the `$(SamName)` placeholder we will wire up):

```powershell
$root   = 'C:\AD-Automation'
$psExe  = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$script = Join-Path $root 'Invoke-ADDuplicatePasswordNotify.ps1'
$action = New-ScheduledTaskAction -Execute $psExe `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -Run -SamAccountName `"`$(SamName)`"" `
  -WorkingDirectory $root
```

2. Build an event trigger that fires on 4720 and captures `TargetUserName`:

```powershell
$class = Get-CimClass -Namespace ROOT\Microsoft\Windows\TaskScheduler -ClassName MSFT_TaskEventTrigger
$trigger = New-CimInstance -CimClass $class -ClientOnly
$trigger.Enabled      = $true
$trigger.Subscription = @'
<QueryList><Query Id="0" Path="Security">
  <Select Path="Security">*[System[(EventID=4720)]]</Select>
</Query></QueryList>
'@
# Map the event's TargetUserName (EventData Data[0]) to the task variable "SamName"
$vq = New-CimInstance -CimClass (Get-CimClass -Namespace ROOT\Microsoft\Windows\TaskScheduler -ClassName MSFT_TaskNamedValue) -ClientOnly
$vq.Name  = 'SamName'
$vq.Value = 'Event/EventData/Data[@Name="TargetUserName"]'
$trigger.ValueQueries = [ciminstance[]]@($vq)

$princ = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'ADAuto-DuplicatePassword-OnCreate' -TaskPath '\AD-Automation' `
  -Action $action -Trigger $trigger -Principal $princ -Force
```

For password changes, use the same pattern with
`Invoke-ADPasswordChangeAudit.ps1` and a subscription matching **4723 or 4724**:

```xml
<QueryList><Query Id="0" Path="Security">
  <Select Path="Security">*[System[(EventID=4723 or EventID=4724)]]</Select>
</Query></QueryList>
```

> Event triggers replace the periodic poll. You can keep a low-frequency poll as a
> safety net (it catches anything missed while a DC/the task was offline); the
> state file makes both modes idempotent.

---

## 5. Least-privilege account

A **group Managed Service Account (gMSA)** is ideal – no stored password, auto-
rotated. Create one and grant only what each job needs:

```powershell
# One-time, if you have no KDS root key yet (wait 10h, or -EffectiveImmediately in a lab)
Add-KdsRootKey -EffectiveImmediately

New-ADServiceAccount -Name 'adauto' -DNSHostName 'adauto.corp.local' `
  -PrincipalsAllowedToRetrieveManagedPassword 'CORP\DC-and-TaskHosts'
# On each host that runs the tasks:
Install-ADServiceAccount -Identity 'adauto'
```

Grant per job (delegate, do **not** make it Domain Admin):

| Job | Rights needed |
|---|---|
| Read-only notifiers (expiry, warning, lockout) | Read user objects; **read the DC Security log** (lockout) |
| Disable inactive | `Disable account` + write `userAccountControl`; **Move** objects into the Disabled OU(s) |
| Delete disabled | `Delete` user objects in the target scope; read `Replicate Directory Changes` metadata |
| Duplicate-password / Password-change audit | **Replicating Directory Changes** *and* **Replicating Directory Changes All** (DCSync) on the domain head |

Delegate disable/move/delete with the **Delegation of Control Wizard** or
`dsacls` on the relevant OUs. Grant replication rights only to the hash jobs'
account, and treat that account as Tier-0.

Reading a DC Security log remotely (lockout job on a non-DC host) needs the
run-as account in the DC's **Event Log Readers** group and the **Remote Event Log
Management** firewall rule enabled on the DCs.

---

## 6. Verify & troubleshoot

```powershell
# See the tasks
Get-ScheduledTask -TaskPath '\AD-Automation\'

# Run one now and read the result
Start-ScheduledTask -TaskName 'ADAuto-PasswordExpiry' -TaskPath '\AD-Automation\'
(Get-ScheduledTaskInfo -TaskName 'ADAuto-PasswordExpiry' -TaskPath '\AD-Automation\').LastTaskResult  # 0 = success

# Every run also writes a timestamped log + CSV
Get-ChildItem 'C:\ProgramData\AD-Automation' -Filter *.log | Sort-Object LastWriteTime | Select-Object -Last 5

# ...and mirrors to the Windows Event Log (Applications and Services Logs >
# AD-Automation, one event source per script; IDs: 1001 = action taken,
# 2000 = warning, 3000 = error)
Get-WinEvent -FilterHashtable @{ LogName = 'AD-Automation'; StartTime = (Get-Date).AddHours(-24) } |
    Format-Table TimeCreated, ProviderName, Id, Message -AutoSize
```

Common issues:

- **`LastTaskResult` 0x1 / nonzero** – run the script's command line by hand in the
  run-as context; the log file shows the real error.
- **No mail** – check `SmtpServer`/`MailFrom`/`MailUseSsl`; a `contoso.` placeholder
  is refused by the hygiene/hash jobs (configure `settings.psd1`).
- **Hash jobs throw on `Get-ADReplAccount`** – the account lacks replication rights,
  or DSInternals isn't installed, or the task isn't running on/against a DC.
- **Lockout job finds nothing on a multi-DC domain** – it defaults to the PDC
  emulator; set `AllDomainControllers = $true` for full coverage.
- **Nothing appears in the AD-Automation event log** – the log/source needs one
  elevated registration: run the installer elevated, or let the task run once as
  SYSTEM/gMSA (it self-registers), or call
  `Register-ADAutomationEventLog -LogName 'AD-Automation' -Sources '<script prefix>'`
  from an elevated prompt. Until then the scripts log to console + file only.
