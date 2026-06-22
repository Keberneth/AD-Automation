# Import-ready Scheduled Task XML

Drop-in `.xml` files you can import straight into Windows Task Scheduler — one per
AD-Automation script. Same triggers, cadence and arguments the bundled installer
(`Install-ADAutomationScheduledTask.ps1`) would create, but as portable files you
can review, hand to another admin, or deploy by GPO.

> Prefer one command for everything? Use the installer instead — see the root
> [README](../README.md) and [docs/SCHEDULED-TASKS.md](../docs/SCHEDULED-TASKS.md).
> These XML files are the alternative for people who want to import by hand.

## What's here

| File | Trigger | Arguments |
|---|---|---|
| `ADAuto-PasswordExpiry.xml` | Daily 07:00 | `-Run` |
| `ADAuto-DisableWarning.xml` | Daily 07:30 | `-Run` |
| `ADAuto-Lockout.xml` | Every 15 min | `-Run -LookbackMinutes 20` |
| `ADAuto-DuplicatePassword.xml` | Every 30 min | `-Run` |
| `ADAuto-PasswordChangeAudit.xml` | Every 30 min | `-Run` |
| `ADAuto-DisableInactive.xml` | Daily 02:00 | **`-DryRun`** |
| `ADAuto-DeleteDisabled.xml` | Weekly Sun 03:00 | **`-DryRun`** |
| `ADAuto-ServerGroups.xml` | Daily 04:00 | *(none)* |

`Build-TaskXml.ps1` is the generator that produced them (via the Task Scheduler
API, so the XML is guaranteed valid). Re-run it any time you want to change the
run-as account, the script location, or a schedule — see **Customise** below.

**Two defaults baked in — read these before importing:**

1. **Run-as = `SYSTEM`** (`S-1-5-18`). Simplest and password-free, but only has AD
   rights when the task runs **on a Domain Controller**. On a non-DC host, change
   the account (see Customise).
2. **The destructive jobs are in `-DryRun`** — they only write a report, they
   change nothing. Flip them to live when you're ready (see Go live).

The scripts are assumed to live in **`C:\AD-Automation`**. If yours are elsewhere,
regenerate with `-ScriptRoot` (see Customise) — don't just move the files.

## Import them

> The PowerShell and `schtasks` snippets below assume you're **inside this
> `scheduled-tasks\` folder** (`cd` here first). From the repo root, prefix the
> paths with `scheduled-tasks\`.

### A. Task Scheduler (GUI) — no code

1. `taskschd.msc` → optionally create/select a folder (e.g. `AD-Automation`).
2. **Action → Import Task… → pick a file → OK.**
3. If you're **not** running as SYSTEM, switch the account on the **General** tab
   ("Change User or Group…") before saving.

### B. PowerShell — import all at once (run elevated)

Registers every file under a `\AD-Automation` task folder, as SYSTEM (the account
baked into the XML):

```powershell
Get-ChildItem .\ADAuto-*.xml | ForEach-Object {
    Register-ScheduledTask -Xml (Get-Content $_.FullName -Raw) `
        -TaskName $_.BaseName -TaskPath '\AD-Automation' -Force
}
```

Running as a **service account** instead? Add credentials (overrides the XML):

```powershell
$pw = Read-Host 'Service account password' -AsSecureString
Get-ChildItem .\ADAuto-*.xml | ForEach-Object {
    Register-ScheduledTask -Xml (Get-Content $_.FullName -Raw) `
        -TaskName $_.BaseName -TaskPath '\AD-Automation' `
        -User 'CORP\svc-adauto' -Password ([System.Net.NetworkCredential]::new('',$pw).Password) -Force
}
```

For a **gMSA** (recommended, no stored password): regenerate with
`-RunAs 'CORP\adauto$'` (see Customise) and import with the first loop.

### C. schtasks.exe (one file)

```cmd
schtasks /Create /TN "AD-Automation\ADAuto-PasswordExpiry" /XML "ADAuto-PasswordExpiry.xml" /RU SYSTEM
```

## Go live (the disable / delete jobs)

`ADAuto-DisableInactive.xml` and `ADAuto-DeleteDisabled.xml` ship in `-DryRun`.
Review the reports under `C:\ProgramData\AD-Automation`, then either:

- **regenerate** with live args — edit the two `Args = '-DryRun'` rows in
  `Build-TaskXml.ps1` to `'-Scheduled'` and re-run it; or
- **edit in place** — change `-DryRun` to `-Scheduled` in the `<Arguments>` line of
  those two files (or on the task's **Actions** tab after import).

No approval list is needed for hands-off operation; `-RequireApprovalList` is
optional manual change-control only. See the root [README](../README.md).

## Customise (run-as, location, schedule)

`Build-TaskXml.ps1` regenerates all eight files. It registers nothing and needs no
elevation — it only serialises XML to disk.

```powershell
# Run as a gMSA, scripts installed under D:\Tools\AD-Automation
.\Build-TaskXml.ps1 -RunAs 'CORP\adauto$' -ScriptRoot 'D:\Tools\AD-Automation'
```

- `-RunAs`     run-as identity (default `SYSTEM`; e.g. `CORP\adauto$`, `CORP\svc-adauto`)
- `-ScriptRoot`  folder on the target host where the `Invoke-AD*.ps1` scripts live (default `C:\AD-Automation`)
- `-OutDir`    where to write the `.xml` (default: this folder)

Change times/intervals by editing the `$tasks` table in the script, then re-run.

## Verify after import

```powershell
Get-ScheduledTask -TaskPath '\AD-Automation\'
Start-ScheduledTask -TaskName 'ADAuto-PasswordExpiry' -TaskPath '\AD-Automation\'
(Get-ScheduledTaskInfo -TaskName 'ADAuto-PasswordExpiry' -TaskPath '\AD-Automation\').LastTaskResult  # 0 = success
```
