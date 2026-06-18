# AD-Automation

A small library of **standalone PowerShell scripts** that keep Active Directory
healthy and secure, designed to run **unattended via Scheduled Tasks** with
**no per-run busy-work**.

---

# Short version (TL;DR)

**What it is.** Drop-in scripts for AD hygiene (disable/delete stale objects),
user notifications (password expiry, lockouts, pending disable) and password
security (duplicate-password + Have I Been Pwned checks). One external settings
file configures everything — you never edit a script for your environment.

**Three principles:** *configure once* (one `.psd1` file) · *works with any AD*
(auto-detects the domain) · *safe & simple by default* (dry-run, automatic caps,
no lists to curate).

**Get going in 3 steps:**

```powershell
Copy-Item config\AD-Automation.settings.sample.psd1 config\AD-Automation.settings.psd1
notepad config\AD-Automation.settings.psd1          # set SMTP, recipients, OUs
.\Invoke-ADHygieneDisableInactive.ps1 -DryRun       # preview - changes nothing
```

Then schedule everything at once:

```powershell
.\Install-ADAutomationScheduledTask.ps1 -UseSystem -ListOnly   # preview tasks
.\Install-ADAutomationScheduledTask.ps1 -UseSystem             # register them
```

**What to run, and how often:**

| Script | Recommended interval | Mode (live) | What it does |
|---|---|---|---|
| `Invoke-ADPasswordExpiryNotify.ps1` | **Daily** (07:00) | `-Run` | Warn users before their password expires |
| `Invoke-ADDisableInactiveWarning.ps1` | **Daily** (07:30) | `-Run` | Warn manager + extras *before* an inactive user is disabled |
| `Invoke-ADLockoutNotify.ps1` | **Every 15 min** | `-Run` | Alert on account lockouts (event 4740) |
| `Invoke-ADDuplicatePasswordNotify.ps1` | **Every 30 min** *or* event 4720 | `-Run` | Alert when a new account reuses another's password |
| `Invoke-ADPasswordChangeAudit.ps1` | **Every 30 min** *or* event 4723/4724 | `-Run` | On password change: duplicate + pwned checks |
| `Invoke-ADHygieneDisableInactive.ps1` | **Daily** (02:00) | `-Scheduled` | Disable inactive users/computers, move to a Disabled OU |
| `Invoke-ADHygieneDeleteDisabledUsers.ps1` | **Weekly** (Sun 03:00) | `-Scheduled` | Delete users disabled for ≥ N days |
| `Invoke-ADServerGroupProvisioning.ps1` | **Daily** (04:00) | *(none)* | Create per-server Admin/RDP groups, nest baselines |

> The destructive jobs (disable/delete) install in `-DryRun` first — review the
> report, then switch to `-Scheduled`. **No approval list is required**; the
> disabled-for-N-days threshold and per-run caps are the automatic safety net.
> Notifications need only a working SMTP relay. The two password jobs additionally
> need **DSInternals** + replication rights and should run on/near a DC.

Full setup, per-script details, security model and event-driven triggers are
below and in **[docs/SCHEDULED-TASKS.md](docs/SCHEDULED-TASKS.md)**.

---

# Full guide

## Contents

| Script | Purpose | Modes |
|---|---|---|
| `Invoke-ADHygieneDisableInactive.ps1` | Disable inactive users (standard + service) & computers; optionally move them to a "Disabled" OU | `-DryRun` / `-Run` / `-Scheduled` |
| `Invoke-ADHygieneDeleteDisabledUsers.ps1` | Delete users that have been **disabled** for N days | `-DryRun` / `-Run` / `-Scheduled` |
| `Invoke-ADDisableInactiveWarning.ps1` | **Warn the manager** (and extra addresses) *before* a user is disabled | `-DryRun` / `-Run` |
| `Invoke-ADLockoutNotify.ps1` | E-mail on account lockouts (event 4740), across all DCs, de-duplicated | `-DryRun` / `-Run` |
| `Invoke-ADPasswordExpiryNotify.ps1` | E-mail users before their password expires | `-DryRun` / `-Run` |
| `Invoke-ADDuplicatePasswordNotify.ps1` | Alert when a **new account** reuses another account's NTLM password | `-DryRun` / `-Run` |
| `Invoke-ADPasswordChangeAudit.ps1` | On password change: **duplicate-password + Have I Been Pwned** checks | `-DryRun` / `-Run` |
| `Invoke-ADServerGroupProvisioning.ps1` | Create per-server Admin/RDP groups and nest baseline groups | `-WhatIf` aware |
| `Install-ADAutomationScheduledTask.ps1` | Register all of the above as Scheduled Tasks | `-WhatIf` / `-ListOnly` |
| `ADAutomation.psm1` / `.psd1` | Shared module (config, logging, mail, hashing, state) | — |

## Prerequisites

- **Windows PowerShell 5.1** (or PowerShell 7+) on a domain-joined host.
- **RSAT ActiveDirectory module** (`Get-Module -ListAvailable ActiveDirectory`).
- **DSInternals** module *only* for the two password-hash scripts
  (`Install-Module DSInternals`).
- A run-as account with the right permissions — see
  [docs/SCHEDULED-TASKS.md](docs/SCHEDULED-TASKS.md#5-least-privilege-account).

## How configuration works (the "configure once" model)

All scripts read the same file. Resolution order:

1. `-ConfigPath <file>` parameter, then
2. the `AD_AUTOMATION_CONFIG` environment variable, then
3. `config\AD-Automation.settings.psd1` (your real file), then `…json`, then
4. `config\AD-Automation.settings.sample.psd1` (the committed sample).

Inside the file, the **`Common`** section applies to every script and each
**per-script section** (e.g. `DisableInactive`) overrides it. Every key matches a
script **parameter name** exactly.

**Precedence:** built-in default **<** config file **<** value passed on the
command line. So the config file sets defaults for everything at once, and any
parameter you pass on the command line still wins.

```powershell
# settings.psd1 (excerpt)
@{
    Common = @{
        SmtpServer  = 'smtp-relay.corp.local'
        MailFrom    = 'ad-automation@corp.local'
        AdminMailTo = @('it-ops@corp.local')
        OutputRoot  = 'C:\ProgramData\AD-Automation'
    }
    DisableInactive = @{
        UserInactiveForDays = 90
        UserLimitToOUs      = @('OU=Users,DC=corp,DC=local')
    }
    DuplicatePasswordNotify = @{ MailTo = @('security@corp.local') }
}
```

> The file is read with `Import-PowerShellDataFile`, which only parses literals —
> **no code executes**, so it is safe on a Domain Controller. A `.json` file with
> the same structure also works.

### Setting where e-mail goes (no code edits)

Put your relay and recipients in `Common`; override per script where needed
(e.g. `DuplicatePasswordNotify.MailTo`, `DisableInactiveWarning.AdditionalMailTo`).
For TLS set `SmtpPort = 587` and `MailUseSsl = $true`. For an authenticated relay,
store a credential once (DPAPI-encrypted to the run-as account + machine):

```powershell
Get-Credential | Export-Clixml 'C:\ProgramData\AD-Automation\smtp.cred'
# config:  MailCredentialPath = 'C:\ProgramData\AD-Automation\smtp.cred'
```

## Recommended schedule & why

| Script | Interval | Why this cadence |
|---|---|---|
| Password expiry notify | **Daily** | Uses discrete day thresholds (e.g. 14/7/3/1) — must run once per day to hit them. |
| Disable-inactive warning | **Daily** | Same discrete-threshold logic (`WarnDays` = 14/7/1). Run it before the disable job. |
| Lockout notify | **Every 15 min** | Near-real-time alerting. A per-DC event-id watermark prevents duplicate mails. |
| Duplicate-password notify | **Every 30 min** or **on event 4720** | Catch a reused password on a new account quickly. Event trigger = instant, per account. |
| Password-change audit | **Every 30 min** or **on event 4723/4724** | Catch a weak/breached new password quickly after the change. |
| Disable inactive | **Daily** (off-hours) | Hygiene only; daily is ample. Start in `-DryRun`, then `-Scheduled`. |
| Delete disabled users | **Weekly** (off-hours) | Low churn; weekly avoids noise. Start in `-DryRun`, then `-Scheduled`. |
| Server group provisioning | **Daily** or on-demand | New servers get their groups by the next day; idempotent so re-runs are cheap. |

> Make the lockout interval **≥** its `-LookbackMinutes`. The installer wires these
> cadences up for you; see [docs/SCHEDULED-TASKS.md](docs/SCHEDULED-TASKS.md) for
> manual `Register-ScheduledTask` examples and **event-driven** triggers.

## The scripts in detail

Each script accepts `-DryRun` (preview) and writes a timestamped **log + CSV** to
`OutputRoot` (default `C:\ProgramData\AD-Automation`, created with a restricted ACL).

### Notifications

- **`Invoke-ADPasswordExpiryNotify.ps1`** — e-mails users whose password expires
  within `NotifyWindowDays`, or exactly on `NotifyDays` thresholds. Sends an admin
  summary CSV to `AdminMailTo`. *Daily.*
- **`Invoke-ADDisableInactiveWarning.ps1`** — projects each inactive user's disable
  date and warns at `WarnDays` (default 14/7/1). Recipients = the account's
  **`manager`** mail **plus** `AdditionalMailTo`. **If `manager` is empty it simply
  continues** — it still notifies the extra addresses and logs the gap; it never
  stops. Read-only (no account changes). Keep `UserInactiveForDays` equal to the
  disable job's value. *Daily.*
- **`Invoke-ADLockoutNotify.ps1`** — reads event 4740 from the **PDC emulator**
  (or every DC with `AllDomainControllers = $true`), e-mails admins and optionally
  the locked-out user. A per-DC `RecordId` high-water mark prevents duplicate mails
  on overlapping runs. *Every 15 min.*

### Hygiene (safe & simple)

- **`Invoke-ADHygieneDisableInactive.ps1`** — disables users/computers inactive
  past their threshold and optionally moves them to a Disabled OU (leave the move
  OU empty to disable in place). `MaxChanges` caps objects changed per run. *Daily,
  `-DryRun` → `-Scheduled`.*
- **`Invoke-ADHygieneDeleteDisabledUsers.ps1`** — deletes users **disabled for ≥
  `DisabledForDays`** (default 180). Safety is automatic: the threshold, a per-run
  `MaxDeletes` cap (default 25; `-Unlimited` lifts it), ignore lists, and skipping
  any account whose disable date can't be reliably determined. **No approval list
  to maintain** — `-RequireApprovalList` exists only if you *want* manual change
  control. *Weekly, `-DryRun` → `-Scheduled`.*

### Password security (require DSInternals + replication rights)

- **`Invoke-ADDuplicatePasswordNotify.ps1`** — alerts when a **newly created**
  account is given a password (NTLM hash) already used by another account. Tracks
  new accounts between runs (first run = baseline only). Accepts `-SamAccountName`
  for event-driven (4720) runs. E-mails `MailTo`. *Every 30 min or on 4720.*
- **`Invoke-ADPasswordChangeAudit.ps1`** — when a user **changes their password**,
  runs a **duplicate-password** check and a **Have I Been Pwned** check on the new
  hash. Tracks `pwdLastSet` between runs (first run = baseline). Accepts
  `-SamAccountName` for event-driven (4723/4724) runs. E-mails `MailTo`.
  *Every 30 min or on 4723/4724.*

Both hash scripts use **k-anonymity** for HIBP (only the first 5 hex chars of a
hash ever leave the host) and **never e-mail raw NTLM hashes** — only a masked
label like `8846F...586C`. Full hashes hit disk only with `-WriteHashCsv`.

### Provisioning

- **`Invoke-ADServerGroupProvisioning.ps1`** — for each computer in `ComputerOUs`,
  creates `SRV-<name>-Administrators` / `-RemoteDesktopUsers` and nests the baseline
  groups. Idempotent, `-WhatIf`-aware, pins one DC so create-then-read never races
  replication. *Daily or on-demand.*

## Safety model

- **Dry-run first.** `-DryRun` changes nothing and writes a CSV + log.
- **Automatic, low-friction guardrails.** Day thresholds + per-run caps
  (`MaxChanges` / `MaxDeletes`, default 25) + ignore lists protect you without any
  list to maintain. An optional `-RequireApprovalList` is there only if you want it.
- **Restricted output.** `OutputRoot` is created with an ACL limited to SYSTEM,
  Administrators and the run-as account.
- **TLS-capable, UTF-8 mail.** Swedish characters (å ä ö) survive; set
  `MailUseSsl` / `MailCredentialPath` to encrypt and authenticate.
- **No secrets leaked.** Password jobs mask hashes and use HIBP k-anonymity.

## Automating it (Scheduled Tasks)

```powershell
# Preview the whole task set (no changes)
.\Install-ADAutomationScheduledTask.ps1 -GmsaUser 'CORP\adauto$' -ListOnly

# Install the notification jobs as SYSTEM on a DC
.\Install-ADAutomationScheduledTask.ps1 -UseSystem -Include PasswordExpiry,Lockout,DisableWarning
```

Run-as options, a least-privilege gMSA, per-task manual `Register-ScheduledTask`
examples, the recommended schedule, and **event-driven** triggers for the password
jobs are all in **[docs/SCHEDULED-TASKS.md](docs/SCHEDULED-TASKS.md)**.

## Naming convention

All scripts use the approved PowerShell **`Verb-Noun`** form prefixed `Invoke-AD…`
so they sort and read consistently. (`create_computer_groups.ps1` was renamed to
`Invoke-ADServerGroupProvisioning.ps1`.)
