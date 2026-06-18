<#
.SYNOPSIS
Warn BEFORE an inactive user is automatically disabled.

.DESCRIPTION
Companion to Invoke-ADHygieneDisableInactive.ps1. Finds enabled users who are
approaching the inactivity threshold and, a configurable number of days before
they would be disabled, e-mails a heads-up to:
  - the user's MANAGER (the account's 'manager' attribute -> manager 'mail'), and
  - any AdditionalMailTo addresses (always included).

If the 'manager' attribute is empty (or the manager has no mailbox) the script
simply continues - it still notifies AdditionalMailTo and logs the gap; it never
stops on a missing manager.

Set -UserInactiveForDays to the SAME value used by the disable job so the warning
lead time is accurate. Run this DAILY so the discrete -WarnDays thresholds fire.
Everything can be configured in config\AD-Automation.settings.psd1 (section
'DisableInactiveWarning' / 'Common').

.EXAMPLE
.\Invoke-ADDisableInactiveWarning.ps1 -DryRun

.EXAMPLE
.\Invoke-ADDisableInactiveWarning.ps1 -Run -WarnDays 14,7,1 -AdditionalMailTo hr@corp.com

.NOTES
- Read-only against AD (sends mail only); makes no account changes.
- Output folder holds account/manager data; it is created with a restricted ACL.
#>

[CmdletBinding(DefaultParameterSetName = 'DryRun')]
param(
    [Parameter(ParameterSetName = 'DryRun', Mandatory = $true)][switch]$DryRun,
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)][switch]$Run,

    # Must match the disable job's threshold for an accurate projected disable date.
    [ValidateRange(21, 3650)][int]$UserInactiveForDays = 90,
    [ValidateRange(0, 3650)][int]$UserNeverLoggedOnMinAccountAgeDays = 30,

    # Send a warning when the projected disable date is exactly this many days away.
    [int[]]$WarnDays = @(14, 7, 1),

    [string[]]$UserLimitToOUs = @(),

    # Extra recipients ALWAYS added on top of the manager.
    [string[]]$AdditionalMailTo = @(),

    [bool]$IncludeServiceAccounts = $false,
    [string[]]$ServiceAccountSamRegex = @('^svc_', '^sa_'),

    [string[]]$IgnoreAccountsExact = @('Administrator', 'Guest', 'krbtgt', 'DefaultAccount', 'WDAGUtilityAccount'),
    [string[]]$IgnoreAccountsRegex = @('^AZURE', '^MSOL', '^BTG', '^DWM-'),

    [string]$SmtpServer = 'smtp-relay.contoso.local',
    [int]$SmtpPort = 25,
    [string]$MailFrom = 'ad-automation@contoso.local',
    [bool]$MailUseSsl = $false,
    [string]$MailCredentialPath = '',
    # Admin summary recipients (a CSV of everyone warned this run).
    [string[]]$AdminMailTo = @(),

    [string]$Server = '',
    [string]$OutputRoot = 'C:\ProgramData\AD-Automation',
    [string]$LogFilePrefix = 'ADDisableInactiveWarning',
    [string]$ConfigPath = ''
)

# --- Bootstrap --------------------------------------------------------------
$modulePath = Join-Path $PSScriptRoot 'ADAutomation.psd1'
if (-not (Test-Path -LiteralPath $modulePath)) { throw "Required module not found next to script: $modulePath" }
Import-Module $modulePath -Force -ErrorAction Stop

$cfg = Import-ADAutomationConfig -Path $ConfigPath -Section 'DisableInactiveWarning'
$boundKeys = @($PSBoundParameters.Keys)
foreach ($k in @($cfg.Keys)) {
    if ($k -eq '__ConfigFile') { continue }
    if ($boundKeys -notcontains $k -and (Get-Variable -Name $k -Scope 0 -ErrorAction SilentlyContinue)) {
        Set-Variable -Name $k -Value $cfg[$k] -Scope 0
    }
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw 'ActiveDirectory module not found. Install RSAT / AD PowerShell module.'
}
Import-Module ActiveDirectory -ErrorAction Stop

# --- Setup ------------------------------------------------------------------
$run = Initialize-ADAutomationLog -OutputRoot $OutputRoot -BaseName $LogFilePrefix
$CsvPath = Join-Path $OutputRoot ("{0}-Report-{1}.csv" -f $LogFilePrefix, $run.RunId)
$whatIf = ($PSCmdlet.ParameterSetName -eq 'DryRun')

if ([string]::IsNullOrWhiteSpace($Server)) { try { $Server = (Get-ADAutomationDomainInfo).Server } catch { $Server = '' } }
$srv = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) { $srv['Server'] = $Server }

$mailCommon = @{
    From = $MailFrom; SmtpServer = $SmtpServer; SmtpPort = $SmtpPort
    UseSsl = $MailUseSsl; CredentialPath = $MailCredentialPath
}
$additional = @($AdditionalMailTo | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

$today = (Get-Date).Date

if (-not $UserLimitToOUs -or @($UserLimitToOUs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
    try { $UserLimitToOUs = @((Get-ADAutomationDomainInfo @srv).DistinguishedName) } catch { }
    Write-ADAutomationLog "No UserLimitToOUs; defaulting to domain root: $($UserLimitToOUs -join ', ')" 'INFO'
}
$userBases = Get-ValidSearchBase -Bases $UserLimitToOUs @srv
if (-not $userBases -or $userBases.Count -eq 0) { throw "No valid AD search bases from UserLimitToOUs ($($UserLimitToOUs -join ', '))." }

Write-ADAutomationLog "=== START (RunId=$($run.RunId)) ==="
Write-ADAutomationLog ("Mode={0} ; WhatIf={1} ; UserInactiveForDays={2} ; WarnDays={3} ; Server={4}" -f `
        $PSCmdlet.ParameterSetName, $whatIf, $UserInactiveForDays, ($WarnDays -join ','), $Server)
Write-ADAutomationLog ("AdditionalMailTo={0} ; AdminMailTo={1}" -f ($additional -join ','), ($AdminMailTo -join ','))

function Test-IsServiceSam {
    param([string]$Sam, [string[]]$Regexes)
    foreach ($p in $Regexes) { if (-not [string]::IsNullOrWhiteSpace($p) -and $Sam -match $p) { return $true } }
    return $false
}

$report = New-Object System.Collections.Generic.List[object]

foreach ($base in $userBases) {
    Write-ADAutomationLog "Processing OU: $base"
    try {
        $users = Get-ADUser -SearchBase $base -SearchScope Subtree @srv `
            -LDAPFilter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            -Properties LastLogonDate, whenCreated, manager, mail, DisplayName, SamAccountName -ErrorAction Stop
    }
    catch { Write-ADAutomationLog "ERROR querying '$base': $($_.Exception.Message)" 'ERROR'; continue }

    foreach ($u in $users) {
        try {
            $sam = $u.SamAccountName
            if (Test-IsIgnoredName -Name $sam -ExactList $IgnoreAccountsExact -RegexList $IgnoreAccountsRegex) { continue }
            if (-not $IncludeServiceAccounts -and (Test-IsServiceSam -Sam $sam -Regexes $ServiceAccountSamRegex)) { continue }

            # Projected disable date mirrors the disable job's logic.
            if ($u.LastLogonDate) { $disableDate = $u.LastLogonDate.AddDays($UserInactiveForDays); $basis = "LastLogon=$($u.LastLogonDate.ToString('yyyy-MM-dd'))" }
            elseif ($u.whenCreated) { $disableDate = $u.whenCreated.AddDays($UserNeverLoggedOnMinAccountAgeDays); $basis = "NeverLoggedOn; Created=$($u.whenCreated.ToString('yyyy-MM-dd'))" }
            else { continue }

            $daysUntil = ($disableDate.Date - $today).Days
            if ($daysUntil -lt 0) { continue }                          # already past -> the disable job handles it
            if ($WarnDays.Count -gt 0 -and ($WarnDays -notcontains $daysUntil)) { continue }

            # Recipients: manager (if any) + always the additional list.
            $managerMail = Resolve-ADManagerMail -AdUser $u @srv
            $recipients = New-Object System.Collections.Generic.List[string]
            if ($managerMail) { $recipients.Add($managerMail) }
            foreach ($a in $additional) { $recipients.Add($a) }
            $recipients = @($recipients | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

            if (-not $managerMail) { Write-ADAutomationLog "No manager mail for $sam (continuing; AdditionalMailTo only)." 'WARN' }

            $report.Add([pscustomobject]@{
                    SamAccountName      = $sam
                    DisplayName         = $u.DisplayName
                    ManagerMail         = $managerMail
                    Basis               = $basis
                    ProjectedDisableDate = $disableDate.ToString('yyyy-MM-dd')
                    DaysUntilDisable    = $daysUntil
                    NotifiedTo          = ($recipients -join ';')
                    OU                  = $base
                }) | Out-Null

            $subject = "Action needed: account '$($u.DisplayName)' will be disabled in $daysUntil day(s)"
            $body = @"
Hello,

The Active Directory account below has been inactive and is scheduled to be
DISABLED automatically in $daysUntil day(s) unless it is used before then.

  Account     : $($u.DisplayName) ($sam)
  Reason      : $basis
  Disable date: $($disableDate.ToString('yyyy-MM-dd'))

If this person still needs access, please ask them to sign in before that date,
or contact IT if the account should be kept active. If the account is no longer
needed, no action is required - it will be disabled automatically.

Thank you,
IT Operations
"@

            if ($recipients.Count -eq 0) {
                Write-ADAutomationLog "No recipients for $sam (no manager, no AdditionalMailTo); logged only." 'WARN'
            }
            elseif ($whatIf) {
                Write-ADAutomationLog "WHATIF: would warn [$($recipients -join ', ')] about $sam (in $daysUntil d)" 'WHATIF'
            }
            else {
                [void](Send-ADAutomationMail @mailCommon -To $recipients -Subject $subject -Body $body)
            }
        }
        catch { Write-ADAutomationLog "Unexpected error processing '$($u.SamAccountName)': $($_.Exception.Message)" 'ERROR'; continue }
    }
}

# --- Reporting --------------------------------------------------------------
try { $report | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8; Write-ADAutomationLog "CSV report written: $CsvPath" 'INFO' }
catch { Write-ADAutomationLog "ERROR writing CSV report: $($_.Exception.Message)" 'ERROR' }

if (-not $whatIf -and @($AdminMailTo).Count -gt 0 -and (Test-Path -LiteralPath $CsvPath)) {
    [void](Send-ADAutomationMail @mailCommon -To $AdminMailTo `
            -Subject ("AD Disable-Inactive Warning summary ({0}) - {1} user(s)" -f $today.ToString('yyyy-MM-dd'), $report.Count) `
            -Body 'Attached is the list of users warned about pending disablement.' -Attachments @($CsvPath))
}

Write-ADAutomationLog "=== END (warned=$($report.Count)) ==="
Write-Output "Done. Mode=$($PSCmdlet.ParameterSetName) Warned=$($report.Count)"
Write-Output "Log: $($run.LogPath)"
Write-Output "CSV: $CsvPath"
