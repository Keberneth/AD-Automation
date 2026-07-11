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

    # Must match the disable job's thresholds for an accurate projected disable date.
    [ValidateRange(21, 3650)][int]$UserInactiveForDays = 90,
    [ValidateRange(0, 3650)][int]$UserNeverLoggedOnMinAccountAgeDays = 30,
    # Service-account thresholds - mirror Invoke-ADHygieneDisableInactive.ps1 so the
    # projected disable date is correct for accounts it classifies as service.
    [ValidateRange(21, 3650)][int]$ServiceInactiveForDays = 180,
    [ValidateRange(0, 3650)][int]$ServiceNeverLoggedOnMinAccountAgeDays = 90,

    # Mirror the disable job's SearchScope (RunInChildOU='no' => OneLevel).
    [ValidateSet('yes', 'no')][string]$RunInChildOU = 'yes',

    # Send a warning when the projected disable date is exactly this many days away.
    [int[]]$WarnDays = @(14, 7, 1),

    [string[]]$UserLimitToOUs = @(),

    # Extra recipients ALWAYS added on top of the manager.
    [string[]]$AdditionalMailTo = @(),

    # Service-account detection - mirror the disable job (any match => service).
    [bool]$IncludeServiceAccounts = $false,
    [string[]]$ServiceAccountOUs = @(),
    [string]$ServiceAccountAttributeName = 'employeeType',
    [string]$ServiceAccountAttributeValueRegex = '^service$',
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

    # Mirror log lines to the Windows Event Log (Applications and Services Logs >
    # EventLogName, source = this script). Source registration needs one elevated
    # run (the installer does it); non-admin runs degrade gracefully.
    [bool]$EventLogEnabled = $true,
    [string]$EventLogName = 'AD-Automation',

    [string]$ConfigPath = ''
)

# --- Bootstrap --------------------------------------------------------------
$modulePath = Join-Path $PSScriptRoot 'ADAutomation.psd1'
if (-not (Test-Path -LiteralPath $modulePath)) { throw "Required module not found next to script: $modulePath" }
Import-Module $modulePath -Force -ErrorAction Stop

$cfg = Import-ADAutomationConfig -Path $ConfigPath -Section 'DisableInactiveWarning'
$boundKeys = @($PSBoundParameters.Keys)
$overlaySkip = @('DryRun', 'Run')
foreach ($k in @($cfg.Keys)) {
    if ($k -eq '__ConfigFile') { continue }
    if ($overlaySkip -contains $k) { Write-Warning "Ignoring config key '$k': run mode is set on the command line only."; continue }
    if ($boundKeys -notcontains $k -and (Get-Variable -Name $k -Scope 0 -ErrorAction SilentlyContinue)) {
        Set-Variable -Name $k -Value $cfg[$k] -Scope 0
    }
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw 'ActiveDirectory module not found. Install RSAT / AD PowerShell module.'
}
Import-Module ActiveDirectory -ErrorAction Stop

# --- Setup ------------------------------------------------------------------
$run = Initialize-ADAutomationLog -OutputRoot $OutputRoot -BaseName $LogFilePrefix -EventLogEnabled $EventLogEnabled -EventLogName $EventLogName
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
$scope = if ($RunInChildOU -eq 'yes') { 'Subtree' } else { 'OneLevel' }

# An empty WarnDays would disable the threshold filter and warn EVERY active user
# every day. Treat empty as "send nothing" rather than "warn everyone".
if (@($WarnDays).Count -eq 0) {
    Write-ADAutomationLog "WarnDays is empty - no warning thresholds configured, nothing to send. Set WarnDays (e.g. 14,7,1)." 'WARN'
}

# Validate the service-detection attribute against the schema; disable it if absent
# so a bad attribute name cannot make Get-ADUser -Properties throw (mirrors the
# disable job).
if (-not [string]::IsNullOrWhiteSpace($ServiceAccountAttributeName)) {
    try {
        $schemaNC = (Get-ADRootDSE @srv -ErrorAction Stop).schemaNamingContext
        $found = @(Get-ADObject -SearchBase $schemaNC @srv -LDAPFilter "(lDAPDisplayName=$ServiceAccountAttributeName)" -ErrorAction Stop)
        if ($found.Count -eq 0) {
            Write-ADAutomationLog "ServiceAccountAttributeName '$ServiceAccountAttributeName' not in schema; attribute-based detection disabled (OU/SAM regex still apply)." 'WARN'
            $ServiceAccountAttributeName = ''
        }
    }
    catch {
        Write-ADAutomationLog "Could not validate ServiceAccountAttributeName '$ServiceAccountAttributeName'; disabling attribute-based detection: $($_.Exception.Message)" 'WARN'
        $ServiceAccountAttributeName = ''
    }
}

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

function Test-IsServiceAccount {
    param($AdUser, [string[]]$ServiceOUs, [string]$AttrName, [string]$AttrValueRegex, [string[]]$SamRegex)
    $sam = $AdUser.SamAccountName
    $dn = $AdUser.DistinguishedName
    if ($ServiceOUs) {
        foreach ($ou in $ServiceOUs) {
            if (-not [string]::IsNullOrWhiteSpace($ou) -and (Test-DNUnderOU -DistinguishedName $dn -OUDistinguishedName $ou)) { return $true }
        }
    }
    if ($SamRegex) {
        foreach ($p in $SamRegex) {
            if (-not [string]::IsNullOrWhiteSpace($p) -and $sam -match $p) { return $true }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($AttrName) -and -not [string]::IsNullOrWhiteSpace($AttrValueRegex)) {
        $val = $AdUser.$AttrName
        if ($val -and ($val.ToString() -match $AttrValueRegex)) { return $true }
    }
    return $false
}

$script:SendFailures = 0
$report = New-Object System.Collections.Generic.List[object]

foreach ($base in $userBases) {
    Write-ADAutomationLog "Processing OU: $base"
    $props = @('LastLogonDate', 'whenCreated', 'manager', 'mail', 'DisplayName', 'SamAccountName', 'DistinguishedName')
    if (-not [string]::IsNullOrWhiteSpace($ServiceAccountAttributeName)) { $props += $ServiceAccountAttributeName }
    try {
        $users = Get-ADUser -SearchBase $base -SearchScope $scope @srv `
            -LDAPFilter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            -Properties $props -ErrorAction Stop
    }
    catch { Write-ADAutomationLog "ERROR querying '$base': $($_.Exception.Message)" 'ERROR'; continue }

    foreach ($u in $users) {
        try {
            $sam = $u.SamAccountName
            if (Test-IsIgnoredName -Name $sam -ExactList $IgnoreAccountsExact -RegexList $IgnoreAccountsRegex) { continue }

            $isService = Test-IsServiceAccount -AdUser $u -ServiceOUs $ServiceAccountOUs -AttrName $ServiceAccountAttributeName -AttrValueRegex $ServiceAccountAttributeValueRegex -SamRegex $ServiceAccountSamRegex
            if (-not $IncludeServiceAccounts -and $isService) { continue }

            # Projected disable date mirrors the disable job's logic, including its
            # separate service-account thresholds.
            $inactiveDays = if ($isService) { $ServiceInactiveForDays } else { $UserInactiveForDays }
            $neverDays = if ($isService) { $ServiceNeverLoggedOnMinAccountAgeDays } else { $UserNeverLoggedOnMinAccountAgeDays }
            if ($u.LastLogonDate) { $disableDate = $u.LastLogonDate.AddDays($inactiveDays); $basis = "LastLogon=$($u.LastLogonDate.ToString('yyyy-MM-dd'))" }
            elseif ($u.whenCreated) { $disableDate = $u.whenCreated.AddDays($neverDays); $basis = "NeverLoggedOn; Created=$($u.whenCreated.ToString('yyyy-MM-dd'))" }
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

            $row = [pscustomobject]@{
                SamAccountName       = $sam
                DisplayName          = $u.DisplayName
                ManagerMail          = $managerMail
                Basis                = $basis
                ProjectedDisableDate = $disableDate.ToString('yyyy-MM-dd')
                DaysUntilDisable     = $daysUntil
                NotifiedTo           = ($recipients -join ';')
                NotifyResult         = 'Pending'
                OU                   = $base
            }

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
                $row.NotifyResult = 'NoRecipients'
            }
            elseif ($whatIf) {
                Write-ADAutomationLog "WHATIF: would warn [$($recipients -join ', ')] about $sam (in $daysUntil d)" 'WHATIF'
                $row.NotifyResult = 'WhatIf'
            }
            elseif (Send-ADAutomationMail @mailCommon -To $recipients -Subject $subject -Body $body) {
                $row.NotifyResult = 'Sent'
            }
            else {
                # A failed send must NOT be recorded as a delivered warning: the user
                # could be disabled the next day having never actually been warned.
                $row.NotifyResult = 'SendFailed'
                $script:SendFailures++
                Write-ADAutomationLog "Warning e-mail FAILED for $sam (recipients: $($recipients -join ', '))." 'ERROR'
            }
            $report.Add($row) | Out-Null
        }
        catch { Write-ADAutomationLog "Unexpected error processing '$($u.SamAccountName)': $($_.Exception.Message)" 'ERROR'; continue }
    }
}

# --- Reporting --------------------------------------------------------------
try { $report | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8; Write-ADAutomationLog "CSV report written: $CsvPath" 'INFO' }
catch { Write-ADAutomationLog "ERROR writing CSV report: $($_.Exception.Message)" 'ERROR' }

if (-not $whatIf -and @($AdminMailTo).Count -gt 0 -and (Test-Path -LiteralPath $CsvPath)) {
    $failSuffix = if ($script:SendFailures -gt 0) { " - {0} SEND FAILURE(S)" -f $script:SendFailures } else { '' }
    [void](Send-ADAutomationMail @mailCommon -To $AdminMailTo `
            -Subject ("AD Disable-Inactive Warning summary ({0}) - {1} user(s){2}" -f $today.ToString('yyyy-MM-dd'), $report.Count, $failSuffix) `
            -Body "Attached is the list of users warned about pending disablement.`nSend failures this run: $($script:SendFailures) (see NotifyResult column)." -Attachments @($CsvPath))
}

if ($script:SendFailures -gt 0) { Write-ADAutomationLog "$($script:SendFailures) warning e-mail(s) FAILED to send this run - affected users may be disabled without warning." 'ERROR' }
Write-ADAutomationLog "=== END (warned=$($report.Count); sendFailures=$($script:SendFailures)) ==="
Write-Output "Done. Mode=$($PSCmdlet.ParameterSetName) Warned=$($report.Count) SendFailures=$($script:SendFailures)"
Write-Output "Log: $($run.LogPath)"
Write-Output "CSV: $CsvPath"
