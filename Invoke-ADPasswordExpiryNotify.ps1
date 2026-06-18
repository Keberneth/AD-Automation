<#
.SYNOPSIS
Notify users (and admins) of upcoming Active Directory password expirations.

.DESCRIPTION
Finds enabled users whose password will expire within a window and e-mails:
  - the user (if a 'mail' attribute exists)
  - an admin summary CSV (AdminMailTo)

Works against ANY domain: with no OUs configured it searches the whole current
domain. All defaults can be set once in config\AD-Automation.settings.psd1
(section 'PasswordExpiryNotify') - no need to edit this script. Anything passed
on the command line overrides the config file.

.PARAMETER ConfigPath
Optional path to a settings .psd1/.json. Defaults to the module's config folder
or the AD_AUTOMATION_CONFIG environment variable.

.EXAMPLE
.\Invoke-ADPasswordExpiryNotify.ps1 -DryRun
Dry run (no e-mail), writes CSV + log.

.EXAMPLE
.\Invoke-ADPasswordExpiryNotify.ps1 -Run -NotifyDays 14,7,3,1
Send reminders only at exactly 14/7/3/1 calendar days remaining.

.NOTES
- Uses msDS-UserPasswordExpiryTimeComputed (handles "never expires" / PSO).
- Output folder holds user PII; it is created with a restricted ACL.
- Requires the ActiveDirectory module and the ADAutomation module (shipped alongside).
#>

[CmdletBinding(DefaultParameterSetName = 'DryRun')]
param(
    [Parameter(ParameterSetName = 'DryRun', Mandatory = $true)][switch]$DryRun,
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)][switch]$Run,

    # Notify if the password expires within this many days.
    [ValidateRange(1, 3650)][int]$NotifyWindowDays = 14,

    # Optional discrete reminder thresholds, e.g. 14,7,3,1 (whole calendar days remaining).
    [int[]]$NotifyDays = @(),

    [ValidateSet('Base', 'OneLevel', 'Subtree')][string]$SearchScope = 'Subtree',

    # Search bases. Empty = whole current domain.
    [string[]]$UserLimitToOUs = @(),

    [string[]]$IgnoreAccountsExact = @('Administrator', 'Guest', 'krbtgt'),

    # SMTP / mail (usually set in [Common]).
    [string]$SmtpServer = 'smtp-relay.contoso.local',
    [int]$SmtpPort = 25,
    [string]$MailFrom = 'ad-automation@contoso.local',
    [bool]$MailUseSsl = $false,
    [string]$MailCredentialPath = '',
    [string[]]$AdminMailTo = @('it-operations@contoso.local'),

    # Target DC. Empty = auto-detect (PDC emulator).
    [string]$Server = '',

    [string]$OutputRoot = 'C:\ProgramData\AD-Automation',
    [string]$LogFilePrefix = 'ADPasswordExpiry',

    [string]$ConfigPath = ''
)

# --- Bootstrap: shared module + external settings ---------------------------
$modulePath = Join-Path $PSScriptRoot 'ADAutomation.psd1'
if (-not (Test-Path -LiteralPath $modulePath)) { throw "Required module not found next to script: $modulePath" }
Import-Module $modulePath -Force -ErrorAction Stop

$cfg = Import-ADAutomationConfig -Path $ConfigPath -Section 'PasswordExpiryNotify'
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

if ([string]::IsNullOrWhiteSpace($Server)) {
    try { $Server = (Get-ADAutomationDomainInfo).Server } catch { $Server = '' }
}
$srv = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) { $srv['Server'] = $Server }

$mailCommon = @{
    From = $MailFrom; SmtpServer = $SmtpServer; SmtpPort = $SmtpPort
    UseSsl = $MailUseSsl; CredentialPath = $MailCredentialPath
}
if ($SmtpServer -match '(?i)contoso\.') {
    Write-ADAutomationLog "SmtpServer is still the sample 'contoso' placeholder; configure config\AD-Automation.settings.psd1." 'WARN'
}

$today = (Get-Date).Date
$windowEnd = $today.AddDays($NotifyWindowDays)

if (-not $UserLimitToOUs -or @($UserLimitToOUs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
    $UserLimitToOUs = @((Get-ADAutomationDomainInfo @srv).DistinguishedName)
    Write-ADAutomationLog "No UserLimitToOUs supplied; defaulting to domain root: $($UserLimitToOUs -join ', ')" 'INFO'
}
$userBases = Get-ValidSearchBase -Bases $UserLimitToOUs @srv
if (-not $userBases -or $userBases.Count -eq 0) {
    throw "No valid AD search bases resolved from UserLimitToOUs ($($UserLimitToOUs -join ', ')). Provide OUs that exist in this domain."
}

Write-ADAutomationLog "=== START (RunId=$($run.RunId)) ==="
Write-ADAutomationLog ("Mode={0} ; WhatIf={1} ; NotifyWindowDays={2} ; NotifyDays={3} ; SearchScope={4} ; Server={5}" -f `
        $PSCmdlet.ParameterSetName, $whatIf, $NotifyWindowDays, ($NotifyDays -join ','), $SearchScope, $Server)
Write-ADAutomationLog ("SMTP={0}:{1} From={2} SSL={3} AdminTo={4}" -f $SmtpServer, $SmtpPort, $MailFrom, $MailUseSsl, ($AdminMailTo -join ','))

$report = New-Object System.Collections.Generic.List[object]

foreach ($base in $userBases) {
    Write-ADAutomationLog "Processing OU: $base"
    try {
        $users = Get-ADUser -SearchBase $base -SearchScope $SearchScope @srv `
            -LDAPFilter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            -Properties mail, Enabled, 'msDS-UserPasswordExpiryTimeComputed', PasswordNeverExpires, SamAccountName -ErrorAction Stop
    }
    catch {
        Write-ADAutomationLog "ERROR querying base '$base': $($_.Exception.Message)" 'ERROR'
        continue
    }

    foreach ($u in $users) {
        try {
            if (-not $u.Enabled) { continue }
            if ($u.PasswordNeverExpires) { continue }
            if (Test-IsIgnoredName -Name $u.SamAccountName -ExactList $IgnoreAccountsExact) { continue }

            $expiryFileTime = $u.'msDS-UserPasswordExpiryTimeComputed'
            # 0/null = must-change-now or unset; Int64.MaxValue = never expires (PSO/UAC). Both are non-convertible sentinels.
            if ($null -eq $expiryFileTime -or $expiryFileTime -le 0 -or $expiryFileTime -ge [Int64]::MaxValue) { continue }

            try { $expiry = [DateTime]::FromFileTime($expiryFileTime) }
            catch {
                Write-ADAutomationLog "Skipping $($u.SamAccountName): invalid expiry filetime '$expiryFileTime'." 'WARN'
                continue
            }

            if ($expiry -gt $windowEnd) { continue }

            # Whole calendar days remaining: "expires today" = 0, "expires in N days" = N.
            $daysLeft = ($expiry.Date - $today).Days
            if ($daysLeft -lt 0) { continue }
            if ($NotifyDays.Count -gt 0 -and ($NotifyDays -notcontains $daysLeft)) { continue }

            $report.Add([pscustomobject]@{
                    SamAccountName = $u.SamAccountName
                    DisplayName    = $u.Name
                    Mail           = $u.mail
                    ExpiryDate     = $expiry
                    DaysLeft       = $daysLeft
                    OU             = $base
                }) | Out-Null

            $subject = "Password expiry notice: $daysLeft day(s) remaining"
            $body = @"
Hello $($u.Name),

Your Active Directory password will expire in $daysLeft day(s).
Expiry date: $($expiry.ToString('yyyy-MM-dd HH:mm'))

Please change your password before it expires to avoid login issues.
If you need help, contact IT support.

Thank you,
IT Operations
"@

            if ($whatIf) {
                Write-ADAutomationLog "WHATIF: would notify '$($u.mail)' ($($u.SamAccountName)) DaysLeft=$daysLeft" 'WHATIF'
            }
            elseif ($u.mail) {
                [void](Send-ADAutomationMail @mailCommon -To @($u.mail) -Subject $subject -Body $body)
            }
            else {
                Write-ADAutomationLog "No mail for $($u.SamAccountName); skipping user notification." 'WARN'
            }
        }
        catch {
            Write-ADAutomationLog "Unexpected error processing '$($u.SamAccountName)': $($_.Exception.Message)" 'ERROR'
            continue
        }
    }
}

# --- Reporting --------------------------------------------------------------
try {
    $report | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-ADAutomationLog "CSV report written: $CsvPath" 'INFO'
}
catch {
    Write-ADAutomationLog "ERROR writing CSV report: $($_.Exception.Message)" 'ERROR'
}

if (-not $whatIf -and @($AdminMailTo).Count -gt 0 -and (Test-Path -LiteralPath $CsvPath)) {
    [void](Send-ADAutomationMail @mailCommon -To $AdminMailTo `
            -Subject ("AD Password Expiry Summary ({0}) - {1} user(s)" -f $today.ToString('yyyy-MM-dd'), $report.Count) `
            -Body 'Attached is the password expiry notification summary CSV.' `
            -Attachments @($CsvPath))
}

Write-ADAutomationLog "=== END (notified=$($report.Count)) ==="
Write-Output "Done. Mode=$($PSCmdlet.ParameterSetName) Notified=$($report.Count)"
Write-Output "Log: $($run.LogPath)"
Write-Output "CSV: $CsvPath"
