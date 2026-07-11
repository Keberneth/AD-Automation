<#
.SYNOPSIS
Notify on Active Directory account lockouts (Security event ID 4740).

.DESCRIPTION
Reads event 4740 from the Domain Controller(s) and e-mails the administrators
(and optionally the locked-out user). Designed to run unattended on a schedule
from ANY host that can read the DC Security log remotely.

Key behaviours:
  - Queries the PDC emulator by default (where 4740 reliably aggregates), or
    every DC with -AllDomainControllers, instead of only the local log.
  - Keeps a per-DC high-water mark (largest processed EventRecordId) so the same
    lockout is never e-mailed twice on overlapping runs.
  - Validates the resolved user mail address and sanitises event-derived fields
    before building the message (recipient/header-injection hardening).

All defaults can be set in config\AD-Automation.settings.psd1 (section
'LockoutNotify' / 'Common'); command-line parameters override the file.

.EXAMPLE
.\Invoke-ADLockoutNotify.ps1 -Run

.EXAMPLE
.\Invoke-ADLockoutNotify.ps1 -DryRun -LookbackMinutes 60

.NOTES
- Remote Get-WinEvent needs the runner account to have read access to the target
  DC Security log and the "Remote Event Log Management" firewall rule enabled.
- Output folder holds lockout data; it is created with a restricted ACL.
#>

[CmdletBinding(DefaultParameterSetName = 'DryRun')]
param(
    [Parameter(ParameterSetName = 'DryRun', Mandatory = $true)][switch]$DryRun,
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)][switch]$Run,

    [ValidateRange(1, 10080)][int]$LookbackMinutes = 15,

    # Cap how far back a catch-up (after a missed/late run) may reach, so a long
    # outage cannot trigger an enormous Security-log scan. Default 1 day.
    [ValidateRange(1, 43200)][int]$MaxCatchupMinutes = 1440,

    # DC whose Security log to read. Empty = PDC emulator.
    [string]$DcServer = '',
    # Query every DC in the domain (full coverage) instead of just one.
    [bool]$AllDomainControllers = $false,
    # Also e-mail the locked-out user (if a mail attribute exists).
    [bool]$NotifyUser = $true,

    [string]$SmtpServer = 'smtp-relay.contoso.local',
    [int]$SmtpPort = 25,
    [string]$MailFrom = 'ad-automation@contoso.local',
    [bool]$MailUseSsl = $false,
    [string]$MailCredentialPath = '',
    [string[]]$AdminMailTo = @('it-operations@contoso.local'),

    [string]$OutputRoot = 'C:\ProgramData\AD-Automation',
    [string]$LogFilePrefix = 'ADLockout',

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

$cfg = Import-ADAutomationConfig -Path $ConfigPath -Section 'LockoutNotify'
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
$run = Initialize-ADAutomationLog -OutputRoot $OutputRoot -BaseName $LogFilePrefix -EventLogEnabled $EventLogEnabled -EventLogName $EventLogName
$CsvPath = Join-Path $OutputRoot ("{0}-Report-{1}.csv" -f $LogFilePrefix, $run.RunId)
$whatIf = ($PSCmdlet.ParameterSetName -eq 'DryRun')

$mailCommon = @{
    From = $MailFrom; SmtpServer = $SmtpServer; SmtpPort = $SmtpPort
    UseSsl = $MailUseSsl; CredentialPath = $MailCredentialPath
}

# Resolve which DC(s) to read.
$dcList = New-Object System.Collections.Generic.List[string]
if ($AllDomainControllers) {
    try { (Get-ADDomainController -Filter *).HostName | ForEach-Object { $dcList.Add($_) } }
    catch { Write-ADAutomationLog "Could not enumerate DCs: $($_.Exception.Message)" 'ERROR' }
}
elseif (-not [string]::IsNullOrWhiteSpace($DcServer)) {
    $dcList.Add($DcServer)
}
else {
    try { $dcList.Add((Get-ADDomain).PDCEmulator) }
    catch {
        Write-ADAutomationLog "Could not resolve PDC emulator; falling back to local host '$($env:COMPUTERNAME)'. $($_.Exception.Message)" 'WARN'
        $dcList.Add($env:COMPUTERNAME)
    }
}

# Per-DC high-water mark state (so overlapping runs do not resend). A corrupt state
# file here only risks a few duplicate mails within the lookback window (not missed
# detections), so degrade to empty watermarks instead of aborting the whole run.
$statePath = Get-ADAutomationStatePath -OutputRoot $OutputRoot -Name 'LockoutNotify'
$state = $null
try { $state = Read-ADAutomationState -Path $statePath }
catch { Write-ADAutomationLog "Lockout state unreadable ($($_.Exception.Message)); continuing with empty watermarks (may re-send within the lookback window)." 'WARN' }
$watermarks = @{}
if ($state -and $state.PSObject.Properties['Watermarks']) {
    foreach ($p in $state.Watermarks.PSObject.Properties) { $watermarks[$p.Name] = [int64]$p.Value }
}

# Query window: normally now-LookbackMinutes, but reach back to the last successful
# run so a skipped/delayed cycle is caught up (the per-DC watermark still dedupes
# the overlap). Cap the reach at MaxCatchupMinutes so a long outage cannot scan the
# whole log.
$startTime = (Get-Date).AddMinutes(-$LookbackMinutes)
if ($state -and $state.PSObject.Properties['UpdatedUtc'] -and -not [string]::IsNullOrWhiteSpace($state.UpdatedUtc)) {
    try {
        $lastRun = ([datetime]::Parse($state.UpdatedUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)).ToLocalTime()
        $floor = (Get-Date).AddMinutes(-$MaxCatchupMinutes)
        if ($lastRun -lt $floor) { $lastRun = $floor }
        if ($lastRun -lt $startTime) { $startTime = $lastRun }
    }
    catch { }
}

Write-ADAutomationLog "=== START (RunId=$($run.RunId)) ==="
Write-ADAutomationLog ("Mode={0} ; WhatIf={1} ; LookbackMinutes={2} ; StartTime={3} ; DCs={4}" -f `
        $PSCmdlet.ParameterSetName, $whatIf, $LookbackMinutes, $startTime, ($dcList -join ', '))
Write-ADAutomationLog ("SMTP={0}:{1} From={2} SSL={3} AdminTo={4} NotifyUser={5}" -f `
        $SmtpServer, $SmtpPort, $MailFrom, $MailUseSsl, ($AdminMailTo -join ','), $NotifyUser)

# Run-level de-duplication of the same lockout reported by more than one DC
# (a 4740 is commonly written on both the enforcing DC and the PDC emulator).
$seenLockouts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

$mailRegex = '^[^@\s,;:<>"]+@[^@\s,;:<>"]+\.[^@\s,;:<>"]+$'
function Get-Clean([string]$s) {
    if ([string]::IsNullOrEmpty($s)) { return '' }
    $c = ($s -replace '[\x00-\x1F\x7F]', ' ').Trim()
    if ($c.Length -gt 256) { $c = $c.Substring(0, 256) }
    return $c
}

$report = New-Object System.Collections.Generic.List[object]

foreach ($dc in $dcList) {
    $lastId = if ($watermarks.ContainsKey($dc)) { [int64]$watermarks[$dc] } else { [int64]0 }

    try {
        $events = Get-WinEvent -ComputerName $dc -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4740
            StartTime = $startTime
        } -ErrorAction Stop
    }
    catch {
        # "No events were found" is not an error. Match the locale-invariant error
        # id, not the message text (which is translated on non-English Windows and
        # would otherwise log a spurious ERROR every quiet run).
        if ($_.FullyQualifiedErrorId -match '^NoMatchingEventsFound') {
            Write-ADAutomationLog "No lockout events on $dc in the window." 'INFO'
        }
        else {
            Write-ADAutomationLog "ERROR reading Security log on '$dc': $($_.Exception.Message)" 'ERROR'
        }
        continue
    }

    # Detect a cleared/recreated Security log: EventRecordId restarts near 1, so if
    # the newest event in the window is BELOW our stored watermark, the old watermark
    # is stale and would suppress every future alert on this DC. Reset it.
    $rawEvents = @($events)
    if ($rawEvents.Count -gt 0 -and $lastId -gt 0) {
        $windowMax = [int64](($rawEvents | Measure-Object -Property RecordId -Maximum).Maximum)
        if ($windowMax -lt $lastId) {
            Write-ADAutomationLog "RecordId regression on $dc (newest=$windowMax < watermark=$lastId): Security log likely cleared/recreated; resetting watermark." 'WARN'
            $lastId = [int64]0
        }
    }

    $events = @($rawEvents | Where-Object { [int64]$_.RecordId -gt $lastId } | Sort-Object RecordId)
    if ($events.Count -eq 0) { continue }

    # Advance the watermark only across a CONTIGUOUS prefix of successfully-notified
    # events, so a failed send (transient SMTP outage) leaves that event and later
    # ones to be retried next run instead of being skipped forever.
    $watermarkCandidate = $lastId
    $stopAdvance = $false

    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

        $lockedUser = Get-Clean $data['TargetUserName']
        $caller = Get-Clean $data['CallerComputerName']
        $domain = Get-Clean $data['TargetDomainName']
        $time = $evt.TimeCreated

        # Resolve the user's mailbox, scoped to the lockout's own domain when possible.
        $userMail = $null
        $resolveStatus = 'OK'
        $safeUser = $lockedUser -replace "'", "''"
        try {
            $adUser = Get-ADUser -Filter "SamAccountName -eq '$safeUser'" -Properties mail -ErrorAction Stop
            if (-not $adUser -and -not [string]::IsNullOrWhiteSpace($domain)) {
                try { $adUser = Get-ADUser -Filter "SamAccountName -eq '$safeUser'" -Server $domain -Properties mail -ErrorAction Stop } catch { }
            }
            if ($adUser) {
                $userMail = $adUser.mail
                if (-not $userMail) { $resolveStatus = 'NoMailbox' }
            }
            else { $resolveStatus = 'NotFound' }
        }
        catch {
            $resolveStatus = 'LookupError'
            Write-ADAutomationLog "Could not resolve AD user '$lockedUser': $($_.Exception.Message)" 'WARN'
        }

        if ($userMail -and ($userMail -notmatch $mailRegex)) {
            Write-ADAutomationLog "Ignoring malformed mail '$userMail' for '$lockedUser'." 'WARN'
            $userMail = $null
            $resolveStatus = 'BadMail'
        }

        # De-duplicate the same lockout reported by multiple DCs in one run.
        $dedupKey = "{0}|{1}|{2}" -f $lockedUser, $domain, ($time.ToString('yyyyMMddHHmm'))
        $isDuplicate = -not $seenLockouts.Add($dedupKey)

        $report.Add([pscustomobject]@{
                TimeCreated   = $time
                Dc            = $dc
                TargetUser    = $lockedUser
                TargetDomain  = $domain
                CallerComputer = $caller
                UserMail      = $userMail
                ResolveStatus = $resolveStatus
                EventRecordId = $evt.RecordId
                Duplicate     = $isDuplicate
            }) | Out-Null

        $subject = "AD Lockout: $lockedUser @ $domain"
        $body = @"
Account locked: $lockedUser
Domain: $domain
Time: $time
Caller computer: $caller
Resolve status: $resolveStatus
Event record id: $($evt.RecordId)
Reported by DC: $dc
"@

        $eventOk = $true
        if ($isDuplicate) {
            Write-ADAutomationLog "Duplicate lockout already reported this run for $lockedUser @ $domain (DC=$dc); not re-sending." 'INFO'
        }
        elseif ($whatIf) {
            Write-ADAutomationLog "WHATIF: would notify admins$(if ($NotifyUser -and $userMail) { " + user($userMail)" }) for $lockedUser / caller=$caller (DC=$dc)" 'WHATIF'
        }
        else {
            $eventOk = [bool](Send-ADAutomationMail @mailCommon -To $AdminMailTo -Subject $subject -Body $body)
            if ($NotifyUser -and $userMail) {
                [void](Send-ADAutomationMail @mailCommon -To @($userMail) -Subject $subject -Body $body)
            }
        }

        # Advance the watermark only across a contiguous prefix of handled events. A
        # duplicate counts as handled; a failed admin send stops advancement so the
        # event (and later ones) are retried on the next run.
        if (-not $whatIf) {
            if ($eventOk -and -not $stopAdvance) { $watermarkCandidate = [int64]$evt.RecordId }
            elseif (-not $eventOk) { $stopAdvance = $true; Write-ADAutomationLog "Admin notification failed for RecordId=$($evt.RecordId) on $dc; will retry next run." 'WARN' }
        }
    }

    # Persist the advanced watermark (real runs only); DryRun never suppresses alerts.
    if (-not $whatIf) {
        $watermarks[$dc] = [int64]$watermarkCandidate
        Write-ADAutomationLog "Watermark for $dc set to RecordId=$watermarkCandidate" 'INFO'
    }
}

# --- Persist state + report -------------------------------------------------
if (-not $whatIf) {
    Save-ADAutomationState -Path $statePath -State ([pscustomobject]@{
            Watermarks = $watermarks
            UpdatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        })
}

try {
    $report | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-ADAutomationLog "CSV report written: $CsvPath" 'INFO'
}
catch {
    Write-ADAutomationLog "ERROR writing CSV report: $($_.Exception.Message)" 'ERROR'
}

Write-ADAutomationLog "=== END (lockouts=$($report.Count)) ==="
Write-Output "Done. Mode=$($PSCmdlet.ParameterSetName) Lockouts=$($report.Count)"
Write-Output "Log: $($run.LogPath)"
Write-Output "CSV: $CsvPath"
