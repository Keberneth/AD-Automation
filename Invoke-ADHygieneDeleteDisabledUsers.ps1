<#
.SYNOPSIS
Delete AD user accounts that have been DISABLED for at least N days (default 180).

.DESCRIPTION
Modes: -DryRun (no changes), -Run (interactive), -Scheduled (unattended).

Safety is AUTOMATIC - no list to maintain, no per-run busy-work:
  - Run -DryRun first to preview exactly what would be deleted (changes nothing).
  - Only accounts DISABLED for at least -DisabledForDays (default 180) are eligible.
  - -MaxDeletes caps deletions per run (default 25) as a surge brake; -Unlimited lifts it.
  - Ignore lists protect built-in/critical accounts; an unreliable disable date is skipped.
  - -RequireApprovalList is OPTIONAL - use it ONLY if you want manual change-control.
    It is NOT required for -Run or -Scheduled; leave it off for hands-off operation.

Scope: with no OUs configured the script runs forest-wide (every domain). Set
UserLimitToOUs to narrow it. All defaults can live in
config\AD-Automation.settings.psd1 (section 'DeleteDisabledUsers' / 'Common').

.EXAMPLE
.\Invoke-ADHygieneDeleteDisabledUsers.ps1 -DryRun

.EXAMPLE
# Hands-off: delete users disabled > 180 days, max 25 per run, no list to curate.
.\Invoke-ADHygieneDeleteDisabledUsers.ps1 -Scheduled

.NOTES
- "Disabled since" is derived from replication metadata on userAccountControl
  (time of the LAST UAC change, not strictly the disable event). The whenChanged
  fallback is unreliable and only used as a last resort (logged as a WARN).
- Requires the ActiveDirectory module and the ADAutomation module.
- Output folder holds account data; it is created with a restricted ACL.
#>

[CmdletBinding(DefaultParameterSetName = 'DryRun')]
param(
    [Parameter(ParameterSetName = 'DryRun', Mandatory = $true)][switch]$DryRun,
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)][switch]$Run,
    [Parameter(ParameterSetName = 'Scheduled', Mandatory = $true)][switch]$Scheduled,

    # OPTIONAL manual change-control. Not required for -Run or -Scheduled.
    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Scheduled')]
    [switch]$RequireApprovalList,

    [Parameter(ParameterSetName = 'DryRun')]
    [switch]$EmailApprovalList,

    [string]$SmtpServer = 'smtp-relay.contoso.local',
    [int]$SmtpPort = 25,
    [string]$MailFrom = 'ad-automation@contoso.local',
    [string[]]$MailTo = @('it-operations@contoso.local'),
    [string]$MailSubject = 'AD Hygiene - Approval list (delete disabled users)',
    [string]$MailBody = @"
Hej,

Bifogat finns CSV-rapport, approval-lista (TXT) och logg over kandidater for
borttagning. Granska, godkann i approval-listan och kor sedan scriptet med
-Run -RequireApprovalList (eller -Scheduled -RequireApprovalList).

Mvh
AD Hygiene
"@,
    [bool]$MailUseSsl = $false,
    [string]$MailCredentialPath = '',

    [string]$OutputRoot = 'C:\ProgramData\AD-Automation',
    [string]$ApprovalListPath = 'C:\ProgramData\AD-Automation\DeleteDisabled-ApprovalList.txt',

    [ValidateSet('yes', 'no')][string]$RunInChildOU = 'yes',

    # Empty = forest-wide.
    [string[]]$UserLimitToOUs = @(),

    [ValidateRange(1, 36500)][int]$DisabledForDays = 180,

    [ValidateSet('ReplicationMetadata', 'WhenChanged', 'StampAttribute')]
    [string]$DisableDateSource = 'ReplicationMetadata',
    [string]$DisableStampAttributeName = 'extensionAttribute15',

    [string[]]$IgnoreAccountsExact = @('Administrator', 'Guest', 'krbtgt', 'DefaultAccount', 'WDAGUtilityAccount'),
    [string[]]$IgnoreAccountsRegex = @('^AZURE', '^MSOL', '^BTG', '^DWM-'),

    # Max delete ACTIONS per run; pass -Unlimited to disable the cap.
    [int]$MaxDeletes = 25,
    [switch]$Unlimited,

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

$cfg = Import-ADAutomationConfig -Path $ConfigPath -Section 'DeleteDisabledUsers'
$boundKeys = @($PSBoundParameters.Keys)
# Never let a settings-file key flip a mode/safety switch: e.g. 'Unlimited = $true'
# lifting the MaxDeletes cap, or 'DryRun = $true' clearing an explicitly requested
# -RequireApprovalList on a live -Run/-Scheduled deletion run.
$overlaySkip = @('DryRun', 'Run', 'Scheduled', 'RequireApprovalList', 'EmailApprovalList', 'Unlimited')
foreach ($k in @($cfg.Keys)) {
    if ($k -eq '__ConfigFile') { continue }
    if ($overlaySkip -contains $k) { Write-Warning "Ignoring config key '$k': run mode/safety switches are set on the command line only."; continue }
    if ($boundKeys -notcontains $k -and (Get-Variable -Name $k -Scope 0 -ErrorAction SilentlyContinue)) {
        Set-Variable -Name $k -Value $cfg[$k] -Scope 0
    }
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw 'ActiveDirectory module not found. Install RSAT / AD PowerShell module.'
}
Import-Module ActiveDirectory -ErrorAction Stop

# --- Mode flags + guardrails ------------------------------------------------
$WhatIf = $true; $IsScheduled = $false
switch ($PSCmdlet.ParameterSetName) {
    'DryRun' { $WhatIf = $true; $IsScheduled = $false }
    'Run' { $WhatIf = $false; $IsScheduled = $false }
    'Scheduled' { $WhatIf = $false; $IsScheduled = $true }
}
if ($DryRun) { $RequireApprovalList = $false }

# --- Helpers ----------------------------------------------------------------
function Import-ApprovalList {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-ADAutomationLog "Approval list not found at '$Path'. With -RequireApprovalList, NO deletes are allowed." 'WARN'
        return @()
    }
    $lines = Get-Content -LiteralPath $Path -ErrorAction Stop |
        ForEach-Object { $_.Trim([char]0xFEFF).Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($l in $lines) { [void]$set.Add($l) }
    return , @($set)
}

function Test-IsApproved {
    param([string]$SamAccountName, [string]$DistinguishedName, [string[]]$ApprovalEntries)
    if (-not $ApprovalEntries -or $ApprovalEntries.Count -eq 0) { return $false }
    foreach ($e in $ApprovalEntries) {
        if ($e.Equals($SamAccountName, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($e.Equals($DistinguishedName, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Write-ApprovalListDraft {
    param($ReportRows, [string]$Path)
    $eligible = $ReportRows | Where-Object { $_.Eligible -eq $true }
    $lines = @(
        '# AD Hygiene Approval List (DELETE disabled users)',
        '# One entry per line: SAMAccountName or DistinguishedName',
        "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        '# Keep only the objects you approve for deletion in the next Run.',
        ''
    )
    # Write DistinguishedNames, not bare SamAccountNames: sAMAccountName is unique
    # only per domain, and this script defaults to forest-wide scope, so a bare-SAM
    # approval could authorise deleting a same-named account in another domain.
    # Test-IsApproved already matches on DN.
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $eligible) { [void]$set.Add($r.DistinguishedName) }
    $lines += (@($set) | Sort-Object)
    $lines | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-ADAutomationLog "Approval list draft written: $Path (eligible unique count=$($set.Count))" 'INFO'
}

function ConvertTo-DateTimeOrNull {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim(); $dt = [datetime]::MinValue
    if ([DateTime]::TryParse($v, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) { return $dt.ToUniversalTime() }
    if ([DateTime]::TryParseExact($v, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) { return $dt.ToUniversalTime() }
    return $null
}

function Get-DisableDate {
    param([string]$DistinguishedName, $AdUser, [string]$Source, [string]$Server, [string]$StampAttributeName)
    switch ($Source) {
        'StampAttribute' {
            if ([string]::IsNullOrWhiteSpace($StampAttributeName)) { return $null }
            $val = $AdUser.$StampAttributeName
            if (-not $val) { return $null }
            return (ConvertTo-DateTimeOrNull -Value $val.ToString())
        }
        'ReplicationMetadata' {
            try {
                $meta = Get-ADReplicationAttributeMetadata -Object $DistinguishedName -Server $Server -ErrorAction Stop |
                    Where-Object { $_.AttributeName -eq 'userAccountControl' } | Select-Object -First 1
                if ($meta -and $meta.LastOriginatingChangeTime) { return ($meta.LastOriginatingChangeTime.ToUniversalTime()) }
            }
            catch { Write-ADAutomationLog "ReplicationMetadata failed for '$DistinguishedName' on '$Server': $($_.Exception.Message)" 'WARN' }
            return $null
        }
        'WhenChanged' {
            if ($AdUser.whenChanged) { return ($AdUser.whenChanged.ToUniversalTime()) }
            return $null
        }
    }
    return $null
}

# --- Setup ------------------------------------------------------------------
$run = Initialize-ADAutomationLog -OutputRoot $OutputRoot -BaseName 'ADHygiene-DeleteDisabledUsers' -EventLogEnabled $EventLogEnabled -EventLogName $EventLogName
$CsvReportPath = Join-Path $OutputRoot ("ADHygiene-DeleteDisabledUsers-Report-{0}.csv" -f $run.RunId)
$ApprovalDraftPath = Join-Path $OutputRoot ("ADHygiene-Delete-ApprovalList-Draft-{0}.txt" -f $run.RunId)

$mailCommon = @{
    From = $MailFrom; SmtpServer = $SmtpServer; SmtpPort = $SmtpPort
    UseSsl = $MailUseSsl; CredentialPath = $MailCredentialPath
}

$scope = if ($RunInChildOU -eq 'yes') { 'Subtree' } else { 'OneLevel' }
$cutoff = (Get-Date).ToUniversalTime().AddDays(-$DisabledForDays)

$approvalEntries = @()
if ($RequireApprovalList) { $approvalEntries = Import-ApprovalList -Path $ApprovalListPath }

Write-ADAutomationLog "=== START (RunId=$($run.RunId)) ==="
Write-ADAutomationLog ("Mode={0} ; WhatIf={1} ; Scheduled={2} ; RequireApprovalList={3} ; MaxDeletes={4} ; Unlimited={5}" -f `
        $PSCmdlet.ParameterSetName, $WhatIf, $IsScheduled, $RequireApprovalList, $MaxDeletes, [bool]$Unlimited)
Write-ADAutomationLog ("Policy: DisabledForDays={0} ; Cutoff(UTC)={1} ; DisableDateSource={2}" -f $DisabledForDays, $cutoff, $DisableDateSource)
Write-ADAutomationLog ("IgnoreExact={0} ; IgnoreRegex={1}" -f ($IgnoreAccountsExact -join ','), (@($IgnoreAccountsRegex | Where-Object { $_ }) -join ','))

$report = New-Object System.Collections.Generic.List[object]
$script:DeleteCount = 0
function Test-CanDelete {
    if ($WhatIf) { return $true }
    if ($Unlimited) { return $true }
    return ($script:DeleteCount -lt $MaxDeletes)
}

# Build targets: explicit OUs, else forest-wide (each domain root, pinned to PDCe).
$targets = New-Object System.Collections.Generic.List[object]
if ($UserLimitToOUs -and @($UserLimitToOUs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
    foreach ($ou in $UserLimitToOUs) {
        if ([string]::IsNullOrWhiteSpace($ou)) { continue }
        $dcs = [regex]::Matches($ou, '(?i)DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }
        $domainFqdn = ($dcs -join '.')
        if ([string]::IsNullOrWhiteSpace($domainFqdn)) { Write-ADAutomationLog "OU has no DC components (skipping): $ou" 'WARN'; continue }
        $server = $domainFqdn
        try { $server = (Get-ADDomain -Server $domainFqdn -ErrorAction Stop).PDCEmulator } catch { Write-ADAutomationLog "Could not resolve PDCEmulator for '$domainFqdn' (using DNS): $($_.Exception.Message)" 'WARN' }
        $targets.Add([pscustomobject]@{ Domain = $domainFqdn; Server = $server; SearchBase = $ou; Scope = $scope; Mode = 'OU' }) | Out-Null
    }
}
else {
    try { $forest = Get-ADForest -ErrorAction Stop } catch { throw "Failed to get forest info: $($_.Exception.Message)" }
    foreach ($domainFqdn in $forest.Domains) {
        $server = $domainFqdn; $domainDn = $null
        try { $d = Get-ADDomain -Server $domainFqdn -ErrorAction Stop; $server = $d.PDCEmulator; $domainDn = $d.DistinguishedName }
        catch {
            Write-ADAutomationLog "Failed to resolve '$domainFqdn' (trying DNS): $($_.Exception.Message)" 'WARN'
            try { $domainDn = (Get-ADDomain -Server $server -ErrorAction Stop).DistinguishedName } catch { Write-ADAutomationLog "Cannot determine DN for '$domainFqdn' (skipping)." 'ERROR'; continue }
        }
        $targets.Add([pscustomobject]@{ Domain = $domainFqdn; Server = $server; SearchBase = $domainDn; Scope = 'Subtree'; Mode = 'Domain' }) | Out-Null
    }
}
Write-ADAutomationLog ("Targets: {0}" -f (($targets | ForEach-Object { "$($_.Mode):$($_.SearchBase)@$($_.Server)" }) -join ' ; '))

# Recycle Bin preflight: without it, Remove-ADUser is an unrecoverable hard delete
# (tombstone only, no attribute recovery). Surface the state so operators know the
# blast radius of the most destructive job in the library.
try {
    $rb = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
    if (-not $rb -or -not $rb.EnabledScopes -or @($rb.EnabledScopes).Count -eq 0) {
        Write-ADAutomationLog "AD Recycle Bin is NOT enabled in this forest - Remove-ADUser is an UNRECOVERABLE hard delete." 'WARN'
    }
    else {
        Write-ADAutomationLog "AD Recycle Bin is enabled (deleted users are recoverable within the deleted-object lifetime)." 'INFO'
    }
}
catch { Write-ADAutomationLog "Could not determine AD Recycle Bin state (continuing): $($_.Exception.Message)" 'WARN' }

function Invoke-TargetProcessing {
    param($Target)
    Write-ADAutomationLog "--- Target: Mode=$($Target.Mode) Domain=$($Target.Domain) Server=$($Target.Server) Base=$($Target.SearchBase) ---"
    $props = @('SamAccountName', 'DistinguishedName', 'Enabled', 'whenChanged', 'isCriticalSystemObject')
    if ($DisableDateSource -eq 'StampAttribute' -and -not [string]::IsNullOrWhiteSpace($DisableStampAttributeName)) { $props += $DisableStampAttributeName }
    $ldap = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(!(isCriticalSystemObject=TRUE)))'

    try {
        $users = Get-ADUser -Server $Target.Server -SearchBase $Target.SearchBase -SearchScope $Target.Scope -LDAPFilter $ldap -Properties $props -ErrorAction Stop
    }
    catch { Write-ADAutomationLog "ERROR querying '$($Target.SearchBase)' on '$($Target.Server)': $($_.Exception.Message)" 'ERROR'; return }

    foreach ($u in $users) {
        $sam = $u.SamAccountName; $dn = $u.DistinguishedName; $ouPath = Get-ParentDN -DistinguishedName $dn

        if (Test-IsIgnoredName -Name $sam -ExactList $IgnoreAccountsExact -RegexList $IgnoreAccountsRegex) {
            Write-ADAutomationLog "SKIP (ignored): $sam" 'SKIP'
            $report.Add([pscustomobject]@{ Domain = $Target.Domain; Server = $Target.Server; SamAccountName = $sam; DistinguishedName = $dn; OU = $ouPath; Enabled = $u.Enabled; WhenChanged = $u.whenChanged; DisableDate = $null; DaysDisabled = $null; Eligible = $false; Approved = $null; Action = 'None'; Result = 'Skipped'; Reason = 'Ignored' }) | Out-Null
            continue
        }

        $disableDate = Get-DisableDate -DistinguishedName $dn -AdUser $u -Source $DisableDateSource -Server $Target.Server -StampAttributeName $DisableStampAttributeName
        $usedSource = $DisableDateSource
        if (-not $disableDate -and $DisableDateSource -eq 'ReplicationMetadata') {
            $disableDate = Get-DisableDate -DistinguishedName $dn -AdUser $u -Source 'WhenChanged' -Server $Target.Server -StampAttributeName $DisableStampAttributeName
            $usedSource = if ($disableDate) { 'WhenChanged(Fallback)' } else { 'Unknown' }
            if ($disableDate) { Write-ADAutomationLog "WARN: ReplicationMetadata unavailable for $sam; using whenChanged (unreliable disable timestamp)." 'WARN' }
        }

        # StampAttribute mode trusts a manually written date. An account re-enabled
        # then re-disabled keeps its OLD stamp, so cross-check the real
        # userAccountControl replication metadata: if UAC changed well after the
        # stamp claims, the stamp is stale and must not authorise a delete.
        if ($DisableDateSource -eq 'StampAttribute' -and $disableDate) {
            $uacChange = Get-DisableDate -DistinguishedName $dn -AdUser $u -Source 'ReplicationMetadata' -Server $Target.Server -StampAttributeName $DisableStampAttributeName
            if ($uacChange -and $uacChange -gt $disableDate.AddDays(1)) {
                Write-ADAutomationLog "WARN: $sam stamp ($($disableDate.ToString('u'))) predates a later userAccountControl change ($($uacChange.ToString('u'))); stamp is stale - skipping." 'WARN'
                $usedSource = 'StampSupersededByUAC'
            }
        }

        $eligible = $false; $reason = $null; $daysDisabled = $null
        if (-not $disableDate) { $reason = "Cannot determine disable date (Source=$usedSource). Not eligible." }
        else {
            $daysDisabled = [int][Math]::Floor(((Get-Date).ToUniversalTime() - $disableDate).TotalDays)
            if ($disableDate -lt $cutoff) { $eligible = $true; $reason = "DisableDate(UTC)=$disableDate (Source=$usedSource) < cutoff (DaysDisabled=$daysDisabled)" }
            else { $reason = "DisableDate(UTC)=$disableDate (Source=$usedSource) >= cutoff (DaysDisabled=$daysDisabled)" }
        }

        $approved = $null
        if ($RequireApprovalList) { $approved = Test-IsApproved -SamAccountName $sam -DistinguishedName $dn -ApprovalEntries $approvalEntries }

        $row = [pscustomobject]@{ Domain = $Target.Domain; Server = $Target.Server; SamAccountName = $sam; DistinguishedName = $dn; OU = $ouPath; Enabled = $u.Enabled; WhenChanged = $u.whenChanged; DisableDate = $disableDate; DaysDisabled = $daysDisabled; Eligible = $eligible; Approved = $approved; Action = 'Remove-ADUser'; Result = 'None'; Reason = $reason }

        if (-not $eligible) { $row.Result = 'NoChange'; $report.Add($row) | Out-Null; continue }
        # Defence-in-depth: never delete on an unreliable date (whenChanged fallback,
        # or a StampAttribute value superseded by a later UAC change). Decide this
        # BEFORE the DryRun/approval branches and clear Eligible, so the -DryRun
        # preview and the approval draft match what a real run will actually do
        # (the draft filters on Eligible).
        if ($usedSource -eq 'WhenChanged(Fallback)' -or $usedSource -eq 'StampSupersededByUAC') {
            $row.Eligible = $false
            Write-ADAutomationLog "SKIP (unreliable date source=$usedSource): $sam" 'SKIP'
            $row.Result = 'SkippedUnreliableDate'; $report.Add($row) | Out-Null; continue
        }
        if ($WhatIf) { Write-ADAutomationLog "WHATIF: would delete $sam ; $reason" 'WHATIF'; $row.Result = 'WhatIf'; $report.Add($row) | Out-Null; continue }
        if ($RequireApprovalList -and -not $approved) { Write-ADAutomationLog "SKIP (not approved): $sam" 'SKIP'; $row.Result = 'NotApproved'; $report.Add($row) | Out-Null; continue }
        if (-not (Test-CanDelete)) { Write-ADAutomationLog "SKIP (MaxDeletes=$MaxDeletes reached): $sam" 'SKIP'; $row.Result = 'MaxDeletesReached'; $report.Add($row) | Out-Null; continue }

        try {
            Remove-ADUser -Identity $dn -Server $Target.Server -Confirm:$false -ErrorAction Stop
            Write-ADAutomationLog "ACTION: Deleted: $sam (DN=$dn)" 'ACTION'
            $script:DeleteCount++
            $row.Result = 'Deleted'
        }
        catch {
            $msg = $_.Exception.Message
            # A user with child objects (e.g. Exchange ActiveSync device containers)
            # cannot be removed with Remove-ADUser; flag it distinctly so it is
            # actionable instead of re-failing identically on every scheduled run.
            $row.Result = if ($msg -match '(?i)leaf') { 'ErrorNonLeaf' } else { 'Error' }
            Write-ADAutomationLog "ERROR: Delete failed for $sam (Result=$($row.Result)): $msg" 'ERROR'
        }
        $report.Add($row) | Out-Null
    }
}
foreach ($t in $targets) { Invoke-TargetProcessing -Target $t }

# --- Approval coverage report ----------------------------------------------
if ($RequireApprovalList -and $approvalEntries.Count -gt 0) {
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $report) { [void]$seen.Add($r.SamAccountName); [void]$seen.Add($r.DistinguishedName) }
    $unmatched = @($approvalEntries | Where-Object { -not $seen.Contains($_) })
    if ($unmatched.Count -gt 0) { Write-ADAutomationLog "Approval entries that matched NO object this run: $($unmatched -join '; ')" 'WARN' }
}

# --- Reporting --------------------------------------------------------------
try { $report | Export-Csv -Path $CsvReportPath -NoTypeInformation -Encoding UTF8; Write-ADAutomationLog "CSV report written: $CsvReportPath" 'INFO' }
catch { Write-ADAutomationLog "ERROR writing CSV report: $($_.Exception.Message)" 'ERROR' }

Write-ADAutomationLog "=== END (DeleteCount=$($script:DeleteCount)) ==="

if ($DryRun) {
    try { Write-ApprovalListDraft -ReportRows $report -Path $ApprovalDraftPath }
    catch { Write-ADAutomationLog "ERROR writing approval draft: $($_.Exception.Message)" 'ERROR' }

    if ($EmailApprovalList) {
        $placeholder = @($SmtpServer, $MailFrom) + @($MailTo) | Where-Object { $_ -match '(?i)contoso\.' }
        if ($placeholder.Count -gt 0) {
            Write-ADAutomationLog "Refusing to e-mail approval package: still uses the 'contoso' placeholder ($($placeholder -join ', ')). Configure SmtpServer/MailFrom/MailTo in config\AD-Automation.settings.psd1." 'ERROR'
        }
        else {
            $attachments = @($CsvReportPath, $ApprovalDraftPath, $run.LogPath)
            [void](Send-ADAutomationMail @mailCommon -To $MailTo -Subject $MailSubject -Body $MailBody -Attachments $attachments)
        }
    }
}

Write-Output "Done. Mode=$($PSCmdlet.ParameterSetName) RequireApprovalList=$RequireApprovalList DeleteCount=$($script:DeleteCount)"
Write-Output "Log: $($run.LogPath)"
Write-Output "CSV: $CsvReportPath"
if ($DryRun) { Write-Output "Approval draft: $ApprovalDraftPath" }
