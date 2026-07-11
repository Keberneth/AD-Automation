<#
.SYNOPSIS
Identify and optionally disable inactive AD users (standard + service) and
computers, then move them to a "disabled" OU.

.DESCRIPTION
Modes (mutually exclusive):
  -DryRun     : no changes; writes CSV + log + an approval-list draft (and can
                e-mail the package with -EmailApprovalList).
  -Run        : make changes (interactive).
  -Scheduled  : make changes (unattended) - intended for a scheduled task.

Safety:
  -RequireApprovalList only disables/moves objects listed in an approval file.
  -MaxChanges caps the number of objects changed per run (per object, not per action).

Generic by design: with no OUs configured it searches the whole current domain.
Move-target OUs are OPTIONAL - if a target is empty the object is disabled but
not moved. Everything can be set once in config\AD-Automation.settings.psd1
(section 'DisableInactive' / 'Common'); command-line parameters override the file.

.EXAMPLE
.\Invoke-ADHygieneDisableInactive.ps1 -DryRun -EmailApprovalList

.EXAMPLE
.\Invoke-ADHygieneDisableInactive.ps1 -Run -RequireApprovalList -ApprovalListPath C:\ProgramData\AD-Automation\DisableInactive-ApprovalList.txt

.NOTES
- LastLogonDate is the replicated lastLogonTimestamp: it can lag real activity by
  up to ~14 days and replicates with normal latency, so inactivity cut-offs are
  enforced at >= 21 days. A null LastLogonDate (treated as "never logged on") can
  also stem from incomplete replication; the whenCreated minimum-age floor mitigates this.
- Move-ADObject does not move across domains; a move-target OU must be in the same
  domain as the object.
- Output folder holds account data; it is created with a restricted ACL.
#>

[CmdletBinding(DefaultParameterSetName = 'DryRun')]
param(
    [Parameter(ParameterSetName = 'DryRun', Mandatory = $true)][switch]$DryRun,
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)][switch]$Run,
    [Parameter(ParameterSetName = 'Scheduled', Mandatory = $true)][switch]$Scheduled,

    [Parameter(ParameterSetName = 'Run')]
    [Parameter(ParameterSetName = 'Scheduled')]
    [switch]$RequireApprovalList,

    [Parameter(ParameterSetName = 'DryRun')]
    [switch]$EmailApprovalList,

    # SMTP / mail (usually set in [Common]).
    [string]$SmtpServer = 'smtp-relay.contoso.local',
    [int]$SmtpPort = 25,
    [string]$MailFrom = 'ad-automation@contoso.local',
    [string[]]$MailTo = @('it-operations@contoso.local'),
    [string]$MailSubject = 'AD Hygiene - Approval list (disable inactive objects)',
    [string]$MailBody = @"
Hej,

Bifogat finns:
1) CSV-rapport over kandidater och beslut (Eligible/Reason)
2) Approval list (TXT) - en rad per objekt (SAMAccountName eller DistinguishedName)
3) Logg (TXT)

Granska och godkann genom att lagga in onskade objekt i approval-listan enligt er process,
och kor sedan scriptet med -Run -RequireApprovalList.

Mvh
AD Hygiene
"@,
    [bool]$MailUseSsl = $false,
    [string]$MailCredentialPath = '',

    [string]$OutputRoot = 'C:\ProgramData\AD-Automation',
    [string]$ApprovalListPath = 'C:\ProgramData\AD-Automation\DisableInactive-ApprovalList.txt',

    [ValidateSet('yes', 'no')][string]$RunInChildOU = 'yes',

    # Inactivity thresholds. Floor of 21 days avoids lastLogonTimestamp lag false-positives.
    [ValidateRange(21, 3650)][int]$UserInactiveForDays = 90,
    [ValidateRange(0, 3650)][int]$UserNeverLoggedOnMinAccountAgeDays = 30,
    [ValidateRange(21, 3650)][int]$ServiceInactiveForDays = 180,
    [ValidateRange(0, 3650)][int]$ServiceNeverLoggedOnMinAccountAgeDays = 90,
    [ValidateRange(21, 3650)][int]$ComputerInactiveForDays = 60,
    [ValidateRange(0, 3650)][int]$ComputerNeverLoggedOnMinAccountAgeDays = 30,

    [ValidateSet('yes', 'no')][string]$ForcePasswordReset = 'no',

    # Move targets. Empty = disable in place (do not move).
    [string]$MoveDisabledUsersToOU = '',
    [string]$MoveDisabledServiceAccountsToOU = '',
    [string]$MoveDisabledComputersToOU = '',

    # Search bases. Empty = whole current domain.
    [string[]]$UserLimitToOUs = @(),
    [string[]]$ComputerLimitToOUs = @(),

    # Service-account detection (any match => service).
    [string[]]$ServiceAccountOUs = @(),
    [string]$ServiceAccountAttributeName = 'employeeType',
    [string]$ServiceAccountAttributeValueRegex = '^service$',
    [string[]]$ServiceAccountSamRegex = @('^svc_', '^sa_'),

    [string[]]$IgnoreAccountsExact = @('Administrator', 'Guest', 'krbtgt', 'DefaultAccount', 'WDAGUtilityAccount'),
    [string[]]$IgnoreAccountsRegex = @('^AZURE', '^MSOL', '^BTG', '^DWM-'),

    [bool]$SkipIfAlreadyInTargetOU = $true,

    # Max objects changed per run (per object, not per action). 0 = unlimited.
    # Defaults to a modest blast-radius cap (matching the sibling delete job's
    # MaxDeletes) so a threshold/clock anomaly cannot disable a whole domain in one
    # unattended run; raise it or set 0 explicitly once you trust a live run.
    [int]$MaxChanges = 25,

    [string]$Server = '',

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

$cfg = Import-ADAutomationConfig -Path $ConfigPath -Section 'DisableInactive'
$boundKeys = @($PSBoundParameters.Keys)
# Mode/safety switches are decided by the invocation (parameter set / command line)
# only. Never let a settings-file key flip them - e.g. 'DryRun = $true' in config
# must not silently disable -RequireApprovalList on a live -Scheduled run.
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

# --- Mode flags -------------------------------------------------------------
$WhatIf = $true
$IsScheduled = $false
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
        Write-ADAutomationLog "Approval list not found at '$Path'. With -RequireApprovalList, NO changes are allowed." 'WARN'
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

function Write-ApprovalListDraft {
    param($ReportRows, [string]$Path)
    $eligible = $ReportRows | Where-Object { $_.Eligible -eq $true -and $_.Enabled -eq $true }
    $lines = @(
        '# AD Hygiene Approval List (DISABLE inactive objects)',
        '# One entry per line: SAMAccountName or DistinguishedName',
        "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        '# Keep only the objects you approve for disabling/move in the next Run.',
        ''
    )
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $eligible) { [void]$set.Add($r.SamAccountName) }
    $lines += (@($set) | Sort-Object)
    $lines | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-ADAutomationLog "Approval list draft written: $Path (eligible unique count=$($set.Count))" 'INFO'
}

# --- Setup ------------------------------------------------------------------
$run = Initialize-ADAutomationLog -OutputRoot $OutputRoot -BaseName 'ADHygiene-DisableInactive' -EventLogEnabled $EventLogEnabled -EventLogName $EventLogName
$CsvReportPath = Join-Path $OutputRoot ("ADHygiene-DisableInactive-Report-{0}.csv" -f $run.RunId)
$ApprovalDraftPath = Join-Path $OutputRoot ("ADHygiene-ApprovalList-Draft-{0}.txt" -f $run.RunId)

if ([string]::IsNullOrWhiteSpace($Server)) {
    try { $Server = (Get-ADAutomationDomainInfo).Server } catch { $Server = '' }
}
$srv = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) { $srv['Server'] = $Server }

$mailCommon = @{
    From = $MailFrom; SmtpServer = $SmtpServer; SmtpPort = $SmtpPort
    UseSsl = $MailUseSsl; CredentialPath = $MailCredentialPath
}

$scope = if ($RunInChildOU -eq 'yes') { 'Subtree' } else { 'OneLevel' }

# Validate the service-detection attribute against the schema; disable it if absent
# so a bad attribute name cannot make Get-ADUser -Properties throw and skip whole OUs.
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

# Default empty search bases to the whole domain.
$domainDN = $null
try { $domainDN = (Get-ADAutomationDomainInfo @srv).DistinguishedName } catch { }
if (-not $UserLimitToOUs -or @($UserLimitToOUs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
    if ($domainDN) { $UserLimitToOUs = @($domainDN); Write-ADAutomationLog "No UserLimitToOUs; defaulting to domain root: $domainDN" 'INFO' }
}
if (-not $ComputerLimitToOUs -or @($ComputerLimitToOUs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
    if ($domainDN) { $ComputerLimitToOUs = @($domainDN); Write-ADAutomationLog "No ComputerLimitToOUs; defaulting to domain root: $domainDN" 'INFO' }
}

# Validate move targets (only the ones that are set).
foreach ($t in @($MoveDisabledUsersToOU, $MoveDisabledServiceAccountsToOU, $MoveDisabledComputersToOU)) {
    if (-not [string]::IsNullOrWhiteSpace($t)) {
        try { $null = Get-ADObject -Identity $t @srv -ErrorAction Stop }
        catch { throw "Move-target OU not found: '$t'. Error: $($_.Exception.Message)" }
    }
}

$userBases = Get-ValidSearchBase -Bases $UserLimitToOUs @srv
$compBases = Get-ValidSearchBase -Bases $ComputerLimitToOUs @srv

# If EVERY configured/derived base is invalid (domain-detection failure, a domain
# rename, or all OUs mistyped) the run would otherwise scan nothing and report a
# successful no-op - hiding a broken hygiene job. Fail loudly instead.
if (@($userBases).Count -eq 0 -and @($compBases).Count -eq 0) {
    throw "No valid AD search bases resolved (users or computers). Check UserLimitToOUs/ComputerLimitToOUs and that the domain is reachable."
}

$userCutoff = (Get-Date).AddDays(-$UserInactiveForDays)
$userNeverCutoff = (Get-Date).AddDays(-$UserNeverLoggedOnMinAccountAgeDays)
$svcCutoff = (Get-Date).AddDays(-$ServiceInactiveForDays)
$svcNeverCutoff = (Get-Date).AddDays(-$ServiceNeverLoggedOnMinAccountAgeDays)
$compCutoff = (Get-Date).AddDays(-$ComputerInactiveForDays)
$compNeverCutoff = (Get-Date).AddDays(-$ComputerNeverLoggedOnMinAccountAgeDays)

$approvalEntries = @()
if ($RequireApprovalList) { $approvalEntries = Import-ApprovalList -Path $ApprovalListPath }

Write-ADAutomationLog "=== START (RunId=$($run.RunId)) ==="
Write-ADAutomationLog ("Mode={0} ; WhatIf={1} ; Scheduled={2} ; RequireApprovalList={3} ; MaxChanges={4} (objects) ; Server={5}" -f `
        $PSCmdlet.ParameterSetName, $WhatIf, $IsScheduled, $RequireApprovalList, $MaxChanges, $Server)
Write-ADAutomationLog "SearchScope=$scope"
Write-ADAutomationLog "User bases: $($userBases -join '; ')"
Write-ADAutomationLog "Computer bases: $($compBases -join '; ')"
Write-ADAutomationLog ("IgnoreExact={0} ; IgnoreRegex={1}" -f ($IgnoreAccountsExact -join ','), (@($IgnoreAccountsRegex | Where-Object { $_ }) -join ','))
Write-ADAutomationLog ("USER InactiveDays={0} MoveTo='{1}' ; SERVICE InactiveDays={2} MoveTo='{3}' ; COMPUTER InactiveDays={4} MoveTo='{5}'" -f `
        $UserInactiveForDays, $MoveDisabledUsersToOU, $ServiceInactiveForDays, $MoveDisabledServiceAccountsToOU, $ComputerInactiveForDays, $MoveDisabledComputersToOU)

$report = New-Object System.Collections.Generic.List[object]
$script:ChangeCount = 0
function Test-CanChange {
    if ($WhatIf) { return $true }
    if ($MaxChanges -le 0) { return $true }
    return ($script:ChangeCount -lt $MaxChanges)
}

# --- Users ------------------------------------------------------------------
function Invoke-UserOuProcessing {
    param([string]$SearchBaseOU)
    Write-ADAutomationLog "--- USERS: $SearchBaseOU ---"
    $props = @('LastLogonDate', 'whenCreated', 'DistinguishedName', 'SamAccountName', 'Enabled')
    if (-not [string]::IsNullOrWhiteSpace($ServiceAccountAttributeName)) { $props += $ServiceAccountAttributeName }

    try {
        $users = Get-ADUser -SearchBase $SearchBaseOU -SearchScope $scope @srv `
            -LDAPFilter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            -Properties $props -ErrorAction Stop
    }
    catch {
        Write-ADAutomationLog "USERS ERROR querying '$SearchBaseOU': $($_.Exception.Message)" 'ERROR'
        return
    }

    foreach ($u in $users) {
        $sam = $u.SamAccountName
        $dn = $u.DistinguishedName
        $ouPath = Get-ParentDN -DistinguishedName $dn

        if (Test-IsIgnoredName -Name $sam -ExactList $IgnoreAccountsExact -RegexList $IgnoreAccountsRegex) {
            Write-ADAutomationLog "USERS SKIP (ignored): $sam" 'SKIP'
            $report.Add([pscustomobject]@{ ObjectType = 'User'; Category = 'Ignored'; SamAccountName = $sam; DistinguishedName = $dn; OU = $ouPath; Enabled = $u.Enabled; LastLogonDate = $u.LastLogonDate; WhenCreated = $u.whenCreated; Reason = 'Ignored'; Eligible = $false; Approved = $null; Action = 'None'; Result = 'Skipped' }) | Out-Null
            continue
        }

        $isService = Test-IsServiceAccount -AdUser $u -ServiceOUs $ServiceAccountOUs -AttrName $ServiceAccountAttributeName -AttrValueRegex $ServiceAccountAttributeValueRegex -SamRegex $ServiceAccountSamRegex
        $cutoff = if ($isService) { $svcCutoff } else { $userCutoff }
        $createdCutoff = if ($isService) { $svcNeverCutoff } else { $userNeverCutoff }
        $targetOU = if ($isService) { $MoveDisabledServiceAccountsToOU } else { $MoveDisabledUsersToOU }
        $category = if ($isService) { 'Service' } else { 'Standard' }

        $eligible = $false; $reason = $null
        if (-not $u.LastLogonDate) {
            if ($u.whenCreated -lt $createdCutoff) { $eligible = $true; $reason = "NeverLoggedOn; Created=$($u.whenCreated)" }
            else { $reason = "NeverLoggedOn but too new; Created=$($u.whenCreated)" }
        }
        elseif ($u.LastLogonDate -lt $cutoff) { $eligible = $true; $reason = "LastLogonDate=$($u.LastLogonDate) < cutoff=$cutoff" }
        else { $reason = "Active; LastLogonDate=$($u.LastLogonDate)" }

        $approved = $null
        if ($RequireApprovalList) { $approved = Test-IsApproved -SamAccountName $sam -DistinguishedName $dn -ApprovalEntries $approvalEntries }

        $actions = New-Object System.Collections.Generic.List[string]
        if ($ForcePasswordReset -eq 'yes' -and -not $isService) { $actions.Add('SetChangePasswordAtLogon') }
        $actions.Add('Disable')
        $willMove = $false
        if (-not [string]::IsNullOrWhiteSpace($targetOU)) {
            $inTarget = Test-DNUnderOU -DistinguishedName $dn -OUDistinguishedName $targetOU
            if (-not ($SkipIfAlreadyInTargetOU -and $inTarget)) { $actions.Add("MoveTo:$targetOU"); $willMove = $true }
        }

        $row = [pscustomobject]@{ ObjectType = 'User'; Category = $category; SamAccountName = $sam; DistinguishedName = $dn; OU = $ouPath; Enabled = $u.Enabled; LastLogonDate = $u.LastLogonDate; WhenCreated = $u.whenCreated; Reason = $reason; Eligible = $eligible; Approved = $approved; Action = ($actions -join ';'); Result = 'None' }

        if (-not $eligible) { $row.Result = 'NoChange'; $report.Add($row) | Out-Null; continue }
        if ($WhatIf) { Write-ADAutomationLog "USERS WHATIF: $sam ; $($row.Action) ; $reason" 'WHATIF'; $row.Result = 'WhatIf'; $report.Add($row) | Out-Null; continue }
        if ($RequireApprovalList -and -not $approved) { Write-ADAutomationLog "USERS SKIP (not approved): $sam" 'SKIP'; $row.Result = 'NotApproved'; $report.Add($row) | Out-Null; continue }
        if (-not (Test-CanChange)) { Write-ADAutomationLog "USERS SKIP (MaxChanges=$MaxChanges reached): $sam" 'SKIP'; $row.Result = 'MaxChangesReached'; $report.Add($row) | Out-Null; continue }

        # Admitted: this object consumes one change budget unit and runs ALL its actions.
        $script:ChangeCount++
        $ok = $true
        if ($ForcePasswordReset -eq 'yes' -and -not $isService) {
            try { Set-ADUser -Identity $dn @srv -ChangePasswordAtLogon $true -ErrorAction Stop; Write-ADAutomationLog "USERS ACTION: ChangePasswordAtLogon: $sam" 'ACTION' }
            catch { $ok = $false; Write-ADAutomationLog "USERS ERROR: ChangePasswordAtLogon $sam : $($_.Exception.Message)" 'ERROR' }
        }
        try { Disable-ADAccount -Identity $dn @srv -ErrorAction Stop; Write-ADAutomationLog "USERS ACTION: Disabled: $sam" 'ACTION' }
        catch { $ok = $false; Write-ADAutomationLog "USERS ERROR: Disable $sam : $($_.Exception.Message)" 'ERROR' }

        # Only move once the disable actually succeeded, so a failed disable never
        # parks a still-ENABLED account in the 'Disabled' OU (where a later run,
        # scoped to source OUs, may never revisit it).
        if ($willMove -and $ok) {
            try { Move-ADObject -Identity $dn @srv -TargetPath $targetOU -ErrorAction Stop; Write-ADAutomationLog "USERS ACTION: Moved: $sam -> $targetOU" 'ACTION' }
            catch { $ok = $false; Write-ADAutomationLog "USERS ERROR: Move $sam : $($_.Exception.Message)" 'ERROR' }
        }
        elseif ($willMove) { Write-ADAutomationLog "USERS SKIP move (disable failed): $sam" 'SKIP' }

        $row.Result = if ($ok) { 'Changed' } else { 'Error' }
        $report.Add($row) | Out-Null
    }
}
foreach ($ou in $userBases) { Invoke-UserOuProcessing -SearchBaseOU $ou }

# --- Computers --------------------------------------------------------------
function Invoke-ComputerOuProcessing {
    param([string]$SearchBaseOU)
    Write-ADAutomationLog "--- COMPUTERS: $SearchBaseOU ---"
    try {
        # Exclude domain controllers (SERVER_TRUST_ACCOUNT 8192) and RODCs
        # (PARTIAL_SECRETS_ACCOUNT 67108864): a DC offline past the threshold must
        # never be disabled/moved out of OU=Domain Controllers by an unattended run.
        $computers = Get-ADComputer -SearchBase $SearchBaseOU -SearchScope $scope @srv `
            -LDAPFilter '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67108864)))' `
            -Properties LastLogonDate, whenCreated, DistinguishedName, SamAccountName, Enabled -ErrorAction Stop
    }
    catch {
        Write-ADAutomationLog "COMPUTERS ERROR querying '$SearchBaseOU': $($_.Exception.Message)" 'ERROR'
        return
    }

    foreach ($c in $computers) {
        $sam = $c.SamAccountName
        $dn = $c.DistinguishedName
        $ouPath = Get-ParentDN -DistinguishedName $dn

        if (Test-IsIgnoredName -Name $sam -ExactList $IgnoreAccountsExact -RegexList $IgnoreAccountsRegex) {
            Write-ADAutomationLog "COMPUTERS SKIP (ignored): $sam" 'SKIP'
            $report.Add([pscustomobject]@{ ObjectType = 'Computer'; Category = 'Ignored'; SamAccountName = $sam; DistinguishedName = $dn; OU = $ouPath; Enabled = $c.Enabled; LastLogonDate = $c.LastLogonDate; WhenCreated = $c.whenCreated; Reason = 'Ignored'; Eligible = $false; Approved = $null; Action = 'None'; Result = 'Skipped' }) | Out-Null
            continue
        }

        $eligible = $false; $reason = $null
        if (-not $c.LastLogonDate) {
            if ($c.whenCreated -lt $compNeverCutoff) { $eligible = $true; $reason = "NeverLoggedOn; Created=$($c.whenCreated)" }
            else { $reason = "NeverLoggedOn but too new; Created=$($c.whenCreated)" }
        }
        elseif ($c.LastLogonDate -lt $compCutoff) { $eligible = $true; $reason = "LastLogonDate=$($c.LastLogonDate) < cutoff=$compCutoff" }
        else { $reason = "Active; LastLogonDate=$($c.LastLogonDate)" }

        $approved = $null
        if ($RequireApprovalList) { $approved = Test-IsApproved -SamAccountName $sam -DistinguishedName $dn -ApprovalEntries $approvalEntries }

        $actions = New-Object System.Collections.Generic.List[string]
        $actions.Add('Disable')
        $willMove = $false
        if (-not [string]::IsNullOrWhiteSpace($MoveDisabledComputersToOU)) {
            $inTarget = Test-DNUnderOU -DistinguishedName $dn -OUDistinguishedName $MoveDisabledComputersToOU
            if (-not ($SkipIfAlreadyInTargetOU -and $inTarget)) { $actions.Add("MoveTo:$MoveDisabledComputersToOU"); $willMove = $true }
        }

        $row = [pscustomobject]@{ ObjectType = 'Computer'; Category = 'Standard'; SamAccountName = $sam; DistinguishedName = $dn; OU = $ouPath; Enabled = $c.Enabled; LastLogonDate = $c.LastLogonDate; WhenCreated = $c.whenCreated; Reason = $reason; Eligible = $eligible; Approved = $approved; Action = ($actions -join ';'); Result = 'None' }

        if (-not $eligible) { $row.Result = 'NoChange'; $report.Add($row) | Out-Null; continue }
        if ($WhatIf) { Write-ADAutomationLog "COMPUTERS WHATIF: $sam ; $($row.Action) ; $reason" 'WHATIF'; $row.Result = 'WhatIf'; $report.Add($row) | Out-Null; continue }
        if ($RequireApprovalList -and -not $approved) { Write-ADAutomationLog "COMPUTERS SKIP (not approved): $sam" 'SKIP'; $row.Result = 'NotApproved'; $report.Add($row) | Out-Null; continue }
        if (-not (Test-CanChange)) { Write-ADAutomationLog "COMPUTERS SKIP (MaxChanges=$MaxChanges reached): $sam" 'SKIP'; $row.Result = 'MaxChangesReached'; $report.Add($row) | Out-Null; continue }

        $script:ChangeCount++
        $ok = $true
        try { Disable-ADAccount -Identity $dn @srv -ErrorAction Stop; Write-ADAutomationLog "COMPUTERS ACTION: Disabled: $sam" 'ACTION' }
        catch { $ok = $false; Write-ADAutomationLog "COMPUTERS ERROR: Disable $sam : $($_.Exception.Message)" 'ERROR' }
        if ($willMove -and $ok) {
            try { Move-ADObject -Identity $dn @srv -TargetPath $MoveDisabledComputersToOU -ErrorAction Stop; Write-ADAutomationLog "COMPUTERS ACTION: Moved: $sam -> $MoveDisabledComputersToOU" 'ACTION' }
            catch { $ok = $false; Write-ADAutomationLog "COMPUTERS ERROR: Move $sam : $($_.Exception.Message)" 'ERROR' }
        }
        elseif ($willMove) { Write-ADAutomationLog "COMPUTERS SKIP move (disable failed): $sam" 'SKIP' }

        $row.Result = if ($ok) { 'Changed' } else { 'Error' }
        $report.Add($row) | Out-Null
    }
}
foreach ($ou in $compBases) { Invoke-ComputerOuProcessing -SearchBaseOU $ou }

# --- Approval coverage report (flag approvals that matched nothing) ----------
if ($RequireApprovalList -and $approvalEntries.Count -gt 0) {
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $report) { [void]$seen.Add($r.SamAccountName); [void]$seen.Add($r.DistinguishedName) }
    $unmatched = @($approvalEntries | Where-Object { -not $seen.Contains($_) })
    if ($unmatched.Count -gt 0) {
        Write-ADAutomationLog "Approval entries that matched NO object this run (check DN spacing/escaping or stale SAM): $($unmatched -join '; ')" 'WARN'
    }
}

# --- Reporting --------------------------------------------------------------
try { $report | Export-Csv -Path $CsvReportPath -NoTypeInformation -Encoding UTF8; Write-ADAutomationLog "CSV report written: $CsvReportPath" 'INFO' }
catch { Write-ADAutomationLog "ERROR writing CSV report: $($_.Exception.Message)" 'ERROR' }

Write-ADAutomationLog "=== END (ChangeCount=$($script:ChangeCount)) ==="

if ($DryRun) {
    try { Write-ApprovalListDraft -ReportRows $report -Path $ApprovalDraftPath }
    catch { Write-ADAutomationLog "ERROR writing approval draft: $($_.Exception.Message)" 'ERROR' }

    if ($EmailApprovalList) {
        # Guard every placeholder-bearing field, not just SmtpServer: MailTo defaults
        # to the contoso placeholder and the sample config supplies no MailTo for this
        # script, so a real relay would otherwise hand the account inventory to an
        # address the operator does not control.
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

Write-Output "Done. Mode=$($PSCmdlet.ParameterSetName) RequireApprovalList=$RequireApprovalList ChangeCount=$($script:ChangeCount)"
Write-Output "Log: $($run.LogPath)"
Write-Output "CSV: $CsvReportPath"
if ($DryRun) { Write-Output "Approval draft: $ApprovalDraftPath" }
