<#
.SYNOPSIS
Invoke-ADHygieneDisableInactive.ps1

AD hygiene script to identify and optionally disable inactive AD Users (standard + service) and Computers,
with:
- Modes: -DryRun, -Run, -Scheduled
- Optional approval gating: -RequireApprovalList
- Full logging (decisions + actions + errors)
- CSV report output
- Draft approval list generation (from eligible candidates)
- Optional email sending of CSV + approval draft + log via unauthenticated SMTP relay (-EmailApprovalList)

.USAGE
  # Dry-run (no changes): generate CSV + log + approval draft
  .\Invoke-ADHygieneDisableInactive.ps1 -DryRun

  # Dry-run + email approval package (CSV + draft + log)
  .\Invoke-ADHygieneDisableInactive.ps1 -DryRun -EmailApprovalList 

  # Execute changes WITHOUT approval gating (not recommended)
  .\Invoke-ADHygieneDisableInactive.ps1 -Run

  # Execute changes WITH approval gating (recommended)
  .\Invoke-ADHygieneDisableInactive.ps1 -Run -RequireApprovalList -ApprovalListPath C:\Temp\AD-Hygiene\AD-Hygiene-ApprovalList.txt

  # Scheduled mode (recommended only with approval gating)
  .\Invoke-ADHygieneDisableInactive.ps1 -Scheduled -RequireApprovalList

.NOTES
- Uses LastLogonTimestamp via LastLogonDate (replicated).
- For "never logged on" objects: uses minimum age based on whenCreated.
- "Already in target OU" detection uses DN suffix regex to avoid false positives.
- Validates search base OUs before querying (skips invalid bases with WARN log).
#>

[CmdletBinding(DefaultParameterSetName='DryRun')]
param(
  # ===== Mode switches (mutually exclusive) =====
  [Parameter(ParameterSetName='DryRun', Mandatory=$true)]
  [switch]$DryRun,

  [Parameter(ParameterSetName='Run', Mandatory=$true)]
  [switch]$Run,

  [Parameter(ParameterSetName='Scheduled', Mandatory=$true)]
  [switch]$Scheduled,

  # ===== Safety gate (recommended for Run/Scheduled) =====
  [Parameter(ParameterSetName='Run')]
  [Parameter(ParameterSetName='Scheduled')]
  [switch]$RequireApprovalList,

  # ===== Email approval package (DryRun only) =====
  [Parameter(ParameterSetName='DryRun')]
  [switch]$EmailApprovalList,

  # ===== SMTP relay (no auth) variables =====
  [string]$SmtpServer = "smtp-relay.contoso.local",
  [int]$SmtpPort = 25,
  [string]$MailFrom = "ad-hygiene@contoso.local",
  [string[]]$MailTo = @("it-operations@contoso.local"),
  [string]$MailSubject = "AD Hygiene – Approval list required (disable inactive objects)",
  [string]$MailBody = @"
Hej,

Bifogat finns:
1) CSV-rapport över kandidater och beslut (Eligible/Reason)
2) Approval list (TXT) – en rad per objekt (SAMAccountName eller DistinguishedName)
3) Logg (TXT)

Granska och godkänn genom att lägga in önskade objekt i approval-listan enligt er process,
och kör sedan scriptet med -Run -RequireApprovalList.

Mvh
AD Hygiene
"@,
  [bool]$MailUseSsl = $false,

  # ===== Output paths =====
  [string]$OutputRoot = "C:\Temp\AD-Hygiene",
  [string]$ApprovalListPath = "C:\Temp\AD-Hygiene\AD-Hygiene-ApprovalList.txt",

  # ===== Scope config =====
  [ValidateSet('yes','no')]
  [string]$RunInChildOU = 'yes',

  # ===== USERS: standard =====
  [int]$UserInactiveForDays = 90,
  [int]$UserNeverLoggedOnMinAccountAgeDays = 30,

  # ===== USERS: service =====
  [int]$ServiceInactiveForDays = 180,
  [int]$ServiceNeverLoggedOnMinAccountAgeDays = 90,

  # ===== COMPUTERS =====
  [int]$ComputerInactiveForDays = 60,
  [int]$ComputerNeverLoggedOnMinAccountAgeDays = 30,

  # Force password reset on standard users (sets ChangePasswordAtLogon prior to disabling)
  [ValidateSet('yes','no')]
  [string]$ForcePasswordReset = 'no',

  # ===== Move targets =====
  [string]$MoveDisabledUsersToOU = "OU=Disabled Users,DC=contoso,DC=local",
  [string]$MoveDisabledServiceAccountsToOU = "OU=Disabled Service Accounts,DC=contoso,DC=local",
  [string]$MoveDisabledComputersToOU = "OU=Disabled Computers,DC=contoso,DC=local",

  # ===== Search bases (multiple OUs) =====
  [string[]]$UserLimitToOUs = @(
    "OU=Users,DC=contoso,DC=local",
    "OU=Contractors,DC=contoso,DC=local"
  ),
  [string[]]$ComputerLimitToOUs = @(
    "OU=Workstations,DC=contoso,DC=local",
    "OU=Servers,DC=contoso,DC=local"
  ),

  # ===== Service account detection (any match => service) =====
  [string[]]$ServiceAccountOUs = @(
    "OU=Service Accounts,DC=contoso,DC=local"
  ),
  [string]$ServiceAccountAttributeName = "employeeType",
  [string]$ServiceAccountAttributeValueRegex = '^service$',
  [string[]]$ServiceAccountSamRegex = @('^svc_','^sa_'),

  # ===== Ignore accounts (exact + regex) =====
  # Includes accounts that should never be touched by default.
  [string[]]$IgnoreAccountsExact = @(
    "Administrator",
    "Guest",
    "krbtgt",
    "DefaultAccount",
    "WDAGUtilityAccount"
  ),
  [string[]]$IgnoreAccountsRegex = @(
    '^AZURE', # Azure AD Connect accounts
    '^MSOL', # MSOL accounts
    '^BTG', # Breake The Glass accounts
    '^DWM-' # Dynamic Windows Machine accounts
  ),

  # ===== Operational toggles =====
  [bool]$SkipIfAlreadyInTargetOU = $true,

  # Extra safety: max number of change ACTIONS (disable/move/reset) per run (Run/Scheduled only).
  # NOTE: One object may consume multiple actions (e.g., Disable + Move + PasswordReset).
  [int]$MaxChanges = 0  # 0 = unlimited
)

# MODE FLAGS =======

$WhatIf = $true
$IsScheduled = $false
switch ($PSCmdlet.ParameterSetName) {
  'DryRun'     { $WhatIf = $true;  $IsScheduled = $false }
  'Run'        { $WhatIf = $false; $IsScheduled = $false }
  'Scheduled'  { $WhatIf = $false; $IsScheduled = $true  }
}

# In DryRun, approval gating is irrelevant.
if ($DryRun) { $RequireApprovalList = $false }


# FUNCTIONS

function Write-Log {
  param(
    [Parameter(Mandatory=$true)][string]$Message,
    [ValidateSet('INFO','WARN','ERROR','ACTION','WHATIF','SKIP')][string]$Level = 'INFO'
  )
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $line = "[$ts][$Level] $Message"
  Write-Output $line
  Add-Content -Path $script:LogPath -Value $line
}

function Get-SearchScope {
  param([string]$RunInChildOU)
  if ($RunInChildOU -eq 'yes') { return 'Subtree' }
  return 'OneLevel'
}

function Test-IsIgnoredSam {
  param(
    [Parameter(Mandatory=$true)][string]$SamAccountName,
    [string[]]$ExactList,
    [string[]]$RegexList
  )
  if ($ExactList -and ($ExactList -contains $SamAccountName)) { return $true }
  if ($RegexList) {
    foreach ($pattern in $RegexList) {
      if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
      if ($SamAccountName -match $pattern) { return $true }
    }
  }
  return $false
}

function Ensure-TargetOU {
  param([string]$OuDn)
  if ([string]::IsNullOrWhiteSpace($OuDn)) { return }
  try {
    $null = Get-ADOrganizationalUnit -Identity $OuDn -ErrorAction Stop
  } catch {
    throw "Target OU not found or not an OU: '$OuDn'. Error: $($_.Exception.Message)"
  }
}

function Get-ValidSearchBases {
  param([string[]]$Bases)

  $valid = New-Object System.Collections.Generic.List[string]
  foreach ($b in $Bases) {
    if ([string]::IsNullOrWhiteSpace($b)) { continue }
    try {
      # Expect OUs as bases (more strict than Get-ADObject)
      $null = Get-ADOrganizationalUnit -Identity $b -ErrorAction Stop
      $valid.Add($b) | Out-Null
    } catch {
      Write-Log "Search base OU not found/invalid (skipping): $b" 'WARN'
    }
  }
  return $valid.ToArray()
}

function Load-ApprovalList {
  param([string]$Path)

  if (-not (Test-Path $Path)) {
    Write-Log "Approval list not found at '$Path'. With -RequireApprovalList, NO changes will be allowed." 'WARN'
    return @()
  }

  $lines = Get-Content -Path $Path -ErrorAction Stop |
    ForEach-Object { $_.Trim([char]0xFEFF).Trim() } |
    Where-Object { $_ -and -not $_.StartsWith('#') }

  # Deduplicate case-insensitively (SAM/DN are effectively case-insensitive in AD usage)
  $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($l in $lines) { [void]$set.Add($l) }
  return $set.ToArray()
}

function Test-IsApproved {
  param(
    [Parameter(Mandatory=$true)][string]$SamAccountName,
    [Parameter(Mandatory=$true)][string]$DistinguishedName,
    [string[]]$ApprovalEntries
  )
  if (-not $ApprovalEntries -or $ApprovalEntries.Count -eq 0) { return $false }

  # Compare case-insensitively
  foreach ($e in $ApprovalEntries) {
    if ($e.Equals($SamAccountName, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($e.Equals($DistinguishedName, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return $false
}

function Test-IsInAnyOU {
  param(
    [Parameter(Mandatory=$true)][string]$DistinguishedName,
    [Parameter(Mandatory=$true)][string[]]$OuDns
  )
  foreach ($ou in $OuDns) {
    if ([string]::IsNullOrWhiteSpace($ou)) { continue }
    if ($DistinguishedName -match ",$([regex]::Escape($ou))$") { return $true }
  }
  return $false
}

function Get-ParentOUFromDN {
  param([Parameter(Mandatory=$true)][string]$DistinguishedName)
  return ($DistinguishedName -replace '^[^,]+,', '')
}

function Classify-IsServiceAccount {
  param(
    [Parameter(Mandatory=$true)]$AdUser,
    [string[]]$ServiceOUs,
    [string]$AttrName,
    [string]$AttrValueRegex,
    [string[]]$SamRegex
  )
  $sam = $AdUser.SamAccountName
  $dn  = $AdUser.DistinguishedName

  if ($ServiceOUs -and (Test-IsInAnyOU -DistinguishedName $dn -OuDns $ServiceOUs)) { return $true }

  if ($SamRegex) {
    foreach ($p in $SamRegex) {
      if ([string]::IsNullOrWhiteSpace($p)) { continue }
      if ($sam -match $p) { return $true }
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($AttrName) -and -not [string]::IsNullOrWhiteSpace($AttrValueRegex)) {
    $val = $AdUser.$AttrName
    if ($val -and ($val.ToString() -match $AttrValueRegex)) { return $true }
  }

  return $false
}

function Write-ApprovalListDraft {
  param(
    [Parameter(Mandatory=$true)]$ReportRows,
    [Parameter(Mandatory=$true)][string]$Path
  )
  $eligible = $ReportRows | Where-Object { $_.Eligible -eq $true -and $_.Enabled -eq $true }

  $lines = @(
    "# AD Hygiene Approval List",
    "# One entry per line: SAMAccountName or DistinguishedName",
    "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    "# Tip: keep only the objects you approve for disabling/move in the next Run.",
    ""
  )

  # Deduplicate for readability
  $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($r in $eligible) { [void]$set.Add($r.SamAccountName) }

  $lines += ($set.ToArray() | Sort-Object)
  $lines | Set-Content -Path $Path -Encoding UTF8

  Write-Log "Approval list draft written: $Path (eligible unique count=$($set.Count))" 'INFO'
}

function Send-ApprovalEmail {
  param(
    [Parameter(Mandatory=$true)][string]$SmtpServer,
    [Parameter(Mandatory=$true)][int]$SmtpPort,
    [Parameter(Mandatory=$true)][string]$From,
    [Parameter(Mandatory=$true)][string[]]$To,
    [Parameter(Mandatory=$true)][string]$Subject,
    [Parameter(Mandatory=$true)][string]$Body,
    [Parameter(Mandatory=$true)][string[]]$Attachments,
    [bool]$UseSsl = $false
  )

  foreach ($a in $Attachments) {
    if (-not (Test-Path $a)) { throw "Attachment not found: $a" }
  }

  try {
    Send-MailMessage `
      -SmtpServer $SmtpServer `
      -Port $SmtpPort `
      -From $From `
      -To $To `
      -Subject $Subject `
      -Body $Body `
      -BodyAsHtml:$false `
      -Attachments $Attachments `
      -UseSsl:$UseSsl `
      -ErrorAction Stop

    Write-Log "Email sent to '$($To -join ',')' via $SmtpServer:$SmtpPort (SSL=$UseSsl). Attachments: $($Attachments -join ';')" 'ACTION'
  } catch {
    Write-Log "ERROR sending email: $($_.Exception.Message)" 'ERROR'
    throw
  }
}

function Test-InTargetOU {
  param(
    [Parameter(Mandatory=$true)][string]$DistinguishedName,
    [Parameter(Mandatory=$true)][string]$TargetOU
  )
  if ([string]::IsNullOrWhiteSpace($TargetOU)) { return $false }
  return ($DistinguishedName -match ",$([regex]::Escape($TargetOU))$")
}


# MAIN SETUP =======

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
  throw "ActiveDirectory module not found. Install RSAT / AD PowerShell module."
}
Import-Module ActiveDirectory

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

$RunId = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:LogPath = Join-Path $OutputRoot "ADHygiene-DisableInactive-$RunId.log"
$CsvReportPath  = Join-Path $OutputRoot "ADHygiene-DisableInactive-Report-$RunId.csv"
$ApprovalDraftPath = Join-Path $OutputRoot "ADHygiene-ApprovalList-Draft-$RunId.txt"

New-Item -ItemType File -Force -Path $script:LogPath | Out-Null

$scope = Get-SearchScope -RunInChildOU $RunInChildOU

# Validate target OUs (move destinations)
Ensure-TargetOU -OuDn $MoveDisabledUsersToOU
Ensure-TargetOU -OuDn $MoveDisabledServiceAccountsToOU
Ensure-TargetOU -OuDn $MoveDisabledComputersToOU

# Validate search bases (skip invalid bases)
$userBases = Get-ValidSearchBases -Bases $UserLimitToOUs
$compBases = Get-ValidSearchBases -Bases $ComputerLimitToOUs

# Thresholds
$userCutoff = (Get-Date).AddDays(-$UserInactiveForDays)
$userNeverLogonCutoffCreated = (Get-Date).AddDays(-$UserNeverLoggedOnMinAccountAgeDays)

$svcCutoff = (Get-Date).AddDays(-$ServiceInactiveForDays)
$svcNeverLogonCutoffCreated = (Get-Date).AddDays(-$ServiceNeverLoggedOnMinAccountAgeDays)

$compCutoff = (Get-Date).AddDays(-$ComputerInactiveForDays)
$compNeverLogonCutoffCreated = (Get-Date).AddDays(-$ComputerNeverLoggedOnMinAccountAgeDays)

# Approval list
$approvalEntries = @()
if ($RequireApprovalList) {
  $approvalEntries = Load-ApprovalList -Path $ApprovalListPath
}

Write-Log "=== START (RunId=$RunId) ==="
Write-Log "Mode=$($PSCmdlet.ParameterSetName) ; WhatIf=$WhatIf ; Scheduled=$IsScheduled ; RequireApprovalList=$RequireApprovalList ; MaxChanges=$MaxChanges (actions, not objects)"
Write-Log "OutputRoot=$OutputRoot"
Write-Log "Log=$script:LogPath"
Write-Log "CSV=$CsvReportPath"
Write-Log "ApprovalListPath=$ApprovalListPath"
Write-Log "SearchScope=$scope"
Write-Log "User search bases (valid): $($userBases -join '; ')" 'INFO'
Write-Log "Computer search bases (valid): $($compBases -join '; ')" 'INFO'
Write-Log "IgnoreExact=$($IgnoreAccountsExact -join ',')" 'INFO'
Write-Log "IgnoreRegex=$($IgnoreAccountsRegex | Where-Object { $_ } -join ',')" 'INFO'

Write-Log "USER policy: InactiveDays=$UserInactiveForDays cutoff=$userCutoff ; NeverLogonMinAgeDays=$UserNeverLoggedOnMinAccountAgeDays createdBefore=$userNeverLogonCutoffCreated ; ForcePasswordReset=$ForcePasswordReset ; MoveTo='$MoveDisabledUsersToOU'"
Write-Log "SERVICE policy: InactiveDays=$ServiceInactiveForDays cutoff=$svcCutoff ; NeverLogonMinAgeDays=$ServiceNeverLoggedOnMinAccountAgeDays createdBefore=$svcNeverLogonCutoffCreated ; MoveTo='$MoveDisabledServiceAccountsToOU'"
Write-Log "COMPUTER policy: InactiveDays=$ComputerInactiveForDays cutoff=$compCutoff ; NeverLogonMinAgeDays=$ComputerNeverLoggedOnMinAccountAgeDays createdBefore=$compNeverLogonCutoffCreated ; MoveTo='$MoveDisabledComputersToOU'"

Write-Log "Service detection: OUs=$($ServiceAccountOUs -join ';') ; Attr=$ServiceAccountAttributeName / Regex=$ServiceAccountAttributeValueRegex ; SamRegex=$($ServiceAccountSamRegex -join ',')" 'INFO'

$report = New-Object System.Collections.Generic.List[object]
$script:ChangeCount = 0

function Add-ChangeCount {
  param([int]$Delta = 1)
  $script:ChangeCount += $Delta
}

function Test-CanChange {
  if ($WhatIf) { return $true }
  if ($MaxChanges -le 0) { return $true }
  if ($script:ChangeCount -ge $MaxChanges) { return $false }
  return $true
}


# ===== USERS HANDLING ====

function Process-UserOU {
  param([Parameter(Mandatory=$true)][string]$SearchBaseOU)

  Write-Log "--- USERS: Processing OU: $SearchBaseOU ---"

  $props = @('LastLogonDate','whenCreated','DistinguishedName','SamAccountName','Enabled')
  if (-not [string]::IsNullOrWhiteSpace($ServiceAccountAttributeName)) { $props += $ServiceAccountAttributeName }

  try {
    $users = Get-ADUser -SearchBase $SearchBaseOU -SearchScope $scope `
  -LDAPFilter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
  -Properties $props -ErrorAction Stop
  } catch {
    Write-Log "USERS ERROR querying base OU '$SearchBaseOU': $($_.Exception.Message)" 'ERROR'
    return
  }

  foreach ($u in $users) {
    $sam = $u.SamAccountName
    $dn  = $u.DistinguishedName
    $ouPath = Get-ParentOUFromDN -DistinguishedName $dn

    if (Test-IsIgnoredSam -SamAccountName $sam -ExactList $IgnoreAccountsExact -RegexList $IgnoreAccountsRegex) {
      Write-Log "USERS SKIP (ignored): $sam" 'SKIP'
      $report.Add([pscustomobject]@{
        ObjectType='User'; Category='Ignored'; SamAccountName=$sam; DistinguishedName=$dn; OU=$ouPath
        Enabled=$u.Enabled; LastLogonDate=$u.LastLogonDate; WhenCreated=$u.whenCreated
        Reason='Ignored by exact/regex'; Eligible=$false; Approved=$null; Action='None'; Result='Skipped'
      }) | Out-Null
      continue
    }

    if (-not $u.Enabled) {
      $report.Add([pscustomobject]@{
        ObjectType='User'; Category='AlreadyDisabled'; SamAccountName=$sam; DistinguishedName=$dn; OU=$ouPath
        Enabled=$u.Enabled; LastLogonDate=$u.LastLogonDate; WhenCreated=$u.whenCreated
        Reason='Already disabled'; Eligible=$false; Approved=$null; Action='None'; Result='NoChange'
      }) | Out-Null
      continue
    }

    $isService = Classify-IsServiceAccount -AdUser $u -ServiceOUs $ServiceAccountOUs -AttrName $ServiceAccountAttributeName -AttrValueRegex $ServiceAccountAttributeValueRegex -SamRegex $ServiceAccountSamRegex

    $cutoff = if ($isService) { $svcCutoff } else { $userCutoff }
    $createdCutoff = if ($isService) { $svcNeverLogonCutoffCreated } else { $userNeverLogonCutoffCreated }
    $targetOU = if ($isService) { $MoveDisabledServiceAccountsToOU } else { $MoveDisabledUsersToOU }
    $category = if ($isService) { 'Service' } else { 'Standard' }

    $eligible = $false
    $reason = $null

    if (-not $u.LastLogonDate) {
      if ($u.whenCreated -lt $createdCutoff) { $eligible = $true; $reason = "NeverLoggedOn; Created=$($u.whenCreated)" }
      else { $reason = "NeverLoggedOn but too new; Created=$($u.whenCreated)" }
    } elseif ($u.LastLogonDate -lt $cutoff) {
      $eligible = $true; $reason = "LastLogonDate=$($u.LastLogonDate) older than cutoff=$cutoff"
    } else {
      $reason = "Active within threshold; LastLogonDate=$($u.LastLogonDate)"
    }

    $approved = $null
    if ($RequireApprovalList) { $approved = Test-IsApproved -SamAccountName $sam -DistinguishedName $dn -ApprovalEntries $approvalEntries }

    $actions = New-Object System.Collections.Generic.List[string]
    if ($ForcePasswordReset -eq 'yes' -and -not $isService) { $actions.Add('SetChangePasswordAtLogon') }
    $actions.Add('Disable')

    if (-not [string]::IsNullOrWhiteSpace($targetOU)) {
      $inTarget = Test-InTargetOU -DistinguishedName $dn -TargetOU $targetOU
      if (-not ($SkipIfAlreadyInTargetOU -and $inTarget)) { $actions.Add("MoveTo:$targetOU") }
    }

    $row = [pscustomobject]@{
      ObjectType='User'
      Category=$category
      SamAccountName=$sam
      DistinguishedName=$dn
      OU=$ouPath
      Enabled=$u.Enabled
      LastLogonDate=$u.LastLogonDate
      WhenCreated=$u.whenCreated
      Reason=$reason
      Eligible=$eligible
      Approved=$approved
      Action=($actions -join ';')
      Result='None'
    }

    if (-not $eligible) {
      $row.Result='NoChange'
      $report.Add($row) | Out-Null
      continue
    }

    if ($WhatIf) {
      Write-Log "USERS WHATIF candidate: $sam ; Category=$category ; Actions=$($row.Action) ; Reason=$reason" 'WHATIF'
      $row.Result='WhatIf'
      $report.Add($row) | Out-Null
      continue
    }

    if ($RequireApprovalList -and -not $approved) {
      Write-Log "USERS SKIP (not approved): $sam ; would have done: $($row.Action)" 'SKIP'
      $row.Result='NotApproved'
      $report.Add($row) | Out-Null
      continue
    }

    if (-not (Test-CanChange)) {
      Write-Log "USERS SKIP (MaxChanges reached=$MaxChanges): $sam ; would have done: $($row.Action)" 'SKIP'
      $row.Result='MaxChangesReached'
      $report.Add($row) | Out-Null
      continue
    }

    $ok = $true

    if ($ForcePasswordReset -eq 'yes' -and -not $isService) {
      try {
        Set-ADUser -Identity $dn -ChangePasswordAtLogon $true -ErrorAction Stop
        Write-Log "USERS ACTION: Set ChangePasswordAtLogon: $sam" 'ACTION'
        Add-ChangeCount -Delta 1
      } catch {
        $ok = $false
        Write-Log "USERS ERROR: Set ChangePasswordAtLogon failed for $sam : $($_.Exception.Message)" 'ERROR'
      }
    }

    try {
      Disable-ADAccount -Identity $dn -ErrorAction Stop
      Write-Log "USERS ACTION: Disabled: $sam" 'ACTION'
      Add-ChangeCount -Delta 1
    } catch {
      $ok = $false
      Write-Log "USERS ERROR: Disable failed for $sam : $($_.Exception.Message)" 'ERROR'
    }

    if (-not [string]::IsNullOrWhiteSpace($targetOU)) {
      $inTarget = Test-InTargetOU -DistinguishedName $dn -TargetOU $targetOU
      if (-not ($SkipIfAlreadyInTargetOU -and $inTarget)) {
        if (-not (Test-CanChange)) {
          Write-Log "USERS SKIP move (MaxChanges reached=$MaxChanges): $sam -> $targetOU" 'SKIP'
          $ok = $false
        } else {
          try {
            Move-ADObject -Identity $dn -TargetPath $targetOU -ErrorAction Stop
            Write-Log "USERS ACTION: Moved: $sam -> $targetOU" 'ACTION'
            Add-ChangeCount -Delta 1
          } catch {
            $ok = $false
            Write-Log "USERS ERROR: Move failed for $sam : $($_.Exception.Message)" 'ERROR'
          }
        }
      } else {
        Write-Log "USERS SKIP: Already under target OU for $sam" 'SKIP'
      }
    }

    $row.Result = if ($ok) { 'Changed' } else { 'Error' }
    $report.Add($row) | Out-Null
  }
}

foreach ($ou in $userBases) { Process-UserOU -SearchBaseOU $ou }


# === COMPUTERS HANDLING ==

function Process-ComputerOU {
  param([Parameter(Mandatory=$true)][string]$SearchBaseOU)

  Write-Log "--- COMPUTERS: Processing OU: $SearchBaseOU ---"

  try {
    $computers = Get-ADComputer -SearchBase $SearchBaseOU -SearchScope $scope `
  -LDAPFilter "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
  -Properties LastLogonDate,whenCreated,DistinguishedName,SamAccountName,Enabled -ErrorAction Stop
  } catch {
    Write-Log "COMPUTERS ERROR querying base OU '$SearchBaseOU': $($_.Exception.Message)" 'ERROR'
    return
  }

  foreach ($c in $computers) {
    $sam = $c.SamAccountName
    $dn  = $c.DistinguishedName
    $ouPath = Get-ParentOUFromDN -DistinguishedName $dn

    if (Test-IsIgnoredSam -SamAccountName $sam -ExactList $IgnoreAccountsExact -RegexList $IgnoreAccountsRegex) {
      Write-Log "COMPUTERS SKIP (ignored): $sam" 'SKIP'
      $report.Add([pscustomobject]@{
        ObjectType='Computer'; Category='Ignored'; SamAccountName=$sam; DistinguishedName=$dn; OU=$ouPath
        Enabled=$c.Enabled; LastLogonDate=$c.LastLogonDate; WhenCreated=$c.whenCreated
        Reason='Ignored by exact/regex'; Eligible=$false; Approved=$null; Action='None'; Result='Skipped'
      }) | Out-Null
      continue
    }

    if (-not $c.Enabled) {
      $report.Add([pscustomobject]@{
        ObjectType='Computer'; Category='AlreadyDisabled'; SamAccountName=$sam; DistinguishedName=$dn; OU=$ouPath
        Enabled=$c.Enabled; LastLogonDate=$c.LastLogonDate; WhenCreated=$c.whenCreated
        Reason='Already disabled'; Eligible=$false; Approved=$null; Action='None'; Result='NoChange'
      }) | Out-Null
      continue
    }

    $eligible = $false
    $reason = $null
    if (-not $c.LastLogonDate) {
      if ($c.whenCreated -lt $compNeverLogonCutoffCreated) { $eligible=$true; $reason="NeverLoggedOn; Created=$($c.whenCreated)" }
      else { $reason="NeverLoggedOn but too new; Created=$($c.whenCreated)" }
    } elseif ($c.LastLogonDate -lt $compCutoff) {
      $eligible=$true; $reason="LastLogonDate=$($c.LastLogonDate) older than cutoff=$compCutoff"
    } else {
      $reason="Active within threshold; LastLogonDate=$($c.LastLogonDate)"
    }

    $approved = $null
    if ($RequireApprovalList) { $approved = Test-IsApproved -SamAccountName $sam -DistinguishedName $dn -ApprovalEntries $approvalEntries }

    $actions = New-Object System.Collections.Generic.List[string]
    $actions.Add('Disable')
    if (-not [string]::IsNullOrWhiteSpace($MoveDisabledComputersToOU)) {
      $inTarget = Test-InTargetOU -DistinguishedName $dn -TargetOU $MoveDisabledComputersToOU
      if (-not ($SkipIfAlreadyInTargetOU -and $inTarget)) { $actions.Add("MoveTo:$MoveDisabledComputersToOU") }
    }

    $row = [pscustomobject]@{
      ObjectType='Computer'
      Category='Standard'
      SamAccountName=$sam
      DistinguishedName=$dn
      OU=$ouPath
      Enabled=$c.Enabled
      LastLogonDate=$c.LastLogonDate
      WhenCreated=$c.whenCreated
      Reason=$reason
      Eligible=$eligible
      Approved=$approved
      Action=($actions -join ';')
      Result='None'
    }

    if (-not $eligible) {
      $row.Result='NoChange'
      $report.Add($row) | Out-Null
      continue
    }

    if ($WhatIf) {
      Write-Log "COMPUTERS WHATIF candidate: $sam ; Actions=$($row.Action) ; Reason=$reason" 'WHATIF'
      $row.Result='WhatIf'
      $report.Add($row) | Out-Null
      continue
    }

    if ($RequireApprovalList -and -not $approved) {
      Write-Log "COMPUTERS SKIP (not approved): $sam ; would have done: $($row.Action)" 'SKIP'
      $row.Result='NotApproved'
      $report.Add($row) | Out-Null
      continue
    }

    if (-not (Test-CanChange)) {
      Write-Log "COMPUTERS SKIP (MaxChanges reached=$MaxChanges): $sam ; would have done: $($row.Action)" 'SKIP'
      $row.Result='MaxChangesReached'
      $report.Add($row) | Out-Null
      continue
    }

    $ok = $true
    try {
      Disable-ADAccount -Identity $dn -ErrorAction Stop
      Write-Log "COMPUTERS ACTION: Disabled: $sam" 'ACTION'
      Add-ChangeCount -Delta 1
    } catch {
      $ok=$false
      Write-Log "COMPUTERS ERROR: Disable failed for $sam : $($_.Exception.Message)" 'ERROR'
    }

    if (-not [string]::IsNullOrWhiteSpace($MoveDisabledComputersToOU)) {
      $inTarget = Test-InTargetOU -DistinguishedName $dn -TargetOU $MoveDisabledComputersToOU
      if (-not ($SkipIfAlreadyInTargetOU -and $inTarget)) {
        if (-not (Test-CanChange)) {
          Write-Log "COMPUTERS SKIP move (MaxChanges reached=$MaxChanges): $sam -> $MoveDisabledComputersToOU" 'SKIP'
          $ok = $false
        } else {
          try {
            Move-ADObject -Identity $dn -TargetPath $MoveDisabledComputersToOU -ErrorAction Stop
            Write-Log "COMPUTERS ACTION: Moved: $sam -> $MoveDisabledComputersToOU" 'ACTION'
            Add-ChangeCount -Delta 1
          } catch {
            $ok=$false
            Write-Log "COMPUTERS ERROR: Move failed for $sam : $($_.Exception.Message)" 'ERROR'
          }
        }
      } else {
        Write-Log "COMPUTERS SKIP: Already under target OU for $sam" 'SKIP'
      }
    }

    $row.Result = if ($ok) { 'Changed' } else { 'Error' }
    $report.Add($row) | Out-Null
  }
}

foreach ($ou in $compBases) { Process-ComputerOU -SearchBaseOU $ou }


# REPORTING

try {
  $report | Export-Csv -Path $CsvReportPath -NoTypeInformation -Encoding UTF8
  Write-Log "CSV report written: $CsvReportPath" 'INFO'
} catch {
  Write-Log "ERROR writing CSV report: $($_.Exception.Message)" 'ERROR'
}

# Write END before optional email so END is included in attached log.
Write-Log "=== END (ChangeCount=$script:ChangeCount) ==="

# DryRun workflow: approval draft + optional email package
if ($DryRun) {
  try {
    Write-ApprovalListDraft -ReportRows $report -Path $ApprovalDraftPath
  } catch {
    Write-Log "ERROR writing approval draft: $($_.Exception.Message)" 'ERROR'
  }

  if ($EmailApprovalList) {
    $attachments = @($CsvReportPath, $ApprovalDraftPath, $script:LogPath)

    Write-Log "Preparing to send approval email via $SmtpServer:$SmtpPort (SSL=$MailUseSsl) From=$MailFrom To=$($MailTo -join ',')" 'INFO'
    Send-ApprovalEmail -SmtpServer $SmtpServer -SmtpPort $SmtpPort -From $MailFrom -To $MailTo -Subject $MailSubject -Body $MailBody -Attachments $attachments -UseSsl:$MailUseSsl
  }
}

Write-Output "Done."
Write-Output "Mode: $($PSCmdlet.ParameterSetName) ; RequireApprovalList=$RequireApprovalList ; ChangeCount=$script:ChangeCount"
Write-Output "Log: $script:LogPath"
Write-Output "CSV: $CsvReportPath"
if ($DryRun) { Write-Output "Approval draft: $ApprovalDraftPath" }
if ($RequireApprovalList) { Write-Output "Approval list (input): $ApprovalListPath" }
