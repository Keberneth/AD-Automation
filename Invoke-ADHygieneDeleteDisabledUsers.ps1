<#
.SYNOPSIS
Invoke-ADHygieneDeleteDisabledUsers.ps1

Deletes AD user accounts that have been DISABLED for N days (default 180), with:
- Modes: -DryRun, -Run, -Scheduled
- Optional approval gating: -RequireApprovalList
- Full logging (decisions + actions + errors)
- CSV report output
- Draft approval list generation (from eligible candidates)
- Optional email sending of CSV + approval draft + log via unauthenticated SMTP relay (-EmailApprovalList)

.NOTES / IMPORTANT
1) “Disabled since” is not a first-class replicated timestamp in AD by default. This script can determine the disable time using:
   - Replication metadata on userAccountControl (recommended): Get-ADReplicationAttributeMetadata
   - whenChanged (fallback; NOT replicated and may reflect replication timing or later edits)
   - A stamped attribute (best if you already stamp on disable via your disable script)

References:
- Remove-ADUser: https://learn.microsoft.com/powershell/module/activedirectory/remove-aduser
- Get-ADUser: https://learn.microsoft.com/powershell/module/activedirectory/get-aduser
- userAccountControl flags (ACCOUNTDISABLE): https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
- whenChanged definition (not replicated): https://learn.microsoft.com/openspecs/windows_protocols/ms-adls/ac3586ae-bf24-42f2-ad23-22bdfaf75b62

.USAGE
  # Dry-run (no changes): generate CSV + log + approval draft
  .\Invoke-ADHygieneDeleteDisabledUsers.ps1 -DryRun

  # Dry-run + email approval package (CSV + draft + log)
  .\Invoke-ADHygieneDeleteDisabledUsers.ps1 -DryRun -EmailApprovalList

  # Execute deletes WITHOUT approval gating (not recommended)
  .\Invoke-ADHygieneDeleteDisabledUsers.ps1 -Run

  # Execute deletes WITH approval gating (recommended)
  .\Invoke-ADHygieneDeleteDisabledUsers.ps1 -Run -RequireApprovalList -ApprovalListPath C:\Temp\AD-Hygiene\AD-Hygiene-Delete-ApprovalList.txt

  # Limit scope to specific OUs (if none specified, it runs forest-wide)
  .\Invoke-ADHygieneDeleteDisabledUsers.ps1 -DryRun -UserLimitToOUs "OU=Disabled Users,DC=contoso,DC=local"

  # Scheduled mode (recommended only with approval gating)
  .\Invoke-ADHygieneDeleteDisabledUsers.ps1 -Scheduled -RequireApprovalList
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
  [string]$MailSubject = "AD Hygiene – Approval list required (delete disabled users)",
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
  [string]$ApprovalListPath = "C:\Temp\AD-Hygiene\AD-Hygiene-Delete-ApprovalList.txt",

  # ===== Scope config =====
  [ValidateSet('yes','no')]
  [string]$RunInChildOU = 'yes',

  # If provided -> only search these OUs. If empty -> forest-wide across all domains.
  [string[]]$UserLimitToOUs = @(),

  # ===== Policy =====
  [int]$DisabledForDays = 180,

  # ===== Disable date source (recommended: ReplicationMetadata) =====
  [ValidateSet('ReplicationMetadata','WhenChanged','StampAttribute')]
  [string]$DisableDateSource = 'ReplicationMetadata',

  # Used only when DisableDateSource=StampAttribute
  [string]$DisableStampAttributeName = "extensionAttribute15",
  # Expected formats: ISO 8601 date/time or yyyy-MM-dd (e.g., 2025-01-31 or 2025-01-31T10:15:00Z)
  # Example value you might stamp: "2025-01-31T10:15:00Z"
  [string]$DisableStampParseHint = "ISO8601",

  # ===== Ignore accounts (exact + regex) =====
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
  # Extra safety: max number of delete ACTIONS per run (Run/Scheduled only).
  [int]$MaxDeletes = 0  # 0 = unlimited
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

# FUNCTIONS =======

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

function Load-ApprovalList {
  param([string]$Path)

  if (-not (Test-Path $Path)) {
    Write-Log "Approval list not found at '$Path'. With -RequireApprovalList, NO deletes will be allowed." 'WARN'
    return @()
  }

  $lines = Get-Content -Path $Path -ErrorAction Stop |
    ForEach-Object { $_.Trim([char]0xFEFF).Trim() } |
    Where-Object { $_ -and -not $_.StartsWith('#') }

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

  foreach ($e in $ApprovalEntries) {
    if ($e.Equals($SamAccountName, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($e.Equals($DistinguishedName, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return $false
}

function Get-ParentOUFromDN {
  param([Parameter(Mandatory=$true)][string]$DistinguishedName)
  return ($DistinguishedName -replace '^[^,]+,', '')
}

function Write-ApprovalListDraft {
  param(
    [Parameter(Mandatory=$true)]$ReportRows,
    [Parameter(Mandatory=$true)][string]$Path
  )

  $eligible = $ReportRows | Where-Object { $_.Eligible -eq $true }

  $lines = @(
    "# AD Hygiene Approval List (DELETE disabled users)",
    "# One entry per line: SAMAccountName or DistinguishedName",
    "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    "# Tip: keep only the objects you approve for deletion in the next Run.",
    ""
  )

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

function Try-Parse-Date {
  param([string]$Value)

  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $v = $Value.Trim()

  $dt = $null
  # Try invariant parse first
  if ([DateTime]::TryParse($v, [System.Globalization.CultureInfo]::InvariantCulture,
      [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) {
    return $dt.ToUniversalTime()
  }

  # Try yyyy-MM-dd
  if ([DateTime]::TryParseExact($v, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture,
      [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) {
    return $dt.ToUniversalTime()
  }

  return $null
}

function Get-DisableDate {
  param(
    [Parameter(Mandatory=$true)][string]$DistinguishedName,
    [Parameter(Mandatory=$true)]$AdUser,
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$Server,
    [string]$StampAttributeName
  )

  switch ($Source) {
    'StampAttribute' {
      if ([string]::IsNullOrWhiteSpace($StampAttributeName)) { return $null }
      $val = $AdUser.$StampAttributeName
      if (-not $val) { return $null }
      return (Try-Parse-Date -Value $val.ToString())
    }

    'ReplicationMetadata' {
      try {
        # Replication attribute metadata provides originating change time for replicated attributes
        $meta = Get-ADReplicationAttributeMetadata -Object $DistinguishedName -Server $Server -ErrorAction Stop |
          Where-Object { $_.AttributeName -eq 'userAccountControl' } |
          Select-Object -First 1

        if ($meta -and $meta.LastOriginatingChangeTime) {
          return ($meta.LastOriginatingChangeTime.ToUniversalTime())
        }
      } catch {
        # Fall through to null; caller can decide fallback
        Write-Log "WARN: ReplicationMetadata failed for DN='$DistinguishedName' on Server='$Server' : $($_.Exception.Message)" 'WARN'
      }
      return $null
    }

    'WhenChanged' {
      if ($AdUser.whenChanged) { return ($AdUser.whenChanged.ToUniversalTime()) }
      return $null
    }
  }

  return $null
}

# MAIN SETUP =======

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
  throw "ActiveDirectory module not found. Install RSAT / AD PowerShell module."
}
Import-Module ActiveDirectory

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

$RunId = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:LogPath = Join-Path $OutputRoot "ADHygiene-DeleteDisabledUsers-$RunId.log"
$CsvReportPath  = Join-Path $OutputRoot "ADHygiene-DeleteDisabledUsers-Report-$RunId.csv"
$ApprovalDraftPath = Join-Path $OutputRoot "ADHygiene-Delete-ApprovalList-Draft-$RunId.txt"

New-Item -ItemType File -Force -Path $script:LogPath | Out-Null

$scope = Get-SearchScope -RunInChildOU $RunInChildOU
$cutoff = (Get-Date).ToUniversalTime().AddDays(-$DisabledForDays)

# Approval list
$approvalEntries = @()
if ($RequireApprovalList) {
  $approvalEntries = Load-ApprovalList -Path $ApprovalListPath
}

Write-Log "=== START (RunId=$RunId) ==="
Write-Log "Mode=$($PSCmdlet.ParameterSetName) ; WhatIf=$WhatIf ; Scheduled=$IsScheduled ; RequireApprovalList=$RequireApprovalList ; MaxDeletes=$MaxDeletes"
Write-Log "OutputRoot=$OutputRoot"
Write-Log "Log=$script:LogPath"
Write-Log "CSV=$CsvReportPath"
Write-Log "ApprovalListPath=$ApprovalListPath"
Write-Log "SearchScope=$scope"
Write-Log "Policy: DisabledForDays=$DisabledForDays ; Cutoff(UTC)=$cutoff"
Write-Log "DisableDateSource=$DisableDateSource ; StampAttribute=$DisableStampAttributeName"
Write-Log "IgnoreExact=$($IgnoreAccountsExact -join ',')" 'INFO'
Write-Log "IgnoreRegex=$($IgnoreAccountsRegex | Where-Object { $_ } -join ',')" 'INFO'

$report = New-Object System.Collections.Generic.List[object]
$script:DeleteCount = 0

function Add-DeleteCount { param([int]$Delta = 1) $script:DeleteCount += $Delta }
function Test-CanDelete {
  if ($WhatIf) { return $true }
  if ($MaxDeletes -le 0) { return $true }
  return ($script:DeleteCount -lt $MaxDeletes)
}

# Determine search targets:
# - If UserLimitToOUs is non-empty -> use those OUs (validated lightly by trying queries)
# - Else -> forest-wide: iterate domains, SearchBase = domain DN
$targets = New-Object System.Collections.Generic.List[object]

if ($UserLimitToOUs -and ($UserLimitToOUs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
  foreach ($ou in $UserLimitToOUs) {
    if ([string]::IsNullOrWhiteSpace($ou)) { continue }

    # Determine domain fqdn from DN DC components
    $dcs = ([regex]::Matches($ou, 'DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value })
    $domainFqdn = ($dcs -join '.')
    if ([string]::IsNullOrWhiteSpace($domainFqdn)) {
      Write-Log "Search base OU does not contain DC components (skipping): $ou" 'WARN'
      continue
    }

    # Choose a DC: PDC emulator (stable) when possible
    $server = $null
    try {
      $server = (Get-ADDomain -Server $domainFqdn -ErrorAction Stop).PDCEmulator
    } catch {
      $server = $domainFqdn
      Write-Log "WARN: Could not resolve PDCEmulator for domain '$domainFqdn' (using domain DNS instead). Error: $($_.Exception.Message)" 'WARN'
    }

    $targets.Add([pscustomobject]@{
      Domain   = $domainFqdn
      Server   = $server
      SearchBase = $ou
      Scope    = $scope
      Mode     = 'OU'
    }) | Out-Null
  }
} else {
  try {
    $forest = Get-ADForest -ErrorAction Stop
  } catch {
    throw "Failed to get forest info: $($_.Exception.Message)"
  }

  foreach ($domainFqdn in $forest.Domains) {
    $server = $null
    $domainDn = $null
    try {
      $d = Get-ADDomain -Server $domainFqdn -ErrorAction Stop
      $server = $d.PDCEmulator
      $domainDn = $d.DistinguishedName
    } catch {
      Write-Log "WARN: Failed to resolve domain DN/PDC for '$domainFqdn' (using domain DNS as server and skipping DN lookup). Error: $($_.Exception.Message)" 'WARN'
      $server = $domainFqdn
      try {
        $domainDn = (Get-ADDomain -Server $server -ErrorAction Stop).DistinguishedName
      } catch {
        Write-Log "ERROR: Cannot determine domain DN for '$domainFqdn' (skipping domain). Error: $($_.Exception.Message)" 'ERROR'
        continue
      }
    }

    $targets.Add([pscustomobject]@{
      Domain   = $domainFqdn
      Server   = $server
      SearchBase = $domainDn
      Scope    = 'Subtree'
      Mode     = 'Domain'
    }) | Out-Null
  }
}

Write-Log "Targets count=$($targets.Count). Target list: $(( $targets | ForEach-Object { "$($_.Mode):$($_.SearchBase)@$($_.Server)" } ) -join ' ; ' )" 'INFO'

function Process-Target {
  param([Parameter(Mandatory=$true)]$Target)

  Write-Log "--- USERS: Processing Target: Mode=$($Target.Mode) Domain=$($Target.Domain) Server=$($Target.Server) Base=$($Target.SearchBase) Scope=$($Target.Scope) ---"

  $props = @('SamAccountName','DistinguishedName','Enabled','whenChanged','isCriticalSystemObject')
  if ($DisableDateSource -eq 'StampAttribute' -and -not [string]::IsNullOrWhiteSpace($DisableStampAttributeName)) {
    $props += $DisableStampAttributeName
  }

  # Disabled accounts: userAccountControl bitwise match on ACCOUNTDISABLE (2)
  # Also avoid critical system objects defensively.
  $ldap = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(!(isCriticalSystemObject=TRUE)))"

  $users = @()
  try {
    $users = Get-ADUser -Server $Target.Server -SearchBase $Target.SearchBase -SearchScope $Target.Scope `
      -LDAPFilter $ldap -Properties $props -ErrorAction Stop
  } catch {
    Write-Log "USERS ERROR querying base '$($Target.SearchBase)' on '$($Target.Server)': $($_.Exception.Message)" 'ERROR'
    return
  }

  foreach ($u in $users) {
    $sam = $u.SamAccountName
    $dn  = $u.DistinguishedName
    $ouPath = Get-ParentOUFromDN -DistinguishedName $dn

    if (Test-IsIgnoredSam -SamAccountName $sam -ExactList $IgnoreAccountsExact -RegexList $IgnoreAccountsRegex) {
      Write-Log "USERS SKIP (ignored): $sam" 'SKIP'
      $report.Add([pscustomobject]@{
        Domain=$Target.Domain; Server=$Target.Server; SearchBase=$Target.SearchBase
        SamAccountName=$sam; DistinguishedName=$dn; OU=$ouPath
        Enabled=$u.Enabled; WhenChanged=$u.whenChanged
        DisableDate=$null; DaysDisabled=$null
        Eligible=$false; Approved=$null
        Action='None'; Result='Skipped'
        Reason='Ignored by exact/regex'
      }) | Out-Null
      continue
    }

    # Determine disable date by configured source; optionally fallback to WhenChanged if ReplicationMetadata fails.
    $disableDate = Get-DisableDate -DistinguishedName $dn -AdUser $u -Source $DisableDateSource -Server $Target.Server -StampAttributeName $DisableStampAttributeName

    $usedSource = $DisableDateSource
    if (-not $disableDate -and $DisableDateSource -eq 'ReplicationMetadata') {
      # safe fallback: WhenChanged (note: not perfect)
      $disableDate = Get-DisableDate -DistinguishedName $dn -AdUser $u -Source 'WhenChanged' -Server $Target.Server -StampAttributeName $DisableStampAttributeName
      $usedSource = if ($disableDate) { 'WhenChanged(Fallback)' } else { 'Unknown' }
    }

    $eligible = $false
    $reason = $null
    $daysDisabled = $null

    if (-not $disableDate) {
      $reason = "Cannot determine disable date (Source=$usedSource). Not eligible."
    } else {
      $daysDisabled = [int][Math]::Floor(((Get-Date).ToUniversalTime() - $disableDate).TotalDays)
      if ($disableDate -lt $cutoff) {
        $eligible = $true
        $reason = "DisabledDate(UTC)=$disableDate (Source=$usedSource) older than cutoff(UTC)=$cutoff (DaysDisabled=$daysDisabled)"
      } else {
        $reason = "DisabledDate(UTC)=$disableDate (Source=$usedSource) newer than cutoff(UTC)=$cutoff (DaysDisabled=$daysDisabled)"
      }
    }

    $approved = $null
    if ($RequireApprovalList) {
      $approved = Test-IsApproved -SamAccountName $sam -DistinguishedName $dn -ApprovalEntries $approvalEntries
    }

    $row = [pscustomobject]@{
      Domain=$Target.Domain; Server=$Target.Server; SearchBase=$Target.SearchBase
      SamAccountName=$sam; DistinguishedName=$dn; OU=$ouPath
      Enabled=$u.Enabled; WhenChanged=$u.whenChanged
      DisableDate=$disableDate; DaysDisabled=$daysDisabled
      Eligible=$eligible; Approved=$approved
      Action='Remove-ADUser'; Result='None'
      Reason=$reason
    }

    if (-not $eligible) {
      $row.Result='NoChange'
      $report.Add($row) | Out-Null
      continue
    }

    if ($WhatIf) {
      Write-Log "USERS WHATIF candidate: $sam ; WouldDelete ; $reason" 'WHATIF'
      $row.Result='WhatIf'
      $report.Add($row) | Out-Null
      continue
    }

    if ($RequireApprovalList -and -not $approved) {
      Write-Log "USERS SKIP (not approved): $sam ; would delete" 'SKIP'
      $row.Result='NotApproved'
      $report.Add($row) | Out-Null
      continue
    }

    if (-not (Test-CanDelete)) {
      Write-Log "USERS SKIP (MaxDeletes reached=$MaxDeletes): $sam ; would delete" 'SKIP'
      $row.Result='MaxDeletesReached'
      $report.Add($row) | Out-Null
      continue
    }

    try {
      Remove-ADUser -Identity $dn -Server $Target.Server -Confirm:$false -ErrorAction Stop
      Write-Log "USERS ACTION: Deleted: $sam (DN=$dn)" 'ACTION'
      Add-DeleteCount -Delta 1
      $row.Result='Deleted'
    } catch {
      Write-Log "USERS ERROR: Delete failed for $sam (DN=$dn): $($_.Exception.Message)" 'ERROR'
      $row.Result='Error'
    }

    $report.Add($row) | Out-Null
  }
}

foreach ($t in $targets) { Process-Target -Target $t }

# REPORTING =======

try {
  $report | Export-Csv -Path $CsvReportPath -NoTypeInformation -Encoding UTF8
  Write-Log "CSV report written: $CsvReportPath" 'INFO'
} catch {
  Write-Log "ERROR writing CSV report: $($_.Exception.Message)" 'ERROR'
}

Write-Log "=== END (DeleteCount=$script:DeleteCount) ==="

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
Write-Output "Mode: $($PSCmdlet.ParameterSetName) ; RequireApprovalList=$RequireApprovalList ; DeleteCount=$script:DeleteCount"
Write-Output "Log: $script:LogPath"
Write-Output "CSV: $CsvReportPath"
if ($DryRun) { Write-Output "Approval draft: $ApprovalDraftPath" }
if ($RequireApprovalList) { Write-Output "Approval list (input): $ApprovalListPath" }
