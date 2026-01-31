<#
.SYNOPSIS
Notify users and admins of upcoming AD password expirations.

.DESCRIPTION
Finds enabled users whose passwords will expire within a specified window
and sends email notifications to:
- the user (if mail attribute exists)
- administrators (summary CSV)

USAGE
  # Dry run (no email) with CSV/log
  .\Invoke-ADPasswordExpiryNotify.ps1 -DryRun

  # Send emails for users expiring within 14 days
  .\Invoke-ADPasswordExpiryNotify.ps1 -Run -NotifyWindowDays 14

  # Use custom day offsets (e.g., notify at 14,7,3,1)
  .\Invoke-ADPasswordExpiryNotify.ps1 -Run -NotifyDays 14,7,3,1

.NOTES
- Requires AD module and permissions to read users.
- Uses msDS-UserPasswordExpiryTimeComputed.
#>

[CmdletBinding(DefaultParameterSetName='DryRun')]
param(
  [Parameter(ParameterSetName='DryRun', Mandatory=$true)]
  [switch]$DryRun,

  [Parameter(ParameterSetName='Run', Mandatory=$true)]
  [switch]$Run,

  # Notify if password expires within this many days
  [int]$NotifyWindowDays = 14,

  # Optional: only notify on specific day offsets (e.g., 14,7,3,1)
  [int[]]$NotifyDays = @(),

  # SMTP settings
  [string]$SmtpServer = "smtp-relay.contoso.local",
  [int]$SmtpPort = 25,
  [string]$MailFrom = "ad-password@contoso.local",
  [string[]]$AdminMailTo = @("it-operations@contoso.local"),
  [bool]$MailUseSsl = $false,

  # Output paths
  [string]$OutputRoot = "C:\Temp\AD-PasswordExpiry",
  [string]$LogFilePrefix = "ADPasswordExpiry",

  # Search scope (optional)
  [string[]]$UserLimitToOUs = @(
    "OU=Users,DC=contoso,DC=local",
    "OU=Contractors,DC=contoso,DC=local"
  ),

  # Ignore accounts
  [string[]]$IgnoreAccountsExact = @(
    "Administrator",
    "Guest",
    "krbtgt"
  )
)

# ==== helpers ====
function Write-Log {
  param(
    [Parameter(Mandatory=$true)][string]$Message,
    [ValidateSet('INFO','WARN','ERROR','ACTION','WHATIF')][string]$Level = 'INFO'
  )
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $line = "[$ts][$Level] $Message"
  Write-Output $line
  Add-Content -Path $script:LogPath -Value $line
}

function Send-Email {
  param(
    [Parameter(Mandatory=$true)][string[]]$To,
    [Parameter(Mandatory=$true)][string]$Subject,
    [Parameter(Mandatory=$true)][string]$Body
  )

  try {
    Send-MailMessage `
      -SmtpServer $SmtpServer `
      -Port $SmtpPort `
      -From $MailFrom `
      -To $To `
      -Subject $Subject `
      -Body $Body `
      -BodyAsHtml:$false `
      -UseSsl:$MailUseSsl `
      -ErrorAction Stop

    Write-Log "Email sent to '$($To -join ',')' Subject='$Subject'" 'ACTION'
  } catch {
    Write-Log "ERROR sending email: $($_.Exception.Message)" 'ERROR'
  }
}

function Get-ValidSearchBases {
  param([string[]]$Bases)
  $valid = New-Object System.Collections.Generic.List[string]
  foreach ($b in $Bases) {
    if ([string]::IsNullOrWhiteSpace($b)) { continue }
    try {
      $null = Get-ADOrganizationalUnit -Identity $b -ErrorAction Stop
      $valid.Add($b) | Out-Null
    } catch {
      Write-Log "Search base OU not found/invalid (skipping): $b" 'WARN'
    }
  }
  return $valid.ToArray()
}

# ==== setup ====
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
  throw "ActiveDirectory module not found. Install RSAT / AD PowerShell module."
}
Import-Module ActiveDirectory

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$RunId = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:LogPath = Join-Path $OutputRoot "$LogFilePrefix-$RunId.log"
$CsvPath = Join-Path $OutputRoot "$LogFilePrefix-Report-$RunId.csv"
New-Item -ItemType File -Force -Path $script:LogPath | Out-Null

$whatIf = $PSCmdlet.ParameterSetName -eq 'DryRun'
$today = (Get-Date).Date
$windowEnd = $today.AddDays($NotifyWindowDays)

$userBases = Get-ValidSearchBases -Bases $UserLimitToOUs

Write-Log "=== START (RunId=$RunId) ==="
Write-Log "Mode=$($PSCmdlet.ParameterSetName) ; WhatIf=$whatIf ; NotifyWindowDays=$NotifyWindowDays ; NotifyDays=$($NotifyDays -join ',')"
Write-Log "OutputRoot=$OutputRoot ; CSV=$CsvPath ; Log=$script:LogPath"
Write-Log "SMTP=$SmtpServer:$SmtpPort From=$MailFrom AdminTo=$($AdminMailTo -join ',') SSL=$MailUseSsl"

$report = New-Object System.Collections.Generic.List[object]

foreach ($base in $userBases) {
  Write-Log "Processing OU: $base"
  $users = Get-ADUser -SearchBase $base -LDAPFilter "(&(objectCategory=person)(objectClass=user))" `
    -Properties mail,Enabled,msDS-UserPasswordExpiryTimeComputed,PasswordNeverExpires,SamAccountName

  foreach ($u in $users) {
    if (-not $u.Enabled) { continue }
    if ($u.PasswordNeverExpires) { continue }
    if ($IgnoreAccountsExact -contains $u.SamAccountName) { continue }

    $expiryFileTime = $u.'msDS-UserPasswordExpiryTimeComputed'
    if (-not $expiryFileTime) { continue }

    $expiry = [DateTime]::FromFileTime($expiryFileTime)
    if ($expiry -gt $windowEnd) { continue }

    $daysLeft = [int]([math]::Ceiling(($expiry - $today).TotalDays))
    if ($daysLeft -lt 0) { continue }

    if ($NotifyDays.Count -gt 0 -and ($NotifyDays -notcontains $daysLeft)) {
      continue
    }

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
Expiry date: $expiry

Please change your password before it expires to avoid login issues.

If you need help, contact IT support.

Thank you,
IT Operations
"@

    if ($whatIf) {
      Write-Log "WHATIF: Would email user '$($u.mail)' ($($u.SamAccountName)) DaysLeft=$daysLeft" 'WHATIF'
    } else {
      if ($u.mail) {
        Send-Email -To @($u.mail) -Subject $subject -Body $body
      } else {
        Write-Log "No mail for $($u.SamAccountName); skipping user notification." 'WARN'
      }
    }
  }
}

# Write CSV + admin summary
try {
  $report | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
  Write-Log "CSV report written: $CsvPath" 'INFO'
} catch {
  Write-Log "ERROR writing CSV report: $($_.Exception.Message)" 'ERROR'
}

if (-not $whatIf -and $AdminMailTo.Count -gt 0 -and (Test-Path $CsvPath)) {
  $subject = "AD Password Expiry Summary ($($today.ToString('yyyy-MM-dd')))"
  $body = "Attached is the password expiry notification summary CSV."
  try {
    Send-MailMessage `
      -SmtpServer $SmtpServer `
      -Port $SmtpPort `
      -From $MailFrom `
      -To $AdminMailTo `
      -Subject $subject `
      -Body $body `
      -Attachments $CsvPath `
      -BodyAsHtml:$false `
      -UseSsl:$MailUseSsl `
      -ErrorAction Stop
    Write-Log "Admin summary email sent." 'ACTION'
  } catch {
    Write-Log "ERROR sending admin summary email: $($_.Exception.Message)" 'ERROR'
  }
}

Write-Log "=== END ==="
Write-Output "Done."
Write-Output "Mode: $($PSCmdlet.ParameterSetName)"
Write-Output "Log: $script:LogPath"
Write-Output "CSV: $CsvPath"