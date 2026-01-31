<#
.SYNOPSIS
Notify on AD account lockouts (Event ID 4740).

.DESCRIPTION
Scans DC Security log for account lockout events within a time window.
Sends email to administrator(s) and the locked user's mail attribute if present.

.USAGE
  # Scan last 15 minutes (default) and send emails
  .\Invoke-ADLockoutNotify.ps1 -Run

  # Dry run only (no email), still writes CSV + log
  .\Invoke-ADLockoutNotify.ps1 -DryRun

  # Scan last 60 minutes
  .\Invoke-ADLockoutNotify.ps1 -Run -LookbackMinutes 60

.NOTES
- Event ID 4740 is logged on the Domain Controller that processed the lockout.
- CallerComputerName is often the source workstation; may be blank.
#>

[CmdletBinding(DefaultParameterSetName='DryRun')]
param(
  [Parameter(ParameterSetName='DryRun', Mandatory=$true)]
  [switch]$DryRun,

  [Parameter(ParameterSetName='Run', Mandatory=$true)]
  [switch]$Run,

  # Look back window in minutes
  [int]$LookbackMinutes = 15,

  # SMTP settings
  [string]$SmtpServer = "smtp-relay.contoso.local",
  [int]$SmtpPort = 25,
  [string]$MailFrom = "ad-lockout@contoso.local",
  [string[]]$AdminMailTo = @("it-operations@contoso.local"),
  [bool]$MailUseSsl = $false,

  # Output paths
  [string]$OutputRoot = "C:\Temp\AD-Lockout",
  [string]$LogFilePrefix = "ADLockout"
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
$startTime = (Get-Date).AddMinutes(-$LookbackMinutes)

Write-Log "=== START (RunId=$RunId) ==="
Write-Log "Mode=$($PSCmdlet.ParameterSetName) ; WhatIf=$whatIf ; LookbackMinutes=$LookbackMinutes ; StartTime=$startTime"
Write-Log "OutputRoot=$OutputRoot ; CSV=$CsvPath ; Log=$script:LogPath"
Write-Log "SMTP=$SmtpServer:$SmtpPort From=$MailFrom AdminTo=$($AdminMailTo -join ',') SSL=$MailUseSsl"

# ==== query DC Security log ====
try {
  $events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4740
    StartTime = $startTime
  } -ErrorAction Stop
} catch {
  Write-Log "ERROR reading Security log: $($_.Exception.Message)" 'ERROR'
  throw
}

if (-not $events) {
  Write-Log "No lockout events found in the last $LookbackMinutes minutes." 'INFO'
  Write-Log "=== END ==="
  return
}

$report = New-Object System.Collections.Generic.List[object]

foreach ($evt in $events) {
  $xml = [xml]$evt.ToXml()
  $data = @{}
  foreach ($d in $xml.Event.EventData.Data) {
    $data[$d.Name] = $d.'#text'
  }

  $lockedUser = $data.TargetUserName
  $caller = $data.CallerComputerName
  $domain = $data.TargetDomainName
  $time = $evt.TimeCreated

  # Lookup user's email if possible
  $userMail = $null
  try {
    $adUser = Get-ADUser -Identity $lockedUser -Properties mail -ErrorAction Stop
    $userMail = $adUser.mail
  } catch {
    Write-Log "WARN: Could not resolve AD user '$lockedUser' for mail lookup." 'WARN'
  }

  $report.Add([pscustomobject]@{
    TimeCreated = $time
    TargetUser = $lockedUser
    TargetDomain = $domain
    CallerComputer = $caller
    UserMail = $userMail
    EventRecordId = $evt.RecordId
  }) | Out-Null

  $subject = "AD Lockout: $lockedUser @ $domain"
  $body = @"
Account locked: $lockedUser
Domain: $domain
Time: $time
CallerComputer: $caller
EventRecordId: $($evt.RecordId)

DC: $($env:COMPUTERNAME)
"@

  if ($whatIf) {
    Write-Log "WHATIF: Would email Admins + User($userMail) for $lockedUser / Caller=$caller" 'WHATIF'
  } else {
    # Always notify admins
    Send-Email -To $AdminMailTo -Subject $subject -Body $body

    # Notify user if email exists
    if ($userMail) {
      Send-Email -To @($userMail) -Subject $subject -Body $body
    } else {
      Write-Log "No user mail found for $lockedUser; skipping user notification." 'WARN'
    }
  }
}

# Write CSV
try {
  $report | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
  Write-Log "CSV report written: $CsvPath" 'INFO'
} catch {
  Write-Log "ERROR writing CSV report: $($_.Exception.Message)" 'ERROR'
}

Write-Log "=== END ==="
Write-Output "Done."
Write-Output "Mode: $($PSCmdlet.ParameterSetName)"
Write-Output "Log: $script:LogPath"
Write-Output "CSV: $CsvPath"