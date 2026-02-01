<#
.SYNOPSIS
  Contoso Create AD User (GUI) - Windows PowerShell 5.1

  Included:
    - WinForms GUI (scrolling)
    - Robust logging (separate operational log + transcript)
    - Identity auto-population from Full Name
    - Password generation + validation
    - Optional account expiration
    - Manager lookup by DisplayName
    - Optional default group assignment (based on employment type) + extra groups
    - Optional runner authorization via AD group
#>

Write-Host "GUI is starting. This will only take a moment..." -ForegroundColor Yellow

#Requires -Modules ActiveDirectory
#Requires -PSEdition Desktop

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Block ISE and PS7
$psISEVar = Get-Variable -Name psISE -Scope Global -ErrorAction SilentlyContinue
if ($psISEVar -and $psISEVar.Value) { throw "Run this in Windows PowerShell (powershell.exe), not ISE." }
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw "This script requires Windows PowerShell Desktop (5.1). PowerShell 7 is not supported." }

Import-Module ActiveDirectory -ErrorAction Stop
Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
Add-Type -AssemblyName System.Drawing -ErrorAction Stop

# -------------------------
# Config (AD-only)
# -------------------------
$OU_Employees = "OU=Employees,OU=Users,OU=Accounts,DC=Contoso,DC=com"
$OU_External  = "OU=External,OU=Users,OU=Accounts,DC=Contoso,DC=com"

# UPN suffix used for UserPrincipalName + EmailAddress attribute
$PrimaryEmailDomain = "Contoso.se"

# Optional: require operator to be member of this AD group to run the script
# Set to $null to disable authorization gating.
$RequiredRunnerGroup = "SEC-Contoso-UserCreate"

$LogDirectory = "C:\Scripts\CreateUserLogs"

$DefaultStreet = "Contosoroad 1"
$DefaultZip    = "123 45"
$DefaultCity   = "Contosocity"

# Account expiration defaults (not enabled by default)
$DefaultExpireRelativeValue = 6
$DefaultExpireRelativeUnit  = "Months" # Days / Weeks / Months
$DefaultExpireDateText      = (Get-Date).AddMonths(6).ToString("yyyy-MM-dd")

$InternalGroups = @(
  "Intune", "Employee-VPN", "License-O365-E5"
)
$InhouseGroups = @(
  "License-O365-E5", "Employee-VPN", "License-O365-DefenderP1"
)
$ExternalGroups = @(
  "License-O365-E3", "License-O365-DefenderP1", "SEC-COMPANY-External", "External-VPN"
)

# -------------------------
# Logging (separate operational log + transcript)
# -------------------------
function Ensure-LogDirectory {
  if (-not (Test-Path -LiteralPath $script:LogDirectory)) {
    try {
      New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
    } catch {
      $fallback = Join-Path $env:TEMP "CreateUserLogs"
      if (-not (Test-Path -LiteralPath $fallback)) {
        New-Item -ItemType Directory -Path $fallback -Force | Out-Null
      }
      $script:LogDirectory = $fallback
    }
  }
}

$RunId = ([guid]::NewGuid().ToString('N')).Substring(0,12)
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
Ensure-LogDirectory

$LogFile        = Join-Path $LogDirectory ("Create-User_{0}_{1}.log" -f $timestamp, $RunId)
$TranscriptFile = Join-Path $LogDirectory ("Create-User_{0}_{1}.transcript.txt" -f $timestamp, $RunId)

$script:InvokerUser = "{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME
$script:HostMachine = $env:COMPUTERNAME
$script:ProcessId   = $PID
$script:ScriptPath  = $PSCommandPath

function Write-Log {
  param(
    [Parameter(Mandatory)][string]$Message,
    [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
  )
  $line = "{0} [{1}] [{2}] [{3}] [{4}] [pid:{5}] {6}" -f `
    (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $RunId, $script:InvokerUser, $script:HostMachine, $script:ProcessId, $Message

  # Retry on transient locks
  for ($i=0; $i -lt 6; $i++) {
    try {
      Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop
      return
    } catch {
      Start-Sleep -Milliseconds (100 + (100 * $i))
    }
  }

  # Last resort fallback
  try {
    $fallback = Join-Path $env:TEMP ("CreateUser_{0}.log" -f $RunId)
    Add-Content -Path $fallback -Value $line -Encoding UTF8
  } catch { }
}

function Msg-Error([string]$Message) {
  [System.Windows.Forms.MessageBox]::Show(
    $Message, "Error",
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Error
  ) | Out-Null
}
function Msg-Info([string]$Message) {
  [System.Windows.Forms.MessageBox]::Show(
    $Message, "Info",
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Information
  ) | Out-Null
}
function Msg-Confirm([string]$Message) {
  $r = [System.Windows.Forms.MessageBox]::Show(
    $Message, "Confirm",
    [System.Windows.Forms.MessageBoxButtons]::YesNo,
    [System.Windows.Forms.MessageBoxIcon]::Question
  )
  return ($r -eq [System.Windows.Forms.DialogResult]::Yes)
}

# Start transcript so everything printed is captured, but to a separate file
try {
  Start-Transcript -Path $TranscriptFile -Append -IncludeInvocationHeader | Out-Null
} catch { }

Write-Log "Script started. ScriptPath='$script:ScriptPath'. PSVersion=$($PSVersionTable.PSVersion). LogFile='$LogFile'. TranscriptFile='$TranscriptFile'."

# -------------------------
# Helpers (AD/Names/Password)
# -------------------------
function Get-ADServerToUse {
  try { return (Get-ADDomainController -Discover -ErrorAction Stop).HostName } catch { return $null }
}

function Ensure-RunnerAuthorized {
  param([string]$GroupSam)

  if ([string]::IsNullOrWhiteSpace($GroupSam)) {
    Write-Log "Authorization gating is disabled (RequiredRunnerGroup not set)."
    return
  }

  $me = $env:USERNAME
  Write-Log "Authorization check: user '$script:InvokerUser' must be a member of '$GroupSam'."
  $m = Get-ADGroupMember -Identity $GroupSam -Recursive -ErrorAction Stop |
    Where-Object { $_.SamAccountName -eq $me }

  if (-not $m) { throw "You must be a member of '$GroupSam' to run this script." }
  Write-Log "Authorization OK for '$script:InvokerUser' in '$GroupSam'."
}

function Test-OUExists {
  param([Parameter(Mandatory)][string]$DistinguishedName)
  try { Get-ADOrganizationalUnit -Identity $DistinguishedName -ErrorAction Stop | Out-Null; return $true } catch { return $false }
}

function Normalize-NameAscii {
  param([Parameter(Mandatory)][string]$InputString)
  $s = $InputString
  $s = $s.Replace('ä','a').Replace('Ä','A')
  $s = $s.Replace('å','a').Replace('Å','A')
  $s = $s.Replace('ö','o').Replace('Ö','O')
  $s = $s.Replace('á','a').Replace('Á','A')
  $s = $s.Replace('é','e').Replace('É','E')
  return $s
}

function Get-FirstNCharsLower {
  param([Parameter(Mandatory)][string]$Text, [int]$N)
  $t = $Text.Trim()
  if ($t.Length -le $N) { return $t.ToLower() }
  return $t.Substring(0,$N).ToLower()
}

function Build-DefaultSamFromName {
  param([Parameter(Mandatory)][string]$First, [Parameter(Mandatory)][string]$Last)
  $f = Normalize-NameAscii $First
  $l = Normalize-NameAscii $Last
  $f3 = Get-FirstNCharsLower -Text $f -N 3
  $l3 = Get-FirstNCharsLower -Text $l -N 3
  return ($f3 + $l3)
}

function Build-DefaultAliasFromName {
  param([Parameter(Mandatory)][string]$First, [Parameter(Mandatory)][string]$Last)
  $f = (Normalize-NameAscii $First).ToLower()
  $l = (Normalize-NameAscii $Last).ToLower()
  return "$f.$l"
}

function New-RandomPassword {
  function Get-RandomCharacters([int]$length, [string]$characters) {
    $idx = 1..$length | ForEach-Object { Get-Random -Maximum $characters.Length }
    $private:ofs=""
    [string]$characters[$idx]
  }
  function Scramble([string]$inputString) {
    $arr = $inputString.ToCharArray()
    -join ($arr | Get-Random -Count $arr.Length)
  }

  $lower   = 'abcdefghjkmnpqrstuvwxyz'
  $upper   = 'ABCDEFGHJKMNPQRSTUVWXYZ'
  $digits  = '23456789'
  $symbols = '#-!?@%()'

  $pw  = Get-RandomCharacters 5 $lower
  $pw += Get-RandomCharacters 5 $upper
  $pw += Get-RandomCharacters 3 $digits
  $pw += Get-RandomCharacters 3 $symbols

  return (Scramble $pw)
}

function Validate-PasswordComplexity {
  param([string]$Password)

  if ([string]::IsNullOrEmpty($Password)) { return "Password is required." }
  if ($Password.Length -ne 16) { return "Password must be exactly 16 characters." }
  if ($Password -match '[iloILO01]') { return "Password may not contain ambiguous characters: i, l, o, I, L, O, 0, 1." }
  if ($Password -notmatch '[A-Z]') { return "Password must include an uppercase letter (A-Z, excluding I/L/O)." }
  if ($Password -notmatch '[a-z]') { return "Password must include a lowercase letter (a-z, excluding i/l/o)." }
  if ($Password -notmatch '\d')    { return "Password must include a digit (2-9)." }

  # Put '-' last to avoid range interpretation
  $allowedSpecialsClass = '#!?@%()\-'  # class content
  if ($Password -notmatch "[$allowedSpecialsClass]") {
    return "Password must include a symbol from: #-!?@%()"
  }
  if ($Password -match "[^A-Za-z0-9$allowedSpecialsClass]") {
    return "Password contains unsupported characters. Allowed symbols are: #-!?@%()"
  }
  return $null
}

function Find-ManagerDNByDisplayName {
  param([Parameter(Mandatory)][string]$DisplayName)
  $u = Get-ADUser -Filter "DisplayName -eq '$DisplayName'" -Properties DistinguishedName -ErrorAction Stop
  return $u.DistinguishedName
}

function Test-SamUnique {
  param([Parameter(Mandatory)][string]$Sam)
  return -not (Get-ADUser -LDAPFilter "(sAMAccountName=$Sam)" -ErrorAction SilentlyContinue)
}
function Test-UpnUniqueInAd {
  param([Parameter(Mandatory)][string]$Upn)
  return -not (Get-ADUser -LDAPFilter "(userPrincipalName=$Upn)" -ErrorAction SilentlyContinue)
}

function Get-ModeFromText {
  param([Parameter(Mandatory)][string]$Text)
  switch ($Text) {
    "No (Employee)"         { return @{ EmployeeType="Employed";   OU=$OU_Employees; GroupSet="Internal" } }
    "Yes (InhouseConsultant)"  { return @{ EmployeeType="Consultant"; OU=$OU_External;  GroupSet="Inhouse" } }
    "Yes (ExternalConsultant)" { return @{ EmployeeType="Consultant"; OU=$OU_External;  GroupSet="External" } }
    default { return $null }
  }
}

function Get-GroupListForSet {
  param([Parameter(Mandatory)][string]$GroupSet)
  switch ($GroupSet) {
    "Internal" { return $InternalGroups }
    "Inhouse"  { return $InhouseGroups }
    "External" { return $ExternalGroups }
    default    { return @() }
  }
}

function Parse-ExtraGroups {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
  return @($Text.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
}

function Get-GroupsPreview {
  param(
    [string]$TypeText,
    [bool]$UseDefaults,
    [string]$ExtraGroupsText
  )
  $base = @()
  if ($UseDefaults -and -not [string]::IsNullOrWhiteSpace($TypeText)) {
    $m = Get-ModeFromText -Text $TypeText
    if ($m) { $base = Get-GroupListForSet -GroupSet $m.GroupSet }
  }
  $extra = Parse-ExtraGroups -Text $ExtraGroupsText
  return @(@($base + $extra) | Where-Object { $_ } | Sort-Object -Unique)
}

function Compute-ExpirationDate {
  param(
    [Parameter(Mandatory)][string]$Mode,      # 'Date' or 'Relative'
    [string]$DateText,                        # yyyy-MM-dd
    [int]$Value,
    [string]$Unit                             # Days/Weeks/Months
  )

  if ($Mode -eq 'Date') {
    if ([string]::IsNullOrWhiteSpace($DateText)) { throw "Expiration date is missing." }
    $dt = $null
    if (-not [DateTime]::TryParseExact($DateText.Trim(), 'yyyy-MM-dd', $null, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {
      throw "Expiration date must be in the format YYYY-MM-DD."
    }
    return $dt.Date.AddHours(23).AddMinutes(59).AddSeconds(59)
  }

  if ($Mode -eq 'Relative') {
    if ($Value -lt 1 -or $Value -gt 3650) { throw "Expiration value must be between 1 and 3650." }
    switch ($Unit) {
      'Days'   { return (Get-Date).AddDays($Value).Date.AddHours(23).AddMinutes(59).AddSeconds(59) }
      'Weeks'  { return (Get-Date).AddDays(7 * $Value).Date.AddHours(23).AddMinutes(59).AddSeconds(59) }
      'Months' { return (Get-Date).AddMonths($Value).Date.AddHours(23).AddMinutes(59).AddSeconds(59) }
      default  { throw "Invalid unit for expiration: $Unit" }
    }
  }
  throw "Invalid expiration mode: $Mode"
}

function Test-EmailLocalPart {
  param([Parameter(Mandatory)][string]$Local)
  if ($Local -notmatch '^[a-z0-9][a-z0-9\.-]*[a-z0-9]$') { return $false }
  if ($Local -match '\.\.') { return $false }
  return $true
}

function Split-FullName {
  param([Parameter(Mandatory)][string]$FullName)

  $s = $FullName.Trim()
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }

  # Normalize separators to spaces
  $s2 = ($s -replace '[\._\-]+',' ').Trim()
  $parts = @($s2.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries))

  if ($parts.Count -ge 2) {
    return @{ Given = $parts[0]; Surname = $parts[$parts.Count - 1] }
  }

  # If only one token, try CamelCase split (e.g., JohnSmith)
  $m = [regex]::Matches($s, '[A-ZÅÄÖÉÁ]?[a-zåäöéá]+|[A-ZÅÄÖÉÁ]+(?![a-zåäöéá])')
  if ($m.Count -ge 2) {
    $given = $m[0].Value
    $sn    = $m[$m.Count - 1].Value
    return @{ Given = $given; Surname = $sn }
  }

  return $null
}

# -------------------------
# GUI with a scrolling panel
# -------------------------
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = "Create AD User Contoso (GUI)"
$form.Size = New-Object System.Drawing.Size(980, 820)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = 'Sizable'
$form.MaximizeBox = $true

$panel = New-Object System.Windows.Forms.Panel
$panel.Dock = 'Fill'
$panel.AutoScroll = $true
$form.Controls.Add($panel) | Out-Null

[int]$leftLabel = 16
[int]$labelWidth = 240
[int]$leftInput = $leftLabel + $labelWidth + 10
[int]$inputWidth = 680
[int]$rowHeight = 28
[int]$y = 14

function Add-Label {
  param([string]$Text, [int]$Top)
  $l = New-Object System.Windows.Forms.Label
  $l.Text = $Text
  $l.Location = New-Object System.Drawing.Point($script:leftLabel, $Top)
  $l.Size = New-Object System.Drawing.Size($script:labelWidth, 20)
  $panel.Controls.Add($l) | Out-Null
}
function Add-TextBox {
  param([int]$Top, [bool]$ReadOnly=$false, [bool]$Multiline=$false, [int]$Height=22)
  $t = New-Object System.Windows.Forms.TextBox
  $t.Location = New-Object System.Drawing.Point($script:leftInput, ($Top - 3))
  $t.Size = New-Object System.Drawing.Size($script:inputWidth, $Height)
  $t.ReadOnly = $ReadOnly
  $t.Multiline = $Multiline
  if ($Multiline) { $t.ScrollBars = 'Vertical' }
  $panel.Controls.Add($t) | Out-Null
  return $t
}
function Add-Combo {
  param([int]$Top, [string[]]$Items)
  $c = New-Object System.Windows.Forms.ComboBox
  $c.Location = New-Object System.Drawing.Point($script:leftInput, ($Top - 3))
  $c.Size = New-Object System.Drawing.Size($script:inputWidth, 22)
  $c.DropDownStyle = 'DropDownList'
  [void]$c.Items.AddRange($Items)
  $panel.Controls.Add($c) | Out-Null
  return $c
}
function Add-Check {
  param([string]$Text, [int]$Top, [bool]$Checked=$false)
  $c = New-Object System.Windows.Forms.CheckBox
  $c.Text = $Text
  $c.Location = New-Object System.Drawing.Point($script:leftInput, ($Top - 4))
  $c.Size = New-Object System.Drawing.Size($script:inputWidth, 22)
  $c.Checked = $Checked
  $panel.Controls.Add($c) | Out-Null
  return $c
}

Add-Label "Full Name * (First Last)" $y;  $txtFullName = Add-TextBox $y; $y += $rowHeight
Add-Label "Description * (AD General tab)" $y; $txtDesc = Add-TextBox $y; $y += $rowHeight
Add-Label "Department *" $y; $txtDept = Add-TextBox $y; $y += $rowHeight
Add-Label "Job Title *" $y; $txtTitle = Add-TextBox $y; $y += $rowHeight
Add-Label "Manager * (exact DisplayName)" $y; $txtManager = Add-TextBox $y; $y += $rowHeight
Add-Label "Phone Number * (use 123 if missing)" $y; $txtPhone = Add-TextBox $y; $y += $rowHeight
Add-Label "Mobile Number *" $y; $txtMobile = Add-TextBox $y; $y += $rowHeight

Add-Label "Street Address *" $y; $txtStreet = Add-TextBox $y; $y += $rowHeight
Add-Label "ZIP Code *" $y; $txtZip = Add-TextBox $y; $y += $rowHeight
Add-Label "City *" $y; $txtCity = Add-TextBox $y; $y += $rowHeight
Add-Label "Company *" $y; $txtCompany = Add-TextBox $y; $y += $rowHeight

Add-Label "Employment Type *" $y; $cmbType = Add-Combo $y @("No (Employee)","Yes (InhouseConsultant)","Yes (ExternalConsultant)"); $y += $rowHeight
Add-Label "Target OU (auto)" $y; $txtOU = Add-TextBox $y $true; $y += $rowHeight

Add-Label "Given Name (auto) *" $y; $txtGiven = Add-TextBox $y; $y += $rowHeight
Add-Label "Surname (auto) *" $y; $txtSurname = Add-TextBox $y; $y += $rowHeight

Add-Label "sAMAccountName (auto) *" $y; $txtSam = Add-TextBox $y $true; $y += $rowHeight
$chkOverrideSam = Add-Check "Override sAMAccountName (manual)" $y $false; $y += $rowHeight

Add-Label "Alias (auto) *" $y; $txtAlias = Add-TextBox $y $true; $y += $rowHeight
$chkOverrideAlias = Add-Check "Override Alias (manual)" $y $false; $y += $rowHeight

Add-Label "UPN/Email (auto) *" $y; $txtUpn = Add-TextBox $y $true; $y += $rowHeight
$chkOverrideUpn = Add-Check "Override UPN/Email (manual)" $y $false; $y += $rowHeight

Add-Label "Initial Password *" $y
$txtPwd = Add-TextBox $y
$txtPwd.UseSystemPasswordChar = $true
$y += $rowHeight

$btnGenPwd = New-Object System.Windows.Forms.Button
$btnGenPwd.Text = "Generate password"
$btnGenPwd.Location = New-Object System.Drawing.Point($leftInput, ($y - 2))
$btnGenPwd.Size = New-Object System.Drawing.Size(160, 26)
$panel.Controls.Add($btnGenPwd) | Out-Null

$btnTogglePwd = New-Object System.Windows.Forms.Button
$btnTogglePwd.Text = "Show/Hide"
$btnTogglePwd.Location = New-Object System.Drawing.Point(($leftInput + 170), ($y - 2))
$btnTogglePwd.Size = New-Object System.Drawing.Size(120, 26)
$panel.Controls.Add($btnTogglePwd) | Out-Null
$y += $rowHeight

# Expiration UI
Add-Label "Account Expiration (optional)" $y
$chkExpire = Add-Check "Enable account expiration" $y $false
$y += $rowHeight

Add-Label "Expiration mode" $y
$cmbExpireMode = Add-Combo $y @("Specific date (YYYY-MM-DD)", "In (value + unit)")
$cmbExpireMode.Enabled = $false
$y += $rowHeight

Add-Label "Expiration date (YYYY-MM-DD)" $y
$txtExpireDate = Add-TextBox $y
$txtExpireDate.Enabled = $false
$y += $rowHeight

Add-Label "Relative value" $y
$txtExpireValue = Add-TextBox $y
$txtExpireValue.Enabled = $false
$y += $rowHeight

Add-Label "Relative unit" $y
$cmbExpireUnit = Add-Combo $y @("Days","Weeks","Months")
$cmbExpireUnit.Enabled = $false
$y += $rowHeight

$cmbExpireMode.SelectedIndex = 0
$txtExpireDate.Text = $DefaultExpireDateText
$txtExpireValue.Text = [string]$DefaultExpireRelativeValue
$cmbExpireUnit.SelectedItem = $DefaultExpireRelativeUnit

function Update-ExpireUI {
  $enabled = [bool]$chkExpire.Checked
  $cmbExpireMode.Enabled = $enabled

  $isDateMode = $enabled -and ($cmbExpireMode.SelectedIndex -eq 0)
  $isRelMode  = $enabled -and ($cmbExpireMode.SelectedIndex -eq 1)

  $txtExpireDate.Enabled = $isDateMode
  $txtExpireValue.Enabled = $isRelMode
  $cmbExpireUnit.Enabled  = $isRelMode

  if (-not $enabled) {
    $txtExpireDate.Enabled = $false
    $txtExpireValue.Enabled = $false
    $cmbExpireUnit.Enabled = $false
  }
}
$chkExpire.Add_CheckedChanged({ Update-ExpireUI })
$cmbExpireMode.Add_SelectedIndexChanged({ Update-ExpireUI })
Update-ExpireUI

# Groups UI (AD-only)
$chkDefaultGroups = Add-Check "Assign default groups based on employment type" $y $true; $y += $rowHeight

Add-Label "Groups to add (preview)" $y
$txtGroupsPreview = Add-TextBox $y -ReadOnly $true -Multiline $true -Height 110
$y += 118

Add-Label "Extra groups (semicolon-separated)" $y
$txtExtraGroups = Add-TextBox $y
$y += $rowHeight

function Refresh-GroupsPreview {
  $typeText = if ($cmbType.SelectedItem) { $cmbType.SelectedItem.ToString() } else { "" }
  $groups = @(Get-GroupsPreview -TypeText $typeText -UseDefaults ([bool]$chkDefaultGroups.Checked) -ExtraGroupsText $txtExtraGroups.Text)
  if ($groups.Count -eq 0) { $txtGroupsPreview.Text = "(none)" }
  else { $txtGroupsPreview.Text = ($groups -join "`r`n") }
}
$chkDefaultGroups.Add_CheckedChanged({ Refresh-GroupsPreview })
$txtExtraGroups.Add_TextChanged({ Refresh-GroupsPreview })
$cmbType.Add_SelectedIndexChanged({ Refresh-GroupsPreview })

# Buttons
$btnCreate = New-Object System.Windows.Forms.Button
$btnCreate.Text = "Create"
$btnCreate.Location = New-Object System.Drawing.Point($leftInput, ($y + 10))
$btnCreate.Size = New-Object System.Drawing.Size(120, 36)
$panel.Controls.Add($btnCreate) | Out-Null

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = "Cancel"
$btnCancel.Location = New-Object System.Drawing.Point(($leftInput + 130), ($y + 10))
$btnCancel.Size = New-Object System.Drawing.Size(120, 36)
$btnCancel.Add_Click({ $form.Close() })
$panel.Controls.Add($btnCancel) | Out-Null

$panel.AutoScrollMinSize = New-Object System.Drawing.Size(0, ($y + 90))

# Defaults
$txtStreet.Text = $DefaultStreet
$txtZip.Text    = $DefaultZip
$txtCity.Text   = $DefaultCity

$btnGenPwd.Add_Click({ $txtPwd.Text = New-RandomPassword; Write-Log "Generated password (value not logged)." })
$btnTogglePwd.Add_Click({ $txtPwd.UseSystemPasswordChar = -not $txtPwd.UseSystemPasswordChar })

# Override toggles and recalculation
$script:InRecalc = $false
$chkOverrideSam.Add_CheckedChanged({ $txtSam.ReadOnly = -not $chkOverrideSam.Checked; Recalc-IdentityFields })
$chkOverrideAlias.Add_CheckedChanged({ $txtAlias.ReadOnly = -not $chkOverrideAlias.Checked; Recalc-IdentityFields })
$chkOverrideUpn.Add_CheckedChanged({ $txtUpn.ReadOnly = -not $chkOverrideUpn.Checked; Recalc-IdentityFields })

function Recalc-IdentityFields {
  if ($script:InRecalc) { return }
  $script:InRecalc = $true
  try {
    $typeText = if ($cmbType.SelectedItem) { $cmbType.SelectedItem.ToString() } else { "" }
    if ($typeText) {
      $mode = Get-ModeFromText -Text $typeText
      $txtOU.Text = if ($mode) { $mode.OU } else { "" }
    } else {
      $txtOU.Text = ""
    }

    $full = $txtFullName.Text
    $split = $null
    if (-not [string]::IsNullOrWhiteSpace($full)) {
      $split = Split-FullName -FullName $full
    }

    if (-not $split) {
      $txtGiven.Text  = ""
      $txtSurname.Text = ""
      if (-not $chkOverrideSam.Checked)   { $txtSam.Text = "" }
      if (-not $chkOverrideAlias.Checked) { $txtAlias.Text = "" }
      if (-not $chkOverrideUpn.Checked)   { $txtUpn.Text = "" }
      return
    }

    # Always update Given/Surname from Full Name
    $txtGiven.Text   = $split.Given
    $txtSurname.Text = $split.Surname

    $givenAscii = Normalize-NameAscii $split.Given
    $snAscii    = Normalize-NameAscii $split.Surname

    if (-not $chkOverrideSam.Checked) {
      $txtSam.Text = Build-DefaultSamFromName -First $givenAscii -Last $snAscii
    }
    if (-not $chkOverrideAlias.Checked) {
      $txtAlias.Text = Build-DefaultAliasFromName -First $givenAscii -Last $snAscii
    }

    $aliasLocal = $txtAlias.Text.Trim().ToLower()
    if ($aliasLocal) {
      if (-not $chkOverrideUpn.Checked) {
        $txtUpn.Text = "$aliasLocal@$PrimaryEmailDomain"
      }
    } else {
      if (-not $chkOverrideUpn.Checked) { $txtUpn.Text = "" }
    }
  } catch {
    Write-Log "Recalc-IdentityFields failed: $($_.Exception.Message)" "WARN"
  } finally {
    $script:InRecalc = $false
  }
}

$txtFullName.Add_TextChanged({ Recalc-IdentityFields; Refresh-GroupsPreview })
$cmbType.Add_SelectedIndexChanged({ Recalc-IdentityFields; Refresh-GroupsPreview })

$txtAlias.Add_TextChanged({
  # If Alias is overridden, keep UPN in sync (unless UPN override is enabled)
  try {
    if ($chkOverrideAlias.Checked -and -not $script:InRecalc) {
      $a = $txtAlias.Text.Trim().ToLower()
      if ($a -and -not $chkOverrideUpn.Checked) {
        $txtUpn.Text = "$a@$PrimaryEmailDomain"
      }
      if (-not $a -and -not $chkOverrideUpn.Checked) {
        $txtUpn.Text = ""
      }
    }
  } catch {
    Write-Log "Alias TextChanged handler failed: $($_.Exception.Message)" "WARN"
  }
})

# -------------------------
# Create action (AD-only)
# -------------------------
function Create-ContosoUserFromForm {
  Write-Log "Create clicked."
  Ensure-RunnerAuthorized -GroupSam $RequiredRunnerGroup

  $typeText = if ($cmbType.SelectedItem) { $cmbType.SelectedItem.ToString() } else { "" }
  $mode = if ($typeText) { Get-ModeFromText -Text $typeText } else { $null }
  if (-not $mode) { throw "Select an employment type." }

  $fullName = $txtFullName.Text.Trim()
  $desc     = $txtDesc.Text.Trim()
  $dept     = $txtDept.Text.Trim()
  $jobTitle = $txtTitle.Text.Trim()
  $mgrName  = $txtManager.Text.Trim()
  $phone    = $txtPhone.Text.Trim()
  $mobile   = $txtMobile.Text.Trim()
  $street   = $txtStreet.Text.Trim()
  $zip      = $txtZip.Text.Trim()
  $city     = $txtCity.Text.Trim()
  $company  = $txtCompany.Text.Trim()

  $given    = $txtGiven.Text.Trim()
  $sn       = $txtSurname.Text.Trim()
  $sam      = $txtSam.Text.Trim()
  $alias    = $txtAlias.Text.Trim().ToLower()
  $upn      = $txtUpn.Text.Trim().ToLower()
  $ouDn     = $txtOU.Text.Trim()
  $pwd      = $txtPwd.Text

  $useDefaultGroups = [bool]$chkDefaultGroups.Checked

  # Account expiration (optional)
  $expireDate = $null
  if ($chkExpire.Checked) {
    if ($cmbExpireMode.SelectedIndex -eq 0) {
      $expireDate = Compute-ExpirationDate -Mode 'Date' -DateText $txtExpireDate.Text
    } else {
      $val = 0
      if (-not [int]::TryParse($txtExpireValue.Text.Trim(), [ref]$val)) { throw "Relative value must be an integer." }
      $unit = if ($cmbExpireUnit.SelectedItem) { $cmbExpireUnit.SelectedItem.ToString() } else { "" }
      $expireDate = Compute-ExpirationDate -Mode 'Relative' -Value $val -Unit $unit
    }
  }

  $required = @(
    @{N="Full Name"; V=$fullName},
    @{N="Description"; V=$desc},
    @{N="Department"; V=$dept},
    @{N="Job Title"; V=$jobTitle},
    @{N="Manager"; V=$mgrName},
    @{N="Phone Number"; V=$phone},
    @{N="Mobile Number"; V=$mobile},
    @{N="Street Address"; V=$street},
    @{N="ZIP Code"; V=$zip},
    @{N="City"; V=$city},
    @{N="Company"; V=$company},
    @{N="Given Name"; V=$given},
    @{N="Surname"; V=$sn},
    @{N="sAMAccountName"; V=$sam},
    @{N="Alias"; V=$alias},
    @{N="UPN/Email"; V=$upn},
    @{N="Password"; V=$pwd},
    @{N="OU"; V=$ouDn}
  )

  $missing = @($required | Where-Object { [string]::IsNullOrWhiteSpace($_.V) } | ForEach-Object { $_.N })
  if ($missing.Count -gt 0) { throw ("Missing required fields: " + ($missing -join ", ")) }

  if (-not (Test-OUExists -DistinguishedName $ouDn)) { throw "OU does not exist or cannot be read: $ouDn" }

  $pwdIssue = Validate-PasswordComplexity -Password $pwd
  if ($pwdIssue) { throw $pwdIssue }

  if ($alias -match '@') { throw "Alias must not contain '@'." }
  if (-not (Test-EmailLocalPart -Local $alias)) { throw "Alias contains invalid characters or dot placement: $alias" }

  $mgrDn = $null
  try { $mgrDn = Find-ManagerDNByDisplayName -DisplayName $mgrName } catch { throw "Manager not found by DisplayName: $mgrName" }

  if (-not (Test-SamUnique -Sam $sam)) { throw "sAMAccountName already exists: $sam" }
  if (-not (Test-UpnUniqueInAd -Upn $upn)) { throw "UPN already exists in AD: $upn" }

  $allGroups = @(Get-GroupsPreview -TypeText $typeText -UseDefaults $useDefaultGroups -ExtraGroupsText $txtExtraGroups.Text)

  $expText = if ($expireDate) { $expireDate.ToString("yyyy-MM-dd") } else { "(disabled)" }

  $summary = @(
    "RunId:        $RunId"
    "Invoker:      $script:InvokerUser"
    "Machine:      $script:HostMachine (pid:$script:ProcessId)"
    "Full Name:    $fullName"
    "Type:         $typeText"
    "OU:           $ouDn"
    "SAM:          $sam"
    "Alias:        $alias"
    "UPN/Email:    $upn"
    "Manager:      $mgrName"
    "Description:  $desc"
    "Department:   $dept"
    "Job Title:    $jobTitle"
    "Company:      $company"
    "Phone/Mobile: $phone / $mobile"
    "Address:      $street, $zip, $city (SE)"
    "EmployeeType: $($mode.EmployeeType)"
    "Expires:      $expText"
    "Groups:       " + ($(if ($allGroups.Count -gt 0) { $allGroups -join "; " } else { "(none)" }))
    "LogFile:      $LogFile"
    "Transcript:   $TranscriptFile"
  ) -join "`r`n"

  if (-not (Msg-Confirm ("Confirm creation:`r`n`r`n{0}" -f $summary))) {
    Write-Log "Cancelled by operator." "WARN"
    return
  }

  $adServer = Get-ADServerToUse
  Write-Log ("Using DomainController: {0}" -f ($(if ($adServer) { $adServer } else { "(default discovery)" })))

  $securePwd = ConvertTo-SecureString -String $pwd -AsPlainText -Force

  $params = @{
    Name              = $fullName
    GivenName         = $given
    Surname           = $sn
    DisplayName       = $fullName
    SamAccountName    = $sam
    UserPrincipalName = $upn
    Path              = $ouDn
    Enabled           = $true
    AccountPassword   = $securePwd
    Description       = $desc
    Department        = $dept
    Company           = $company
    Title             = $jobTitle
    Manager           = $mgrDn
    StreetAddress     = $street
    City              = $city
    State             = $city
    PostalCode        = $zip
    EmailAddress      = $upn
    MobilePhone       = $mobile
    OfficePhone       = $phone
  }
  if ($adServer) { $params['Server'] = $adServer }
  if ($expireDate) { $params['AccountExpirationDate'] = $expireDate }

  Write-Log "Creating AD user: sam='$sam' upn='$upn' ou='$ouDn'."
  New-ADUser @params
  Write-Log "New-ADUser completed."

  $add = @{
    extensionAttribute4 = $jobTitle
    extensionAttribute5 = $dept
    employeeType        = $mode.EmployeeType
  }
  $setParams = @{ Identity = $sam; Add = $add }
  if ($adServer) { $setParams['Server'] = $adServer }
  Write-Log "Setting additional AD attributes: extensionAttribute4/5, employeeType."
  Set-ADUser @setParams

  $repParams = @{ Identity = $sam; Replace = @{ c="SE"; co="Sweden"; countrycode=752 } }
  if ($adServer) { $repParams['Server'] = $adServer }
  Write-Log "Setting country attributes (c/co/countrycode)."
  Set-ADUser @repParams

  foreach ($g in $allGroups) {
    $gp = @{ Identity = $g; Members = $sam }
    if ($adServer) { $gp['Server'] = $adServer }
    Write-Log "Adding to group: $g"
    Add-ADGroupMember @gp
  }

  Write-Log "SUCCESS: Created sam='$sam' upn='$upn'."
  Msg-Info ("Done!`r`n`r`nSAM: {0}`r`nUPN: {1}`r`nRunId: {2}`r`nLog: {3}`r`nTranscript: {4}" -f $sam, $upn, $RunId, $LogFile, $TranscriptFile)
}

$btnCreate.Add_Click({
  try {
    Create-ContosoUserFromForm
  } catch {
    Write-Log "FAILED: $($_.Exception.Message)" "ERROR"
    Msg-Error ("Error: {0}`r`n`r`nRunId: {1}`r`nLog: {2}`r`nTranscript: {3}" -f $_.Exception.Message, $RunId, $LogFile, $TranscriptFile)
  } finally {
    try { Stop-Transcript | Out-Null } catch { }
    Write-Log "Create handler finished."
  }
})

# Initial previews
Refresh-GroupsPreview
Recalc-IdentityFields
Write-Log "GUI started."
[void]$form.ShowDialog()
Write-Log "GUI closed."
Write-Log "Script finished."

try { Stop-Transcript | Out-Null } catch { }
Write-Log "Transcript stopped."
