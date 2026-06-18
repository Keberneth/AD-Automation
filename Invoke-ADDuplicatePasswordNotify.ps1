<#
.SYNOPSIS
Notify when a NEWLY created account shares its NTLM password hash with one or
more existing accounts (i.e. a new user was given a password already in use).

.DESCRIPTION
Reads replicated account data with DSInternals (Get-ADReplAccount), groups
accounts by NTLM hash, and reports any NEW account whose hash collides with at
least one other account. A short, hash-masked summary is e-mailed to the
address(es) in -MailTo. Inspired by adaudit's same_passwd_prof.ps1, but scoped
to *new* accounts and driven by external configuration.

Detecting "new":
  - Scan mode (default): the set of accounts is compared to a JSON state file
    from the previous run; accounts not seen before are "new". The FIRST run only
    records a baseline (it does not alert on every pre-existing duplicate).
  - Single-account mode: pass -SamAccountName (e.g. from a Task Scheduler trigger
    on event 4720 - user created); only those accounts are checked.

.EXAMPLE
.\Invoke-ADDuplicatePasswordNotify.ps1 -Run

.EXAMPLE
.\Invoke-ADDuplicatePasswordNotify.ps1 -Run -SamAccountName jdoe

.NOTES
SECURITY / REQUIREMENTS
- Requires the DSInternals module and an account with directory replication
  rights (DCSync-level: "Replicating Directory Changes" + "...All"). Run ON or
  near a DC.
- Raw NTLM hashes are NEVER e-mailed; only a masked label is shown. Full hashes
  are written to disk only with -WriteHashCsv, into the ACL-restricted output
  folder. Treat that file as a secret.
#>

[CmdletBinding(DefaultParameterSetName = 'DryRun')]
param(
    [Parameter(ParameterSetName = 'DryRun', Mandatory = $true)][switch]$DryRun,
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)][switch]$Run,

    # Optional: check only these account(s) (event-triggered mode). Empty = scan deltas.
    [string[]]$SamAccountName = @(),

    # Where the alert goes.
    [string[]]$MailTo = @('security-team@contoso.local'),

    [bool]$IncludeComputers = $false,
    [bool]$WriteHashCsv = $false,

    [string]$SmtpServer = 'smtp-relay.contoso.local',
    [int]$SmtpPort = 25,
    [string]$MailFrom = 'ad-automation@contoso.local',
    [bool]$MailUseSsl = $false,
    [string]$MailCredentialPath = '',

    [string]$Server = '',
    [string]$OutputRoot = 'C:\ProgramData\AD-Automation',
    [string]$LogFilePrefix = 'ADDuplicatePassword',
    [string]$ConfigPath = ''
)

# --- Bootstrap --------------------------------------------------------------
$modulePath = Join-Path $PSScriptRoot 'ADAutomation.psd1'
if (-not (Test-Path -LiteralPath $modulePath)) { throw "Required module not found next to script: $modulePath" }
Import-Module $modulePath -Force -ErrorAction Stop

$cfg = Import-ADAutomationConfig -Path $ConfigPath -Section 'DuplicatePasswordNotify'
$boundKeys = @($PSBoundParameters.Keys)
foreach ($k in @($cfg.Keys)) {
    if ($k -eq '__ConfigFile') { continue }
    if ($boundKeys -notcontains $k -and (Get-Variable -Name $k -Scope 0 -ErrorAction SilentlyContinue)) {
        Set-Variable -Name $k -Value $cfg[$k] -Scope 0
    }
}

foreach ($mod in 'ActiveDirectory', 'DSInternals') {
    if (-not (Get-Module -ListAvailable -Name $mod)) { throw "$mod module not found. It is required to read/replicate NTLM hashes." }
    Import-Module $mod -ErrorAction Stop
}

# --- Setup ------------------------------------------------------------------
$run = Initialize-ADAutomationLog -OutputRoot $OutputRoot -BaseName $LogFilePrefix
$whatIf = ($PSCmdlet.ParameterSetName -eq 'DryRun')

$di = Get-ADAutomationDomainInfo -Server $Server
if ([string]::IsNullOrWhiteSpace($Server)) { $Server = $di.Server }
$domainDN = $di.DistinguishedName

$mailCommon = @{
    From = $MailFrom; SmtpServer = $SmtpServer; SmtpPort = $SmtpPort
    UseSsl = $MailUseSsl; CredentialPath = $MailCredentialPath
}
$targets = @($SamAccountName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$singleMode = ($targets.Count -gt 0)

Write-ADAutomationLog "=== START (RunId=$($run.RunId)) ==="
Write-ADAutomationLog ("Mode={0} ; Server={1} ; IncludeComputers={2} ; SingleAccountMode={3} ({4})" -f `
        $PSCmdlet.ParameterSetName, $Server, $IncludeComputers, $singleMode, ($targets -join ','))

# --- Read all account hashes (the comparison corpus) ------------------------
Write-ADAutomationLog 'Reading replicated account hashes (Get-ADReplAccount -All)...'
$repl = @(Get-ADReplAccount -All -Server $Server -NamingContext $domainDN -ErrorAction Stop)
if ($repl.Count -eq 0) { throw "No replication accounts returned from $Server." }

$samToHash = @{}
$hashToSams = @{}
$currentSams = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

foreach ($ra in $repl) {
    $sam = [string]$ra.SamAccountName
    if ([string]::IsNullOrWhiteSpace($sam)) { continue }
    if (-not $IncludeComputers -and $sam -match '\$$') { continue }
    $hash = Convert-NtHashToHex -Bytes $ra.NTHash
    if ([string]::IsNullOrWhiteSpace($hash)) { continue }

    [void]$currentSams.Add($sam)
    $samToHash[$sam] = $hash
    if (-not $hashToSams.ContainsKey($hash)) { $hashToSams[$hash] = New-Object System.Collections.Generic.List[string] }
    $hashToSams[$hash].Add($sam)
}
Write-ADAutomationLog "Accounts considered: $($currentSams.Count)"

# --- Determine which accounts are "new" -------------------------------------
$statePath = Get-ADAutomationStatePath -OutputRoot $OutputRoot -Name 'DuplicatePasswordNotify'
$newSams = @()
$baselineRun = $false

if ($singleMode) {
    $newSams = @($targets | Where-Object { $currentSams.Contains($_) })
    $missing = @($targets | Where-Object { -not $currentSams.Contains($_) })
    if ($missing.Count -gt 0) { Write-ADAutomationLog "Requested account(s) not found in corpus: $($missing -join ', ')" 'WARN' }
}
else {
    $state = Read-ADAutomationState -Path $statePath
    if (-not $state -or -not $state.PSObject.Properties['KnownSams']) {
        $baselineRun = $true
        Write-ADAutomationLog 'First run: recording baseline of existing accounts (no alerts this run).' 'INFO'
    }
    else {
        $known = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($s in @($state.KnownSams)) { [void]$known.Add([string]$s) }
        $newSams = @($currentSams | Where-Object { -not $known.Contains($_) })
        Write-ADAutomationLog "New accounts since last run: $($newSams.Count)"
    }
}

# --- Find collisions among the new accounts ---------------------------------
$results = New-Object System.Collections.Generic.List[object]
if (-not $baselineRun) {
    foreach ($sam in $newSams) {
        $hash = $samToHash[$sam]
        if (-not $hash) { continue }
        $others = @($hashToSams[$hash] | Where-Object { -not $_.Equals($sam, [System.StringComparison]::OrdinalIgnoreCase) } | Sort-Object -Unique)
        if ($others.Count -gt 0) {
            $results.Add([pscustomobject]@{
                    NewAccount       = $sam
                    SharedWith       = ($others -join ';')
                    SharedWithCount  = $others.Count
                    HashLabel        = Format-MaskedNtHash $hash
                    NTHash           = $hash
                }) | Out-Null
            Write-ADAutomationLog "DUPLICATE: '$sam' shares a password with $($others.Count) account(s): $($others -join ', ')" 'ACTION'
        }
    }
}

# --- Report + notify --------------------------------------------------------
$maskedCsv = Join-Path $OutputRoot ("{0}-Report-{1}.csv" -f $LogFilePrefix, $run.RunId)
try {
    $results | Select-Object NewAccount, SharedWith, SharedWithCount, HashLabel | Export-Csv -Path $maskedCsv -NoTypeInformation -Encoding UTF8
    Write-ADAutomationLog "Masked report written: $maskedCsv" 'INFO'
}
catch { Write-ADAutomationLog "ERROR writing report: $($_.Exception.Message)" 'ERROR' }

if ($WriteHashCsv -and $results.Count -gt 0) {
    $hashCsv = Join-Path $OutputRoot ("{0}-Hashes-{1}.csv" -f $LogFilePrefix, $run.RunId)
    $results | Select-Object NewAccount, SharedWith, NTHash | Export-Csv -Path $hashCsv -NoTypeInformation -Encoding UTF8
    Write-ADAutomationLog "FULL-HASH report written (treat as secret): $hashCsv" 'WARN'
}

if ($results.Count -gt 0) {
    $lines = $results | ForEach-Object { " - $($_.NewAccount)  shares password with: $($_.SharedWith)  [hash $($_.HashLabel)]" }
    $body = @"
The following NEWLY observed account(s) were created/changed with a password that
is ALREADY in use by other accounts in the domain. Shared passwords let one
compromised credential unlock multiple accounts.

$($lines -join "`n")

Recommended action: force a unique password reset on the new account(s).
(Full NTLM hashes are not included by design.)

Domain: $($di.DnsRoot)   Reported by: $($env:COMPUTERNAME)
"@
    $subject = "AD duplicate-password alert: $($results.Count) new account(s) reuse an existing password"

    if ($whatIf) { Write-ADAutomationLog "WHATIF: would e-mail $($MailTo -join ', ') about $($results.Count) collision(s)." 'WHATIF' }
    elseif ($SmtpServer -match '(?i)contoso\.') { Write-ADAutomationLog "Refusing to e-mail: SmtpServer still uses the 'contoso' placeholder." 'ERROR' }
    else { [void](Send-ADAutomationMail @mailCommon -To $MailTo -Subject $subject -Body $body) }
}
else {
    Write-ADAutomationLog 'No duplicate-password collisions among new accounts.' 'INFO'
}

# --- Persist baseline state (scan mode, real run only) ----------------------
if (-not $singleMode -and -not $whatIf) {
    Save-ADAutomationState -Path $statePath -State ([pscustomobject]@{
            KnownSams  = @($currentSams)
            UpdatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        })
    Write-ADAutomationLog "State updated: $($currentSams.Count) known account(s)." 'INFO'
}

Write-ADAutomationLog "=== END (collisions=$($results.Count)) ==="
Write-Output "Done. Mode=$($PSCmdlet.ParameterSetName) Collisions=$($results.Count) BaselineRun=$baselineRun"
Write-Output "Log: $($run.LogPath)"
Write-Output "Report: $maskedCsv"
