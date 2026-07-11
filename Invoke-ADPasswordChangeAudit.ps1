<#
.SYNOPSIS
When a user changes their password, check the new password for (a) reuse across
other accounts and (b) presence in the Have I Been Pwned breach corpus.

.DESCRIPTION
Detects password changes (pwdLastSet moved forward since the previous run, or an
account passed in -SamAccountName), reads the new NTLM hash with DSInternals, and
for each changed account runs:
  1. Duplicate check  - does any OTHER account share this exact NTLM hash?
  2. Pwned check       - is the hash in Have I Been Pwned? (k-anonymity range API;
                         only the first 5 hex chars are ever sent.)
Accounts that fail either check are e-mailed (hash-masked) to -MailTo.

Detecting changes:
  - Scan mode (default): pwdLastSet is compared to a JSON state file. The FIRST
    run records a baseline only (no alerts).
  - Single-account mode: pass -SamAccountName (e.g. from a Task Scheduler trigger
    on event 4723/4724 - password change/reset); only those accounts are audited.

Inspired by adaudit's pwned_password_prof.ps1, combined with a duplicate check
and driven by external configuration.

.EXAMPLE
.\Invoke-ADPasswordChangeAudit.ps1 -Run

.EXAMPLE
.\Invoke-ADPasswordChangeAudit.ps1 -Run -SamAccountName jdoe

.NOTES
SECURITY / REQUIREMENTS
- Requires the DSInternals module and directory replication (DCSync) rights. Run
  ON or near a DC.
- Raw NTLM hashes are NEVER e-mailed; only a masked label. Full hashes are written
  only with -WriteHashCsv into the ACL-restricted output folder.
- The pwned check makes outbound HTTPS calls to api.pwnedpasswords.com. Disable it
  with -CheckPwned:$false in air-gapped environments.
#>

[CmdletBinding(DefaultParameterSetName = 'DryRun')]
param(
    [Parameter(ParameterSetName = 'DryRun', Mandatory = $true)][switch]$DryRun,
    [Parameter(ParameterSetName = 'Run', Mandatory = $true)][switch]$Run,

    [string[]]$SamAccountName = @(),

    [string[]]$MailTo = @('security-team@contoso.local'),

    [bool]$CheckPwned = $true,
    [bool]$IncludeComputers = $false,
    [bool]$WriteHashCsv = $false,

    [string[]]$UserLimitToOUs = @(),
    [string[]]$IgnoreAccountsExact = @('krbtgt'),

    [string]$SmtpServer = 'smtp-relay.contoso.local',
    [int]$SmtpPort = 25,
    [string]$MailFrom = 'ad-automation@contoso.local',
    [bool]$MailUseSsl = $false,
    [string]$MailCredentialPath = '',

    [string]$Server = '',
    [string]$OutputRoot = 'C:\ProgramData\AD-Automation',
    [string]$LogFilePrefix = 'ADPasswordChangeAudit',

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

$cfg = Import-ADAutomationConfig -Path $ConfigPath -Section 'PasswordChangeAudit'
$boundKeys = @($PSBoundParameters.Keys)
$overlaySkip = @('DryRun', 'Run')
foreach ($k in @($cfg.Keys)) {
    if ($k -eq '__ConfigFile') { continue }
    if ($overlaySkip -contains $k) { Write-Warning "Ignoring config key '$k': run mode is set on the command line only."; continue }
    if ($boundKeys -notcontains $k -and (Get-Variable -Name $k -Scope 0 -ErrorAction SilentlyContinue)) {
        Set-Variable -Name $k -Value $cfg[$k] -Scope 0
    }
}

foreach ($mod in 'ActiveDirectory', 'DSInternals') {
    if (-not (Get-Module -ListAvailable -Name $mod)) { throw "$mod module not found. It is required to read/replicate NTLM hashes." }
    Import-Module $mod -ErrorAction Stop
}

# --- Setup ------------------------------------------------------------------
$run = Initialize-ADAutomationLog -OutputRoot $OutputRoot -BaseName $LogFilePrefix -EventLogEnabled $EventLogEnabled -EventLogName $EventLogName
$whatIf = ($PSCmdlet.ParameterSetName -eq 'DryRun')

$serverExplicit = -not [string]::IsNullOrWhiteSpace($Server)
$di = Get-ADAutomationDomainInfo -Server $Server
if ([string]::IsNullOrWhiteSpace($Server)) { $Server = $di.Server }
$domainDN = $di.DistinguishedName

$mailCommon = @{
    From = $MailFrom; SmtpServer = $SmtpServer; SmtpPort = $SmtpPort
    UseSsl = $MailUseSsl; CredentialPath = $MailCredentialPath
}
$targets = @($SamAccountName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$singleMode = ($targets.Count -gt 0)

# Event-driven single-account runs (4723/4724 trigger) fire on the DC where the
# password changed, before it replicates. Read the fresh hash from the LOCAL DC in
# that case (unless a server was explicitly requested).
if ($singleMode -and -not $serverExplicit) {
    $Server = $env:COMPUTERNAME
    Write-ADAutomationLog "Single-account mode: reading from local DC '$Server' (event source) instead of the PDC emulator." 'INFO'
}
$srv = @{ Server = $Server }

Write-ADAutomationLog "=== START (RunId=$($run.RunId)) ==="
Write-ADAutomationLog ("Mode={0} ; Server={1} ; CheckPwned={2} ; SingleAccountMode={3} ({4})" -f `
        $PSCmdlet.ParameterSetName, $Server, $CheckPwned, $singleMode, ($targets -join ','))

# --- Determine which accounts changed their password ------------------------
$statePath = Get-ADAutomationStatePath -OutputRoot $OutputRoot -Name 'PasswordChangeAudit'
$changedSams = @()
$baselineRun = $false
$currentPwdLastSet = @{}
$queryFailed = $false   # a base query failed -> do NOT overwrite state (would evict that OU)

if ($singleMode) {
    $changedSams = $targets
}
else {
    # Snapshot pwdLastSet for the monitored scope.
    if (-not $UserLimitToOUs -or @($UserLimitToOUs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
        $UserLimitToOUs = @($domainDN)
    }
    $bases = Get-ValidSearchBase -Bases $UserLimitToOUs @srv
    $filter = if ($IncludeComputers) { '(|(objectClass=user)(objectClass=computer))' } else { '(&(objectCategory=person)(objectClass=user))' }
    foreach ($base in $bases) {
        try {
            $accs = Get-ADUser -SearchBase $base -SearchScope Subtree @srv -LDAPFilter $filter -Properties PasswordLastSet, SamAccountName -ErrorAction Stop
            foreach ($a in $accs) {
                $sam = [string]$a.SamAccountName
                if ([string]::IsNullOrWhiteSpace($sam)) { continue }
                $ticks = if ($a.PasswordLastSet) { [int64]$a.PasswordLastSet.Ticks } else { [int64]0 }
                $currentPwdLastSet[$sam] = $ticks
            }
        }
        catch { Write-ADAutomationLog "ERROR querying '$base': $($_.Exception.Message)" 'ERROR'; $queryFailed = $true }
    }

    $state = Read-ADAutomationState -Path $statePath
    if (-not $state -or -not $state.PSObject.Properties['PwdLastSet']) {
        $baselineRun = $true
        Write-ADAutomationLog 'First run: recording baseline of pwdLastSet (no alerts this run).' 'INFO'
    }
    else {
        $prev = @{}
        foreach ($p in $state.PwdLastSet.PSObject.Properties) { $prev[$p.Name] = [int64]$p.Value }
        $changed = New-Object System.Collections.Generic.List[string]
        foreach ($sam in $currentPwdLastSet.Keys) {
            $now = [int64]$currentPwdLastSet[$sam]
            if ($prev.ContainsKey($sam)) {
                if ($now -gt [int64]$prev[$sam]) { $changed.Add($sam) }
            }
            else {
                # Newly seen account whose password is already set.
                if ($now -gt 0) { $changed.Add($sam) }
            }
        }
        $changedSams = @($changed)
        Write-ADAutomationLog "Accounts with a password change since last run: $($changedSams.Count)"
    }
}

$changedSams = @($changedSams | Where-Object { -not (Test-IsIgnoredName -Name $_ -ExactList $IgnoreAccountsExact) })

# --- Audit the changed accounts ---------------------------------------------
$results = New-Object System.Collections.Generic.List[object]
$alertPending = $false                 # a finding could not be e-mailed
$recheckSams = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
if (-not $baselineRun -and $changedSams.Count -gt 0) {

    Write-ADAutomationLog 'Reading replicated account hashes for duplicate comparison (Get-ADReplAccount -All)...'
    $repl = @(Get-ADReplAccount -All -Server $Server -NamingContext $domainDN -ErrorAction Stop)
    $samToHash = @{}
    $hashToSams = @{}
    foreach ($ra in $repl) {
        $sam = [string]$ra.SamAccountName
        if ([string]::IsNullOrWhiteSpace($sam)) { continue }
        $hash = Convert-NtHashToHex -Bytes $ra.NTHash
        if ([string]::IsNullOrWhiteSpace($hash)) { continue }
        $samToHash[$sam] = $hash
        if (-not $hashToSams.ContainsKey($hash)) { $hashToSams[$hash] = New-Object System.Collections.Generic.List[string] }
        $hashToSams[$hash].Add($sam)
    }

    $pwnedCache = @{}
    foreach ($sam in ($changedSams | Sort-Object -Unique)) {
        $hash = $samToHash[$sam]
        if (-not $hash) { Write-ADAutomationLog "No hash found for '$sam' (skipping)." 'WARN'; continue }

        $others = @($hashToSams[$hash] | Where-Object { -not $_.Equals($sam, [System.StringComparison]::OrdinalIgnoreCase) } | Sort-Object -Unique)

        $pwned = 'NotChecked'; $pwnedCount = $null
        if ($CheckPwned) {
            if (-not $pwnedCache.ContainsKey($hash)) { $pwnedCache[$hash] = Test-NtlmHashPwned -NtlmHash $hash }
            $pwned = $pwnedCache[$hash].Pwned
            $pwnedCount = $pwnedCache[$hash].PwnedCount
        }

        $isDuplicate = ($others.Count -gt 0)
        $isPwned = ($pwned -eq 'Yes')
        # A failed HIBP lookup is NOT 'clean': surface it and schedule a re-check so
        # a transient outage cannot permanently hide a breached password.
        $lookupFailed = ($pwned -eq 'LookupFailed')
        if ($lookupFailed) { [void]$recheckSams.Add($sam) }
        if ($isDuplicate -or $isPwned -or $lookupFailed) {
            $results.Add([pscustomobject]@{
                    Account     = $sam
                    Duplicate   = $isDuplicate
                    SharedWith  = ($others -join ';')
                    Pwned       = $pwned
                    PwnedCount  = $pwnedCount
                    HashLabel   = Format-MaskedNtHash $hash
                    NTHash      = $hash
                }) | Out-Null
            Write-ADAutomationLog ("FINDING: '{0}' Duplicate={1} ({2}) Pwned={3} ({4})" -f $sam, $isDuplicate, ($others -join ','), $pwned, $pwnedCount) 'ACTION'
        }
        else {
            Write-ADAutomationLog "Clean: '$sam' (no reuse, not pwned)." 'INFO'
        }
    }
}

# --- Report + notify --------------------------------------------------------
$maskedCsv = Join-Path $OutputRoot ("{0}-Report-{1}.csv" -f $LogFilePrefix, $run.RunId)
try {
    $results | Select-Object Account, Duplicate, SharedWith, Pwned, PwnedCount, HashLabel | Export-Csv -Path $maskedCsv -NoTypeInformation -Encoding UTF8
    Write-ADAutomationLog "Masked report written: $maskedCsv" 'INFO'
}
catch { Write-ADAutomationLog "ERROR writing report: $($_.Exception.Message)" 'ERROR' }

# Full NTLM hashes are secret material; never write them during a -DryRun preview.
if ($WriteHashCsv -and -not $whatIf -and $results.Count -gt 0) {
    $hashCsv = Join-Path $OutputRoot ("{0}-Hashes-{1}.csv" -f $LogFilePrefix, $run.RunId)
    $results | Select-Object Account, SharedWith, Pwned, NTHash | Export-Csv -Path $hashCsv -NoTypeInformation -Encoding UTF8
    Write-ADAutomationLog "FULL-HASH report written (treat as secret): $hashCsv" 'WARN'
}

if ($results.Count -gt 0) {
    $lines = $results | ForEach-Object {
        $bits = @()
        if ($_.Duplicate) { $bits += "reused by: $($_.SharedWith)" }
        if ($_.Pwned -eq 'Yes') { $bits += "PWNED (seen $($_.PwnedCount) times)" }
        if ($_.Pwned -eq 'LookupFailed') { $bits += 'pwned check UNVERIFIED (HIBP unreachable - will re-check next run)' }
        " - $($_.Account): $($bits -join '; ')  [$($_.HashLabel)]"
    }
    $body = @"
The following account(s) changed their password to one that is weak/reused:

$($lines -join "`n")

A reused password lets one compromised credential unlock several accounts; a
pwned password appears in public breach corpora. Recommended action: require a
unique, non-breached password reset for the account(s) above.
(Full NTLM hashes are not included by design.)

Domain: $($di.DnsRoot)   Reported by: $($env:COMPUTERNAME)
"@
    $subject = "AD password-change audit: $($results.Count) account(s) with reused/pwned passwords"

    if ($whatIf) { Write-ADAutomationLog "WHATIF: would e-mail $($MailTo -join ', ') about $($results.Count) finding(s)." 'WHATIF' }
    elseif ($SmtpServer -match '(?i)contoso\.') { Write-ADAutomationLog "Refusing to e-mail: SmtpServer still uses the 'contoso' placeholder." 'ERROR'; $alertPending = $true }
    elseif (Send-ADAutomationMail @mailCommon -To $MailTo -Subject $subject -Body $body) { }
    else { $alertPending = $true; Write-ADAutomationLog "Alert e-mail FAILED to send; NOT advancing state so these findings are re-checked next run." 'ERROR' }
}
else {
    Write-ADAutomationLog 'No reused/pwned passwords among changed accounts.' 'INFO'
}

# --- Persist state (scan mode, real run only) -------------------------------
# Skip the save entirely when a base query failed (a partial snapshot would evict a
# whole OU and cause a mass false-positive audit next run) or when an alert could
# not be delivered (findings must be re-checked). Otherwise drop accounts whose HIBP
# lookup failed so they are re-audited next run instead of being marked done.
if (-not $singleMode -and -not $whatIf -and $currentPwdLastSet.Count -gt 0 -and -not $queryFailed -and -not $alertPending) {
    foreach ($rs in @($recheckSams)) { [void]$currentPwdLastSet.Remove($rs) }
    Save-ADAutomationState -Path $statePath -State ([pscustomobject]@{
            PwdLastSet = $currentPwdLastSet
            UpdatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        })
    Write-ADAutomationLog "State updated: $($currentPwdLastSet.Count) account(s) tracked (deferred re-check: $($recheckSams.Count))." 'INFO'
}
elseif (-not $singleMode -and -not $whatIf) {
    $why = if ($queryFailed) { 'a base query failed' } elseif ($alertPending) { 'an alert could not be delivered' } else { 'no accounts tracked' }
    Write-ADAutomationLog "State NOT advanced ($why) - affected accounts will be re-audited next run." 'WARN'
}

Write-ADAutomationLog "=== END (findings=$($results.Count)) ==="
Write-Output "Done. Mode=$($PSCmdlet.ParameterSetName) Findings=$($results.Count) BaselineRun=$baselineRun"
Write-Output "Log: $($run.LogPath)"
Write-Output "Report: $maskedCsv"
