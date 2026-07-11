<#
.SYNOPSIS
Create per-server Admin/RDP groups for computers in one or more OUs and nest
baseline groups into them.

.DESCRIPTION
For every computer found under -ComputerOUs this creates (idempotently):
  - SRV-<ComputerName>-Administrators       in -AdminGroupOU
  - SRV-<ComputerName>-RemoteDesktopUsers    in -RDPGroupOU
and nests the baseline groups (-BaselineAdmin / -BaselineRdp) into them.

All inputs can be set once in config\AD-Automation.settings.psd1 (section
'ServerGroupProvisioning'); command-line parameters override the file. The five
structural inputs (ComputerOUs, AdminGroupOU, RDPGroupOU, BaselineAdmin,
BaselineRdp) are site-specific and must be supplied (script throws if missing).

Supports -WhatIf / -Verbose. Pins all reads/writes to one DC (the PDC emulator
by default) so create-then-read never races replication.

.EXAMPLE
.\Invoke-ADServerGroupProvisioning.ps1 -WhatIf -Verbose

.NOTES
- Requires the ActiveDirectory module and the ADAutomation module.
- Group sAMAccountName is kept identical to the group name (groups allow up to 256
  chars). Only names past that limit fall back to a deterministic 32-bit-hash short
  form, verified unique with numeric rotation on collision.
- Per-server resource groups are created with -GroupScope (default DomainLocal,
  the AGDLP-correct scope for resource-access groups).
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [string[]]$ComputerOUs = @(),
    [string]$AdminGroupOU = '',
    [string]$RDPGroupOU = '',
    [string]$BaselineAdmin = '',
    [string]$BaselineRdp = '',

    # Scope for the per-server resource groups. DomainLocal is correct AGDLP for
    # resource-access groups and can contain baseline Global/Universal groups from
    # any trusted domain; Global (the old hardcoded value) rejects a DomainLocal
    # baseline. Existing groups are matched by CN and never re-scoped.
    [ValidateSet('DomainLocal', 'Global', 'Universal')][string]$GroupScope = 'DomainLocal',

    # Target DC. Empty = PDC emulator (derived from AdminGroupOU's domain).
    [string]$Server = '',
    [int]$PauseSeconds = 0,

    [string]$OutputRoot = 'C:\ProgramData\AD-Automation',

    # Mirror log lines to the Windows Event Log (Applications and Services Logs >
    # EventLogName, source = this script). Source registration needs one elevated
    # run (the installer does it); non-admin runs degrade gracefully.
    [bool]$EventLogEnabled = $true,
    [string]$EventLogName = 'AD-Automation',

    [string]$ConfigPath = ''
)

Set-StrictMode -Version Latest

# --- Bootstrap --------------------------------------------------------------
$modulePath = Join-Path $PSScriptRoot 'ADAutomation.psd1'
if (-not (Test-Path -LiteralPath $modulePath)) { throw "Required module not found next to script: $modulePath" }
Import-Module $modulePath -Force -ErrorAction Stop

$cfg = Import-ADAutomationConfig -Path $ConfigPath -Section 'ServerGroupProvisioning'
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

# --- Validate required, site-specific inputs --------------------------------
$missing = @()
if (-not $ComputerOUs -or @($ComputerOUs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) { $missing += 'ComputerOUs' }
if ([string]::IsNullOrWhiteSpace($AdminGroupOU)) { $missing += 'AdminGroupOU' }
if ([string]::IsNullOrWhiteSpace($RDPGroupOU)) { $missing += 'RDPGroupOU' }
if ([string]::IsNullOrWhiteSpace($BaselineAdmin)) { $missing += 'BaselineAdmin' }
if ([string]::IsNullOrWhiteSpace($BaselineRdp)) { $missing += 'BaselineRdp' }
if ($missing.Count -gt 0) {
    throw "Missing required setting(s): $($missing -join ', '). Set them via -<Name> or in config (section 'ServerGroupProvisioning')."
}

# --- Setup ------------------------------------------------------------------
$run = Initialize-ADAutomationLog -OutputRoot $OutputRoot -BaseName 'ADServerGroupProvisioning' -EventLogEnabled $EventLogEnabled -EventLogName $EventLogName

# Pin one DC for the whole run (PDC emulator of the AdminGroupOU's domain).
if ([string]::IsNullOrWhiteSpace($Server)) {
    # Case-insensitive: DN attribute types are case-insensitive, so a valid lowercase
    # 'dc=' must still yield the domain FQDN.
    $dcs = [regex]::Matches($AdminGroupOU, '(?i)DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }
    $domainFqdn = ($dcs -join '.')
    if ([string]::IsNullOrWhiteSpace($domainFqdn)) {
        throw "AdminGroupOU '$AdminGroupOU' has no DC= components - it does not look like a distinguished name. Set -Server explicitly or fix AdminGroupOU."
    }
    try { $Server = (Get-ADDomain -Server $domainFqdn -ErrorAction Stop).PDCEmulator }
    catch { $Server = $domainFqdn; Write-ADAutomationLog "Could not resolve PDCEmulator for '$domainFqdn' (using DNS): $($_.Exception.Message)" 'WARN' }
}
Write-ADAutomationLog "=== START (RunId=$($run.RunId)) === Server=$Server"

# --- Helpers ----------------------------------------------------------------
function Get-SafeSamAccountName {
    # The 20-character cap applies to USER logon names, not groups: a group
    # sAMAccountName may be up to 256 chars (built-in groups routinely exceed 20).
    # Keep sam == CN so the group resolves under the name operators expect (GPO
    # Restricted Groups, 'net localgroup DOMAIN\<name>', audit tooling); only fall
    # back to a hash-suffixed short form past the real limit.
    param([Parameter(Mandatory)][string]$GroupName)
    if ($GroupName.Length -le 256) { return $GroupName }
    $prefix = $GroupName.Substring(0, 247)           # 247 + '-' + 8 hex = 256
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try { $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($GroupName)) }
    finally { $sha.Dispose() }
    $hex = -join ($hash[0..3] | ForEach-Object { $_.ToString('x2') })   # full 32 bits
    return ('{0}-{1}' -f $prefix, $hex)
}

function Get-OrCreateAdGroup {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Description, [Parameter(Mandatory)][string]$Server)

    # Idempotency identity is the group CN (Name) under the target OU.
    $existing = Get-ADGroup -Server $Server -SearchBase $Path -Filter { Name -eq $Name } -ErrorAction SilentlyContinue
    if ($existing) { return $existing }

    # Derive a unique, length-safe sAMAccountName; rotate on rare collision.
    $sam = Get-SafeSamAccountName -GroupName $Name
    if (Get-ADGroup -Server $Server -Filter { SamAccountName -eq $sam } -ErrorAction SilentlyContinue) {
        $base = $sam.Substring(0, [Math]::Min(17, $sam.Length))
        for ($i = 1; $i -le 99; $i++) {
            $cand = '{0}-{1:D2}' -f $base, $i
            if (-not (Get-ADGroup -Server $Server -Filter { SamAccountName -eq $cand } -ErrorAction SilentlyContinue)) { $sam = $cand; break }
        }
    }

    if ($PSCmdlet.ShouldProcess("Group '$Name' in '$Path'", 'Create')) {
        try {
            $created = New-ADGroup -Server $Server -Name $Name -SamAccountName $sam -GroupScope $GroupScope -GroupCategory Security -Path $Path -Description $Description -PassThru -ErrorAction Stop
            Write-ADAutomationLog "CREATED group Name='$Name' Sam='$sam' DN='$($created.DistinguishedName)'" 'ACTION'
            return $created
        }
        catch {
            Write-ADAutomationLog "ERROR creating group '$Name' (Sam='$sam'): $($_.Exception.Message)" 'ERROR'
            return $null
        }
    }
    return [pscustomobject]@{ Name = $Name; SamAccountName = $sam; DistinguishedName = "CN=$Name,$Path"; Simulated = $true }
}

function Add-GroupMemberIfMissing {
    param([Parameter(Mandatory)][string]$TargetGroupDn, [Parameter(Mandatory)][string]$MemberDn, [Parameter(Mandatory)][string]$MemberNameForLog, [Parameter(Mandatory)][string]$Server)
    $target = Get-ADGroup -Server $Server -Identity $TargetGroupDn -Properties member -ErrorAction Stop
    $members = @($target.member)
    if ($members -contains $MemberDn) { Write-Verbose "'$MemberNameForLog' already in '$($target.SamAccountName)'"; return $false }
    if ($PSCmdlet.ShouldProcess($target.SamAccountName, "Add member '$MemberNameForLog'")) {
        Add-ADGroupMember -Server $Server -Identity $TargetGroupDn -Members $MemberDn -Confirm:$false -ErrorAction Stop
        Write-ADAutomationLog "ADDED member='$MemberNameForLog' to group='$($target.SamAccountName)'" 'ACTION'
        return $true
    }
    return $false
}

function Get-ComputersFromOUs {
    param([Parameter(Mandatory)][string[]]$SearchBases, [Parameter(Mandatory)][string]$Server)
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($ou in $SearchBases) {
        if ([string]::IsNullOrWhiteSpace($ou)) { continue }
        try {
            $null = Get-ADObject -Server $Server -Identity $ou -ErrorAction Stop
            $cs = Get-ADComputer -Server $Server -SearchBase $ou -Filter * -Properties Name, DistinguishedName
            foreach ($c in $cs) { $all.Add($c) }
            Write-ADAutomationLog "LOADED ComputersFromOU='$ou' Count=$(@($cs).Count)" 'INFO'
        }
        catch { Write-ADAutomationLog "ERROR reading search base '$ou': $($_.Exception.Message)" 'ERROR' }
    }
    return ($all | Sort-Object DistinguishedName -Unique | Sort-Object Name)
}

# --- Preflight baseline groups ---------------------------------------------
$baselineAdminObj = Get-ADGroup -Server $Server -Identity $BaselineAdmin -ErrorAction Stop
$baselineRdpObj = Get-ADGroup -Server $Server -Identity $BaselineRdp -ErrorAction Stop

# --- Preflight target OUs (a typo here would otherwise fail every New-ADGroup,
#     one error per computer per day, while the run still reports success) ------
foreach ($ouDn in @($AdminGroupOU, $RDPGroupOU)) {
    try { $null = Get-ADObject -Server $Server -Identity $ouDn -ErrorAction Stop }
    catch { throw "Target group OU not found: '$ouDn'. Error: $($_.Exception.Message)" }
}

# --- Load computers ---------------------------------------------------------
$computers = Get-ComputersFromOUs -SearchBases $ComputerOUs -Server $Server
if (-not $computers -or @($computers).Count -eq 0) {
    Write-ADAutomationLog 'No computer objects found in the provided OUs.' 'WARN'
    Write-Output 'No computers found.'
    return
}

# --- Create + nest ----------------------------------------------------------
$addedAdmin = 0; $addedRdp = 0
foreach ($c in $computers) {
    if (-not $c.Name) { continue }
    $serverId = $c.Name.TrimEnd('$')
    $adminGroupName = "SRV-$serverId-Administrators"
    $rdpGroupName = "SRV-$serverId-RemoteDesktopUsers"

    # Isolate each computer: one bad group ACL, scope conflict, or transient AD fault
    # must not abort the whole unattended run (skipping every later server + the END
    # summary). Log it and carry on, mirroring Get-OrCreateAdGroup's own handling.
    try {
        $adminGroup = Get-OrCreateAdGroup -Name $adminGroupName -Path $AdminGroupOU -Description "Per-server local admin delegation for $serverId" -Server $Server
        $rdpGroup = Get-OrCreateAdGroup -Name $rdpGroupName -Path $RDPGroupOU -Description "Per-server RDP delegation for $serverId" -Server $Server

        if ($adminGroup -and -not $adminGroup.PSObject.Properties['Simulated']) {
            if (Add-GroupMemberIfMissing -TargetGroupDn $adminGroup.DistinguishedName -MemberDn $baselineAdminObj.DistinguishedName -MemberNameForLog $BaselineAdmin -Server $Server) { $addedAdmin++ }
        }
        elseif ($adminGroup) { Write-Verbose "[WhatIf] Would add $BaselineAdmin to $adminGroupName" }

        if ($rdpGroup -and -not $rdpGroup.PSObject.Properties['Simulated']) {
            if (Add-GroupMemberIfMissing -TargetGroupDn $rdpGroup.DistinguishedName -MemberDn $baselineRdpObj.DistinguishedName -MemberNameForLog $BaselineRdp -Server $Server) { $addedRdp++ }
        }
        elseif ($rdpGroup) { Write-Verbose "[WhatIf] Would add $BaselineRdp to $rdpGroupName" }
    }
    catch { Write-ADAutomationLog "ERROR processing computer '$serverId' (continuing): $($_.Exception.Message)" 'ERROR' }

    # Throttle BETWEEN computers so PauseSeconds actually paces DC writes.
    if ($PauseSeconds -gt 0) { Start-Sleep -Seconds $PauseSeconds }
}

Write-ADAutomationLog "=== END === ComputersProcessed=$(@($computers).Count) AdminNested=$addedAdmin RdpNested=$addedRdp" 'INFO'
Write-Output "Done. Computers processed (deduped): $(@($computers).Count)"
Write-Output "Baseline nested into Admin groups: $addedAdmin ; RDP groups: $addedRdp"
Write-Output "Log: $($run.LogPath)"
