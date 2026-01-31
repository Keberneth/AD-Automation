<#
.SYNOPSIS
Create per-computer Admin/RDP groups based on computers in one or more OUs and nest baseline groups.

.DESCRIPTION
- Reads computers from one or more OUs in $ComputerOUs
- Creates:
  - SRV-<ComputerName>-Administrators in $AdminGroupOU
  - SRV-<ComputerName>-RemoteDesktopUsers in $RDPGroupOU
- Nests:
  - Contoso-Server-Administrators into each SRV-<Computer>-Administrators
  - Contoso-Server-RDP into each SRV-<Computer>-RemoteDesktopUsers

.NOTES
- Requires RSAT ActiveDirectory module
- sAMAccountName max length is 20 characters; script generates a safe SamAccountName if needed.
- Idempotent and supports -WhatIf / -Verbose.
- LDAP filter values are escaped for stability.

Example usage:
.\Create-PerServerGroups.ps1 -ComputerOUs @(
  "OU=Windows Server 2025,OU=Servers,DC=contoso,DC=com",
  "OU=Windows Server 2022,OU=Servers,DC=contoso,DC=com",
  "OU=Windows Server 2019,OU=Servers,DC=contoso,DC=com"
) -WhatIf -Verbose
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    # Accept one or many DNs (OU or container) to search for computers
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerOUs = @(
        "OU=Windows Server 2025,OU=Servers,DC=contoso,DC=com",
        "OU=Windows Server 2022,OU=Servers,DC=contoso,DC=com"
    ),

    [ValidateNotNullOrEmpty()][string]$AdminGroupOU  = "OU=Server Administration,OU=Groups,DC=contoso,DC=com",
    [ValidateNotNullOrEmpty()][string]$RDPGroupOU    = "OU=Server Remote Desktop,OU=Groups,DC=contoso,DC=com",

    [ValidateNotNullOrEmpty()][string]$BaselineAdmin = "Contoso-Server-Administrators",
    [ValidateNotNullOrEmpty()][string]$BaselineRdp   = "Contoso-Server-RDP",

    [int]$PauseSeconds = 3,

    [ValidateNotNullOrEmpty()][string]$LogDirectory  = "C:\Logs\AD\GroupCreation"
)

Set-StrictMode -Version Latest
Import-Module ActiveDirectory -ErrorAction Stop

# --- Logging ---
try {
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }
} catch {
    Write-Warning "Could not ensure log directory '$LogDirectory'. $_"
}

$LogFile = Join-Path $LogDirectory ("GroupCreation_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

function Write-Log {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message)

    try {
        $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Add-Content -LiteralPath $LogFile -Value ("{0}`t{1}" -f $ts, $Message)
    } catch {
        Write-Warning "Failed writing to log '$LogFile'. $_"
    }
}

# --- Helpers ---

function Get-SafeSamAccountName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GroupName
    )

    # sAMAccountName max length = 20
    if ($GroupName.Length -le 20) { return $GroupName }

    # Deterministic short form: first 12 chars + "-" + 7-char hash = 20
    $prefix = $GroupName.Substring(0, 12)
    $bytes  = [System.Text.Encoding]::UTF8.GetBytes($GroupName)
    $hash   = (New-Object System.Security.Cryptography.SHA1Managed).ComputeHash($bytes)
    $hex    = -join ($hash[0..3] | ForEach-Object { $_.ToString("x2") }) # 8 hex chars
    return ("{0}-{1}" -f $prefix, $hex.Substring(0,7))
}

function Get-OrCreateAdGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    # Escape filter value (stability)
    $escapedName = [System.DirectoryServices.Protocols.LdapFilter]::Escape($Name)

    # Search by Name under the target OU to avoid collisions elsewhere
    $existing = Get-ADGroup -SearchBase $Path -LDAPFilter "(name=$escapedName)" -ErrorAction SilentlyContinue
    if ($existing) { return $existing }

    $sam = Get-SafeSamAccountName -GroupName $Name

    if ($PSCmdlet.ShouldProcess("Group '$Name' in '$Path'", "Create")) {
        New-ADGroup -Name $Name -SamAccountName $sam -GroupScope Global -GroupCategory Security -Path $Path `
            -Description $Description -ErrorAction Stop | Out-Null

        $created = Get-ADGroup -SearchBase $Path -LDAPFilter "(name=$escapedName)" -ErrorAction Stop
        Write-Log "CREATED group Name='$Name' Sam='$sam' DN='$($created.DistinguishedName)'"
        return $created
    }

    # WhatIf path: return a simulated object with DN-like string
    return [pscustomobject]@{
        Name              = $Name
        SamAccountName    = $sam
        DistinguishedName = "CN=$Name,$Path"
        Simulated         = $true
    }
}

function Ensure-GroupMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetGroupDn,
        [Parameter(Mandatory)][string]$MemberDn,
        [Parameter(Mandatory)][string]$MemberNameForLog
    )

    $target  = Get-ADGroup -Identity $TargetGroupDn -Properties member -ErrorAction Stop
    $members = @($target.member)

    if ($members -contains $MemberDn) {
        Write-Verbose "'$MemberNameForLog' already member of '$($target.SamAccountName)'"
        return $false
    }

    if ($PSCmdlet.ShouldProcess($target.SamAccountName, "Add member '$MemberNameForLog'")) {
        Add-ADGroupMember -Identity $TargetGroupDn -Members $MemberDn -Confirm:$false -ErrorAction Stop
        Write-Log "ADDED member='$MemberNameForLog' to group='$($target.SamAccountName)'"
        return $true
    }

    return $false
}

function Get-ComputersFromOUs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$SearchBases
    )

    $all = New-Object System.Collections.Generic.List[object]

    foreach ($ou in $SearchBases) {
        try {
            # Validate that the DN exists (OU or container) before querying
            Get-ADObject -Identity $ou -ErrorAction Stop | Out-Null

            $cs = Get-ADComputer -SearchBase $ou -Filter * -Properties Name, DistinguishedName
            foreach ($c in $cs) { $all.Add($c) }

            Write-Verbose "Loaded $($cs.Count) computers from '$ou'"
            Write-Log "LOADED ComputersFromOU='$ou' Count=$($cs.Count)"
        }
        catch {
            Write-Warning "Failed to read computers from search base '$ou'. $_"
            Write-Log "ERROR ReadingSearchBase='$ou' $_"
        }
    }

    # De-duplicate by DistinguishedName (safe even if same name exists in multiple places)
    return ($all | Sort-Object DistinguishedName -Unique | Sort-Object Name)
}

# --- Preflight baseline groups ---
$baselineAdminObj = Get-ADGroup -Identity $BaselineAdmin -ErrorAction Stop
$baselineRdpObj   = Get-ADGroup -Identity $BaselineRdp   -ErrorAction Stop

# --- Load computers from multiple OUs ---
$computers = Get-ComputersFromOUs -SearchBases $ComputerOUs
if (-not $computers -or $computers.Count -eq 0) {
    Write-Warning "No computer objects found in the provided OUs/search bases."
    Write-Host "ComputerOUs/SearchBases:"
    $ComputerOUs | ForEach-Object { Write-Host " - $_" }
    return
}

# --- Create groups and nest baseline groups ---
$addedAdmin = 0
$addedRdp   = 0

foreach ($c in $computers) {
    if (-not $c.Name) { continue }

    $serverId = $c.Name.TrimEnd('$')

    $adminGroupName = "SRV-$serverId-Administrators"
    $rdpGroupName   = "SRV-$serverId-RemoteDesktopUsers"

    $adminGroup = Get-OrCreateAdGroup -Name $adminGroupName -Path $AdminGroupOU `
        -Description "Per-server local admin delegation for $serverId"

    $rdpGroup = Get-OrCreateAdGroup -Name $rdpGroupName -Path $RDPGroupOU `
        -Description "Per-server RDP delegation for $serverId"

    # Nest baselines (skip if simulated WhatIf)
    if (-not ($adminGroup.PSObject.Properties.Match('Simulated'))) {
        if (Ensure-GroupMember -TargetGroupDn $adminGroup.DistinguishedName `
                -MemberDn $baselineAdminObj.DistinguishedName `
                -MemberNameForLog $BaselineAdmin) {
            $addedAdmin++
        }
    } else {
        Write-Host "[WhatIf] Would add $BaselineAdmin to $adminGroupName"
    }

    if (-not ($rdpGroup.PSObject.Properties.Match('Simulated'))) {
        if (Ensure-GroupMember -TargetGroupDn $rdpGroup.DistinguishedName `
                -MemberDn $baselineRdpObj.DistinguishedName `
                -MemberNameForLog $BaselineRdp) {
            $addedRdp++
        }
    } else {
        Write-Host "[WhatIf] Would add $BaselineRdp to $rdpGroupName"
    }
}

if ($PauseSeconds -gt 0) { Start-Sleep -Seconds $PauseSeconds }

Write-Host ""
Write-Host "Computer OUs searched:"
$ComputerOUs | ForEach-Object { Write-Host " - $_" }
Write-Host ""
Write-Host "Computers processed (deduped): $($computers.Count)"
Write-Host "Baseline nested into Admin groups: $addedAdmin"
Write-Host "Baseline nested into RDP groups:   $addedRdp"
Write-Host "Admin baseline: $BaselineAdmin"
Write-Host "RDP baseline:   $BaselineRdp"
Write-Host "Log: $LogFile"
Write-Host ""
