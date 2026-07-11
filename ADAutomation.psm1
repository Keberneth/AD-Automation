<#
.SYNOPSIS
ADAutomation - shared helper module for the AD-Automation script library.

.DESCRIPTION
Central place for everything the standalone scripts share, so behaviour stays
consistent and an administrator can configure the whole library from ONE
external settings file without editing any script:

  - Import-ADAutomationConfig    : load settings from an external .psd1/.json file
  - Initialize-ADAutomationLog   : create the run log + output folder
  - Write-ADAutomationLog        : timestamped logging to console + file + Event Log
  - Register-ADAutomationEventLog: create the AD-Automation Windows Event Log
                                   (one event source per script; admin, one-time)
  - Send-ADAutomationMail        : UTF-8 mail, optional TLS + authentication
  - Resolve-ADManagerMail        : read the 'manager' attribute -> manager e-mail
  - Resolve-ADObjectMail         : read the 'mail' attribute of any account
  - Get-ADAutomationDomainInfo   : auto-detect domain (DN, DNS root, PDC emulator)
  - Test-IsIgnoredName           : exact + regex ignore-list matching
  - Get-ValidSearchBase          : validate OU/container search bases
  - Test-DNUnderOU / Get-ParentDN: distinguished-name helpers
  - Convert-NtHashToHex          : DSInternals NTHash bytes -> hex string
  - Format-MaskedNtHash          : safe (non-reversible) hash label for reports
  - Test-NtlmHashPwned           : Have I Been Pwned range API (k-anonymity)
  - Read-ADAutomationState /
    Save-ADAutomationState       : JSON state files for delta detection

.NOTES
Targets Windows PowerShell 5.1 and PowerShell 7+. No third-party modules are
required by the module itself; ActiveDirectory / DSInternals are imported by the
individual scripts only when they need them.
#>

Set-StrictMode -Version Latest

$script:ModuleRoot = $PSScriptRoot
$script:ADAutomationLogPath = $null

# Per-process random salt for hash-group labels. Never persisted, so a label can
# never be reversed to hash material across processes; stable within one run so
# accounts sharing a password get the same label in a single report/e-mail.
$script:ADAutomationMaskSalt = [guid]::NewGuid().ToByteArray()

# Regex patterns already reported as invalid, so an unattended run warns once per
# bad pattern instead of on every account it is tested against.
$script:ADAutomationBadRegex = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)

# Windows Event Log mirroring (set up by Initialize-ADAutomationLog). One custom
# log ('AD-Automation' under Applications and Services Logs) with one event SOURCE
# per script - Windows caps custom log names at 8 significant characters, so one
# log per script would collide; filtering by Source gives per-script separation.
$script:ADAutomationEventLogName = $null
$script:ADAutomationEventSource = $null
$script:ADAutomationEventLogEnabled = $false

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

function ConvertTo-ADAutomationHashtable {
    <#
    .SYNOPSIS
    Recursively converts a PSCustomObject (e.g. from ConvertFrom-Json) into a
    case-insensitive hashtable so it behaves like an Import-PowerShellDataFile result.
    #>
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)]$InputObject)

    process {
        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IDictionary]) {
            $ht = @{}
            foreach ($key in $InputObject.Keys) {
                $ht[$key] = ConvertTo-ADAutomationHashtable -InputObject $InputObject[$key]
            }
            return $ht
        }

        if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
            $ht = @{}
            foreach ($prop in $InputObject.PSObject.Properties) {
                $ht[$prop.Name] = ConvertTo-ADAutomationHashtable -InputObject $prop.Value
            }
            return $ht
        }

        # Arrays (but not strings) -> map elements; strings/scalars pass through.
        # The unary comma stops the pipeline from unrolling the result, so a
        # single-element JSON array stays an array (and an empty one stays @()),
        # matching what Import-PowerShellDataFile would return for a .psd1.
        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            return , @($InputObject | ForEach-Object { ConvertTo-ADAutomationHashtable -InputObject $_ })
        }

        return $InputObject
    }
}

function Resolve-ADAutomationConfigPath {
    [CmdletBinding()]
    param([string]$Path)

    $candidates = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($Path)) { $candidates.Add($Path) }
    if (-not [string]::IsNullOrWhiteSpace($env:AD_AUTOMATION_CONFIG)) { $candidates.Add($env:AD_AUTOMATION_CONFIG) }
    $candidates.Add((Join-Path $script:ModuleRoot 'config\AD-Automation.settings.psd1'))
    $candidates.Add((Join-Path $script:ModuleRoot 'config\AD-Automation.settings.json'))
    $candidates.Add((Join-Path $script:ModuleRoot 'config\AD-Automation.settings.sample.psd1'))

    foreach ($c in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($c) -and (Test-Path -LiteralPath $c)) { return $c }
    }
    return $null
}

function Import-ADAutomationConfig {
    <#
    .SYNOPSIS
    Loads the external settings file and returns the effective settings for a script
    as a hashtable: the [Common] section overlaid by the named [Section].

    .DESCRIPTION
    Resolution order for the file: -Path, then $env:AD_AUTOMATION_CONFIG, then
    <module>\config\AD-Automation.settings.psd1 (or .json), then the committed
    .sample.psd1. .psd1 is loaded with Import-PowerShellDataFile (no code execution),
    .json with ConvertFrom-Json. If no file is found an empty hashtable is returned
    and the script falls back to its built-in parameter defaults.

    Keys in the returned hashtable are intended to match script parameter names 1:1.
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [string]$Section
    )

    # A path the caller explicitly asked for (parameter or environment variable)
    # must exist. Silently falling through to the committed sample would make an
    # unattended run execute with placeholder settings after a simple typo.
    if (-not [string]::IsNullOrWhiteSpace($Path) -and -not (Test-Path -LiteralPath $Path)) {
        throw "AD-Automation config path not found: '$Path' (from -Path/-ConfigPath)."
    }
    if (-not [string]::IsNullOrWhiteSpace($env:AD_AUTOMATION_CONFIG) -and -not (Test-Path -LiteralPath $env:AD_AUTOMATION_CONFIG)) {
        throw "AD-Automation config path not found: '$env:AD_AUTOMATION_CONFIG' (from `$env:AD_AUTOMATION_CONFIG)."
    }

    $file = Resolve-ADAutomationConfigPath -Path $Path
    if (-not $file) {
        Write-Verbose "AD-Automation: no settings file found; using built-in defaults."
        return @{}
    }

    # Landing on the committed sample means no real settings file exists yet; warn
    # loudly because the placeholder 'contoso' values are almost never what an
    # operator intends for a real (especially destructive) run.
    if ($file -like '*settings.sample.psd1') {
        Write-Warning "AD-Automation: using the committed SAMPLE settings ($file) - no real config found. Copy it to config\AD-Automation.settings.psd1 and edit it for your environment."
    }

    try {
        $ext = [System.IO.Path]::GetExtension($file).ToLowerInvariant()
        if ($ext -eq '.psd1') {
            $data = Import-PowerShellDataFile -LiteralPath $file -ErrorAction Stop
        }
        elseif ($ext -eq '.json') {
            $raw = Get-Content -LiteralPath $file -Raw -ErrorAction Stop
            $data = ConvertTo-ADAutomationHashtable -InputObject (ConvertFrom-Json $raw)
        }
        else {
            throw "Unsupported settings file extension '$ext' (use .psd1 or .json)."
        }
    }
    catch {
        throw "Failed to load AD-Automation settings from '$file': $($_.Exception.Message)"
    }

    if ($null -eq $data) { return @{} }

    # Start from the Common section (case-insensitive lookup).
    $effective = @{}
    if ($data.ContainsKey('Common') -and $data['Common'] -is [System.Collections.IDictionary]) {
        foreach ($k in $data['Common'].Keys) { $effective[$k] = $data['Common'][$k] }
    }

    # Overlay the requested script-specific section.
    if (-not [string]::IsNullOrWhiteSpace($Section) -and $data.ContainsKey($Section) -and $data[$Section] -is [System.Collections.IDictionary]) {
        foreach ($k in $data[$Section].Keys) { $effective[$k] = $data[$Section][$k] }
    }

    $effective['__ConfigFile'] = $file
    return $effective
}

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------

function Protect-ADAutomationDirectory {
    <#
    .SYNOPSIS
    Hardens an output directory's ACL so the reports/logs/state it holds (which
    enumerate account names, OUs, expiry dates, masked hashes, etc.) are readable
    only by SYSTEM, the local Administrators group, and the account running the
    script. Inheritance is disabled and inherited ACEs are dropped. Best-effort:
    failures are logged as a warning, never thrown (the script keeps working even
    if it lacks the right to change the ACL).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, drop inherited ACEs

        $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
        $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $prop = [System.Security.AccessControl.PropagationFlags]::None
        $allow = [System.Security.AccessControl.AccessControlType]::Allow

        # SYSTEM (S-1-5-18) and BUILTIN\Administrators (S-1-5-32-544) - locale independent.
        foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
            $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, $rights, $inherit, $prop, $allow)))
        }

        # The account running this script (so an unattended service account keeps access).
        try {
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, $rights, $inherit, $prop, $allow)))
        }
        catch { }

        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    }
    catch {
        Write-ADAutomationLog "Could not harden ACL on '$Path' (continuing): $($_.Exception.Message)" 'WARN'
    }
}

function Register-ADAutomationEventLog {
    <#
    .SYNOPSIS
    Ensures the AD-Automation Windows Event Log and one event source per script
    exist (Event Viewer: Applications and Services Logs > <LogName>).

    .DESCRIPTION
    Creating a log/source writes HKLM registry keys and therefore needs
    administrative rights - a one-time operation. The installer calls this while
    elevated; scheduled runs as SYSTEM/gMSA also auto-register on first use.
    Uses the .NET EventLog API directly so it works on Windows PowerShell 5.1 AND
    PowerShell 7 (which removed New-EventLog/Write-EventLog). Never throws; returns
    $true when every source is usable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LogName,
        [Parameter(Mandatory = $true)][string[]]$Sources
    )

    $allOk = $true
    foreach ($src in $Sources) {
        if ([string]::IsNullOrWhiteSpace($src)) { continue }
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($src)) {
                $data = New-Object System.Diagnostics.EventSourceCreationData($src, $LogName)
                [System.Diagnostics.EventLog]::CreateEventSource($data)
            }
            elseif ([System.Diagnostics.EventLog]::LogNameFromSourceName($src, '.') -ne $LogName) {
                Write-Warning "Event source '$src' is already registered to another log ('$([System.Diagnostics.EventLog]::LogNameFromSourceName($src, '.'))'); leaving it as-is."
                $allOk = $false
            }
        }
        catch {
            # Typically 'requested registry access is not allowed' when not elevated.
            Write-Warning "Could not register event source '$src' in log '$LogName' (needs admin once): $($_.Exception.Message)"
            $allOk = $false
        }
    }

    # Give the log a sane retention policy (defaults are tiny). Best-effort.
    try {
        $el = New-Object System.Diagnostics.EventLog($LogName)
        if ($el.MaximumKilobytes -lt 16384) { $el.MaximumKilobytes = 16384 }
        $el.ModifyOverflowPolicy([System.Diagnostics.OverflowAction]::OverwriteAsNeeded, 7)
        $el.Dispose()
    }
    catch { }

    return $allOk
}

function Write-ADAutomationEventLogEntry {
    # Internal: mirror one log line to the Windows Event Log. Disables itself on the
    # first failure (e.g. source not yet registered and no rights to create it) so an
    # unattended run degrades to console+file logging with a single notice.
    param([string]$Message, [string]$Level)

    if (-not $script:ADAutomationEventLogEnabled) { return }

    $entryType = switch ($Level) {
        'ERROR' { [System.Diagnostics.EventLogEntryType]::Error }
        'WARN'  { [System.Diagnostics.EventLogEntryType]::Warning }
        default { [System.Diagnostics.EventLogEntryType]::Information }
    }
    $eventId = switch ($Level) {
        'INFO'   { 1000 }
        'ACTION' { 1001 }
        'WHATIF' { 1002 }
        'SKIP'   { 1003 }
        'WARN'   { 2000 }
        'ERROR'  { 3000 }
        default  { 1000 }
    }

    try {
        [System.Diagnostics.EventLog]::WriteEntry($script:ADAutomationEventSource, $Message, $entryType, $eventId)
    }
    catch {
        $script:ADAutomationEventLogEnabled = $false
        # Write-Host directly - Write-ADAutomationLog would recurse into this function.
        Write-Host "[WARN] Event Log mirroring disabled for this run (source '$($script:ADAutomationEventSource)' in log '$($script:ADAutomationEventLogName)'): $($_.Exception.Message). Run the installer elevated (or any script once as admin/SYSTEM) to register it." -ForegroundColor Yellow
    }
}

function Initialize-ADAutomationLog {
    <#
    .SYNOPSIS
    Ensures the output folder exists (with a hardened ACL by default) and creates a
    timestamped run log. Returns an object with RunId / OutputRoot / LogPath.
    Subsequent calls to Write-ADAutomationLog write to this log - and, when
    -EventLogEnabled, mirror to the Windows Event Log (Applications and Services
    Logs > <EventLogName>) under a per-script event source.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$BaseName,
        [bool]$Harden = $true,
        [bool]$EventLogEnabled = $true,
        [string]$EventLogName = 'AD-Automation',
        # Event source shown in Event Viewer; defaults to BaseName (one per script).
        [string]$EventLogSource = ''
    )

    if (-not (Test-Path -LiteralPath $OutputRoot)) {
        New-Item -ItemType Directory -Force -Path $OutputRoot -ErrorAction Stop | Out-Null
    }

    # Harden on EVERY run, not only when we created the folder. The documented
    # setup pre-creates this folder (smtp.cred, approval lists), and a folder that
    # already exists otherwise keeps the permissive inherited C:\ProgramData ACL -
    # leaving logs, PII reports, state and full-hash CSVs readable by all users.
    # Protect-ADAutomationDirectory is idempotent and best-effort (never throws).
    if ($Harden) { Protect-ADAutomationDirectory -Path $OutputRoot }

    # RunId includes the PID so two runs in the same second cannot collide.
    $runId = "{0}-{1}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $PID
    $logPath = Join-Path $OutputRoot ("{0}-{1}.log" -f $BaseName, $runId)
    New-Item -ItemType File -Force -Path $logPath -ErrorAction Stop | Out-Null
    $script:ADAutomationLogPath = $logPath

    # Windows Event Log mirroring: one shared log, one source per script. Source
    # registration needs admin once; scheduled runs (SYSTEM/gMSA, elevated) register
    # automatically, and a non-admin interactive run degrades gracefully.
    $script:ADAutomationEventLogEnabled = $false
    if ($EventLogEnabled) {
        $src = if ([string]::IsNullOrWhiteSpace($EventLogSource)) { $BaseName } else { $EventLogSource }
        $script:ADAutomationEventLogName = $EventLogName
        $script:ADAutomationEventSource = $src
        [void](Register-ADAutomationEventLog -LogName $EventLogName -Sources @($src) -WarningAction SilentlyContinue)
        # Enable optimistically; the first failed write disables it with one notice.
        $script:ADAutomationEventLogEnabled = $true
    }

    return [pscustomobject]@{
        RunId      = $runId
        OutputRoot = $OutputRoot
        LogPath    = $logPath
    }
}

function Write-ADAutomationLog {
    <#
    .SYNOPSIS
    Writes a timestamped, levelled log line to the console and to the active run log.
    Uses Write-Host (not the success stream) so logging never pollutes a captured pipeline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'ACTION', 'WHATIF', 'SKIP')][string]$Level = 'INFO',
        [string]$Path
    )

    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][$Level] $Message"

    $target = $Path
    if ([string]::IsNullOrWhiteSpace($target)) { $target = $script:ADAutomationLogPath }

    $color = switch ($Level) {
        'ERROR'  { 'Red' }
        'WARN'   { 'Yellow' }
        'ACTION' { 'Green' }
        'WHATIF' { 'Cyan' }
        'SKIP'   { 'DarkGray' }
        default  { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color

    if (-not [string]::IsNullOrWhiteSpace($target)) {
        try { Add-Content -LiteralPath $target -Value $line -Encoding UTF8 -ErrorAction Stop }
        catch { Write-Host "[$ts][ERROR] Failed to write log file '$target': $($_.Exception.Message)" -ForegroundColor Red }
    }

    Write-ADAutomationEventLogEntry -Message $Message -Level $Level
}

# ----------------------------------------------------------------------------
# Mail
# ----------------------------------------------------------------------------

function Get-ADAutomationMailCredential {
    <#
    .SYNOPSIS
    Loads SMTP credentials for authenticated relays without storing a plaintext
    password in code. Accepts either an exported PSCredential CLIXML file
    (Export-Clixml, machine/user-bound DPAPI) or an inline PSCredential.
    #>
    [CmdletBinding()]
    param(
        [pscredential]$Credential,
        [string]$CredentialPath
    )

    if ($Credential) { return $Credential }
    if (-not [string]::IsNullOrWhiteSpace($CredentialPath)) {
        if (-not (Test-Path -LiteralPath $CredentialPath)) {
            throw "SMTP credential file not found: '$CredentialPath'."
        }
        try { return (Import-Clixml -LiteralPath $CredentialPath) }
        catch { throw "Failed to import SMTP credential from '$CredentialPath': $($_.Exception.Message)" }
    }
    return $null
}

function Send-ADAutomationMail {
    <#
    .SYNOPSIS
    Sends mail via an SMTP relay with UTF-8 encoding (so Swedish characters survive),
    optional STARTTLS and optional authentication. Recipients are de-duplicated and
    validated. Returns $true on success, $false on failure (logged, never throws).

    .NOTES
    Send-MailMessage is used for broad compatibility with internal relays. Microsoft
    flags it as obsolete; prefer -UseSsl (and -Credential / -CredentialPath) when the
    relay supports it. For hardened environments replace this one function with a
    MailKit-based implementation - no script changes required.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$To,
        [Parameter(Mandatory = $true)][string]$Subject,
        [Parameter(Mandatory = $true)][string]$Body,
        [string[]]$Cc,
        [string[]]$Attachments = @(),
        [Parameter(Mandatory = $true)][string]$From,
        [Parameter(Mandatory = $true)][string]$SmtpServer,
        [int]$SmtpPort = 25,
        [bool]$UseSsl = $false,
        [bool]$BodyAsHtml = $false,
        [pscredential]$Credential,
        [string]$CredentialPath
    )

    # Strip control characters (incl. CR/LF) from the subject: a newline in an AD
    # attribute (e.g. displayName) interpolated into the subject otherwise makes
    # System.Net.Mail throw - silently dropping the message - and would be header
    # injection under any mailer that does not reject bare CRLF.
    $Subject = (($Subject -replace '[\x00-\x1F\x7F]', ' ').Trim())
    if ($Subject.Length -gt 512) { $Subject = $Subject.Substring(0, 512) }

    $recipients = @($To | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Sort-Object -Unique)
    if ($recipients.Count -eq 0) {
        Write-ADAutomationLog "Send-ADAutomationMail: no valid recipients for subject '$Subject'; skipping." 'WARN'
        return $false
    }

    foreach ($a in $Attachments) {
        if (-not [string]::IsNullOrWhiteSpace($a) -and -not (Test-Path -LiteralPath $a)) {
            Write-ADAutomationLog "Send-ADAutomationMail: attachment not found '$a'; skipping send." 'ERROR'
            return $false
        }
    }

    $params = @{
        SmtpServer  = $SmtpServer
        Port        = $SmtpPort
        From        = $From
        To          = $recipients
        Subject     = $Subject
        Body        = $Body
        BodyAsHtml  = $BodyAsHtml
        UseSsl      = $UseSsl
        Encoding    = ([System.Text.Encoding]::UTF8)
        ErrorAction = 'Stop'
        WarningAction = 'SilentlyContinue'   # suppress the Send-MailMessage obsolescence warning
    }
    $cleanCc = @($Cc | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($cleanCc.Count -gt 0) { $params['Cc'] = $cleanCc }
    $realAttach = @($Attachments | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($realAttach.Count -gt 0) { $params['Attachments'] = $realAttach }

    $cred = Get-ADAutomationMailCredential -Credential $Credential -CredentialPath $CredentialPath
    if ($cred) { $params['Credential'] = $cred }

    try {
        Send-MailMessage @params
        Write-ADAutomationLog "Mail sent to '$($recipients -join ', ')' subject='$Subject'" 'ACTION'
        return $true
    }
    catch {
        Write-ADAutomationLog "ERROR sending mail to '$($recipients -join ', ')' subject='$Subject': $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

# ----------------------------------------------------------------------------
# Directory helpers
# ----------------------------------------------------------------------------

function Get-ADAutomationDomainInfo {
    <#
    .SYNOPSIS
    Returns domain context so scripts work against ANY domain without hardcoding.
    Output: DistinguishedName, DnsRoot, NetBIOSName, PdcEmulator, Server.
    #>
    [CmdletBinding()]
    param([string]$Server)

    $params = @{ ErrorAction = 'Stop' }
    if (-not [string]::IsNullOrWhiteSpace($Server)) { $params['Server'] = $Server }
    $d = Get-ADDomain @params

    return [pscustomobject]@{
        DistinguishedName = $d.DistinguishedName
        DnsRoot           = $d.DNSRoot
        NetBIOSName       = $d.NetBIOSName
        PdcEmulator       = $d.PDCEmulator
        Server            = $(if ([string]::IsNullOrWhiteSpace($Server)) { $d.PDCEmulator } else { $Server })
    }
}

function Test-IsIgnoredName {
    <#
    .SYNOPSIS
    True if a sAMAccountName matches an exact ignore entry or any ignore regex.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string[]]$ExactList,
        [string[]]$RegexList
    )

    if ($ExactList) {
        foreach ($e in $ExactList) {
            if (-not [string]::IsNullOrWhiteSpace($e) -and $e.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
    }
    if ($RegexList) {
        foreach ($pattern in $RegexList) {
            if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
            try {
                if ([System.Text.RegularExpressions.Regex]::IsMatch($Name, $pattern)) { return $true }
            }
            catch {
                # A malformed ignore pattern (config typo) must NOT abort the run or
                # silently strip protection. Treat the account as ignored (the safe,
                # no-action outcome for the destructive callers) and warn once.
                if ($script:ADAutomationBadRegex.Add($pattern)) {
                    Write-ADAutomationLog "Invalid ignore-list regex '$pattern' ($($_.Exception.Message)); treating matching accounts as IGNORED until it is fixed." 'WARN'
                }
                return $true
            }
        }
    }
    return $false
}

function Get-ValidSearchBase {
    <#
    .SYNOPSIS
    Validates that each supplied search base exists (OU OR container) and returns
    only the valid ones. Invalid bases are logged and skipped so a single typo never
    aborts an unattended run.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Bases,
        [string]$Server
    )

    $valid = New-Object System.Collections.Generic.List[string]
    foreach ($b in $Bases) {
        if ([string]::IsNullOrWhiteSpace($b)) { continue }
        $p = @{ Identity = $b; ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) { $p['Server'] = $Server }
        try {
            # Get-ADObject accepts OUs *and* containers (e.g. CN=Users), unlike Get-ADOrganizationalUnit.
            $null = Get-ADObject @p
            $valid.Add($b)
        }
        catch {
            Write-ADAutomationLog "Search base not found/invalid (skipping): $b" 'WARN'
        }
    }
    return $valid.ToArray()
}

function Get-ParentDN {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)
    return ($DistinguishedName -replace '^(?:[^,\\]|\\.)+,', '')
}

function Test-DNUnderOU {
    <#
    .SYNOPSIS
    True if a distinguished name is located at or under the given OU/container DN.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][string]$OUDistinguishedName
    )
    if ([string]::IsNullOrWhiteSpace($OUDistinguishedName)) { return $false }
    return ($DistinguishedName -match (",{0}$" -f [regex]::Escape($OUDistinguishedName)))
}

function Resolve-ADObjectMail {
    <#
    .SYNOPSIS
    Returns the 'mail' attribute of an account (any object class), or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Identity,
        [string]$Server
    )
    $p = @{ Identity = $Identity; Properties = 'mail'; ErrorAction = 'Stop' }
    if (-not [string]::IsNullOrWhiteSpace($Server)) { $p['Server'] = $Server }
    try {
        $o = Get-ADObject @p
        if ($o -and -not [string]::IsNullOrWhiteSpace($o.mail)) { return [string]$o.mail }
        return $null
    }
    catch {
        # A manager DN can legitimately live in another domain of the forest, where
        # the domain DC pinned in -Server returns ObjectNotFound. Retry once against
        # a global catalog (port 3268) before giving up, so cross-domain managers
        # are still resolved instead of silently degrading to the fallback list.
        try {
            if (-not [string]::IsNullOrWhiteSpace($Server)) {
                $gcHost = ($Server -split ':')[0]
            }
            else {
                $gcHost = @((Get-ADDomainController -Discover -Service GlobalCatalog -ErrorAction Stop).HostName)[0]
            }
            $o = Get-ADObject -Identity $Identity -Properties mail -Server ("{0}:3268" -f $gcHost) -ErrorAction Stop
            if ($o -and -not [string]::IsNullOrWhiteSpace($o.mail)) { return [string]$o.mail }
        }
        catch {
            Write-ADAutomationLog "Could not resolve mail for '$Identity' (incl. global-catalog retry): $($_.Exception.Message)" 'WARN'
        }
    }
    return $null
}

function Resolve-ADManagerMail {
    <#
    .SYNOPSIS
    Resolves the e-mail address of an account's manager. Returns $null when the
    'manager' attribute is empty or the manager has no mail - callers should treat
    $null as "no manager notification, continue".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$AdUser,
        [string]$Server
    )

    $managerDn = $null
    if ($AdUser.PSObject.Properties.Match('manager').Count -gt 0) { $managerDn = $AdUser.manager }
    if ([string]::IsNullOrWhiteSpace($managerDn)) { return $null }

    return (Resolve-ADObjectMail -Identity $managerDn -Server $Server)
}

# ----------------------------------------------------------------------------
# Password / hash helpers
# ----------------------------------------------------------------------------

function Convert-NtHashToHex {
    <#
    .SYNOPSIS
    Converts DSInternals NTHash bytes to an upper-case hex string, or $null.
    #>
    [CmdletBinding()]
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Count -eq 0) { return $null }
    return (-join ($Bytes | ForEach-Object { $_.ToString('x2') })).ToUpperInvariant()
}

function Format-MaskedNtHash {
    <#
    .SYNOPSIS
    Returns a NON-reversible label for an NTLM hash so reports/e-mails can reference
    a shared-password group without exposing any hash material.

    .DESCRIPTION
    The label is SHA-256 over a random per-process salt plus the hash, truncated to
    32 bits and rendered as 'grp:XXXXXXXX'. Because the salt is random per run and
    never persisted, the label leaks no bits of the real hash (unlike the old
    first5...last4 form, whose 5-char prefix was exactly the HIBP k-anonymity prefix
    and whose 9 exposed hex chars were enough to recover the full hash from the
    public HIBP range API / an offline dictionary attack). Within a single run the
    same hash always yields the same label, so accounts sharing a password still
    correlate in the report and e-mail.
    #>
    [CmdletBinding()]
    param([string]$NtlmHash)
    if ([string]::IsNullOrWhiteSpace($NtlmHash)) { return '<none>' }
    $h = $NtlmHash.Trim().ToUpperInvariant()
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = @($script:ADAutomationMaskSalt) + [System.Text.Encoding]::ASCII.GetBytes($h)
        $digest = $sha.ComputeHash([byte[]]$bytes)
    }
    finally { $sha.Dispose() }
    $hex = -join ($digest[0..3] | ForEach-Object { $_.ToString('x2') })
    return ('grp:{0}' -f $hex.ToUpperInvariant())
}

function Test-NtlmHashPwned {
    <#
    .SYNOPSIS
    Checks an NTLM hash against the Have I Been Pwned Pwned Passwords range API using
    k-anonymity: only the first 5 hex characters are ever sent; matching is local.
    Returns an object { Pwned = Yes|No|LookupFailed ; PwnedCount }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$NtlmHash)

    $h = $NtlmHash.Trim().ToUpperInvariant()
    if ($h -notmatch '^[A-F0-9]{32}$') {
        throw "Invalid NTLM hash format: $NtlmHash"
    }

    $prefix = $h.Substring(0, 5)
    $suffix = $h.Substring(5)
    $uri = 'https://api.pwnedpasswords.com/range/{0}?mode=ntlm' -f $prefix

    # Force TLS 1.2 on Windows PowerShell 5.1 (no-op / harmless on PS7).
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

    try {
        $response = Invoke-WebRequest -Uri $uri -Method Get -Headers @{
            'User-Agent'  = 'AD-Automation'
            'Add-Padding' = 'true'
        } -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
    }
    catch {
        Write-ADAutomationLog "HIBP lookup failed for prefix $prefix : $($_.Exception.Message)" 'WARN'
        return [pscustomobject]@{ Pwned = 'LookupFailed'; PwnedCount = $null }
    }

    if ([string]::IsNullOrWhiteSpace($response.Content)) {
        return [pscustomobject]@{ Pwned = 'No'; PwnedCount = 0 }
    }

    foreach ($line in ($response.Content -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = $line.Split(':', 2)
        if ($parts.Count -ne 2) { continue }

        $returnedSuffix = $parts[0].Trim().ToUpperInvariant()
        $countText = $parts[1].Trim()
        if ($countText -eq '0') { continue }   # padded fake row (Add-Padding=true)

        if ($returnedSuffix -eq $suffix) {
            $countValue = [int64]0
            [void][int64]::TryParse($countText, [ref]$countValue)
            return [pscustomobject]@{ Pwned = 'Yes'; PwnedCount = $countValue }
        }
    }

    return [pscustomobject]@{ Pwned = 'No'; PwnedCount = 0 }
}

# ----------------------------------------------------------------------------
# State (delta detection for new-user / password-change scripts)
# ----------------------------------------------------------------------------

function Get-ADAutomationStatePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $stateDir = Join-Path $OutputRoot 'state'
    if (-not (Test-Path -LiteralPath $stateDir)) {
        New-Item -ItemType Directory -Force -Path $stateDir -ErrorAction Stop | Out-Null
    }
    return (Join-Path $stateDir ("{0}.json" -f $Name))
}

function Read-ADAutomationState {
    <#
    .SYNOPSIS
    Reads a JSON state file and returns a PSCustomObject, or $null if it does not exist.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    # Absent (or empty) state is a legitimate first run -> $null.
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    try {
        return (ConvertFrom-Json $raw)
    }
    catch {
        # A present-but-corrupt state file is NOT a first run. Swallowing it would
        # silently re-baseline (suppressing duplicate/pwned/lockout alerts for a
        # whole cycle), so fail closed: surface the error and let the run abort.
        Write-ADAutomationLog "State file '$Path' exists but is unreadable/corrupt: $($_.Exception.Message)" 'ERROR'
        throw "Corrupt state file '$Path' - refusing to re-baseline. Inspect or delete it to reset intentionally: $($_.Exception.Message)"
    }
}

function Save-ADAutomationState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$State
    )
    try {
        $json = $State | ConvertTo-Json -Depth 8
        # Write atomically: a crash/power-loss mid-write must not leave a truncated
        # file that the next run would read as corrupt (or, previously, as empty and
        # silently re-baseline). Write a sibling temp file, then replace in one step.
        $tmp = "{0}.tmp.{1}" -f $Path, $PID
        Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $tmp -Destination $Path -Force -ErrorAction Stop
    }
    catch {
        if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        Write-ADAutomationLog "Could not write state file '$Path': $($_.Exception.Message)" 'ERROR'
    }
}

Export-ModuleMember -Function @(
    'Import-ADAutomationConfig',
    'Initialize-ADAutomationLog',
    'Protect-ADAutomationDirectory',
    'Register-ADAutomationEventLog',
    'Write-ADAutomationLog',
    'Send-ADAutomationMail',
    'Get-ADAutomationDomainInfo',
    'Test-IsIgnoredName',
    'Get-ValidSearchBase',
    'Get-ParentDN',
    'Test-DNUnderOU',
    'Resolve-ADObjectMail',
    'Resolve-ADManagerMail',
    'Convert-NtHashToHex',
    'Format-MaskedNtHash',
    'Test-NtlmHashPwned',
    'Get-ADAutomationStatePath',
    'Read-ADAutomationState',
    'Save-ADAutomationState'
)
