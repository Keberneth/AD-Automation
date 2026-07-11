#
# AD-Automation central settings (SAMPLE)
# ---------------------------------------------------------------------------
# Copy this file to  AD-Automation.settings.psd1  (same folder) and edit the
# values for YOUR environment. That real file is git-ignored so your domain
# details never get committed.
#
# You can also point the scripts at any path with either:
#   - the  -ConfigPath  parameter, or
#   - the  AD_AUTOMATION_CONFIG  environment variable.
#
# HOW IT WORKS
#   * Every key below matches a script PARAMETER name exactly.
#   * [Common] is applied to ALL scripts. A per-script section (e.g.
#     [DisableInactive]) overrides Common for that one script.
#   * Precedence:  built-in default  <  this file  <  value passed on the
#     command line. So a value you pass explicitly always wins.
#
# This is a PowerShell *data* file: it is read with Import-PowerShellDataFile,
# which only parses literals (no code runs), so it is safe to store on a DC.
# A .json file with the same structure is also supported.
# ---------------------------------------------------------------------------
@{

    # =======================================================================
    # Settings shared by every script
    # =======================================================================
    Common = @{
        # --- SMTP / e-mail --------------------------------------------------
        SmtpServer = 'smtp-relay.contoso.local'
        SmtpPort   = 25                       # 587 with MailUseSsl=$true for STARTTLS
        MailFrom   = 'ad-automation@contoso.local'
        MailUseSsl = $false                   # $true = require TLS to the relay

        # Optional authenticated relay. Create the file once, as the account the
        # scheduled task runs under, with:
        #   Get-Credential | Export-Clixml 'C:\ProgramData\AD-Automation\smtp.cred'
        # (DPAPI-encrypted to that user+machine; leave empty for anonymous relay)
        # MailCredentialPath = 'C:\ProgramData\AD-Automation\smtp.cred'

        # Where operational/admin mail goes (summaries, alerts).
        AdminMailTo = @('it-operations@contoso.local')

        # Root folder for logs/CSV/state. Hardened to a restricted ACL
        # (SYSTEM + Administrators + the running account only) on every run.
        OutputRoot = 'C:\ProgramData\AD-Automation'

        # --- Windows Event Log -----------------------------------------------
        # Mirror every log line to Event Viewer: Applications and Services Logs >
        # EventLogName, with one event SOURCE per script (filter by Source for a
        # per-script view). Event IDs: 1000 INFO, 1001 ACTION, 1002 WHATIF,
        # 1003 SKIP, 2000 WARN, 3000 ERROR. The log/sources are registered by the
        # installer (elevated) or automatically on the first SYSTEM/gMSA run.
        EventLogEnabled = $true
        EventLogName    = 'AD-Automation'

        # Target DC. Empty = auto-detect (PDC emulator) so it works in any domain.
        # NOTE: Server does NOT apply to Invoke-ADHygieneDeleteDisabledUsers (it
        # always resolves each domain's PDC emulator) or Invoke-ADLockoutNotify
        # (which uses DcServer / AllDomainControllers instead).
        Server = ''
    }

    # =======================================================================
    # Invoke-ADHygieneDisableInactive.ps1
    # =======================================================================
    DisableInactive = @{
        UserLimitToOUs    = @(
            'OU=Users,DC=contoso,DC=local',
            'OU=Contractors,DC=contoso,DC=local'
        )
        ComputerLimitToOUs = @(
            'OU=Workstations,DC=contoso,DC=local',
            'OU=Servers,DC=contoso,DC=local'
        )
        ServiceAccountOUs  = @('OU=Service Accounts,DC=contoso,DC=local')

        MoveDisabledUsersToOU           = 'OU=Disabled Users,DC=contoso,DC=local'
        MoveDisabledServiceAccountsToOU = 'OU=Disabled Service Accounts,DC=contoso,DC=local'
        MoveDisabledComputersToOU       = 'OU=Disabled Computers,DC=contoso,DC=local'

        UserInactiveForDays     = 90
        ServiceInactiveForDays  = 180
        ComputerInactiveForDays = 60

        MaxChanges       = 25                  # per-run blast-radius cap; 0 = unlimited
        # Where the -DryRun -EmailApprovalList package goes (this script uses MailTo,
        # not AdminMailTo). Set a real address once SMTP is configured.
        MailTo           = @('it-operations@contoso.local')
        # OPTIONAL: only used if you run with -RequireApprovalList (manual change-control).
        # Hands-off operation needs NO approval list - leave -RequireApprovalList off.
        ApprovalListPath = 'C:\ProgramData\AD-Automation\DisableInactive-ApprovalList.txt'

        IgnoreAccountsExact = @('Administrator', 'Guest', 'krbtgt', 'DefaultAccount', 'WDAGUtilityAccount')
        IgnoreAccountsRegex = @('^AZURE', '^MSOL', '^BTG', '^DWM-', '^SM_', '^HealthMailbox')
    }

    # =======================================================================
    # Invoke-ADHygieneDeleteDisabledUsers.ps1
    # =======================================================================
    DeleteDisabledUsers = @{
        # Empty = forest-wide (every domain). Set OUs to limit scope.
        UserLimitToOUs    = @()
        DisabledForDays   = 180
        DisableDateSource = 'ReplicationMetadata'   # ReplicationMetadata | WhenChanged | StampAttribute
        MaxDeletes        = 25                       # blast-radius cap; pass -Unlimited to lift
        # Where the -DryRun -EmailApprovalList package goes (this script uses MailTo).
        MailTo            = @('it-operations@contoso.local')
        # OPTIONAL: only used if you run with -RequireApprovalList (manual change-control).
        # Hands-off operation needs NO approval list.
        ApprovalListPath  = 'C:\ProgramData\AD-Automation\DeleteDisabled-ApprovalList.txt'

        IgnoreAccountsExact = @('Administrator', 'Guest', 'krbtgt', 'DefaultAccount', 'WDAGUtilityAccount')
        IgnoreAccountsRegex = @('^AZURE', '^MSOL', '^BTG', '^DWM-')
    }

    # =======================================================================
    # Invoke-ADLockoutNotify.ps1
    # =======================================================================
    LockoutNotify = @{
        LookbackMinutes      = 15
        DcServer             = ''       # empty = PDC emulator (where 4740 aggregates)
        AllDomainControllers = $false   # $true = query every DC (full coverage)
        NotifyUser           = $true    # also e-mail the locked-out user
    }

    # =======================================================================
    # Invoke-ADPasswordExpiryNotify.ps1
    # =======================================================================
    PasswordExpiryNotify = @{
        NotifyWindowDays = 14
        NotifyDays       = @()          # e.g. @(14,7,3,1) for discrete reminders only
        SearchScope      = 'Subtree'    # Base | OneLevel | Subtree
        UserLimitToOUs   = @()          # empty = whole domain
        IgnoreAccountsExact = @('Administrator', 'Guest', 'krbtgt')
    }

    # =======================================================================
    # Invoke-ADDisableInactiveWarning.ps1  (warn BEFORE a user is disabled)
    # =======================================================================
    DisableInactiveWarning = @{
        # Keep these in sync with the DisableInactive section so the projected disable
        # date and the set of ignored/service accounts match the actual disable job.
        UserInactiveForDays    = 90
        ServiceInactiveForDays = 180
        WarnDays               = @(14, 7, 1)   # warn this many days before the disable date
        UserLimitToOUs         = @(
            'OU=Users,DC=contoso,DC=local',
            'OU=Contractors,DC=contoso,DC=local'
        )
        # Extra recipients ALWAYS added on top of the user's manager.
        AdditionalMailTo       = @('it-operations@contoso.local')
        IncludeServiceAccounts = $false
        ServiceAccountOUs      = @('OU=Service Accounts,DC=contoso,DC=local')
        IgnoreAccountsExact    = @('Administrator', 'Guest', 'krbtgt', 'DefaultAccount', 'WDAGUtilityAccount')
        IgnoreAccountsRegex    = @('^AZURE', '^MSOL', '^BTG', '^DWM-', '^SM_', '^HealthMailbox')
    }

    # =======================================================================
    # Invoke-ADDuplicatePasswordNotify.ps1  (new account shares a password)
    #   Requires DSInternals + replication (DCSync) rights.
    # =======================================================================
    DuplicatePasswordNotify = @{
        MailTo          = @('security-team@contoso.local')
        IncludeComputers = $false
        WriteHashCsv    = $false        # $true writes full NTLM hashes to a restricted CSV
    }

    # =======================================================================
    # Invoke-ADPasswordChangeAudit.ps1  (on password change: duplicate + pwned)
    #   Requires DSInternals + replication (DCSync) rights.
    # =======================================================================
    PasswordChangeAudit = @{
        MailTo           = @('security-team@contoso.local')
        IncludeComputers = $false
        CheckPwned       = $true        # query Have I Been Pwned (k-anonymity)
        WriteHashCsv     = $false
    }

    # =======================================================================
    # Invoke-ADServerGroupProvisioning.ps1  (per-server admin/RDP groups)
    # =======================================================================
    ServerGroupProvisioning = @{
        ComputerOUs   = @(
            'OU=Windows Server 2025,OU=Servers,DC=contoso,DC=local',
            'OU=Windows Server 2022,OU=Servers,DC=contoso,DC=local'
        )
        AdminGroupOU  = 'OU=Server Administration,OU=Groups,DC=contoso,DC=local'
        RDPGroupOU    = 'OU=Server Remote Desktop,OU=Groups,DC=contoso,DC=local'
        BaselineAdmin = 'Contoso-Server-Administrators'
        BaselineRdp   = 'Contoso-Server-RDP'
        # Scope for the per-server resource groups: DomainLocal (AGDLP, default) |
        # Global | Universal. DomainLocal can nest baseline Global/Universal groups.
        GroupScope    = 'DomainLocal'
    }
}
