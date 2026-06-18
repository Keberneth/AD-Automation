@{
    RootModule        = 'ADAutomation.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '328f28f7-792f-44d2-8537-718883d91592'
    Author            = 'AD-Automation'
    CompanyName       = 'AD-Automation'
    Copyright         = '(c) AD-Automation. All rights reserved.'
    Description       = 'Shared helpers for the AD-Automation script library: external configuration, logging, UTF-8 mail, manager lookup, HIBP k-anonymity, NT-hash masking and JSON state.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Import-ADAutomationConfig',
        'Initialize-ADAutomationLog',
        'Protect-ADAutomationDirectory',
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
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('ActiveDirectory', 'Automation', 'Security', 'Hygiene')
            ProjectUri = 'https://github.com/Keberneth/AD-Automation'
        }
    }
}
