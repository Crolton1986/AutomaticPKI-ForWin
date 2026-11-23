@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Write-Host is not used; logging goes through Write-APKILog.
        'PSAvoidUsingWriteHost'
    )
    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.4')
        }
        PSUseCompatibleCmdlets = @{
            Compatibility = @('desktop-5.1.14393.206-windows')
        }
    }
}
