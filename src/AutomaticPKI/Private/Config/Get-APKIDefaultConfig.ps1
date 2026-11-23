function Get-APKIDefaultConfig {
    <#
    .SYNOPSIS
        Returns a fresh copy of the default global configuration (docs/contracts.md, config.json).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    [pscustomobject]@{
        RenewalDaysBefore       = 30
        OldCertRetentionDays    = 14
        DefaultProvider         = 'AdcsRpc'
        DefaultProviderSettings = [pscustomobject]@{
            CAConfig = ''
            Template = 'WebServer'
        }
        Smtp                    = [pscustomobject]@{
            Enabled       = $false
            Server        = ''
            Port          = 25
            UseSsl        = $true
            From          = ''
            To            = @()
            CredentialRef = $null
        }
        LogRetentionDays        = 30
        RevocationPolicy        = 'Strict'
    }
}
